/*
 * icmp.c - ICMP Echo handler and error message generation
 */

#include "icmp.h"
#include "ethernet.h"
#include "arp.h"
#include "routing.h"
#include "netdev.h"
#include "stats.h"
#include "router.h"
#include <string.h>
#include <stdio.h>

/* ── Checksum helper (re-use from ipv4.c via extern) ───────────────────── */
extern u16 ip4_checksum(const void *data, u32 len);

/* ── Build and transmit a raw ICMP packet ───────────────────────────────── */
void icmp_send_raw(u32 src_ip4, u32 dst_ip4,
                   const u8 dst_mac[ETH_ALEN],
                   int egress_iface_idx,
                   u8 type, u8 code,
                   u32 rest_of_header,
                   const u8 *payload, u32 payload_len)
{
    netdev_iface_t *iface = netdev_find_by_index(egress_iface_idx);
    if (!iface) return;

    /* Limit payload to avoid exceeding MTU */
    if (payload_len > 548) payload_len = 548;   /* 576 - 20(IP) - 8(ICMP) */

    /* ── Build ICMP message ── */
    u8 icmp_buf[8 + 548];
    icmp_hdr_t *icmp = (icmp_hdr_t *)icmp_buf;
    icmp->type     = type;
    icmp->code     = code;
    icmp->checksum = 0;
    icmp->un.unused = htonl(rest_of_header);

    u32 icmp_len = (u32)ICMP_HDR_LEN + payload_len;
    if (payload && payload_len)
        memcpy(icmp_buf + ICMP_HDR_LEN, payload, payload_len);

    icmp->checksum = ip4_checksum(icmp_buf, icmp_len);

    /* ── Build IPv4 header ── */
    ip4_hdr_t ip_hdr;
    memset(&ip_hdr, 0, sizeof(ip_hdr));
    ip_hdr.ver_ihl  = (IP4_VERSION << 4) | 5;   /* version=4, IHL=5       */
    ip_hdr.tos      = 0;
    ip_hdr.tot_len  = htons((u16)(IP4_HDR_MIN_LEN + icmp_len));
    ip_hdr.id       = 0;
    ip_hdr.frag_off = 0;
    ip_hdr.ttl      = 64;
    ip_hdr.protocol = IP_PROTO_ICMP;
    ip_hdr.check    = 0;
    ip_hdr.saddr    = src_ip4;
    ip_hdr.daddr    = dst_ip4;
    ip_hdr.check    = ip4_checksum(&ip_hdr, IP4_HDR_MIN_LEN);

    /* ── Assemble IP payload (IP header + ICMP) ── */
    u8 ip_payload[IP4_HDR_MIN_LEN + 8 + 548];
    memcpy(ip_payload, &ip_hdr, IP4_HDR_MIN_LEN);
    memcpy(ip_payload + IP4_HDR_MIN_LEN, icmp_buf, icmp_len);
    u32 ip_payload_len = IP4_HDR_MIN_LEN + icmp_len;

    /* ── Build Ethernet frame ── */
    packet_t pkt;
    pkt.len = eth_build(pkt.data, sizeof(pkt.data),
                         iface->mac, dst_mac,
                         ETHERTYPE_IPV4,
                         ip_payload, ip_payload_len);
    pkt.iface_idx = egress_iface_idx;

    netdev_send(iface, &pkt);
}

/* ── Helper: resolve sender's MAC for ICMP error replies ───────────────── */
static bool resolve_reply_path(u32 orig_src_ip,
                               int ingress_iface_idx,
                               u32 *our_ip_out,
                               u8  *dst_mac_out,
                               int *egress_iface_idx_out)
{
    /* Route back to the original source */
    const route_entry_t *rt = routing_lpm(orig_src_ip);
    if (!rt) return false;

    int eidx = rt->iface_idx;
    netdev_iface_t *iface = netdev_find_by_index(eidx);
    if (!iface) return false;

    u32 nexthop = rt->gateway ? rt->gateway : orig_src_ip;
    const u8 *mac = arp_cache_lookup(nexthop);
    if (!mac) {
        /* Use ingress Ethernet source as a best-effort MAC (common case
           when replying directly to the host that sent the packet)      */
        (void)ingress_iface_idx;
        return false;
    }

    *our_ip_out           = iface->ip4;
    *egress_iface_idx_out = eidx;
    memcpy(dst_mac_out, mac, ETH_ALEN);
    return true;
}

/* ── Echo Reply ─────────────────────────────────────────────────────────── */
void icmp_send_echo_reply(packet_t *req_pkt, int ingress_iface_idx)
{
    const ip4_hdr_t *ip = (const ip4_hdr_t *)(req_pkt->data + ETH_HDR_LEN);
    const eth_hdr_t *eth = (const eth_hdr_t *)req_pkt->data;

    u32 ihl       = ip4_hdr_len(ip);
    u32 icmp_off  = ETH_HDR_LEN + ihl;
    if (req_pkt->len < icmp_off + ICMP_HDR_LEN) return;

    const icmp_hdr_t *req_icmp =
        (const icmp_hdr_t *)(req_pkt->data + icmp_off);

    /* Payload = everything after ICMP header in the original request    */
    const u8 *echo_data   = req_pkt->data + icmp_off + ICMP_HDR_LEN;
    u32       echo_data_len = req_pkt->len - icmp_off - (u32)ICMP_HDR_LEN;

    netdev_iface_t *iface = netdev_find_by_index(ingress_iface_idx);
    if (!iface) return;

    /* rest_of_header encodes id+seq (same as request) */
    u32 roh = ((u32)ntohs(req_icmp->un.echo.id) << 16) |
               ntohs(req_icmp->un.echo.seq);

    icmp_send_raw(ip->daddr, ip->saddr,
                  eth->src,          /* reply goes back to requester's MAC */
                  ingress_iface_idx,
                  ICMP_ECHO_REPLY, 0,
                  roh,
                  echo_data, echo_data_len);

    g_stats.icmp_tx_echo_replies++;
    LOG_DBG("ICMP Echo Reply sent to %s", ip4_str(ip->saddr));
}

/* ── Process incoming ICMP ──────────────────────────────────────────────── */
void icmp_process(packet_t *pkt, int iface_idx)
{
    const ip4_hdr_t *ip = (const ip4_hdr_t *)(pkt->data + ETH_HDR_LEN);
    u32 ihl = ip4_hdr_len(ip);
    u32 icmp_off = ETH_HDR_LEN + ihl;

    if (pkt->len < icmp_off + ICMP_HDR_LEN) return;

    const icmp_hdr_t *icmp =
        (const icmp_hdr_t *)(pkt->data + icmp_off);

    if (icmp->type == ICMP_ECHO_REQUEST) {
        g_stats.icmp_rx_echo_requests++;
        LOG_INFO("ICMP Echo Request from %s id=%u seq=%u",
                 ip4_str(ip->saddr),
                 ntohs(icmp->un.echo.id),
                 ntohs(icmp->un.echo.seq));
        icmp_send_echo_reply(pkt, iface_idx);
    }
}

/* ── Time Exceeded ──────────────────────────────────────────────────────── */
void icmp_send_time_exceeded(const packet_t *orig_pkt, int ingress_iface_idx)
{
    const ip4_hdr_t *ip = (const ip4_hdr_t *)(orig_pkt->data + ETH_HDR_LEN);
    const eth_hdr_t *eth = (const eth_hdr_t *)orig_pkt->data;

    netdev_iface_t *iface = netdev_find_by_index(ingress_iface_idx);
    if (!iface) return;

    /* ICMP Time Exceeded payload: original IP header + 8 bytes of data  */
    u32 ihl = ip4_hdr_len(ip);
    u32 orig_payload = MIN(ihl + 8, orig_pkt->len - ETH_HDR_LEN);
    const u8 *orig_data = orig_pkt->data + ETH_HDR_LEN;

    icmp_send_raw(iface->ip4, ip->saddr,
                  eth->src,
                  ingress_iface_idx,
                  ICMP_TIME_EXCEEDED, ICMP_TTL_EXCEEDED,
                  0,
                  orig_data, orig_payload);

    g_stats.icmp_tx_time_exceeded++;
    LOG_INFO("ICMP Time Exceeded -> %s", ip4_str(ip->saddr));
}

/* ── Destination Unreachable ────────────────────────────────────────────── */
void icmp_send_dest_unreachable(const packet_t *orig_pkt,
                                int ingress_iface_idx, u8 code)
{
    const ip4_hdr_t *ip = (const ip4_hdr_t *)(orig_pkt->data + ETH_HDR_LEN);
    const eth_hdr_t *eth = (const eth_hdr_t *)orig_pkt->data;

    netdev_iface_t *iface = netdev_find_by_index(ingress_iface_idx);
    if (!iface) return;

    u32 ihl       = ip4_hdr_len(ip);
    u32 orig_payload = MIN(ihl + 8, orig_pkt->len - ETH_HDR_LEN);
    const u8 *orig_data = orig_pkt->data + ETH_HDR_LEN;

    icmp_send_raw(iface->ip4, ip->saddr,
                  eth->src,
                  ingress_iface_idx,
                  ICMP_DST_UNREACH, code,
                  0,
                  orig_data, orig_payload);

    g_stats.icmp_tx_dest_unreach++;
    LOG_INFO("ICMP Dest-Unreach (code=%u) -> %s", code, ip4_str(ip->saddr));
}
