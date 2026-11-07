/*
 * router.c - Central packet dispatcher and IPv4 forwarding pipeline
 */

#include "router.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

/* ── Globals ────────────────────────────────────────────────────────────── */
router_ctx_t  g_router;
int           g_log_level = LOG_LEVEL_INFO;

/* ── Signal handler ─────────────────────────────────────────────────────── */
void router_signal_handler(int sig)
{
    (void)sig;
    g_router.running = false;
}

/* ── Subsystem initialisation ───────────────────────────────────────────── */
int router_init(const router_config_t *cfg)
{
    g_router.cfg     = *cfg;
    g_router.running = true;
    g_log_level      = cfg->log_level;

    stats_reset();
    routing_init();
    arp_cache_init();
    acl_init();

    /* Open network interfaces */
    for (int i = 0; i < g_num_ifaces; i++) {
        int rc;
        if (cfg->use_mock)
            rc = netdev_mock_open(&g_ifaces[i]);
        else
            rc = netdev_tap_open(&g_ifaces[i]);
        if (rc < 0) {
            LOG_ERR("Failed to open interface %s", g_ifaces[i].name);
            return -1;
        }
    }

    signal(SIGINT,  router_signal_handler);
    signal(SIGTERM, router_signal_handler);

    LOG_INFO("Router initialized (%d interfaces, %s mode)",
             g_num_ifaces, cfg->use_mock ? "MOCK" : "TAP");
    return 0;
}

/* ── Helpers ────────────────────────────────────────────────────────────── */
bool router_is_local_ip(u32 ip4_net)
{
    for (int i = 0; i < g_num_ifaces; i++)
        if (g_ifaces[i].ip4 == ip4_net) return true;
    return false;
}

int router_find_iface_for_ip(u32 ip4_net)
{
    for (int i = 0; i < g_num_ifaces; i++) {
        if ((ip4_net & g_ifaces[i].netmask) ==
            (g_ifaces[i].ip4 & g_ifaces[i].netmask))
            return i;
    }
    return -1;
}

/* ── IPv4 forwarding pipeline ────────────────────────────────────────────── */
void router_forward_ipv4(packet_t *pkt, const ip4_hdr_t *ip_hdr)
{
    /* ── ACL Ingress ── */
    acl_action_t ingress_action = acl_evaluate(pkt, pkt->iface_idx,
                                               ACL_DIR_INGRESS);
    if (ingress_action == ACL_ACTION_DENY) {
        g_stats.acl_ingress_deny++;
        LOG_INFO("ACL DENY ingress: %s -> %s",
                 ip4_str(ip_hdr->saddr), ip4_str(ip_hdr->daddr));
        if (g_router.cfg.send_icmp_on_deny)
            icmp_send_dest_unreachable(pkt, pkt->iface_idx,
                                       ICMP_ADMIN_PROHIB);
        return;
    }
    g_stats.acl_ingress_permit++;

    /* ── Local delivery ── */
    if (router_is_local_ip(ip_hdr->daddr)) {
        g_stats.ipv4_local_delivered++;
        if (ip_hdr->protocol == IP_PROTO_ICMP)
            icmp_process(pkt, pkt->iface_idx);
        else
            LOG_DBG("Local delivery proto=%u (not ICMP)", ip_hdr->protocol);
        return;
    }

    /* ── Route lookup (LPM) ── */
    const route_entry_t *rt = routing_lpm(ip_hdr->daddr);
    if (!rt) {
        g_stats.ipv4_dropped_no_route++;
        LOG_INFO("No route to %s, sending ICMP Unreachable",
                 ip4_str(ip_hdr->daddr));
        icmp_send_dest_unreachable(pkt, pkt->iface_idx, ICMP_NET_UNREACH);
        return;
    }

    /* ── TTL decrement ── */
    /* We must cast away const here: ip_hdr points inside pkt->data     */
    ip4_hdr_t *ip_mut = (ip4_hdr_t *)(pkt->data + ETH_HDR_LEN);
    u8 new_ttl = ip4_decrement_ttl(ip_mut);
    if (new_ttl == 0) {
        g_stats.ipv4_dropped_ttl++;
        LOG_INFO("TTL expired: %s -> %s",
                 ip4_str(ip_hdr->saddr), ip4_str(ip_hdr->daddr));
        icmp_send_time_exceeded(pkt, pkt->iface_idx);
        return;
    }

    int eidx = rt->iface_idx;
    netdev_iface_t *egress = netdev_find_by_index(eidx);
    if (!egress) {
        g_stats.ipv4_dropped_no_route++;
        return;
    }

    /* ── ACL Egress ── */
    packet_t tmp_pkt = *pkt;
    tmp_pkt.iface_idx = eidx;
    acl_action_t egress_action = acl_evaluate(&tmp_pkt, eidx,
                                              ACL_DIR_EGRESS);
    if (egress_action == ACL_ACTION_DENY) {
        g_stats.acl_egress_deny++;
        LOG_INFO("ACL DENY egress iface=%d: %s -> %s",
                 eidx, ip4_str(ip_hdr->saddr), ip4_str(ip_hdr->daddr));
        if (g_router.cfg.send_icmp_on_deny)
            icmp_send_dest_unreachable(pkt, pkt->iface_idx,
                                       ICMP_ADMIN_PROHIB);
        return;
    }
    g_stats.acl_egress_permit++;

    /* ── Determine next-hop IP ── */
    u32 nexthop_ip = rt->gateway ? rt->gateway : ip_hdr->daddr;

    /* ── ARP resolution ── */
    const u8 *dst_mac = arp_cache_lookup(nexthop_ip);
    if (!dst_mac) {
        g_stats.ipv4_dropped_arp_fail++;
        LOG_INFO("ARP miss for nexthop %s, queuing packet",
                 ip4_str(nexthop_ip));
        /* Rewrite source MAC before queuing */
        eth_rewrite_macs(pkt, egress->mac,
                         (const u8 *)"\xff\xff\xff\xff\xff\xff");
        arp_queue_packet(nexthop_ip, eidx, pkt->data, pkt->len);
        return;
    }

    /* ── Ethernet rewrite and transmit ── */
    eth_rewrite_macs(pkt, egress->mac, dst_mac);
    pkt->iface_idx = eidx;
    netdev_send(egress, pkt);
    g_stats.ipv4_forwarded++;
    g_stats.total_tx_packets++;
    g_stats.total_tx_bytes += pkt->len;

    LOG_DBG("Forwarded %s -> %s via iface %d nexthop %s",
            ip4_str(ip_hdr->saddr), ip4_str(ip_hdr->daddr),
            eidx, ip4_str(nexthop_ip));
}

/* ── Frame dispatcher ────────────────────────────────────────────────────── */
void router_dispatch(packet_t *pkt)
{
    g_stats.total_rx_packets++;
    g_stats.total_rx_bytes += pkt->len;

    const eth_hdr_t *eth = eth_parse(pkt);
    if (!eth) {
        g_stats.ipv4_dropped_malformed++;
        return;
    }

    u16 ethertype = ntohs(eth->ethertype);

    if (ethertype == ETHERTYPE_ARP) {
        arp_process(pkt, pkt->iface_idx);
        return;
    }

    if (ethertype == ETHERTYPE_IPV4) {
        g_stats.ipv4_rx++;
        const ip4_hdr_t *ip = ip4_parse(pkt);
        if (!ip) {
            g_stats.ipv4_dropped_malformed++;
            return;
        }
        router_forward_ipv4(pkt, ip);
        return;
    }

    LOG_DBG("Unknown EtherType 0x%04x, dropping", ethertype);
}

/* ── Main event loop ────────────────────────────────────────────────────── */
void router_run(void)
{
    LOG_INFO("Router event loop started");
    packet_t pkt;
    time_t last_tick = time(NULL);

    while (g_router.running) {
        int ready[NETDEV_MAX_IFACES];
        int nready = netdev_poll(ready, NETDEV_MAX_IFACES,
                                 g_router.cfg.poll_timeout_ms);

        for (int r = 0; r < nready; r++) {
            netdev_iface_t *iface = &g_ifaces[ready[r]];
            int n = netdev_recv(iface, &pkt);
            if (n > 0)
                router_dispatch(&pkt);
        }

        /* Periodic 1-second maintenance */
        time_t now = time(NULL);
        if (now - last_tick >= 1) {
            arp_cache_tick();
            last_tick = now;
        }

        if (g_router.cfg.run_once) break;
    }

    LOG_INFO("Router event loop stopped");
}

/* ── Shutdown ────────────────────────────────────────────────────────────── */
void router_shutdown(void)
{
    for (int i = 0; i < g_num_ifaces; i++)
        netdev_close(&g_ifaces[i]);
    LOG_INFO("Router shut down cleanly");
}
