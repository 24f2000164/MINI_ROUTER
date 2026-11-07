/*
 * ipv4.c - IPv4 header parsing, validation, and checksum routines
 */

#include "ipv4.h"
#include "ethernet.h"
#include <string.h>

/* ── Checksum ────────────────────────────────────────────────────────────── */

u16 ip4_checksum(const void *data, u32 len)
{
    const u16 *p  = (const u16 *)data;
    u32        sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const u8 *)p;   /* last odd byte                        */

    /* fold 32-bit sum to 16 bits */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (u16)(~sum);
}

bool ip4_checksum_valid(const ip4_hdr_t *hdr)
{
    return ip4_checksum(hdr, ip4_hdr_len(hdr)) == 0;
}

void ip4_update_checksum(ip4_hdr_t *hdr)
{
    hdr->check = 0;
    hdr->check = ip4_checksum(hdr, ip4_hdr_len(hdr));
}

/* ── TTL decrement (RFC 1624 incremental update) ─────────────────────────── */

u8 ip4_decrement_ttl(ip4_hdr_t *hdr)
{
    if (hdr->ttl == 0) return 0;

    /*
     * RFC 1624 incremental checksum:
     * new_sum = ~(~old_sum - old_field + new_field)
     * TTL is a single byte at a known offset.  We treat the 16-bit word
     * containing TTL and Protocol as the changed word.
     */
    u16 old_word = *(u16 *)&hdr->ttl;   /* ttl + protocol as one u16    */
    hdr->ttl--;
    u16 new_word = *(u16 *)&hdr->ttl;

    u32 sum = (u16)(~hdr->check);
    sum    -= (u16)(~old_word);
    sum    += (u16)(~new_word);

    /* Adjust for wrap-around carries */
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    hdr->check = (u16)(~sum);

    return hdr->ttl;
}

/* ── Parsing ─────────────────────────────────────────────────────────────── */

const ip4_hdr_t *ip4_parse(const packet_t *pkt)
{
    /* Must have Ethernet header + at least minimum IPv4 header           */
    if (pkt->len < ETH_HDR_LEN + IP4_HDR_MIN_LEN) {
        LOG_DBG("ip4_parse: packet too short (%u)", pkt->len);
        return NULL;
    }

    const ip4_hdr_t *hdr = (const ip4_hdr_t *)(pkt->data + ETH_HDR_LEN);

    /* Version check */
    if (ip4_version(hdr) != IP4_VERSION) {
        LOG_DBG("ip4_parse: bad version %u", ip4_version(hdr));
        return NULL;
    }

    /* IHL check */
    u32 ihl = ip4_hdr_len(hdr);
    if (ihl < IP4_HDR_MIN_LEN) {
        LOG_DBG("ip4_parse: IHL too small (%u)", ihl);
        return NULL;
    }

    /* Total length bounds check */
    u32 tot_len = ntohs(hdr->tot_len);
    if (tot_len < ihl) {
        LOG_DBG("ip4_parse: tot_len < ihl");
        return NULL;
    }
    if (pkt->len < ETH_HDR_LEN + tot_len) {
        LOG_DBG("ip4_parse: frame truncated");
        return NULL;
    }

    /* Checksum verification */
    if (!ip4_checksum_valid(hdr)) {
        LOG_DBG("ip4_parse: bad checksum for %s->%s",
                ip4_str(hdr->saddr), ip4_str(hdr->daddr));
        return NULL;
    }

    return hdr;
}

/* ── Port extraction ─────────────────────────────────────────────────────── */

bool ip4_get_ports(const packet_t *pkt, const ip4_hdr_t *hdr,
                   u16 *sport_out, u16 *dport_out)
{
    if (hdr->protocol != IP_PROTO_TCP && hdr->protocol != IP_PROTO_UDP)
        return false;

    u32 ip_offset = ETH_HDR_LEN;
    u32 transport_offset = ip_offset + ip4_hdr_len(hdr);

    if (pkt->len < transport_offset + 4)   /* need at least 4 bytes    */
        return false;

    const tcp_udp_hdr_t *th =
        (const tcp_udp_hdr_t *)(pkt->data + transport_offset);

    *sport_out = ntohs(th->sport);
    *dport_out = ntohs(th->dport);
    return true;
}
