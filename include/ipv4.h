/*
 * ipv4.h - IPv4 header structures, parsing, validation, checksum
 */

#ifndef MINIROUTER_IPV4_H
#define MINIROUTER_IPV4_H

#include "types.h"

/* ── IPv4 header (20 bytes minimum, no options) ────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    u8  ver_ihl;        /* version (4) | IHL (units of 4 bytes)           */
    u8  tos;            /* type of service / DSCP                         */
    u16 tot_len;        /* total length including header (network order)  */
    u16 id;             /* identification                                  */
    u16 frag_off;       /* flags (3 bits) + fragment offset (13 bits)     */
    u8  ttl;            /* time to live                                   */
    u8  protocol;       /* upper layer protocol (IP_PROTO_*)              */
    u16 check;          /* header checksum                                */
    u32 saddr;          /* source IPv4 (network byte order)               */
    u32 daddr;          /* destination IPv4 (network byte order)          */
} ip4_hdr_t;
#pragma pack(pop)

#define IP4_HDR_MIN_LEN  20          /* bytes, IHL == 5 (5 × 4 = 20)    */
#define IP4_VERSION       4
#define IP4_DF_FLAG      0x4000      /* don't-fragment flag (net order word) */

static inline u32 ip4_hdr_len(const ip4_hdr_t *h) {
    return (u32)((h->ver_ihl & 0x0F) << 2);
}

static inline u8 ip4_version(const ip4_hdr_t *h) {
    return (h->ver_ihl >> 4) & 0x0F;
}

/* ── TCP / UDP minimal headers for port extraction ──────────────────────── */
#pragma pack(push, 1)
typedef struct {
    u16 sport;
    u16 dport;
    /* remaining fields omitted – we only need ports for ACL              */
} tcp_udp_hdr_t;
#pragma pack(pop)

/* ── API ────────────────────────────────────────────────────────────────── */

/* Parse and validate the IPv4 header inside pkt (skips Ethernet header).
   Returns pointer to ip4_hdr_t, or NULL if the packet is malformed.    */
const ip4_hdr_t *ip4_parse(const packet_t *pkt);

/* Verify IPv4 header checksum.  Returns true if valid.                  */
bool ip4_checksum_valid(const ip4_hdr_t *hdr);

/* Compute full 16-bit 1's complement checksum over len bytes.           */
u16  ip4_checksum(const void *data, u32 len);

/* Recalculate header checksum in-place (after modifying fields).        */
void ip4_update_checksum(ip4_hdr_t *hdr);

/* Decrement TTL by 1.  Returns new TTL (may be 0, caller must check).
   Also updates header checksum incrementally (RFC 1624).               */
u8   ip4_decrement_ttl(ip4_hdr_t *hdr);

/* Extract source and dest port from the transport header that follows
   the IPv4 header.  Returns false if protocol has no ports (ICMP).    */
bool ip4_get_ports(const packet_t *pkt, const ip4_hdr_t *hdr,
                   u16 *sport_out, u16 *dport_out);

/* Return pointer to payload beyond the IPv4 header.                     */
static inline const u8 *ip4_payload(const packet_t *pkt,
                                    const ip4_hdr_t *hdr) {
    u32 eth_plus_ip = (u32)sizeof(u8) * 14 + ip4_hdr_len(hdr);
    if (pkt->len < eth_plus_ip) return NULL;
    return pkt->data + eth_plus_ip;
}

#endif /* MINIROUTER_IPV4_H */
