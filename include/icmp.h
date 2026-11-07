/*
 * icmp.h - ICMP message structures and generation helpers
 */

#ifndef MINIROUTER_ICMP_H
#define MINIROUTER_ICMP_H

#include "types.h"
#include "ipv4.h"

/* ── ICMP header ────────────────────────────────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    u8  type;
    u8  code;
    u16 checksum;
    union {
        struct { u16 id; u16 seq; } echo;   /* Echo Request/Reply        */
        u32 unused;                          /* Dest Unreachable / TTL   */
        u32 gateway;                         /* Redirect                 */
    } un;
} icmp_hdr_t;
#pragma pack(pop)

#define ICMP_HDR_LEN  sizeof(icmp_hdr_t)   /* 8 bytes                   */

/* ── API ────────────────────────────────────────────────────────────────── */

/* Process a received ICMP packet destined to one of our IPs.
   Handles Echo Requests and generates Echo Replies.                     */
void icmp_process(packet_t *pkt, int iface_idx);

/* Generate and send an ICMP Echo Reply in response to an Echo Request.  */
void icmp_send_echo_reply(packet_t *req_pkt, int ingress_iface_idx);

/* Generate ICMP Time Exceeded (TTL) error toward orig_pkt's source.    */
void icmp_send_time_exceeded(const packet_t *orig_pkt, int ingress_iface_idx);

/* Generate ICMP Destination Unreachable with specified code.            */
void icmp_send_dest_unreachable(const packet_t *orig_pkt,
                                int ingress_iface_idx, u8 code);

/* Low-level ICMP packet builder.
   Builds raw ICMP payload + IP + Ethernet frame and transmits it.
   src_ip4 and dst_ip4 are network byte order.                          */
void icmp_send_raw(u32 src_ip4, u32 dst_ip4,
                   const u8 dst_mac[ETH_ALEN],
                   int egress_iface_idx,
                   u8 type, u8 code,
                   u32 rest_of_header,         /* 4-byte ICMP word        */
                   const u8 *payload, u32 payload_len);

#endif /* MINIROUTER_ICMP_H */
