/*
 * ethernet.h - Layer 2 Ethernet frame parsing and construction
 */

#ifndef MINIROUTER_ETHERNET_H
#define MINIROUTER_ETHERNET_H

#include "types.h"

/* ── Ethernet II header (14 bytes, no VLAN) ────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    u8  dst[ETH_ALEN];   /* destination MAC                               */
    u8  src[ETH_ALEN];   /* source MAC                                    */
    u16 ethertype;        /* network byte order                            */
} eth_hdr_t;
#pragma pack(pop)

#define ETH_HDR_LEN  sizeof(eth_hdr_t)   /* 14 bytes                      */
#define ETH_MTU      1500                 /* max payload                   */
#define ETH_MIN_FRAME 64                  /* min Ethernet frame size       */

static const u8 ETH_BCAST[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};

/* ── API ────────────────────────────────────────────────────────────────── */

/* Parse pkt->data and return pointer to Ethernet header, NULL if
   the frame is too short to hold an Ethernet header.                    */
const eth_hdr_t *eth_parse(const packet_t *pkt);

/* Build an Ethernet frame into dst_buf.
   Returns total frame length (eth_hdr + payload_len).                   */
u32 eth_build(u8 *dst_buf, u32 buf_size,
              const u8 src_mac[ETH_ALEN],
              const u8 dst_mac[ETH_ALEN],
              u16 ethertype,
              const u8 *payload, u32 payload_len);

/* Rewrite the destination and source MAC of an existing frame in-place.  */
void eth_rewrite_macs(packet_t *pkt,
                      const u8 new_src[ETH_ALEN],
                      const u8 new_dst[ETH_ALEN]);

/* Return pointer to the payload bytes that follow the Ethernet header.   */
static inline u8 *eth_payload(packet_t *pkt) {
    if (pkt->len < ETH_HDR_LEN) return NULL;
    return pkt->data + ETH_HDR_LEN;
}

static inline u32 eth_payload_len(const packet_t *pkt) {
    if (pkt->len < ETH_HDR_LEN) return 0;
    return pkt->len - (u32)ETH_HDR_LEN;
}

#endif /* MINIROUTER_ETHERNET_H */
