/*
 * arp.h - ARP (RFC 826) cache, resolver, and packet generation
 */

#ifndef MINIROUTER_ARP_H
#define MINIROUTER_ARP_H

#include "types.h"

/* ── ARP packet layout (Ethernet/IPv4 specialization) ─────────────────── */
#pragma pack(push, 1)
typedef struct {
    u16 htype;          /* Hardware type: 1 = Ethernet                    */
    u16 ptype;          /* Protocol type: 0x0800 = IPv4                   */
    u8  hlen;           /* Hardware addr length: 6                        */
    u8  plen;           /* Protocol addr length: 4                        */
    u16 oper;           /* Operation: 1=Request, 2=Reply                  */
    u8  sha[ETH_ALEN];  /* Sender hardware address                        */
    u32 spa;            /* Sender protocol (IPv4) address (net order)     */
    u8  tha[ETH_ALEN];  /* Target hardware address                        */
    u32 tpa;            /* Target protocol (IPv4) address (net order)     */
} arp_pkt_t;
#pragma pack(pop)

#define ARP_PKT_LEN  sizeof(arp_pkt_t)   /* 28 bytes                      */

/* ── ARP cache entry states ─────────────────────────────────────────────── */
typedef enum {
    ARP_ENTRY_FREE = 0,
    ARP_ENTRY_INCOMPLETE,   /* ARP request sent, waiting for reply        */
    ARP_ENTRY_REACHABLE,    /* MAC known and fresh                        */
    ARP_ENTRY_STALE,        /* MAC known but aged; will re-verify on use  */
} arp_state_t;

/* ── ARP cache entry ────────────────────────────────────────────────────── */
#define ARP_CACHE_SIZE      64
#define ARP_REACHABLE_TTL   300   /* seconds before entry becomes STALE   */
#define ARP_INCOMPLETE_TTL    3   /* seconds before incomplete entry times out */
#define ARP_MAX_RETRIES       3   /* ARP requests before giving up        */

/* Max pending packets queued per unresolved ARP entry                    */
#define ARP_PENDING_QUEUE_DEPTH  4

typedef struct {
    u32        ip4;                    /* target IPv4 (network order)      */
    u8         mac[ETH_ALEN];          /* resolved MAC                     */
    int        iface_idx;              /* interface on which entry learned */
    arp_state_t state;
    time_t     timestamp;              /* time of last state change        */
    int        retry_count;

    /* buffered packets waiting for this resolution                       */
    u8  pkt_buf[ARP_PENDING_QUEUE_DEPTH][PKT_BUF_SIZE];
    u32 pkt_len[ARP_PENDING_QUEUE_DEPTH];
    int pkt_pending;                   /* number of queued packets         */
    int pkt_egress_iface[ARP_PENDING_QUEUE_DEPTH]; /* egress iface for each */
} arp_entry_t;

/* ── ARP cache (global) ─────────────────────────────────────────────────── */
extern arp_entry_t g_arp_cache[ARP_CACHE_SIZE];

/* ── API ────────────────────────────────────────────────────────────────── */

/* Initialize the ARP cache.                                              */
void arp_cache_init(void);

/* Look up MAC for an IPv4 address.
   Returns pointer to MAC bytes if REACHABLE/STALE, NULL otherwise.     */
const u8 *arp_cache_lookup(u32 ip4_net);

/* Learn (or update) an ARP cache entry from a received ARP or IP packet. */
void arp_cache_learn(u32 ip4_net, const u8 mac[ETH_ALEN], int iface_idx);

/* Age out stale/incomplete entries; flush pending packets on timeout.
   Call periodically (e.g. every 1 second).                              */
void arp_cache_tick(void);

/* Process a received ARP packet (request or reply).
   Generates reply if request is for one of our IPs.                    */
void arp_process(packet_t *pkt, int iface_idx);

/* Queue a packet while ARP resolution is pending.
   Sends an ARP request if no existing incomplete entry exists.          */
void arp_queue_packet(u32 target_ip4, int egress_iface_idx,
                      const u8 *frame, u32 frame_len);

/* Flush pending packets once ARP reply arrives (called internally).     */
void arp_flush_pending(arp_entry_t *entry);

/* Send an ARP Request for target_ip4 out of iface.                      */
void arp_send_request(int iface_idx, u32 target_ip4);

/* Send an ARP Reply back to the requester.                              */
void arp_send_reply(int iface_idx,
                    const u8  req_sha[ETH_ALEN], u32 req_spa,
                    u32 our_ip4);

/* Print the ARP cache table.                                             */
void arp_cache_print(void);

#endif /* MINIROUTER_ARP_H */
