/*
 * stats.h - Router-wide statistics and telemetry
 */

#ifndef MINIROUTER_STATS_H
#define MINIROUTER_STATS_H

#include "types.h"

/* ── Global forwarding-plane counters ──────────────────────────────────── */
typedef struct {
    u64 total_rx_packets;
    u64 total_tx_packets;
    u64 total_rx_bytes;
    u64 total_tx_bytes;

    u64 ipv4_rx;
    u64 ipv4_forwarded;
    u64 ipv4_local_delivered;
    u64 ipv4_dropped_ttl;
    u64 ipv4_dropped_no_route;
    u64 ipv4_dropped_arp_fail;
    u64 ipv4_dropped_malformed;

    u64 arp_rx_requests;
    u64 arp_rx_replies;
    u64 arp_tx_requests;
    u64 arp_tx_replies;
    u64 arp_cache_hits;
    u64 arp_cache_misses;
    u64 arp_pending_queued;
    u64 arp_pending_flushed;
    u64 arp_pending_dropped;

    u64 acl_ingress_permit;
    u64 acl_ingress_deny;
    u64 acl_egress_permit;
    u64 acl_egress_deny;

    u64 icmp_rx_echo_requests;
    u64 icmp_tx_echo_replies;
    u64 icmp_tx_time_exceeded;
    u64 icmp_tx_dest_unreach;
} router_stats_t;

extern router_stats_t g_stats;

/* ── API ────────────────────────────────────────────────────────────────── */
void stats_reset(void);
void stats_print(void);

#endif /* MINIROUTER_STATS_H */
