/*
 * arp.c - ARP cache, resolver, request/reply generation, pending queue
 */

#include "arp.h"
#include "ethernet.h"
#include "netdev.h"
#include "stats.h"
#include "router.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ── Global ARP cache ───────────────────────────────────────────────────── */
arp_entry_t g_arp_cache[ARP_CACHE_SIZE];

/* ── Init ───────────────────────────────────────────────────────────────── */
void arp_cache_init(void)
{
    memset(g_arp_cache, 0, sizeof(g_arp_cache));
    LOG_INFO("ARP cache initialized (%d slots)", ARP_CACHE_SIZE);
}

/* ── Lookup ─────────────────────────────────────────────────────────────── */
const u8 *arp_cache_lookup(u32 ip4_net)
{
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        arp_entry_t *e = &g_arp_cache[i];
        if (e->state == ARP_ENTRY_FREE) continue;
        if (e->ip4 != ip4_net) continue;
        if (e->state == ARP_ENTRY_REACHABLE ||
            e->state == ARP_ENTRY_STALE) {
            g_stats.arp_cache_hits++;
            return e->mac;
        }
    }
    g_stats.arp_cache_misses++;
    return NULL;
}

/* ── Learn ──────────────────────────────────────────────────────────────── */
void arp_cache_learn(u32 ip4_net, const u8 mac[ETH_ALEN], int iface_idx)
{
    time_t now = time(NULL);

    /* Update existing entry if present */
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        arp_entry_t *e = &g_arp_cache[i];
        if (e->state == ARP_ENTRY_FREE) continue;
        if (e->ip4 != ip4_net) continue;

        bool was_incomplete = (e->state == ARP_ENTRY_INCOMPLETE);
        memcpy(e->mac, mac, ETH_ALEN);
        e->state     = ARP_ENTRY_REACHABLE;
        e->timestamp = now;
        e->iface_idx = iface_idx;
        e->retry_count = 0;

        LOG_DBG("ARP cache updated: %s -> %s (iface %d)",
                ip4_str(ip4_net), mac_str(mac), iface_idx);

        /* Flush pending packets */
        if (was_incomplete && e->pkt_pending > 0)
            arp_flush_pending(e);
        return;
    }

    /* Add new entry – find a free or oldest stale slot */
    int slot = -1;
    time_t oldest = now;
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        if (g_arp_cache[i].state == ARP_ENTRY_FREE) { slot = i; break; }
        if (g_arp_cache[i].timestamp <= oldest) {
            oldest = g_arp_cache[i].timestamp;
            slot = i;
        }
    }
    if (slot < 0) slot = 0;   /* evict index 0 as last resort            */

    arp_entry_t *e = &g_arp_cache[slot];
    memset(e, 0, sizeof(*e));
    e->ip4       = ip4_net;
    memcpy(e->mac, mac, ETH_ALEN);
    e->iface_idx = iface_idx;
    e->state     = ARP_ENTRY_REACHABLE;
    e->timestamp = now;

    LOG_INFO("ARP cache new entry: %s -> %s (iface %d)",
             ip4_str(ip4_net), mac_str(mac), iface_idx);
}

/* ── Tick / aging ───────────────────────────────────────────────────────── */
void arp_cache_tick(void)
{
    time_t now = time(NULL);
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        arp_entry_t *e = &g_arp_cache[i];
        switch (e->state) {
        case ARP_ENTRY_FREE: break;

        case ARP_ENTRY_REACHABLE:
            if (now - e->timestamp >= ARP_REACHABLE_TTL) {
                e->state = ARP_ENTRY_STALE;
                LOG_DBG("ARP entry stale: %s", ip4_str(e->ip4));
            }
            break;

        case ARP_ENTRY_STALE:
            /* Keep stale entries – they'll be refreshed on next use      */
            break;

        case ARP_ENTRY_INCOMPLETE:
            if (now - e->timestamp >= ARP_INCOMPLETE_TTL) {
                if (e->retry_count < ARP_MAX_RETRIES) {
                    arp_send_request(e->iface_idx, e->ip4);
                    e->retry_count++;
                    e->timestamp = now;
                } else {
                    /* Give up: drop pending packets */
                    LOG_WARN("ARP resolution failed for %s, dropping %d pkts",
                             ip4_str(e->ip4), e->pkt_pending);
                    g_stats.arp_pending_dropped += (u64)e->pkt_pending;
                    memset(e, 0, sizeof(*e));
                }
            }
            break;
        }
    }
}

/* ── Send ARP Request ───────────────────────────────────────────────────── */
void arp_send_request(int iface_idx, u32 target_ip4)
{
    netdev_iface_t *iface = netdev_find_by_index(iface_idx);
    if (!iface) return;

    arp_pkt_t arp;
    memset(&arp, 0, sizeof(arp));
    arp.htype = htons(1);           /* Ethernet                           */
    arp.ptype = htons(ETHERTYPE_IPV4);
    arp.hlen  = ETH_ALEN;
    arp.plen  = IPV4_ALEN;
    arp.oper  = htons(ARP_REQUEST);
    memcpy(arp.sha, iface->mac, ETH_ALEN);
    arp.spa   = iface->ip4;
    memset(arp.tha, 0, ETH_ALEN);
    arp.tpa   = target_ip4;

    packet_t pkt;
    pkt.len = eth_build(pkt.data, sizeof(pkt.data),
                         iface->mac, ETH_BCAST,
                         ETHERTYPE_ARP,
                         (const u8 *)&arp, sizeof(arp));
    pkt.iface_idx = iface_idx;

    netdev_send(iface, &pkt);
    g_stats.arp_tx_requests++;
    LOG_DBG("ARP Request sent: who-has %s tell %s",
            ip4_str(target_ip4), ip4_str(iface->ip4));
}

/* ── Send ARP Reply ─────────────────────────────────────────────────────── */
void arp_send_reply(int iface_idx,
                    const u8  req_sha[ETH_ALEN], u32 req_spa,
                    u32 our_ip4)
{
    netdev_iface_t *iface = netdev_find_by_index(iface_idx);
    if (!iface) return;

    arp_pkt_t arp;
    arp.htype = htons(1);
    arp.ptype = htons(ETHERTYPE_IPV4);
    arp.hlen  = ETH_ALEN;
    arp.plen  = IPV4_ALEN;
    arp.oper  = htons(ARP_REPLY);
    memcpy(arp.sha, iface->mac, ETH_ALEN);
    arp.spa   = our_ip4;
    memcpy(arp.tha, req_sha, ETH_ALEN);
    arp.tpa   = req_spa;

    packet_t pkt;
    pkt.len = eth_build(pkt.data, sizeof(pkt.data),
                         iface->mac, req_sha,
                         ETHERTYPE_ARP,
                         (const u8 *)&arp, sizeof(arp));
    pkt.iface_idx = iface_idx;

    netdev_send(iface, &pkt);
    g_stats.arp_tx_replies++;
    LOG_DBG("ARP Reply sent: %s is-at %s",
            ip4_str(our_ip4), mac_str(iface->mac));
}

/* ── Process incoming ARP packet ────────────────────────────────────────── */
void arp_process(packet_t *pkt, int iface_idx)
{
    if (pkt->len < ETH_HDR_LEN + ARP_PKT_LEN) {
        LOG_DBG("arp_process: packet too short");
        return;
    }

    const arp_pkt_t *arp =
        (const arp_pkt_t *)(pkt->data + ETH_HDR_LEN);

    /* Sanity checks */
    if (ntohs(arp->htype) != 1 ||
        ntohs(arp->ptype) != ETHERTYPE_IPV4 ||
        arp->hlen != ETH_ALEN ||
        arp->plen != IPV4_ALEN)
        return;

    u16 oper = ntohs(arp->oper);

    /* Learn sender's IP-to-MAC mapping */
    arp_cache_learn(arp->spa, arp->sha, iface_idx);

    if (oper == ARP_REQUEST) {
        g_stats.arp_rx_requests++;
        /* Is the target IP one of ours? */
        netdev_iface_t *target_iface = netdev_find_by_ip(arp->tpa);
        if (target_iface) {
            LOG_DBG("ARP Request for our IP %s, sending reply",
                    ip4_str(arp->tpa));
            arp_send_reply(iface_idx, arp->sha, arp->spa, arp->tpa);
        }
    } else if (oper == ARP_REPLY) {
        g_stats.arp_rx_replies++;
        LOG_DBG("ARP Reply: %s is-at %s",
                ip4_str(arp->spa), mac_str(arp->sha));
        /* Learning above already handled flush-on-incomplete             */
    }
}

/* ── Queue packet while ARP resolves ────────────────────────────────────── */
void arp_queue_packet(u32 target_ip4, int egress_iface_idx,
                      const u8 *frame, u32 frame_len)
{
    /* Look for existing incomplete entry */
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        arp_entry_t *e = &g_arp_cache[i];
        if (e->state == ARP_ENTRY_INCOMPLETE && e->ip4 == target_ip4) {
            if (e->pkt_pending < ARP_PENDING_QUEUE_DEPTH) {
                u32 copy_len = MIN(frame_len, PKT_BUF_SIZE);
                memcpy(e->pkt_buf[e->pkt_pending], frame, copy_len);
                e->pkt_len[e->pkt_pending]         = copy_len;
                e->pkt_egress_iface[e->pkt_pending] = egress_iface_idx;
                e->pkt_pending++;
                g_stats.arp_pending_queued++;
            } else {
                LOG_WARN("ARP pending queue full for %s, dropping packet",
                         ip4_str(target_ip4));
                g_stats.arp_pending_dropped++;
            }
            return;
        }
    }

    /* Find a free slot for a new incomplete entry */
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        arp_entry_t *e = &g_arp_cache[i];
        if (e->state == ARP_ENTRY_FREE) {
            memset(e, 0, sizeof(*e));
            e->ip4       = target_ip4;
            e->iface_idx = egress_iface_idx;
            e->state     = ARP_ENTRY_INCOMPLETE;
            e->timestamp = time(NULL);

            if (frame && frame_len) {
                u32 copy_len = MIN(frame_len, PKT_BUF_SIZE);
                memcpy(e->pkt_buf[0], frame, copy_len);
                e->pkt_len[0]          = copy_len;
                e->pkt_egress_iface[0] = egress_iface_idx;
                e->pkt_pending         = 1;
                g_stats.arp_pending_queued++;
            }

            arp_send_request(egress_iface_idx, target_ip4);
            return;
        }
    }

    LOG_WARN("ARP cache full, cannot queue packet for %s",
             ip4_str(target_ip4));
    g_stats.arp_pending_dropped++;
}

/* ── Flush pending packets once MAC is resolved ─────────────────────────── */
void arp_flush_pending(arp_entry_t *entry)
{
    for (int i = 0; i < entry->pkt_pending; i++) {
        int eidx = entry->pkt_egress_iface[i];
        netdev_iface_t *egress = netdev_find_by_index(eidx);
        if (!egress) continue;

        /* Rewrite destination MAC in the buffered frame */
        if (entry->pkt_len[i] >= ETH_HDR_LEN) {
            eth_hdr_t *eh = (eth_hdr_t *)entry->pkt_buf[i];
            memcpy(eh->dst, entry->mac, ETH_ALEN);
        }

        packet_t pkt;
        u32 len = MIN(entry->pkt_len[i], PKT_BUF_SIZE);
        memcpy(pkt.data, entry->pkt_buf[i], len);
        pkt.len       = len;
        pkt.iface_idx = eidx;
        netdev_send(egress, &pkt);
        g_stats.arp_pending_flushed++;
        LOG_DBG("ARP flush: sent pending packet %d/%d for %s",
                i + 1, entry->pkt_pending, ip4_str(entry->ip4));
    }
    entry->pkt_pending = 0;
}

/* ── Print ARP cache ────────────────────────────────────────────────────── */
void arp_cache_print(void)
{
    time_t now = time(NULL);
    printf("\n=== ARP Cache ===\n");
    printf("%-16s %-20s %-6s %-12s %-6s\n",
           "IP", "MAC", "Iface", "State", "Age(s)");
    printf("%-16s %-20s %-6s %-12s %-6s\n",
           "---------------", "-------------------", "-----",
           "-----------", "------");
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
        const arp_entry_t *e = &g_arp_cache[i];
        if (e->state == ARP_ENTRY_FREE) continue;
        const char *state_s =
            e->state == ARP_ENTRY_INCOMPLETE ? "INCOMPLETE" :
            e->state == ARP_ENTRY_REACHABLE  ? "REACHABLE"  :
            e->state == ARP_ENTRY_STALE      ? "STALE"      : "UNKNOWN";
        printf("%-16s %-20s %-6d %-12s %-6ld\n",
               ip4_str(e->ip4), mac_str(e->mac),
               e->iface_idx, state_s,
               (long)(now - e->timestamp));
    }
    printf("\n");
}
