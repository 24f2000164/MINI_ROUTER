/*
 * netdev.c - Shared network device state, dispatch, and utilities.
 *
 * Owns: global interface table, dispatch shims for recv/send/close/poll,
 * and utility helpers.  Compiled into every build (router + all tests).
 *
 * Driver-specific back-ends:
 *   TAP  → netdev_tap.c   (requires /dev/net/tun + CAP_NET_ADMIN)
 *   Mock → netdev_mock.c  (in-memory queues, no root needed)
 */

#include "netdev.h"
#include <stdio.h>
#include <string.h>

/* ── Global interface table ─────────────────────────────────────────────── */
netdev_iface_t g_ifaces[NETDEV_MAX_IFACES];
int            g_num_ifaces = 0;

/* ── Forward declarations for back-end implementations ─────────────────── */
/* TAP back-end (netdev_tap.c) */
int  netdev_tap_recv(netdev_iface_t *iface, packet_t *pkt);
int  netdev_tap_send(netdev_iface_t *iface, const packet_t *pkt);
void netdev_tap_close(netdev_iface_t *iface);
int  netdev_tap_poll(int *ready, int max_ready, int timeout_ms);

/* Mock back-end (netdev_mock.c) */
int  netdev_mock_recv(netdev_iface_t *iface, packet_t *pkt);
int  netdev_mock_send(netdev_iface_t *iface, const packet_t *pkt);
void netdev_mock_close(netdev_iface_t *iface);
int  netdev_mock_poll(int *ready, int max_ready, int timeout_ms);

/* ── Dispatch: recv ─────────────────────────────────────────────────────── */
int netdev_recv(netdev_iface_t *iface, packet_t *pkt)
{
    if (iface->flags & NETDEV_FLAG_MOCK)
        return netdev_mock_recv(iface, pkt);
#ifdef NETDEV_USE_TAP
    return netdev_tap_recv(iface, pkt);
#else
    return -1;
#endif
}

/* ── Dispatch: send ─────────────────────────────────────────────────────── */
int netdev_send(netdev_iface_t *iface, const packet_t *pkt)
{
    if (iface->flags & NETDEV_FLAG_MOCK)
        return netdev_mock_send(iface, pkt);
#ifdef NETDEV_USE_TAP
    return netdev_tap_send(iface, pkt);
#else
    return -1;
#endif
}

/* ── Dispatch: close ────────────────────────────────────────────────────── */
void netdev_close(netdev_iface_t *iface)
{
    if (iface->flags & NETDEV_FLAG_MOCK)
        netdev_mock_close(iface);
#ifdef NETDEV_USE_TAP
    else
        netdev_tap_close(iface);
#endif
}

/* ── Dispatch: poll ─────────────────────────────────────────────────────── */
int netdev_poll(int *ready, int max_ready, int timeout_ms)
{
#ifdef NETDEV_USE_TAP
    return netdev_tap_poll(ready, max_ready, timeout_ms);
#else
    return netdev_mock_poll(ready, max_ready, timeout_ms);
#endif
}

/* ── Utility helpers ────────────────────────────────────────────────────── */
netdev_iface_t *netdev_find_by_index(int idx)
{
    if (idx < 0 || idx >= g_num_ifaces) return NULL;
    return &g_ifaces[idx];
}

netdev_iface_t *netdev_find_by_ip(u32 ip4_net)
{
    for (int i = 0; i < g_num_ifaces; i++)
        if (g_ifaces[i].ip4 == ip4_net) return &g_ifaces[i];
    return NULL;
}

void netdev_print_stats(void)
{
    printf("\n=== Interface Statistics ===\n");
    printf("%-8s %-10s %-10s %-10s %-10s %-8s %-8s\n",
           "Name", "RX-pkts", "RX-bytes", "TX-pkts", "TX-bytes",
           "RX-err", "TX-drop");
    for (int i = 0; i < g_num_ifaces; i++) {
        const netdev_iface_t *iface = &g_ifaces[i];
        printf("%-8s %-10llu %-10llu %-10llu %-10llu %-8llu %-8llu\n",
               iface->name,
               (unsigned long long)iface->rx_packets,
               (unsigned long long)iface->rx_bytes,
               (unsigned long long)iface->tx_packets,
               (unsigned long long)iface->tx_bytes,
               (unsigned long long)iface->rx_errors,
               (unsigned long long)iface->tx_drops);
    }
    printf("\n");
}
