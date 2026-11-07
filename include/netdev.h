/*
 * netdev.h - Network device abstraction layer
 * Supports: Linux TAP devices and in-memory mock devices (for unit tests)
 */

#ifndef MINIROUTER_NETDEV_H
#define MINIROUTER_NETDEV_H

#include "types.h"

/* ── Maximum interfaces supported ─────────────────────────────────────── */
#define NETDEV_MAX_IFACES  8

/* ── Interface flags ───────────────────────────────────────────────────── */
#define NETDEV_FLAG_UP      (1 << 0)
#define NETDEV_FLAG_MOCK    (1 << 1)   /* in-memory mock device            */

/* ── A single network interface descriptor ─────────────────────────────── */
typedef struct netdev_iface {
    char   name[16];           /* e.g. "tap0", "eth1"                      */
    u8     mac[ETH_ALEN];      /* hardware / assigned MAC address           */
    u32    ip4;                /* IPv4 address (network byte order)         */
    u32    netmask;            /* subnet mask (network byte order)          */
    u32    flags;
    int    fd;                 /* file descriptor (TAP fd or mock index)   */
    int    index;              /* position in global iface array           */

    /* per-interface counters */
    u64    rx_packets;
    u64    rx_bytes;
    u64    tx_packets;
    u64    tx_bytes;
    u64    rx_drops;
    u64    tx_drops;
    u64    rx_errors;
} netdev_iface_t;

/* ── Global interface table ─────────────────────────────────────────────── */
extern netdev_iface_t g_ifaces[NETDEV_MAX_IFACES];
extern int            g_num_ifaces;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

/* Open a Linux TAP device.  Returns 0 on success, -1 on error.           */
int  netdev_tap_open(netdev_iface_t *iface);

/* Open an in-memory mock interface (for unit tests, no root needed).     */
int  netdev_mock_open(netdev_iface_t *iface);

/* Close and release a device.                                            */
void netdev_close(netdev_iface_t *iface);

/* ── I/O ────────────────────────────────────────────────────────────────── */

/* Read one Ethernet frame from iface into pkt.
   Returns number of bytes read, 0 if no data, -1 on error.              */
int  netdev_recv(netdev_iface_t *iface, packet_t *pkt);

/* Write one Ethernet frame from pkt out through iface.
   Returns number of bytes written, -1 on error.                         */
int  netdev_send(netdev_iface_t *iface, const packet_t *pkt);

/* ── Mock helpers (for tests) ───────────────────────────────────────────── */

/* Inject a raw packet into mock interface iface_idx so the next
   netdev_recv() on that interface returns it.                            */
void netdev_mock_inject(int iface_idx, const u8 *data, u32 len);

/* Retrieve the last packet transmitted on mock interface iface_idx.
   Returns false if no packet has been sent.                              */
bool netdev_mock_dequeue_tx(int iface_idx, packet_t *out);

/* Reset all mock queues (call between test cases).                        */
void netdev_mock_reset(void);

/* ── Poll helper ────────────────────────────────────────────────────────── */

/* Wait up to timeout_ms for any registered interface to become readable.
   Fills ready[] with indices of ready interfaces and returns count.
   Pass timeout_ms = 0 for a non-blocking check.                         */
int  netdev_poll(int *ready, int max_ready, int timeout_ms);

/* ── Utility ────────────────────────────────────────────────────────────── */
netdev_iface_t *netdev_find_by_index(int idx);
netdev_iface_t *netdev_find_by_ip(u32 ip4_net);
void            netdev_print_stats(void);

#endif /* MINIROUTER_NETDEV_H */
