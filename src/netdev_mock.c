/*
 * netdev_mock.c - In-memory mock network device driver for unit testing
 *
 * Does NOT require root or /dev/net/tun.
 * Inject packets with netdev_mock_inject(); retrieve transmitted packets
 * with netdev_mock_dequeue_tx().
 */

#include "netdev.h"
#include <string.h>
#include <stdio.h>

/* ── Per-interface mock queues ──────────────────────────────────────────── */
#define MOCK_QUEUE_DEPTH  32

typedef struct {
    u8  data[PKT_BUF_SIZE];
    u32 len;
} mock_pkt_t;

typedef struct {
    mock_pkt_t pkts[MOCK_QUEUE_DEPTH];
    int head;
    int tail;
    int count;
} mock_queue_t;

static mock_queue_t s_rx_queue[NETDEV_MAX_IFACES];
static mock_queue_t s_tx_queue[NETDEV_MAX_IFACES];

/* ── Reset ──────────────────────────────────────────────────────────────── */
void netdev_mock_reset(void)
{
    memset(s_rx_queue, 0, sizeof(s_rx_queue));
    memset(s_tx_queue, 0, sizeof(s_tx_queue));
}

/* ── Open mock interface ────────────────────────────────────────────────── */
int netdev_mock_open(netdev_iface_t *iface)
{
    iface->fd    = iface->index;    /* use index as pseudo-fd              */
    iface->flags = NETDEV_FLAG_UP | NETDEV_FLAG_MOCK;
    LOG_INFO("Mock interface %s opened (index=%d, ip=%s)",
             iface->name, iface->index, ip4_str(iface->ip4));
    return 0;
}

/* ── Inject a packet into the mock RX queue ─────────────────────────────── */
void netdev_mock_inject(int iface_idx, const u8 *data, u32 len)
{
    if (iface_idx < 0 || iface_idx >= NETDEV_MAX_IFACES) return;
    mock_queue_t *q = &s_rx_queue[iface_idx];
    if (q->count >= MOCK_QUEUE_DEPTH) {
        LOG_WARN("mock RX queue full for iface %d", iface_idx);
        return;
    }
    mock_pkt_t *slot = &q->pkts[q->tail];
    u32 copy = len < PKT_BUF_SIZE ? len : PKT_BUF_SIZE;
    memcpy(slot->data, data, copy);
    slot->len = copy;
    q->tail   = (q->tail + 1) % MOCK_QUEUE_DEPTH;
    q->count++;
}

/* ── Receive from mock RX queue ─────────────────────────────────────────── */
int netdev_recv(netdev_iface_t *iface, packet_t *pkt)
{
    if (!(iface->flags & NETDEV_FLAG_MOCK)) return -1;

    int idx = iface->index;
    if (idx < 0 || idx >= NETDEV_MAX_IFACES) return -1;

    mock_queue_t *q = &s_rx_queue[idx];
    if (q->count == 0) return 0;

    mock_pkt_t *slot = &q->pkts[q->head];
    memcpy(pkt->data, slot->data, slot->len);
    pkt->len       = slot->len;
    pkt->iface_idx = idx;
    q->head  = (q->head + 1) % MOCK_QUEUE_DEPTH;
    q->count--;

    iface->rx_packets++;
    iface->rx_bytes += (u64)pkt->len;
    return (int)pkt->len;
}

/* ── Send to mock TX queue ──────────────────────────────────────────────── */
int netdev_send(netdev_iface_t *iface, const packet_t *pkt)
{
    if (!(iface->flags & NETDEV_FLAG_MOCK)) return -1;

    int idx = iface->index;
    if (idx < 0 || idx >= NETDEV_MAX_IFACES) return -1;

    mock_queue_t *q = &s_tx_queue[idx];
    if (q->count >= MOCK_QUEUE_DEPTH) {
        LOG_WARN("mock TX queue full for iface %d", idx);
        iface->tx_drops++;
        return -1;
    }
    mock_pkt_t *slot = &q->pkts[q->tail];
    u32 copy = pkt->len < PKT_BUF_SIZE ? pkt->len : PKT_BUF_SIZE;
    memcpy(slot->data, pkt->data, copy);
    slot->len = copy;
    q->tail   = (q->tail + 1) % MOCK_QUEUE_DEPTH;
    q->count++;

    iface->tx_packets++;
    iface->tx_bytes += (u64)copy;
    return (int)copy;
}

/* ── Dequeue from mock TX queue (for test assertions) ───────────────────── */
bool netdev_mock_dequeue_tx(int iface_idx, packet_t *out)
{
    if (iface_idx < 0 || iface_idx >= NETDEV_MAX_IFACES) return false;
    mock_queue_t *q = &s_tx_queue[iface_idx];
    if (q->count == 0) return false;

    mock_pkt_t *slot = &q->pkts[q->head];
    memcpy(out->data, slot->data, slot->len);
    out->len       = slot->len;
    out->iface_idx = iface_idx;
    q->head  = (q->head + 1) % MOCK_QUEUE_DEPTH;
    q->count--;
    return true;
}

/* ── Poll mock – simply check if any RX queue has data ──────────────────── */
int netdev_poll(int *ready, int max_ready, int timeout_ms)
{
    (void)timeout_ms;
    int count = 0;
    for (int i = 0; i < g_num_ifaces && count < max_ready; i++) {
        if ((g_ifaces[i].flags & NETDEV_FLAG_MOCK) &&
            s_rx_queue[i].count > 0)
            ready[count++] = i;
    }
    return count;
}

/* ── Close mock ─────────────────────────────────────────────────────────── */
void netdev_close(netdev_iface_t *iface)
{
    iface->flags = 0;
    LOG_INFO("Mock interface %s closed", iface->name);
}
