/*
 * ethernet.c - Ethernet frame parsing and construction
 */

#include "ethernet.h"
#include "types.h"
#include <string.h>

const eth_hdr_t *eth_parse(const packet_t *pkt)
{
    if (pkt->len < ETH_HDR_LEN) {
        LOG_DBG("eth_parse: frame too short (%u bytes)", pkt->len);
        return NULL;
    }
    return (const eth_hdr_t *)pkt->data;
}

u32 eth_build(u8 *dst_buf, u32 buf_size,
              const u8 src_mac[ETH_ALEN],
              const u8 dst_mac[ETH_ALEN],
              u16 ethertype,
              const u8 *payload, u32 payload_len)
{
    u32 total = (u32)ETH_HDR_LEN + payload_len;
    if (total > buf_size) {
        LOG_ERR("eth_build: buffer too small (%u < %u)", buf_size, total);
        return 0;
    }
    eth_hdr_t *hdr = (eth_hdr_t *)dst_buf;
    memcpy(hdr->dst, dst_mac, ETH_ALEN);
    memcpy(hdr->src, src_mac, ETH_ALEN);
    hdr->ethertype = htons(ethertype);
    if (payload && payload_len)
        memcpy(dst_buf + ETH_HDR_LEN, payload, payload_len);
    return total;
}

void eth_rewrite_macs(packet_t *pkt,
                      const u8 new_src[ETH_ALEN],
                      const u8 new_dst[ETH_ALEN])
{
    if (pkt->len < ETH_HDR_LEN) return;
    eth_hdr_t *hdr = (eth_hdr_t *)pkt->data;
    memcpy(hdr->src, new_src, ETH_ALEN);
    memcpy(hdr->dst, new_dst, ETH_ALEN);
}
