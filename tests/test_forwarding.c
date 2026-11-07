/*
 * test_forwarding.c - End-to-end packet forwarding simulation using mock devices
 *
 * Topology:
 *   [host-A 10.0.1.100] --iface0(tap0, 10.0.1.1)--> [ROUTER] --iface1(tap1, 10.0.2.1)--> [host-B 10.0.2.100]
 *
 * Tests:
 *   1. ICMP ping from host-A to router's iface0 IP -> Echo Reply
 *   2. IPv4 forwarding: IP packet from host-A destined for host-B
 *      a. ARP miss -> ARP Request generated for host-B
 *      b. After ARP reply injection -> packet forwarded with rewritten MACs
 *   3. TTL=1 packet -> ICMP Time Exceeded
 *   4. No-route packet -> ICMP Destination Unreachable
 */

#include "../include/router.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* ── Stubs / globals (satisfy linker for mock build) ───────────────────── */
int           g_log_level = LOG_LEVEL_ERR;

static int s_pass = 0, s_fail = 0;

#define CHECK(cond, msg) \
    do { if (cond) { printf("  PASS: %s\n", msg); s_pass++; } \
         else      { printf("  FAIL: %s  [%s:%d]\n", msg, __FILE__, __LINE__); s_fail++; } } while(0)

/* ── Helper: build an Ethernet/IPv4/ICMP Echo Request ──────────────────── */
static u32 make_echo_request(u8 *buf, u32 buf_sz,
                              const u8 src_mac[6], const u8 dst_mac[6],
                              u32 src_ip, u32 dst_ip,
                              u16 id, u16 seq)
{
    /* Ethernet */
    eth_hdr_t *eth = (eth_hdr_t *)buf;
    memcpy(eth->src, src_mac, 6);
    memcpy(eth->dst, dst_mac, 6);
    eth->ethertype = htons(ETHERTYPE_IPV4);

    /* ICMP Echo header (8 bytes) */
    u8 icmp[8] = {ICMP_ECHO_REQUEST, 0, 0, 0,
                  (u8)(id>>8), (u8)id, (u8)(seq>>8), (u8)seq};
    u16 icmp_csum = ip4_checksum(icmp, 8);
    icmp[2] = (u8)(icmp_csum >> 8);
    icmp[3] = (u8)(icmp_csum);

    /* IPv4 */
    ip4_hdr_t *ip = (ip4_hdr_t *)(buf + 14);
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl  = (4<<4)|5;
    ip->tot_len  = htons(20 + 8);
    ip->ttl      = 64;
    ip->protocol = IP_PROTO_ICMP;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = ip4_checksum(ip, 20);

    memcpy(buf + 14 + 20, icmp, 8);
    return 14 + 20 + 8;
}

/* Build a minimal Ethernet/IPv4 frame (no transport payload) */
static u32 make_ip_frame(u8 *buf,
                          const u8 src_mac[6], const u8 dst_mac[6],
                          u32 src_ip, u32 dst_ip,
                          u8 ttl, u8 proto)
{
    eth_hdr_t *eth = (eth_hdr_t *)buf;
    memcpy(eth->src, src_mac, 6);
    memcpy(eth->dst, dst_mac, 6);
    eth->ethertype = htons(ETHERTYPE_IPV4);

    ip4_hdr_t *ip = (ip4_hdr_t *)(buf + 14);
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl  = (4<<4)|5;
    ip->tot_len  = htons(20);
    ip->ttl      = ttl;
    ip->protocol = proto;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = ip4_checksum(ip, 20);
    return 14 + 20;
}

/* Build ARP reply frame */
static u32 make_arp_reply(u8 *buf,
                           const u8 sha[6], u32 spa,
                           const u8 tha[6], u32 tpa)
{
    eth_hdr_t *eth = (eth_hdr_t *)buf;
    memcpy(eth->src, sha, 6);
    memcpy(eth->dst, tha, 6);
    eth->ethertype = htons(ETHERTYPE_ARP);

    arp_pkt_t *arp = (arp_pkt_t *)(buf + 14);
    arp->htype = htons(1);
    arp->ptype = htons(ETHERTYPE_IPV4);
    arp->hlen  = 6;
    arp->plen  = 4;
    arp->oper  = htons(ARP_REPLY);
    memcpy(arp->sha, sha, 6);
    arp->spa   = spa;
    memcpy(arp->tha, tha, 6);
    arp->tpa   = tpa;
    return 14 + 28;
}

static inline u32 mkip(unsigned a, unsigned b, unsigned c, unsigned d)
{ return htonl((a<<24)|(b<<16)|(c<<8)|d); }

/* ── Setup router with 2 mock interfaces ───────────────────────────────── */
static void setup_router(void)
{
    /* Reset everything */
    memset(g_ifaces, 0, sizeof(g_ifaces));
    g_num_ifaces = 0;
    netdev_mock_reset();
    stats_reset();
    routing_init();
    arp_cache_init();
    acl_init();

    /* Interface 0: tap0 10.0.1.1/24 */
    netdev_iface_t *i0 = &g_ifaces[0];
    strncpy(i0->name, "tap0", 4);
    i0->index   = 0;
    i0->ip4     = mkip(10,0,1,1);
    i0->netmask = htonl(0xFFFFFF00);
    u8 mac0[6] = {0xAA,0x00,0x00,0x00,0x01,0x00};
    memcpy(i0->mac, mac0, 6);
    netdev_mock_open(i0);
    g_num_ifaces++;

    /* Interface 1: tap1 10.0.2.1/24 */
    netdev_iface_t *i1 = &g_ifaces[1];
    strncpy(i1->name, "tap1", 4);
    i1->index   = 1;
    i1->ip4     = mkip(10,0,2,1);
    i1->netmask = htonl(0xFFFFFF00);
    u8 mac1[6] = {0xAA,0x00,0x00,0x00,0x02,0x00};
    memcpy(i1->mac, mac1, 6);
    netdev_mock_open(i1);
    g_num_ifaces++;

    /* Routes */
    routing_add(mkip(10,0,1,0), htonl(0xFFFFFF00), 24, 0, 0, 1);
    routing_add(mkip(10,0,2,0), htonl(0xFFFFFF00), 24, 0, 1, 1);
}

/* ── Test 1: ICMP Echo to router's own IP ────────────────────────────────── */
void test_icmp_local(void)
{
    setup_router();

    u8 host_mac[6] = {0xBB,0x00,0x00,0x00,0x01,0x00};
    u8 rtr_mac0[6] = {0xAA,0x00,0x00,0x00,0x01,0x00};

    u8 buf[256];
    u32 len = make_echo_request(buf, sizeof(buf),
                                 host_mac, rtr_mac0,
                                 mkip(10,0,1,100), mkip(10,0,1,1),
                                 0x1234, 1);

    /* Inject packet into iface 0 */
    /* First teach ARP so the reply can be sent */
    arp_cache_learn(mkip(10,0,1,100), host_mac, 0);

    packet_t pkt;
    memcpy(pkt.data, buf, len);
    pkt.len = len;
    pkt.iface_idx = 0;

    router_dispatch(&pkt);

    /* Expect an ICMP Echo Reply on iface 0 */
    packet_t tx;
    bool got = netdev_mock_dequeue_tx(0, &tx);
    CHECK(got, "ICMP Echo Reply was sent");

    if (got) {
        const eth_hdr_t *eth = (eth_hdr_t *)tx.data;
        const ip4_hdr_t *ip  = (ip4_hdr_t *)(tx.data + 14);
        u8 *icmp = tx.data + 14 + 20;
        CHECK(ntohs(eth->ethertype) == ETHERTYPE_IPV4, "Reply EtherType = IPv4");
        CHECK(ip->protocol == IP_PROTO_ICMP,          "Reply protocol = ICMP");
        CHECK(ip->daddr == mkip(10,0,1,100),          "Reply dst IP = 10.0.1.100");
        CHECK(ip->saddr == mkip(10,0,1,1),            "Reply src IP = 10.0.1.1");
        CHECK(icmp[0] == ICMP_ECHO_REPLY,              "ICMP type = Echo Reply");
    }
}

/* ── Test 2: IPv4 forwarding with ARP resolution ─────────────────────────── */
void test_forwarding(void)
{
    setup_router();

    u8 host_a_mac[6] = {0xBB,0x00,0x00,0x00,0x01,0x00};
    u8 host_b_mac[6] = {0xCC,0x00,0x00,0x00,0x02,0x00};
    u8 rtr_mac0[6]   = {0xAA,0x00,0x00,0x00,0x01,0x00};
    u8 rtr_mac1[6]   = {0xAA,0x00,0x00,0x00,0x02,0x00};

    /* Learn host-A's ARP on iface 0 */
    arp_cache_learn(mkip(10,0,1,100), host_a_mac, 0);

    /* Send IP frame from 10.0.1.100 to 10.0.2.100 via iface 0 */
    u8 buf[256];
    u32 len = make_ip_frame(buf, host_a_mac, rtr_mac0,
                             mkip(10,0,1,100), mkip(10,0,2,100),
                             64, IP_PROTO_ICMP);

    packet_t pkt;
    memcpy(pkt.data, buf, len);
    pkt.len = len;
    pkt.iface_idx = 0;

    /* First dispatch: ARP cache miss for 10.0.2.100 -> router buffers packet
       and sends ARP Request on iface 1 */
    router_dispatch(&pkt);

    packet_t arp_req_pkt;
    bool got_arp = netdev_mock_dequeue_tx(1, &arp_req_pkt);
    CHECK(got_arp, "ARP Request sent on iface1 for 10.0.2.100");

    if (got_arp) {
        const eth_hdr_t *eth = (eth_hdr_t *)arp_req_pkt.data;
        const arp_pkt_t *arp = (arp_pkt_t *)(arp_req_pkt.data + 14);
        CHECK(ntohs(eth->ethertype) == ETHERTYPE_ARP, "ARP Request EtherType");
        CHECK(ntohs(arp->oper) == ARP_REQUEST,         "ARP Operation = Request");
        CHECK(arp->tpa == mkip(10,0,2,100),            "ARP target = 10.0.2.100");
    }

    /* Inject ARP Reply from host-B */
    u8 arp_buf[256];
    u32 arp_len = make_arp_reply(arp_buf,
                                  host_b_mac, mkip(10,0,2,100),
                                  rtr_mac1,   mkip(10,0,2,1));
    packet_t arp_reply;
    memcpy(arp_reply.data, arp_buf, arp_len);
    arp_reply.len = arp_len;
    arp_reply.iface_idx = 1;

    router_dispatch(&arp_reply);

    /* After ARP reply, the buffered packet should be forwarded on iface 1 */
    packet_t fwd_pkt;
    bool got_fwd = netdev_mock_dequeue_tx(1, &fwd_pkt);
    CHECK(got_fwd, "Forwarded packet arrived on iface1 after ARP resolution");

    if (got_fwd) {
        const eth_hdr_t *eth = (eth_hdr_t *)fwd_pkt.data;
        const ip4_hdr_t *ip  = (ip4_hdr_t *)(fwd_pkt.data + 14);
        CHECK(memcmp(eth->src, rtr_mac1, 6) == 0, "Egress src MAC = router tap1 MAC");
        CHECK(memcmp(eth->dst, host_b_mac, 6) == 0, "Egress dst MAC = host-B MAC");
        CHECK(ip->daddr == mkip(10,0,2,100), "Destination IP unchanged = 10.0.2.100");
        CHECK(ip->ttl == 63,                 "TTL decremented to 63");
    }
}

/* ── Test 3: TTL = 1 -> ICMP Time Exceeded ───────────────────────────────── */
void test_ttl_expired(void)
{
    setup_router();

    u8 host_mac[6] = {0xBB,0x00,0x00,0x00,0x01,0x00};
    u8 rtr_mac0[6] = {0xAA,0x00,0x00,0x00,0x01,0x00};

    arp_cache_learn(mkip(10,0,1,100), host_mac, 0);

    u8 buf[256];
    u32 len = make_ip_frame(buf, host_mac, rtr_mac0,
                             mkip(10,0,1,100), mkip(10,0,2,100),
                             1,   /* TTL = 1 -> will reach 0 on decrement */
                             IP_PROTO_ICMP);

    packet_t pkt;
    memcpy(pkt.data, buf, len);
    pkt.len = len;
    pkt.iface_idx = 0;

    router_dispatch(&pkt);

    /* Expect ICMP Time Exceeded on iface 0 */
    packet_t tx;
    bool got = netdev_mock_dequeue_tx(0, &tx);
    CHECK(got, "ICMP Time Exceeded sent");
    if (got) {
        const ip4_hdr_t *ip = (ip4_hdr_t *)(tx.data + 14);
        u8 *icmp = tx.data + 14 + 20;
        CHECK(ip->protocol == IP_PROTO_ICMP,  "Time Exceeded: protocol ICMP");
        CHECK(icmp[0] == ICMP_TIME_EXCEEDED,   "ICMP type = Time Exceeded");
        CHECK(icmp[1] == ICMP_TTL_EXCEEDED,    "ICMP code = TTL Exceeded");
        CHECK(ip->daddr == mkip(10,0,1,100),   "ICMP sent back to source");
    }
}

/* ── Test 4: No route -> ICMP Destination Unreachable ────────────────────── */
void test_no_route(void)
{
    setup_router();

    u8 host_mac[6] = {0xBB,0x00,0x00,0x00,0x01,0x00};
    u8 rtr_mac0[6] = {0xAA,0x00,0x00,0x00,0x01,0x00};

    arp_cache_learn(mkip(10,0,1,100), host_mac, 0);

    /* Packet to 1.2.3.4 – no route exists */
    u8 buf[256];
    u32 len = make_ip_frame(buf, host_mac, rtr_mac0,
                             mkip(10,0,1,100), mkip(1,2,3,4),
                             64, IP_PROTO_ICMP);

    packet_t pkt;
    memcpy(pkt.data, buf, len);
    pkt.len = len;
    pkt.iface_idx = 0;

    router_dispatch(&pkt);

    packet_t tx;
    bool got = netdev_mock_dequeue_tx(0, &tx);
    CHECK(got, "ICMP Dest Unreachable sent");
    if (got) {
        u8 *icmp = tx.data + 14 + 20;
        CHECK(icmp[0] == ICMP_DST_UNREACH,   "ICMP type = Dest Unreachable");
        CHECK(icmp[1] == ICMP_NET_UNREACH,    "ICMP code = Net Unreachable");
    }
}

/* ── Test 5: ACL deny ─────────────────────────────────────────────────────── */
void test_acl_deny_forwarding(void)
{
    setup_router();

    /* Add ACL rule: deny all TCP */
    acl_rule_t r = {
        .valid = true, .id = 1,
        .src_ip = 0, .src_mask = 0,
        .dst_ip = 0, .dst_mask = 0,
        .protocol = IP_PROTO_TCP,
        .src_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .dst_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .iface_idx = -1,
        .direction = ACL_DIR_INGRESS,
        .action = ACL_ACTION_DENY,
    };
    strncpy(r.name, "no-tcp", sizeof(r.name)-1);
    acl_add_rule(&r);

    u8 host_mac[6] = {0xBB,0x00,0x00,0x00,0x01,0x00};
    u8 rtr_mac0[6] = {0xAA,0x00,0x00,0x00,0x01,0x00};

    arp_cache_learn(mkip(10,0,1,100), host_mac, 0);

    /* Build a TCP frame to trigger the ACL */
    eth_hdr_t *eth;
    u8 buf[256];
    u32 len = make_ip_frame(buf, host_mac, rtr_mac0,
                             mkip(10,0,1,100), mkip(10,0,2,100),
                             64, IP_PROTO_TCP);

    packet_t pkt;
    memcpy(pkt.data, buf, len);
    pkt.len = len;
    pkt.iface_idx = 0;

    g_router.cfg.send_icmp_on_deny = false;   /* quiet deny */
    router_dispatch(&pkt);

    /* Nothing should be forwarded */
    packet_t tx;
    bool got = netdev_mock_dequeue_tx(1, &tx);
    CHECK(!got, "TCP packet dropped by ACL (no forwarding on iface1)");

    CHECK(g_stats.acl_ingress_deny == 1, "ACL ingress deny counter == 1");
}

/* ── main ───────────────────────────────────────────────────────────────── */
int main(void)
{
    /* Minimal router context setup */
    memset(&g_router, 0, sizeof(g_router));
    g_router.cfg.send_icmp_on_deny = true;
    g_router.cfg.use_mock          = true;

    printf("=== Forwarding Integration Tests ===\n");
    test_icmp_local();
    test_forwarding();
    test_ttl_expired();
    test_no_route();
    test_acl_deny_forwarding();

    printf("\nResults: %d passed, %d failed\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
