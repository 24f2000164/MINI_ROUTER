/*
 * test_acl.c - Unit tests for the 5-tuple ACL engine
 */

#include "../include/acl.h"
#include "../include/ipv4.h"
#include "../include/ethernet.h"
#include "../include/types.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

int g_log_level = LOG_LEVEL_ERR;

/* Global stubs required by acl.c -> ip4_parse -> packet validation      */
/* (netdev globals are not needed for ACL tests)                         */
netdev_iface_t g_ifaces[NETDEV_MAX_IFACES];
int            g_num_ifaces = 0;

static int s_pass = 0, s_fail = 0;

#define CHECK(cond, msg) \
    do { if (cond) { printf("  PASS: %s\n", msg); s_pass++; } \
         else      { printf("  FAIL: %s  [%s:%d]\n", msg, __FILE__, __LINE__); s_fail++; } } while(0)

/* Helper: build a minimal valid IPv4/TCP Ethernet frame in buf */
static u32 make_ip_tcp_frame(u8 *buf, u32 buf_sz,
                               u32 src_ip, u32 dst_ip,
                               u16 sport, u16 dport,
                               u8 proto)
{
    /* Ethernet header */
    u8 smac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    u8 dmac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    eth_hdr_t *eth = (eth_hdr_t *)buf;
    memcpy(eth->src, smac, 6);
    memcpy(eth->dst, dmac, 6);
    eth->ethertype = htons(ETHERTYPE_IPV4);

    /* IPv4 header */
    ip4_hdr_t *ip = (ip4_hdr_t *)(buf + 14);
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl  = (4 << 4) | 5;
    ip->tot_len  = htons(20 + 4);   /* 20 IP + 4 transport (sport+dport) */
    ip->ttl      = 64;
    ip->protocol = proto;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = 0;
    ip->check    = ip4_checksum(ip, 20);

    /* Minimal transport (just ports) */
    u16 *ports = (u16 *)(buf + 14 + 20);
    ports[0] = htons(sport);
    ports[1] = htons(dport);

    return 14 + 20 + 4;
}

static u32 make_icmp_frame(u8 *buf, u32 buf_sz,
                            u32 src_ip, u32 dst_ip)
{
    eth_hdr_t *eth = (eth_hdr_t *)buf;
    u8 smac[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    u8 dmac[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    memcpy(eth->src, smac, 6);
    memcpy(eth->dst, dmac, 6);
    eth->ethertype = htons(ETHERTYPE_IPV4);

    ip4_hdr_t *ip = (ip4_hdr_t *)(buf + 14);
    memset(ip, 0, sizeof(*ip));
    ip->ver_ihl  = (4 << 4) | 5;
    ip->tot_len  = htons(20 + 8);
    ip->ttl      = 64;
    ip->protocol = IP_PROTO_ICMP;
    ip->saddr    = src_ip;
    ip->daddr    = dst_ip;
    ip->check    = ip4_checksum(ip, 20);
    return 14 + 20 + 8;
}

static inline u32 mkip(unsigned a, unsigned b, unsigned c, unsigned d)
{ return htonl((a<<24)|(b<<16)|(c<<8)|d); }

void test_acl_permit_deny(void)
{
    acl_init();

    /* Rule 1: deny all TCP port 80 */
    acl_rule_t r1 = {
        .valid = true, .id = 1,
        .src_ip = 0, .src_mask = 0,
        .dst_ip = 0, .dst_mask = 0,
        .protocol = IP_PROTO_TCP,
        .src_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .dst_port = {80, 80},
        .iface_idx = -1,
        .direction = ACL_DIR_BOTH,
        .action = ACL_ACTION_DENY,
    };
    strncpy(r1.name, "deny-http", sizeof(r1.name)-1);
    acl_add_rule(&r1);

    /* Rule 2: permit TCP from 10.0.0.0/8 (any port) */
    acl_rule_t r2 = {
        .valid = true, .id = 2,
        .src_ip   = mkip(10,0,0,0), .src_mask = htonl(0xFF000000),
        .dst_ip   = 0, .dst_mask = 0,
        .protocol = IP_PROTO_TCP,
        .src_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .dst_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .iface_idx = -1,
        .direction = ACL_DIR_BOTH,
        .action = ACL_ACTION_PERMIT,
    };
    strncpy(r2.name, "permit-10", sizeof(r2.name)-1);
    acl_add_rule(&r2);

    packet_t pkt;

    /* TCP from anywhere to port 80 -> DENY (rule 1 matches first) */
    pkt.len = make_ip_tcp_frame(pkt.data, sizeof(pkt.data),
                                 mkip(192,168,1,1), mkip(10,0,0,2),
                                 12345, 80, IP_PROTO_TCP);
    pkt.iface_idx = 0;
    CHECK(acl_evaluate(&pkt, 0, ACL_DIR_BOTH) == ACL_ACTION_DENY,
          "TCP dst port 80 -> DENY (rule 1)");

    /* TCP from 10.0.0.1 to port 443 -> PERMIT (rule 2) */
    pkt.len = make_ip_tcp_frame(pkt.data, sizeof(pkt.data),
                                 mkip(10,0,0,1), mkip(10,0,0,2),
                                 54321, 443, IP_PROTO_TCP);
    pkt.iface_idx = 0;
    CHECK(acl_evaluate(&pkt, 0, ACL_DIR_BOTH) == ACL_ACTION_PERMIT,
          "TCP from 10.0.0.1 dst port 443 -> PERMIT (rule 2)");

    /* UDP -> no TCP rules match, default PERMIT */
    pkt.len = make_ip_tcp_frame(pkt.data, sizeof(pkt.data),
                                 mkip(1,2,3,4), mkip(5,6,7,8),
                                 1000, 53, IP_PROTO_UDP);
    pkt.iface_idx = 0;
    CHECK(acl_evaluate(&pkt, 0, ACL_DIR_BOTH) == ACL_ACTION_PERMIT,
          "UDP -> default PERMIT");
}

void test_acl_icmp_block(void)
{
    acl_init();

    /* Deny all ICMP */
    acl_rule_t r = {
        .valid = true, .id = 10,
        .src_ip = 0, .src_mask = 0,
        .dst_ip = 0, .dst_mask = 0,
        .protocol = IP_PROTO_ICMP,
        .src_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .dst_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .iface_idx = -1,
        .direction = ACL_DIR_BOTH,
        .action = ACL_ACTION_DENY,
    };
    strncpy(r.name, "no-ping", sizeof(r.name)-1);
    acl_add_rule(&r);

    packet_t pkt;
    pkt.len = make_icmp_frame(pkt.data, sizeof(pkt.data),
                               mkip(1,1,1,1), mkip(2,2,2,2));
    pkt.iface_idx = 0;
    CHECK(acl_evaluate(&pkt, 0, ACL_DIR_BOTH) == ACL_ACTION_DENY,
          "ICMP blocked by no-ping rule");
}

void test_acl_direction_filter(void)
{
    acl_init();

    /* Deny TCP ingress only */
    acl_rule_t r = {
        .valid = true, .id = 20,
        .src_ip = 0, .src_mask = 0,
        .dst_ip = 0, .dst_mask = 0,
        .protocol = IP_PROTO_TCP,
        .src_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .dst_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .iface_idx = -1,
        .direction = ACL_DIR_INGRESS,
        .action = ACL_ACTION_DENY,
    };
    strncpy(r.name, "deny-in-tcp", sizeof(r.name)-1);
    acl_add_rule(&r);

    packet_t pkt;
    pkt.len = make_ip_tcp_frame(pkt.data, sizeof(pkt.data),
                                 mkip(1,2,3,4), mkip(5,6,7,8),
                                 1000, 80, IP_PROTO_TCP);
    pkt.iface_idx = 0;

    CHECK(acl_evaluate(&pkt, 0, ACL_DIR_INGRESS) == ACL_ACTION_DENY,
          "TCP denied on ingress direction");
    CHECK(acl_evaluate(&pkt, 0, ACL_DIR_EGRESS) == ACL_ACTION_PERMIT,
          "TCP permitted on egress direction (ingress-only rule skipped)");
}

void test_acl_hit_counters(void)
{
    acl_init();

    acl_rule_t r = {
        .valid = true, .id = 30,
        .src_ip = 0, .src_mask = 0,
        .dst_ip = 0, .dst_mask = 0,
        .protocol = ACL_PROTO_ANY,
        .src_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .dst_port = {PORT_ANY_MIN, PORT_ANY_MAX},
        .iface_idx = -1,
        .direction = ACL_DIR_BOTH,
        .action = ACL_ACTION_PERMIT,
    };
    strncpy(r.name, "count-all", sizeof(r.name)-1);
    acl_add_rule(&r);

    packet_t pkt;
    pkt.len = make_icmp_frame(pkt.data, sizeof(pkt.data),
                               mkip(1,1,1,1), mkip(2,2,2,2));
    pkt.iface_idx = 0;

    acl_evaluate(&pkt, 0, ACL_DIR_BOTH);
    acl_evaluate(&pkt, 0, ACL_DIR_BOTH);
    acl_evaluate(&pkt, 0, ACL_DIR_BOTH);

    CHECK(g_acl_rules[0].hit_packets == 3,
          "ACL hit counter incremented 3 times");
}

int main(void)
{
    printf("=== ACL Engine Unit Tests ===\n");
    test_acl_permit_deny();
    test_acl_icmp_block();
    test_acl_direction_filter();
    test_acl_hit_counters();

    printf("\nResults: %d passed, %d failed\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
