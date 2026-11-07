/*
 * test_lpm.c - Unit tests for the Longest Prefix Match routing engine
 */

#include "../include/routing.h"
#include "../include/types.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* ── Global required by router.c / stats.c ─────────────────────────────── */
int g_log_level = LOG_LEVEL_ERR;

/* Helper: build a network-order IPv4 from dotted-decimal */
static u32 mkip(unsigned a, unsigned b, unsigned c, unsigned d)
{
    return htonl((a << 24) | (b << 16) | (c << 8) | d);
}

static int s_pass = 0, s_fail = 0;

#define CHECK(cond, msg) \
    do { if (cond) { printf("  PASS: %s\n", msg); s_pass++; } \
         else      { printf("  FAIL: %s  [%s:%d]\n", msg, __FILE__, __LINE__); s_fail++; } } while(0)

void test_lpm_basic(void)
{
    routing_init();

    /* /24 route */
    routing_add(mkip(10,0,1,0), htonl(0xFFFFFF00), 24,
                mkip(10,0,0,1), 0, 1);

    /* /16 route */
    routing_add(mkip(10,0,0,0), htonl(0xFFFF0000), 16,
                mkip(192,168,1,1), 1, 1);

    /* default route */
    routing_add(mkip(0,0,0,0), htonl(0), 0,
                mkip(203,0,113,1), 0, 100);

    const route_entry_t *r;

    /* Should match /24 */
    r = routing_lpm(mkip(10,0,1,100));
    CHECK(r && r->prefix_len == 24, "LPM /24 match for 10.0.1.100");

    /* Should match /16 */
    r = routing_lpm(mkip(10,0,2,1));
    CHECK(r && r->prefix_len == 16, "LPM /16 match for 10.0.2.1");

    /* Should match default */
    r = routing_lpm(mkip(8,8,8,8));
    CHECK(r && r->prefix_len == 0,  "LPM default for 8.8.8.8");

    /* Exact /32 added later should beat /24 */
    routing_add(mkip(10,0,1,50), htonl(0xFFFFFFFF), 32,
                mkip(10,0,1,254), 0, 1);
    r = routing_lpm(mkip(10,0,1,50));
    CHECK(r && r->prefix_len == 32, "LPM /32 beats /24 for 10.0.1.50");
}

void test_lpm_no_route(void)
{
    routing_init();
    routing_add(mkip(192,168,1,0), htonl(0xFFFFFF00), 24,
                0, 0, 1);

    const route_entry_t *r = routing_lpm(mkip(10,0,0,1));
    CHECK(r == NULL, "LPM returns NULL when no route exists");
}

void test_lpm_delete(void)
{
    routing_init();
    routing_add(mkip(172,16,0,0), htonl(0xFFFF0000), 16, 0, 0, 1);

    const route_entry_t *r = routing_lpm(mkip(172,16,5,1));
    CHECK(r != NULL, "Route found before deletion");

    routing_del(mkip(172,16,0,0), 16);
    r = routing_lpm(mkip(172,16,5,1));
    CHECK(r == NULL, "Route not found after deletion");
}

void test_lpm_cidr_parser(void)
{
    u32 dest, mask;
    u8  plen;

    CHECK(routing_parse_cidr("192.168.1.0/24", &dest, &mask, &plen) == 0,
          "CIDR parse OK: 192.168.1.0/24");
    CHECK(plen == 24,            "Prefix length == 24");
    CHECK(dest == mkip(192,168,1,0), "Dest == 192.168.1.0");

    CHECK(routing_parse_cidr("0.0.0.0/0", &dest, &mask, &plen) == 0,
          "CIDR parse OK: 0.0.0.0/0");
    CHECK(plen == 0,  "Prefix length == 0");

    CHECK(routing_parse_cidr("10.0.0.1/32", &dest, &mask, &plen) == 0,
          "CIDR parse OK: 10.0.0.1/32");
    CHECK(plen == 32, "Prefix length == 32");

    CHECK(routing_parse_cidr("bad_input", &dest, &mask, &plen) != 0,
          "CIDR parse returns error for bad input");
}

int main(void)
{
    printf("=== LPM Routing Unit Tests ===\n");
    test_lpm_basic();
    test_lpm_no_route();
    test_lpm_delete();
    test_lpm_cidr_parser();

    printf("\nResults: %d passed, %d failed\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
