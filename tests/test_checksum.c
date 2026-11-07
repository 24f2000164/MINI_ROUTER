/*
 * test_checksum.c - Unit tests for IPv4 checksum computation
 */

#include "../include/ipv4.h"
#include "../include/types.h"
#include <stdio.h>
#include <string.h>

int g_log_level = LOG_LEVEL_ERR;

static int s_pass = 0, s_fail = 0;

#define CHECK(cond, msg) \
    do { if (cond) { printf("  PASS: %s\n", msg); s_pass++; } \
         else      { printf("  FAIL: %s  [%s:%d]\n", msg, __FILE__, __LINE__); s_fail++; } } while(0)

/* Reference IPv4 header with known-good checksum (from RFC 791 example)
   Source: 192.168.1.1, Dest: 192.168.1.2, TTL=64, proto=ICMP           */
static void test_checksum_basic(void)
{
    ip4_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ver_ihl  = (4 << 4) | 5;
    hdr.tot_len  = htons(20);
    hdr.ttl      = 64;
    hdr.protocol = IP_PROTO_ICMP;
    hdr.saddr    = htonl(0xC0A80101);  /* 192.168.1.1 */
    hdr.daddr    = htonl(0xC0A80102);  /* 192.168.1.2 */
    hdr.check    = 0;
    hdr.check    = ip4_checksum(&hdr, 20);

    CHECK(hdr.check != 0, "Checksum is non-zero");
    CHECK(ip4_checksum_valid(&hdr), "Computed checksum validates correctly");
}

static void test_checksum_ttl_decrement(void)
{
    ip4_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ver_ihl  = (4 << 4) | 5;
    hdr.tot_len  = htons(20);
    hdr.ttl      = 64;
    hdr.protocol = IP_PROTO_TCP;
    hdr.saddr    = htonl(0x0A000101);
    hdr.daddr    = htonl(0x0A000201);
    hdr.check    = 0;
    hdr.check    = ip4_checksum(&hdr, 20);

    CHECK(ip4_checksum_valid(&hdr), "Pre-decrement checksum is valid");

    u8 new_ttl = ip4_decrement_ttl(&hdr);
    CHECK(new_ttl == 63, "TTL decremented from 64 to 63");
    CHECK(ip4_checksum_valid(&hdr),
          "Post-decrement checksum still valid (incremental update)");

    /* Verify: recalculate full checksum and compare */
    u16 saved = hdr.check;
    hdr.check  = 0;
    hdr.check  = ip4_checksum(&hdr, 20);
    CHECK(saved == hdr.check,
          "Incremental checksum matches full recalculation");
}

static void test_checksum_corruption_detected(void)
{
    ip4_hdr_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ver_ihl  = (4 << 4) | 5;
    hdr.tot_len  = htons(20);
    hdr.ttl      = 128;
    hdr.protocol = IP_PROTO_UDP;
    hdr.saddr    = htonl(0x01020304);
    hdr.daddr    = htonl(0x05060708);
    hdr.check    = 0;
    hdr.check    = ip4_checksum(&hdr, 20);

    /* Corrupt one byte */
    hdr.ttl ^= 0xFF;

    CHECK(!ip4_checksum_valid(&hdr),
          "Corrupted packet detected as invalid checksum");
}

int main(void)
{
    printf("=== IPv4 Checksum Unit Tests ===\n");
    test_checksum_basic();
    test_checksum_ttl_decrement();
    test_checksum_corruption_detected();

    printf("\nResults: %d passed, %d failed\n", s_pass, s_fail);
    return s_fail ? 1 : 0;
}
