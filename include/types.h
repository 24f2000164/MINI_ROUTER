/*
 * types.h - Common type definitions, macros, and byte-order utilities
 * Mini Router: L2/L3 Packet Forwarding and ACL Engine
 */

#ifndef MINIROUTER_TYPES_H
#define MINIROUTER_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

/* ── Sized integer aliases ─────────────────────────────────────────────── */
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

/* ── Packet buffer ─────────────────────────────────────────────────────── */
#define PKT_BUF_SIZE   2048   /* bytes – generous for Ethernet MTU 1500   */
#define ETH_ALEN         6    /* MAC address length in bytes               */
#define IPV4_ALEN        4    /* IPv4 address length in bytes              */

typedef struct {
    u8  data[PKT_BUF_SIZE];
    u32 len;          /* valid bytes in data[]                            */
    int iface_idx;    /* ingress interface index                          */
} packet_t;

/* ── EtherTypes ────────────────────────────────────────────────────────── */
#define ETHERTYPE_IPV4   0x0800
#define ETHERTYPE_ARP    0x0806

/* ── IP Protocols ──────────────────────────────────────────────────────── */
#define IP_PROTO_ICMP    1
#define IP_PROTO_TCP     6
#define IP_PROTO_UDP     17

/* ── ICMP types ────────────────────────────────────────────────────────── */
#define ICMP_ECHO_REPLY    0
#define ICMP_DST_UNREACH   3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_ECHO_REQUEST  8

/* ── ICMP codes ────────────────────────────────────────────────────────── */
#define ICMP_NET_UNREACH   0
#define ICMP_HOST_UNREACH  1
#define ICMP_ADMIN_PROHIB  13
#define ICMP_TTL_EXCEEDED  0

/* ── ARP Operation codes ───────────────────────────────────────────────── */
#define ARP_REQUEST  1
#define ARP_REPLY    2

/* ── Byte order helpers (host ↔ network, big-endian) ─────────────────── */
/* On Linux, arpa/inet.h provides htons/ntohs/htonl/ntohl.
   Here we provide portable fallbacks so the code compiles
   cleanly under CI on any host endianness.                               */
#ifdef __linux__
#  include <arpa/inet.h>
#  include <netinet/in.h>
#else
/* Portable big-endian converters for cross-compilation / unit tests       */
static inline u16 _bswap16(u16 v) { return (u16)((v >> 8) | (v << 8)); }
static inline u32 _bswap32(u32 v) {
    return ((v & 0xFF000000u) >> 24) |
           ((v & 0x00FF0000u) >>  8) |
           ((v & 0x0000FF00u) <<  8) |
           ((v & 0x000000FFu) << 24);
}
#  if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#    define htons(x)  _bswap16(x)
#    define ntohs(x)  _bswap16(x)
#    define htonl(x)  _bswap32(x)
#    define ntohl(x)  _bswap32(x)
#  else
#    define htons(x)  (x)
#    define ntohs(x)  (x)
#    define htonl(x)  (x)
#    define ntohl(x)  (x)
#  endif
#endif

/* ── Logging macros ────────────────────────────────────────────────────── */
#define LOG_LEVEL_ERR   0
#define LOG_LEVEL_WARN  1
#define LOG_LEVEL_INFO  2
#define LOG_LEVEL_DBG   3

extern int g_log_level;

#define LOG(level, fmt, ...) \
    do { if ((level) <= g_log_level) \
        fprintf(stderr, "[%s] " fmt "\n", \
            (level)==0?"ERR":(level)==1?"WARN":(level)==2?"INFO":"DBG", \
            ##__VA_ARGS__); } while (0)

#define LOG_ERR(fmt,  ...) LOG(LOG_LEVEL_ERR,  fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) LOG(LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) LOG(LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define LOG_DBG(fmt,  ...) LOG(LOG_LEVEL_DBG,  fmt, ##__VA_ARGS__)

/* ── Misc utilities ────────────────────────────────────────────────────── */
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define MIN(a,b)     ((a) < (b) ? (a) : (b))
#define MAX(a,b)     ((a) > (b) ? (a) : (b))

/* Format an IPv4 address (network byte order u32) into a static buffer.
   NOT thread-safe – for logging only.                                     */
static inline const char *ip4_str(u32 ip_net) {
    static char buf[4][16];
    static int  slot = 0;
    u8 *b = (u8 *)&ip_net;
    slot = (slot + 1) & 3;
    snprintf(buf[slot], 16, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf[slot];
}

/* Format a MAC address into a static buffer. NOT thread-safe.            */
static inline const char *mac_str(const u8 mac[ETH_ALEN]) {
    static char buf[4][18];
    static int  slot = 0;
    slot = (slot + 1) & 3;
    snprintf(buf[slot], 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf[slot];
}

#endif /* MINIROUTER_TYPES_H */
