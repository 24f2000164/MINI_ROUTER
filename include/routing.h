/*
 * routing.h - IPv4 Longest Prefix Match (LPM) routing engine
 *             Implemented as a Binary Trie (bit-by-bit, MSB-first)
 */

#ifndef MINIROUTER_ROUTING_H
#define MINIROUTER_ROUTING_H

#include "types.h"

/* ── Route entry ────────────────────────────────────────────────────────── */
#define ROUTE_MAX_ENTRIES  256

typedef struct {
    u32  dest;          /* destination network (network byte order)       */
    u32  mask;          /* subnet mask (network byte order)               */
    u8   prefix_len;    /* prefix length 0-32                             */
    u32  gateway;       /* next-hop IP, 0 = directly connected            */
    int  iface_idx;     /* egress interface index                         */
    u32  metric;        /* routing metric / administrative distance       */
    bool valid;
} route_entry_t;

/* ── Binary Trie node ───────────────────────────────────────────────────── */
typedef struct trie_node {
    struct trie_node *child[2];   /* 0 = left (bit 0), 1 = right (bit 1) */
    int route_idx;                /* index into g_routes[], -1 = no entry */
} trie_node_t;

/* ── Globals ────────────────────────────────────────────────────────────── */
extern route_entry_t g_routes[ROUTE_MAX_ENTRIES];
extern int           g_num_routes;

/* ── API ────────────────────────────────────────────────────────────────── */

/* Initialize / reset the routing table and trie.                        */
void routing_init(void);

/* Add a route entry.  Returns 0 on success, -1 on error.               */
int  routing_add(u32 dest_net, u32 mask, u8 prefix_len,
                 u32 gateway, int iface_idx, u32 metric);

/* Delete a route.  Returns 0 if found and removed, -1 otherwise.       */
int  routing_del(u32 dest_net, u8 prefix_len);

/* Longest prefix match lookup for dst_ip.
   Returns pointer to best-matching route entry, or NULL if no route.   */
const route_entry_t *routing_lpm(u32 dst_ip_net);

/* Print the full routing table.                                         */
void routing_print(void);

/* Parse "A.B.C.D/prefix_len" string into dest and mask.
   Returns 0 on success, -1 on parse error.                             */
int  routing_parse_cidr(const char *cidr, u32 *dest_out, u32 *mask_out,
                         u8 *prefix_len_out);

#endif /* MINIROUTER_ROUTING_H */
