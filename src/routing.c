/*
 * routing.c - Longest Prefix Match routing engine (Binary Trie)
 */

#include "routing.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ── Global routing table ───────────────────────────────────────────────── */
route_entry_t g_routes[ROUTE_MAX_ENTRIES];
int           g_num_routes = 0;

/* ── Binary Trie (pool-allocated) ──────────────────────────────────────── */
#define TRIE_POOL_SIZE  (ROUTE_MAX_ENTRIES * 34)  /* generous upper bound */

static trie_node_t  s_pool[TRIE_POOL_SIZE];
static int          s_pool_used = 0;
static trie_node_t *s_root      = NULL;

static trie_node_t *trie_alloc(void)
{
    if (s_pool_used >= TRIE_POOL_SIZE) return NULL;
    trie_node_t *n = &s_pool[s_pool_used++];
    n->child[0] = n->child[1] = NULL;
    n->route_idx = -1;
    return n;
}

static void trie_reset(void)
{
    s_pool_used = 0;
    s_root      = NULL;
    memset(s_pool, 0, sizeof(s_pool));
}

/* ── Insert a route into the trie ──────────────────────────────────────── */
static void trie_insert(u32 dest_host, u8 prefix_len, int route_idx)
{
    if (!s_root) {
        s_root = trie_alloc();
        if (!s_root) return;
    }

    trie_node_t *cur = s_root;
    for (int bit = 31; bit >= (32 - (int)prefix_len); bit--) {
        int b = (dest_host >> bit) & 1;
        if (!cur->child[b]) {
            cur->child[b] = trie_alloc();
            if (!cur->child[b]) return;
        }
        cur = cur->child[b];
    }
    cur->route_idx = route_idx;
}

/* ── Rebuild trie from g_routes[] ──────────────────────────────────────── */
static void trie_rebuild(void)
{
    trie_reset();
    s_root = trie_alloc();
    for (int i = 0; i < g_num_routes; i++) {
        if (g_routes[i].valid) {
            u32 dest_h = ntohl(g_routes[i].dest);
            trie_insert(dest_h, g_routes[i].prefix_len, i);
        }
    }
}

/* ── Public API ─────────────────────────────────────────────────────────── */

void routing_init(void)
{
    memset(g_routes, 0, sizeof(g_routes));
    g_num_routes = 0;
    trie_reset();
    s_root = trie_alloc();
    LOG_INFO("Routing engine initialized");
}

int routing_add(u32 dest_net, u32 mask, u8 prefix_len,
                u32 gateway, int iface_idx, u32 metric)
{
    if (g_num_routes >= ROUTE_MAX_ENTRIES) {
        LOG_ERR("routing_add: table full");
        return -1;
    }

    /* Check for duplicate prefix */
    for (int i = 0; i < g_num_routes; i++) {
        if (g_routes[i].valid &&
            g_routes[i].dest == dest_net &&
            g_routes[i].prefix_len == prefix_len) {
            /* Update existing */
            g_routes[i].gateway   = gateway;
            g_routes[i].iface_idx = iface_idx;
            g_routes[i].metric    = metric;
            g_routes[i].mask      = mask;
            trie_rebuild();
            LOG_INFO("Route updated: %s/%u via %s dev %d",
                     ip4_str(dest_net), prefix_len,
                     ip4_str(gateway), iface_idx);
            return i;
        }
    }

    int idx = g_num_routes++;
    g_routes[idx].dest       = dest_net;
    g_routes[idx].mask       = mask;
    g_routes[idx].prefix_len = prefix_len;
    g_routes[idx].gateway    = gateway;
    g_routes[idx].iface_idx  = iface_idx;
    g_routes[idx].metric     = metric;
    g_routes[idx].valid      = true;

    trie_insert(ntohl(dest_net), prefix_len, idx);

    LOG_INFO("Route added: %s/%u via %s dev %d metric %u",
             ip4_str(dest_net), prefix_len,
             ip4_str(gateway), iface_idx, metric);
    return idx;
}

int routing_del(u32 dest_net, u8 prefix_len)
{
    for (int i = 0; i < g_num_routes; i++) {
        if (g_routes[i].valid &&
            g_routes[i].dest == dest_net &&
            g_routes[i].prefix_len == prefix_len) {
            g_routes[i].valid = false;
            trie_rebuild();
            LOG_INFO("Route deleted: %s/%u", ip4_str(dest_net), prefix_len);
            return 0;
        }
    }
    return -1;
}

const route_entry_t *routing_lpm(u32 dst_ip_net)
{
    if (!s_root) return NULL;

    u32 dst_host = ntohl(dst_ip_net);
    trie_node_t  *cur  = s_root;
    int           best = s_root->route_idx;   /* may be -1 if no /0 default */

    for (int bit = 31; bit >= 0; bit--) {
        int b = (dst_host >> bit) & 1;
        if (!cur->child[b]) break;
        cur = cur->child[b];
        if (cur->route_idx >= 0)
            best = cur->route_idx;   /* longer match found                */
    }

    if (best < 0) {
        LOG_DBG("routing_lpm: no route for %s", ip4_str(dst_ip_net));
        return NULL;
    }
    return &g_routes[best];
}

void routing_print(void)
{
    printf("\n=== Routing Table ===\n");
    printf("%-20s %-16s %-8s %-6s\n",
           "Destination", "Gateway", "Dev", "Metric");
    printf("%-20s %-16s %-8s %-6s\n",
           "-------------------", "---------------", "-------", "------");
    for (int i = 0; i < g_num_routes; i++) {
        if (!g_routes[i].valid) continue;
        char dst[20];
        snprintf(dst, sizeof(dst), "%s/%u",
                 ip4_str(g_routes[i].dest), g_routes[i].prefix_len);
        printf("%-20s %-16s %-8d %-6u\n",
               dst,
               g_routes[i].gateway ? ip4_str(g_routes[i].gateway) : "0.0.0.0",
               g_routes[i].iface_idx,
               g_routes[i].metric);
    }
    printf("\n");
}

int routing_parse_cidr(const char *cidr, u32 *dest_out, u32 *mask_out,
                        u8 *prefix_len_out)
{
    char ip_str[16];
    int  prefix = 32;

    const char *slash = strchr(cidr, '/');
    if (slash) {
        size_t ip_len = (size_t)(slash - cidr);
        if (ip_len >= sizeof(ip_str)) return -1;
        strncpy(ip_str, cidr, ip_len);
        ip_str[ip_len] = '\0';
        prefix = atoi(slash + 1);
    } else {
        strncpy(ip_str, cidr, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str)-1] = '\0';
    }

    if (prefix < 0 || prefix > 32) return -1;

    /* Parse dotted-decimal */
    unsigned a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;

    u32 ip_host = (a << 24) | (b << 16) | (c << 8) | d;
    u32 mask_host = prefix == 0 ? 0 : (~0u << (32 - prefix));

    *dest_out       = htonl(ip_host & mask_host);
    *mask_out       = htonl(mask_host);
    *prefix_len_out = (u8)prefix;
    return 0;
}
