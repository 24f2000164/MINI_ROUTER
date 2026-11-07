/*
 * acl.c - 5-tuple ACL engine: rule storage, matching, hit accounting
 */

#include "acl.h"
#include "ipv4.h"
#include "ethernet.h"
#include <string.h>
#include <stdio.h>

/* ── Globals ────────────────────────────────────────────────────────────── */
acl_rule_t   g_acl_rules[ACL_MAX_RULES];
int          g_num_acl_rules  = 0;
acl_action_t g_acl_default_action = ACL_ACTION_PERMIT;

/* ── Init ───────────────────────────────────────────────────────────────── */
void acl_init(void)
{
    memset(g_acl_rules, 0, sizeof(g_acl_rules));
    g_num_acl_rules = 0;
    g_acl_default_action = ACL_ACTION_PERMIT;
    LOG_INFO("ACL engine initialized (default: PERMIT)");
}

/* ── Add rule ───────────────────────────────────────────────────────────── */
int acl_add_rule(const acl_rule_t *rule)
{
    if (g_num_acl_rules >= ACL_MAX_RULES) {
        LOG_ERR("acl_add_rule: table full");
        return -1;
    }
    int idx = g_num_acl_rules++;
    g_acl_rules[idx] = *rule;
    g_acl_rules[idx].valid = true;
    g_acl_rules[idx].hit_packets = 0;
    g_acl_rules[idx].hit_bytes   = 0;
    LOG_INFO("ACL rule[%d] added: id=%d %s",
             idx, rule->id,
             rule->action == ACL_ACTION_PERMIT ? "PERMIT" : "DENY");
    return idx;
}

/* ── Delete rule ────────────────────────────────────────────────────────── */
int acl_del_rule(int rule_id)
{
    for (int i = 0; i < g_num_acl_rules; i++) {
        if (g_acl_rules[i].valid && g_acl_rules[i].id == rule_id) {
            g_acl_rules[i].valid = false;
            LOG_INFO("ACL rule id=%d deleted", rule_id);
            return 0;
        }
    }
    return -1;
}

/* ── Matching helpers ───────────────────────────────────────────────────── */

static inline bool ip_match(u32 pkt_ip, u32 rule_ip, u32 rule_mask)
{
    /* rule_ip = 0.0.0.0 with mask 0.0.0.0 means "any"                   */
    return (pkt_ip & rule_mask) == (rule_ip & rule_mask);
}

static inline bool port_match(u16 port, port_range_t range)
{
    /* treat (min=0, max=65535) as "any"                                  */
    return (port >= range.min && port <= range.max);
}

/* ── Evaluate ───────────────────────────────────────────────────────────── */

acl_action_t acl_evaluate(const packet_t *pkt, int iface_idx,
                           acl_dir_t dir)
{
    const ip4_hdr_t *ip_hdr = ip4_parse(pkt);
    if (!ip_hdr) {
        /* Non-IP packets not filtered by this engine – default policy    */
        return g_acl_default_action;
    }

    u16 sport = 0, dport = 0;
    bool has_ports = ip4_get_ports(pkt, ip_hdr, &sport, &dport);

    for (int i = 0; i < g_num_acl_rules; i++) {
        const acl_rule_t *r = &g_acl_rules[i];
        if (!r->valid) continue;

        /* Direction filter */
        if (r->direction != ACL_DIR_BOTH && r->direction != dir) continue;

        /* Interface filter */
        if (r->iface_idx >= 0 && r->iface_idx != iface_idx) continue;

        /* IP address matching */
        if (!ip_match(ip_hdr->saddr, r->src_ip, r->src_mask)) continue;
        if (!ip_match(ip_hdr->daddr, r->dst_ip, r->dst_mask)) continue;

        /* Protocol matching */
        if (r->protocol != ACL_PROTO_ANY &&
            r->protocol != ip_hdr->protocol) continue;

        /* Port matching (only if packet has ports) */
        if (r->src_port.min != PORT_ANY_MIN ||
            r->src_port.max != PORT_ANY_MAX) {
            if (!has_ports) continue;
            if (!port_match(sport, r->src_port)) continue;
        }
        if (r->dst_port.min != PORT_ANY_MIN ||
            r->dst_port.max != PORT_ANY_MAX) {
            if (!has_ports) continue;
            if (!port_match(dport, r->dst_port)) continue;
        }

        /* Match! Update hit counters */
        ((acl_rule_t *)r)->hit_packets++;
        ((acl_rule_t *)r)->hit_bytes += pkt->len;

        LOG_DBG("ACL rule[%d] id=%d %s matched: %s -> %s proto=%u",
                i, r->id,
                r->action == ACL_ACTION_PERMIT ? "PERMIT" : "DENY",
                ip4_str(ip_hdr->saddr), ip4_str(ip_hdr->daddr),
                ip_hdr->protocol);

        return r->action;
    }

    /* No rule matched: apply default policy */
    return g_acl_default_action;
}

/* ── Print ──────────────────────────────────────────────────────────────── */

void acl_print_rules(void)
{
    printf("\n=== ACL Rules (default: %s) ===\n",
           g_acl_default_action == ACL_ACTION_PERMIT ? "PERMIT" : "DENY");
    printf("%-4s %-12s %-18s %-18s %-6s %-11s %-11s %-6s %-8s %-10s %-10s\n",
           "ID", "Name", "SrcIP/Mask", "DstIP/Mask",
           "Proto", "SrcPort", "DstPort", "Dir", "Action",
           "Hits", "Bytes");
    printf("%s\n", "----------------------------------------------------"
                   "----------------------------------------------------");
    for (int i = 0; i < g_num_acl_rules; i++) {
        const acl_rule_t *r = &g_acl_rules[i];
        if (!r->valid) continue;

        char src_net[20], dst_net[20];
        /* Convert mask to prefix length */
        u32 m = ntohl(r->src_mask);
        int plen = 0;
        while (m & 0x80000000u) { plen++; m <<= 1; }
        snprintf(src_net, sizeof(src_net), "%s/%d", ip4_str(r->src_ip), plen);

        m = ntohl(r->dst_mask);
        plen = 0;
        while (m & 0x80000000u) { plen++; m <<= 1; }
        snprintf(dst_net, sizeof(dst_net), "%s/%d", ip4_str(r->dst_ip), plen);

        char proto[8];
        if (r->protocol == ACL_PROTO_ANY) snprintf(proto, 8, "ANY");
        else if (r->protocol == IP_PROTO_TCP)  snprintf(proto, 8, "TCP");
        else if (r->protocol == IP_PROTO_UDP)  snprintf(proto, 8, "UDP");
        else if (r->protocol == IP_PROTO_ICMP) snprintf(proto, 8, "ICMP");
        else snprintf(proto, 8, "%u", r->protocol);

        char sport_s[12], dport_s[12];
        if (r->src_port.min == PORT_ANY_MIN && r->src_port.max == PORT_ANY_MAX)
            snprintf(sport_s, 12, "any");
        else
            snprintf(sport_s, 12, "%u-%u", r->src_port.min, r->src_port.max);

        if (r->dst_port.min == PORT_ANY_MIN && r->dst_port.max == PORT_ANY_MAX)
            snprintf(dport_s, 12, "any");
        else
            snprintf(dport_s, 12, "%u-%u", r->dst_port.min, r->dst_port.max);

        const char *dir_s = r->direction == ACL_DIR_INGRESS ? "IN" :
                            r->direction == ACL_DIR_EGRESS  ? "OUT": "BOTH";

        printf("%-4d %-12s %-18s %-18s %-6s %-11s %-11s %-6s %-8s %-10llu %-10llu\n",
               r->id, r->name, src_net, dst_net,
               proto, sport_s, dport_s, dir_s,
               r->action == ACL_ACTION_PERMIT ? "PERMIT" : "DENY",
               (unsigned long long)r->hit_packets,
               (unsigned long long)r->hit_bytes);
    }
    printf("\n");
}
