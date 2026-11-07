/*
 * acl.h - Access Control List (ACL) engine
 *         5-tuple matching: src IP/mask, dst IP/mask, protocol, src port range, dst port range
 */

#ifndef MINIROUTER_ACL_H
#define MINIROUTER_ACL_H

#include "types.h"

/* ── ACL action ─────────────────────────────────────────────────────────── */
typedef enum {
    ACL_ACTION_PERMIT = 0,
    ACL_ACTION_DENY   = 1,
} acl_action_t;

/* ── ACL direction ──────────────────────────────────────────────────────── */
typedef enum {
    ACL_DIR_INGRESS = 0,
    ACL_DIR_EGRESS  = 1,
    ACL_DIR_BOTH    = 2,
} acl_dir_t;

/* ── Port range helper ─────────────────────────────────────────────────── */
typedef struct {
    u16 min;    /* 0 = wildcard (any port) if max==65535 and min==0      */
    u16 max;
} port_range_t;

#define PORT_ANY_MIN  0
#define PORT_ANY_MAX  65535

/* ── ACL rule ───────────────────────────────────────────────────────────── */
#define ACL_PROTO_ANY  0xFF    /* matches any IP protocol                  */
#define ACL_MAX_RULES  128

typedef struct {
    bool         valid;
    int          id;           /* rule number / priority (lower = higher prio) */
    char         name[32];     /* human-readable label                     */

    /* Matching criteria */
    u32          src_ip;       /* network byte order                       */
    u32          src_mask;     /* network byte order                       */
    u32          dst_ip;
    u32          dst_mask;
    u8           protocol;     /* ACL_PROTO_ANY or IP_PROTO_*              */
    port_range_t src_port;     /* source port range                        */
    port_range_t dst_port;     /* dest   port range                        */
    int          iface_idx;    /* -1 = any interface                       */
    acl_dir_t    direction;

    /* Action */
    acl_action_t action;

    /* Hit statistics */
    u64 hit_packets;
    u64 hit_bytes;
} acl_rule_t;

/* ── Globals ────────────────────────────────────────────────────────────── */
extern acl_rule_t  g_acl_rules[ACL_MAX_RULES];
extern int         g_num_acl_rules;
extern acl_action_t g_acl_default_action; /* applied when no rule matches */

/* ── API ────────────────────────────────────────────────────────────────── */

/* Initialize ACL engine and clear all rules.                            */
void acl_init(void);

/* Add a rule.  Returns rule index on success, -1 on error.             */
int  acl_add_rule(const acl_rule_t *rule);

/* Delete rule by id.  Returns 0 on success, -1 if not found.           */
int  acl_del_rule(int rule_id);

/* Evaluate all ACL rules for a packet (top-down first-match).
   iface_idx : ingress or egress interface
   dir       : ACL_DIR_INGRESS or ACL_DIR_EGRESS
   pkt_len   : for byte counters
   Returns ACL_ACTION_PERMIT or ACL_ACTION_DENY.                         */
acl_action_t acl_evaluate(const packet_t *pkt, int iface_idx,
                           acl_dir_t dir);

/* Print all ACL rules with hit counters.                                */
void acl_print_rules(void);

#endif /* MINIROUTER_ACL_H */
