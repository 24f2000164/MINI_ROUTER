/*
 * main.c - CLI entry point, configuration file loader, and event loop starter
 *
 * Usage:
 *   sudo ./minirouter [-c config_file] [-l log_level] [-m (mock mode)]
 *
 * Config file format (see config/router.conf for example)
 */

#include "router.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

/* ── Config file parser ─────────────────────────────────────────────────── */
/*
 * Supported directives:
 *
 *   interface <name> <ip/prefix> <mac>
 *   route     <dst/prefix> <gateway|0.0.0.0> <iface_name> [metric]
 *   acl       <id> <name> <src_ip/mask> <dst_ip/mask> <proto>
 *             <src_port_min> <src_port_max> <dst_port_min> <dst_port_max>
 *             <dir:IN|OUT|BOTH> <action:PERMIT|DENY>
 *   default_acl <PERMIT|DENY>
 *   loglevel  <0-3>
 *   icmp_on_deny <0|1>
 */

static int parse_mac(const char *s, u8 mac[ETH_ALEN])
{
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return -1;
    for (int i = 0; i < ETH_ALEN; i++) mac[i] = (u8)v[i];
    return 0;
}

static int parse_ip(const char *s, u32 *ip_out)
{
    unsigned a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return -1;
    if (a > 255 || b > 255 || c > 255 || d > 255) return -1;
    *ip_out = htonl((a << 24) | (b << 16) | (c << 8) | d);
    return 0;
}

static int iface_index_by_name(const char *name)
{
    for (int i = 0; i < g_num_ifaces; i++)
        if (strcmp(g_ifaces[i].name, name) == 0) return i;
    return -1;
}

int router_load_config(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        LOG_ERR("Cannot open config: %s", path);
        return -1;
    }

    char line[512];
    int  lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        /* Strip comments and trailing whitespace */
        char *hash = strchr(line, '#');
        if (hash) *hash = '\0';
        /* Trim trailing newlines */
        char *p = line + strlen(line) - 1;
        while (p >= line && (*p == '\n' || *p == '\r' || *p == ' ')) *p-- = '\0';
        if (strlen(line) == 0) continue;

        char directive[32];
        if (sscanf(line, "%31s", directive) != 1) continue;

        /* ── interface ── */
        if (strcmp(directive, "interface") == 0) {
            char name[16], cidr[32], mac_s[20];
            if (sscanf(line, "%*s %15s %31s %19s", name, cidr, mac_s) < 2) {
                LOG_WARN("config line %d: bad interface directive", lineno);
                continue;
            }
            if (g_num_ifaces >= NETDEV_MAX_IFACES) {
                LOG_ERR("config: too many interfaces");
                break;
            }
            netdev_iface_t *iface = &g_ifaces[g_num_ifaces];
            memset(iface, 0, sizeof(*iface));
            strncpy(iface->name, name, sizeof(iface->name) - 1);
            iface->index = g_num_ifaces;

            u32 dest, mask;
            u8  plen;
            if (routing_parse_cidr(cidr, &dest, &mask, &plen) < 0) {
                LOG_WARN("config line %d: bad IP/CIDR %s", lineno, cidr);
                continue;
            }
            iface->ip4     = dest;
            iface->netmask = mask;

            if (strlen(mac_s) > 0 && strcmp(mac_s, "-") != 0)
                parse_mac(mac_s, iface->mac);

            g_num_ifaces++;
            LOG_INFO("Config: interface %s ip=%s/%u",
                     name, ip4_str(dest), plen);
        }

        /* ── route ── */
        else if (strcmp(directive, "route") == 0) {
            char cidr[32], gw_s[20], ifname[16];
            u32  metric = 1;
            if (sscanf(line, "%*s %31s %19s %15s %u",
                       cidr, gw_s, ifname, &metric) < 3) {
                LOG_WARN("config line %d: bad route directive", lineno);
                continue;
            }
            u32 dest, mask, gw;
            u8  plen;
            if (routing_parse_cidr(cidr, &dest, &mask, &plen) < 0) {
                LOG_WARN("config line %d: bad dest CIDR %s", lineno, cidr);
                continue;
            }
            if (parse_ip(gw_s, &gw) < 0 && strcmp(gw_s, "0.0.0.0") != 0)
                gw = 0;

            int iidx = iface_index_by_name(ifname);
            if (iidx < 0) {
                LOG_WARN("config line %d: unknown interface %s", lineno, ifname);
                continue;
            }
            routing_add(dest, mask, plen, gw, iidx, metric);
        }

        /* ── acl ── */
        else if (strcmp(directive, "acl") == 0) {
            acl_rule_t r;
            memset(&r, 0, sizeof(r));
            r.src_port.min = PORT_ANY_MIN;
            r.src_port.max = PORT_ANY_MAX;
            r.dst_port.min = PORT_ANY_MIN;
            r.dst_port.max = PORT_ANY_MAX;
            r.iface_idx = -1;
            r.protocol  = ACL_PROTO_ANY;

            char src_cidr[32], dst_cidr[32], proto_s[8];
            char dir_s[8], action_s[8];
            unsigned sport_min, sport_max, dport_min, dport_max;

            int n = sscanf(line,
                "%*s %d %31s %31s %31s %7s "
                "%u %u %u %u %7s %7s",
                &r.id, r.name,
                src_cidr, dst_cidr, proto_s,
                &sport_min, &sport_max, &dport_min, &dport_max,
                dir_s, action_s);

            if (n < 11) {
                LOG_WARN("config line %d: bad acl directive (got %d tokens)",
                         lineno, n);
                continue;
            }

            u32 s_dest, s_mask, d_dest, d_mask;
            u8  s_plen, d_plen;
            if (routing_parse_cidr(src_cidr, &s_dest, &s_mask, &s_plen) < 0) {
                s_dest = 0; s_mask = 0;
            }
            if (routing_parse_cidr(dst_cidr, &d_dest, &d_mask, &d_plen) < 0) {
                d_dest = 0; d_mask = 0;
            }

            r.src_ip   = s_dest; r.src_mask = s_mask;
            r.dst_ip   = d_dest; r.dst_mask = d_mask;

            if      (strcmp(proto_s, "TCP")  == 0) r.protocol = IP_PROTO_TCP;
            else if (strcmp(proto_s, "UDP")  == 0) r.protocol = IP_PROTO_UDP;
            else if (strcmp(proto_s, "ICMP") == 0) r.protocol = IP_PROTO_ICMP;
            else                                    r.protocol = ACL_PROTO_ANY;

            r.src_port.min = (u16)sport_min; r.src_port.max = (u16)sport_max;
            r.dst_port.min = (u16)dport_min; r.dst_port.max = (u16)dport_max;

            if      (strcmp(dir_s, "IN")   == 0) r.direction = ACL_DIR_INGRESS;
            else if (strcmp(dir_s, "OUT")  == 0) r.direction = ACL_DIR_EGRESS;
            else                                  r.direction = ACL_DIR_BOTH;

            r.action = (strcmp(action_s, "PERMIT") == 0) ?
                        ACL_ACTION_PERMIT : ACL_ACTION_DENY;
            r.valid  = true;
            acl_add_rule(&r);
        }

        /* ── default_acl ── */
        else if (strcmp(directive, "default_acl") == 0) {
            char val[16];
            if (sscanf(line, "%*s %15s", val) == 1)
                g_acl_default_action = strcmp(val, "DENY") == 0 ?
                                       ACL_ACTION_DENY : ACL_ACTION_PERMIT;
        }

        /* ── loglevel ── */
        else if (strcmp(directive, "loglevel") == 0) {
            int lv;
            if (sscanf(line, "%*s %d", &lv) == 1)
                g_log_level = lv;
        }

        /* ── icmp_on_deny ── */
        else if (strcmp(directive, "icmp_on_deny") == 0) {
            int v;
            if (sscanf(line, "%*s %d", &v) == 1)
                g_router.cfg.send_icmp_on_deny = (bool)v;
        }

        else {
            LOG_WARN("config line %d: unknown directive '%s'",
                     lineno, directive);
        }
    }

    fclose(f);
    LOG_INFO("Config loaded from %s (%d ifaces, %d routes, %d ACL rules)",
             path, g_num_ifaces, g_num_routes, g_num_acl_rules);
    return 0;
}

/* ── Usage ──────────────────────────────────────────────────────────────── */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  -c <config>   Configuration file (default: config/router.conf)\n"
        "  -l <level>    Log level 0=ERR 1=WARN 2=INFO 3=DBG (default: 2)\n"
        "  -m            Mock mode (no TAP, no root required)\n"
        "  -h            Show this help\n",
        prog);
}

/* ── main ───────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    router_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.config_file, "config/router.conf",
            sizeof(cfg.config_file) - 1);
    cfg.log_level       = LOG_LEVEL_INFO;
    cfg.use_mock        = false;
    cfg.poll_timeout_ms = 100;
    cfg.run_once        = false;
    cfg.send_icmp_on_deny = true;

    int opt;
    while ((opt = getopt(argc, argv, "c:l:mh")) != -1) {
        switch (opt) {
        case 'c':
            strncpy(cfg.config_file, optarg, sizeof(cfg.config_file) - 1);
            break;
        case 'l':
            cfg.log_level = atoi(optarg);
            break;
        case 'm':
            cfg.use_mock = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    printf("=== Mini Router: L2/L3 Forwarding + ACL Engine ===\n");

    /* Load config (populates g_ifaces[], routes, ACL rules) */
    if (router_load_config(cfg.config_file) < 0) {
        fprintf(stderr, "Failed to load config file: %s\n", cfg.config_file);
        return 1;
    }

    /* Initialize and run */
    if (router_init(&cfg) < 0) {
        fprintf(stderr, "Router initialization failed\n");
        return 1;
    }

    routing_print();
    acl_print_rules();

    router_run();

    /* On exit, print final statistics */
    printf("\n=== Shutdown – Final Statistics ===\n");
    stats_print();
    arp_cache_print();
    routing_print();
    acl_print_rules();

    router_shutdown();
    return 0;
}
