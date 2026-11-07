/*
 * router.h - Central router context: configuration and packet dispatch
 */

#ifndef MINIROUTER_ROUTER_H
#define MINIROUTER_ROUTER_H

#include "types.h"
#include "netdev.h"
#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"
#include "routing.h"
#include "acl.h"
#include "icmp.h"
#include "stats.h"

/* ── Router configuration ───────────────────────────────────────────────── */
typedef struct {
    bool use_mock;             /* use in-memory mock devices (no root)    */
    int  log_level;            /* LOG_LEVEL_ERR … LOG_LEVEL_DBG           */
    char config_file[256];     /* path to router.conf                     */
    bool run_once;             /* process single batch then exit (tests)  */
    int  poll_timeout_ms;      /* epoll/poll wait time                    */
    bool send_icmp_on_deny;    /* send ICMP Admin-Prohibited on ACL deny  */
} router_config_t;

/* ── Router context ─────────────────────────────────────────────────────── */
typedef struct {
    router_config_t cfg;
    bool running;
} router_ctx_t;

extern router_ctx_t g_router;

/* ── Lifecycle ──────────────────────────────────────────────────────────── */

/* Load configuration from file (interfaces, routes, ACL rules).        */
int  router_load_config(const char *path);

/* Initialize all subsystems and open network devices.                   */
int  router_init(const router_config_t *cfg);

/* Main event loop.  Returns when g_router.running becomes false.        */
void router_run(void);

/* Graceful shutdown.                                                    */
void router_shutdown(void);

/* ── Packet dispatch (called by event loop for each received frame) ──── */
void router_dispatch(packet_t *pkt);

/* ── IPv4 forwarding pipeline ────────────────────────────────────────── */
void router_forward_ipv4(packet_t *pkt, const ip4_hdr_t *ip_hdr);

/* ── Helpers ─────────────────────────────────────────────────────────── */

/* Returns true if ip4_net matches any of the router's interface IPs.   */
bool router_is_local_ip(u32 ip4_net);

/* Returns the interface index whose network contains ip4_net.          */
int  router_find_iface_for_ip(u32 ip4_net);

/* Signal handler – sets g_router.running = false.                      */
void router_signal_handler(int sig);

#endif /* MINIROUTER_ROUTER_H */
