/*
 * stats.c - Global router statistics
 */

#include "stats.h"
#include "netdev.h"
#include <string.h>
#include <stdio.h>

router_stats_t g_stats;

void stats_reset(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}

void stats_print(void)
{
    printf("\n=== Router Statistics ===\n");
    printf("  Total RX:                 %llu pkts  %llu bytes\n",
           (unsigned long long)g_stats.total_rx_packets,
           (unsigned long long)g_stats.total_rx_bytes);
    printf("  Total TX:                 %llu pkts  %llu bytes\n",
           (unsigned long long)g_stats.total_tx_packets,
           (unsigned long long)g_stats.total_tx_bytes);

    printf("\n  IPv4:\n");
    printf("    RX:                     %llu\n",
           (unsigned long long)g_stats.ipv4_rx);
    printf("    Forwarded:              %llu\n",
           (unsigned long long)g_stats.ipv4_forwarded);
    printf("    Local Delivered:        %llu\n",
           (unsigned long long)g_stats.ipv4_local_delivered);
    printf("    Dropped (TTL):          %llu\n",
           (unsigned long long)g_stats.ipv4_dropped_ttl);
    printf("    Dropped (No Route):     %llu\n",
           (unsigned long long)g_stats.ipv4_dropped_no_route);
    printf("    Dropped (ARP Fail):     %llu\n",
           (unsigned long long)g_stats.ipv4_dropped_arp_fail);
    printf("    Dropped (Malformed):    %llu\n",
           (unsigned long long)g_stats.ipv4_dropped_malformed);

    printf("\n  ARP:\n");
    printf("    RX Requests:            %llu\n",
           (unsigned long long)g_stats.arp_rx_requests);
    printf("    RX Replies:             %llu\n",
           (unsigned long long)g_stats.arp_rx_replies);
    printf("    TX Requests:            %llu\n",
           (unsigned long long)g_stats.arp_tx_requests);
    printf("    TX Replies:             %llu\n",
           (unsigned long long)g_stats.arp_tx_replies);
    printf("    Cache Hits:             %llu\n",
           (unsigned long long)g_stats.arp_cache_hits);
    printf("    Cache Misses:           %llu\n",
           (unsigned long long)g_stats.arp_cache_misses);
    printf("    Pending Queued:         %llu\n",
           (unsigned long long)g_stats.arp_pending_queued);
    printf("    Pending Flushed:        %llu\n",
           (unsigned long long)g_stats.arp_pending_flushed);
    printf("    Pending Dropped:        %llu\n",
           (unsigned long long)g_stats.arp_pending_dropped);

    printf("\n  ACL:\n");
    printf("    Ingress Permit:         %llu\n",
           (unsigned long long)g_stats.acl_ingress_permit);
    printf("    Ingress Deny:           %llu\n",
           (unsigned long long)g_stats.acl_ingress_deny);
    printf("    Egress Permit:          %llu\n",
           (unsigned long long)g_stats.acl_egress_permit);
    printf("    Egress Deny:            %llu\n",
           (unsigned long long)g_stats.acl_egress_deny);

    printf("\n  ICMP:\n");
    printf("    RX Echo Requests:       %llu\n",
           (unsigned long long)g_stats.icmp_rx_echo_requests);
    printf("    TX Echo Replies:        %llu\n",
           (unsigned long long)g_stats.icmp_tx_echo_replies);
    printf("    TX Time Exceeded:       %llu\n",
           (unsigned long long)g_stats.icmp_tx_time_exceeded);
    printf("    TX Dest Unreachable:    %llu\n",
           (unsigned long long)g_stats.icmp_tx_dest_unreach);

    netdev_print_stats();
}
