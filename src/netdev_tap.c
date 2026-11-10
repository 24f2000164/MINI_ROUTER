/*
 * netdev_tap.c - Linux TAP device driver back-end.
 * Opens /dev/net/tun and assigns an interface name, sets it UP.
 * Requires CAP_NET_ADMIN (run as root or with setcap).
 *
 * Public API uses the netdev_tap_* prefix; the dispatch shim in
 * netdev.c calls these when NETDEV_USE_TAP is defined at build time.
 */

#include "netdev.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
/* linux/if.h and net/if.h must NOT both be included; use net/if.h +
   individual linux headers for what net/if.h misses                     */
#include <net/if.h>
#include <linux/if_tun.h>
#include <linux/if_arp.h>   /* ARPHRD_ETHER                              */
#include <poll.h>
#include <errno.h>

/* ── Open TAP device ────────────────────────────────────────────────────── */
int netdev_tap_open(netdev_iface_t *iface)
{
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        LOG_ERR("Cannot open /dev/net/tun: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;   /* TAP, no packet info header  */
    strncpy(ifr.ifr_name, iface->name, IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        LOG_ERR("TUNSETIFF failed for %s: %s", iface->name, strerror(errno));
        close(fd);
        return -1;
    }

    /* Bring interface UP with IP and MAC */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        close(fd);
        return -1;
    }

    /* Set IP address */
    struct ifreq ifr2;
    memset(&ifr2, 0, sizeof(ifr2));
    strncpy(ifr2.ifr_name, iface->name, IFNAMSIZ - 1);
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr2.ifr_addr;
    sin->sin_family      = AF_INET;
    sin->sin_addr.s_addr = iface->ip4;
    if (ioctl(sock, SIOCSIFADDR, &ifr2) < 0)
        LOG_WARN("SIOCSIFADDR: %s", strerror(errno));

    /* Set netmask */
    sin->sin_addr.s_addr = iface->netmask;
    if (ioctl(sock, SIOCSIFNETMASK, &ifr2) < 0)
        LOG_WARN("SIOCSIFNETMASK: %s", strerror(errno));

    /* Set MAC if provided */
    if (iface->mac[0] || iface->mac[1]) {
        memset(&ifr2, 0, sizeof(ifr2));
        strncpy(ifr2.ifr_name, iface->name, IFNAMSIZ - 1);
        ifr2.ifr_hwaddr.sa_family = ARPHRD_ETHER;
        memcpy(ifr2.ifr_hwaddr.sa_data, iface->mac, ETH_ALEN);
        if (ioctl(sock, SIOCSIFHWADDR, &ifr2) < 0)
            LOG_WARN("SIOCSIFHWADDR: %s", strerror(errno));
    }

    /* Bring UP */
    memset(&ifr2, 0, sizeof(ifr2));
    strncpy(ifr2.ifr_name, iface->name, IFNAMSIZ - 1);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr2) == 0) {
        ifr2.ifr_flags |= IFF_UP | IFF_RUNNING;
        ioctl(sock, SIOCSIFFLAGS, &ifr2);
    }
    close(sock);

    iface->fd    = fd;
    iface->flags = NETDEV_FLAG_UP;
    LOG_INFO("TAP device %s opened (fd=%d, ip=%s)",
             iface->name, fd, ip4_str(iface->ip4));
    return 0;
}

/* ── Receive ────────────────────────────────────────────────────────────── */
int netdev_tap_recv(netdev_iface_t *iface, packet_t *pkt)
{
    ssize_t n = read(iface->fd, pkt->data, PKT_BUF_SIZE);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        LOG_ERR("read %s: %s", iface->name, strerror(errno));
        iface->rx_errors++;
        return -1;
    }
    pkt->len       = (u32)n;
    pkt->iface_idx = iface->index;
    iface->rx_packets++;
    iface->rx_bytes += (u64)n;
    return (int)n;
}

/* ── Transmit ───────────────────────────────────────────────────────────── */
int netdev_tap_send(netdev_iface_t *iface, const packet_t *pkt)
{
    ssize_t n = write(iface->fd, pkt->data, pkt->len);
    if (n < 0) {
        LOG_ERR("write %s: %s", iface->name, strerror(errno));
        iface->tx_drops++;
        return -1;
    }
    iface->tx_packets++;
    iface->tx_bytes += (u64)n;
    return (int)n;
}

/* ── Close ──────────────────────────────────────────────────────────────── */
void netdev_tap_close(netdev_iface_t *iface)
{
    if (iface->fd >= 0) {
        close(iface->fd);
        iface->fd = -1;
    }
    iface->flags = 0;
    LOG_INFO("TAP interface %s closed", iface->name);
}

/* ── Poll ───────────────────────────────────────────────────────────────── */
int netdev_tap_poll(int *ready, int max_ready, int timeout_ms)
{
    struct pollfd fds[NETDEV_MAX_IFACES];
    int n = 0;

    for (int i = 0; i < g_num_ifaces && n < NETDEV_MAX_IFACES; i++) {
        if (!(g_ifaces[i].flags & NETDEV_FLAG_MOCK) &&
             (g_ifaces[i].flags & NETDEV_FLAG_UP)) {
            fds[n].fd     = g_ifaces[i].fd;
            fds[n].events = POLLIN;
            n++;
        }
    }
    if (n == 0) return 0;

    int ret = poll(fds, (nfds_t)n, timeout_ms);
    if (ret <= 0) return 0;

    int count = 0;
    int fi = 0;
    for (int i = 0; i < g_num_ifaces && fi < n && count < max_ready; i++) {
        if (!(g_ifaces[i].flags & NETDEV_FLAG_MOCK) &&
             (g_ifaces[i].flags & NETDEV_FLAG_UP)) {
            if (fds[fi].revents & POLLIN)
                ready[count++] = i;
            fi++;
        }
    }
    return count;
}
