# Mini Router — L2/L3 Packet Forwarding & ACL Engine

A fully functional, modular Linux software router written in **C (C99)** from scratch.  
It implements the complete forwarding plane: Ethernet frame processing, ARP cache with pending-packet queue, IPv4 forwarding with TTL handling, a Binary-Trie Longest Prefix Match routing engine, a 5-tuple ACL policy engine, and ICMP error generation — all driven by a non-blocking `poll`-based event loop over Linux TAP interfaces.

---

## Features

| Layer | Capability |
|-------|-----------|
| **L2 (Data Link)** | Ethernet II frame parsing · MAC rewrite · ARP Request/Reply · ARP cache with TTL aging · Pending-packet queue |
| **L3 (Network)**   | IPv4 header parsing & checksum validation · TTL decrement (incremental RFC 1624 checksum) · Longest Prefix Match routing (Binary Trie, O(32)) |
| **ICMP**           | Echo Request → Echo Reply · Time Exceeded (TTL=0) · Destination Unreachable (no route / host / admin-prohibit) |
| **ACL Engine**     | 5-tuple rules (src/dst IP+mask, protocol, src/dst port range) · Ingress & Egress direction · First-match, ordered evaluation · Per-rule hit/byte counters |
| **I/O Drivers**    | Linux TAP (`/dev/net/tun`) live mode · In-memory **mock** driver for root-free unit testing |
| **Observability**  | Per-interface RX/TX/drop counters · ARP cache table dump · Route table print · ACL rule hit statistics · Global forwarding-plane statistics |

---

## Repository Structure

```
minirouter/
├── Makefile                  Build system (all / test / clean)
├── config/
│   └── router.conf           Example config: interfaces, routes, ACL rules
├── include/
│   ├── types.h               Common types, byte-order helpers, logging macros
│   ├── netdev.h              Network device abstraction (TAP / Mock)
│   ├── ethernet.h            L2 header structs and helpers
│   ├── arp.h                 ARP cache, resolver, packet structs
│   ├── ipv4.h                IPv4 header parsing, checksum API
│   ├── routing.h             LPM routing engine header
│   ├── acl.h                 ACL rule struct and matching API
│   ├── icmp.h                ICMP header structs and generation API
│   ├── stats.h               Global statistics counters
│   └── router.h              Central router context, dispatch API
├── src/
│   ├── main.c                CLI entry point, config file loader
│   ├── router.c              Packet dispatcher, IPv4 forwarding pipeline
│   ├── ethernet.c            Ethernet frame parse/build/rewrite
│   ├── arp.c                 ARP cache, aging, request/reply, pending queue
│   ├── ipv4.c                IPv4 parsing, checksum, TTL decrement
│   ├── routing.c             Binary Trie LPM routing engine
│   ├── acl.c                 5-tuple ACL engine
│   ├── icmp.c                ICMP Echo + error message generation
│   ├── stats.c               Statistics display
│   ├── netdev_tap.c          Linux TAP device driver
│   └── netdev_mock.c         In-memory mock driver for unit tests
├── tests/
│   ├── test_lpm.c            LPM Trie unit tests
│   ├── test_acl.c            ACL 5-tuple matching unit tests
│   ├── test_forwarding.c     End-to-end simulation tests (uses mock driver)
│   └── test_checksum.c       IPv4 checksum unit tests
└── scripts/
    ├── setup_netns.sh        Linux network namespace topology setup
    └── teardown_netns.sh     Cleanup script
```

---

## Build

Requires: **Linux**, **GCC** (or Clang), **make**.

```bash
# Build the main router binary
make all

# Build and run all unit tests (no root required)
make test

# Individual test targets
make test_lpm    # Longest Prefix Match Trie tests
make test_acl    # 5-tuple ACL engine tests
make test_fwd    # End-to-end forwarding simulation tests
make test_csum   # IPv4 checksum tests

make clean
```

---

## Running the Router

### Mode 1 — Live TAP mode (Linux, requires root/CAP_NET_ADMIN)

```bash
# 1. Create the namespace topology
sudo bash scripts/setup_netns.sh

# 2. Run the router
sudo ./build/minirouter -c config/router.conf -l 2

# 3. Test from another terminal
sudo ip netns exec ns_a ping -c 4 10.0.2.100   # ns_a -> ns_b via router
sudo ip netns exec ns_b ping -c 4 10.0.1.100   # ns_b -> ns_a via router

# 4. Cleanup
sudo bash scripts/teardown_netns.sh
```

### Mode 2 — Mock mode (no root, for quick sanity checks)

```bash
./build/minirouter -c config/router.conf -m -l 3
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-c <file>` | `config/router.conf` | Configuration file path |
| `-l <0-3>` | `2` | Log level: 0=ERR, 1=WARN, 2=INFO, 3=DBG |
| `-m` | off | Enable mock device mode (no `/dev/net/tun`, no root) |
| `-h` | — | Print help |

---

## Configuration File Format

```
# router.conf

# Interface: <name> <ip/prefix> <mac>
interface tap0  10.0.1.1/24  aa:00:00:00:01:00
interface tap1  10.0.2.1/24  aa:00:00:00:02:00

# Route: <dst/prefix> <nexthop|0.0.0.0> <iface_name> [metric]
route 10.0.1.0/24  0.0.0.0    tap0  1
route 10.0.2.0/24  0.0.0.0    tap1  1
route 0.0.0.0/0    203.0.113.1  tap1  100   # default route

# Default ACL policy
default_acl PERMIT

# ACL: <id> <name> <src_cidr> <dst_cidr> <proto>
#      <sport_min> <sport_max> <dport_min> <dport_max>
#      <dir:IN|OUT|BOTH> <action:PERMIT|DENY>
acl 10  block-ssh    0.0.0.0/0  0.0.0.0/0  TCP  0 65535  22 22   IN   DENY
acl 20  block-telnet 0.0.0.0/0  0.0.0.0/0  TCP  0 65535  23 23   BOTH DENY
acl 30  no-ping      0.0.0.0/0  0.0.0.0/0  ICMP 0 65535  0  65535 BOTH DENY
acl 100 allow-all    0.0.0.0/0  0.0.0.0/0  ANY  0 65535  0  65535 BOTH PERMIT

# Send ICMP Administratively Prohibited when ACL denies a packet
icmp_on_deny 1

# Logging level
loglevel 2
```

---

## Architecture — Packet Forwarding Pipeline

```
Ingress Frame (TAP fd / mock RX)
        │
        ▼
   Ethernet Parser
   ┌────────────┐
   │ ARP?       │──► ARP Cache Learn + Reply Generator
   │ IPv4?      │──► ACL Ingress Filter (5-tuple)
   └────────────┘           │ DENY ──► Drop (+ ICMP Admin-Prohibit)
                            │ PERMIT
                            ▼
                    IPv4 Header Validation
                    (version, IHL, length, checksum)
                            │
                   Local IP? ──YES──► ICMP Echo Handler
                            │ NO
                            ▼
                    LPM Route Lookup
                    (Binary Trie O(32))
                    ┌───────────────┐
                    │ No Route?     │──► ICMP Dest-Unreachable
                    └───────────────┘
                            │ Route found
                            ▼
                    TTL Decrement + Incremental Checksum
                    ┌───────────────┐
                    │ TTL == 0?     │──► ICMP Time-Exceeded
                    └───────────────┘
                            │
                    ACL Egress Filter
                            │ DENY ──► Drop (+ ICMP Admin-Prohibit)
                            │ PERMIT
                            ▼
                    ARP Cache Lookup (next-hop MAC)
                    ┌───────────────┐
                    │ MAC unknown?  │──► ARP Request + Packet Queue
                    └───────────────┘
                            │ MAC known
                            ▼
                    Ethernet Header Rewrite
                    (src = router egress MAC,
                     dst = next-hop MAC)
                            │
                            ▼
                   Egress Transmit (TAP fd / mock TX)
```

---

## Unit Tests Summary

| Test file | Tests |
|-----------|-------|
| `test_lpm.c` | Exact /32, /24, /16, default /0 · Longer prefix wins · Delete · CIDR parser |
| `test_acl.c` | TCP port 80 deny · Proto wildcard · Direction filter · Hit counters |
| `test_forwarding.c` | ICMP local echo · ARP miss + buffering + flush on reply · TTL expiry · No route · ACL ingress deny |
| `test_checksum.c` | RFC checksum correctness · Incremental update after TTL decrement · Corruption detection |

---

## License

MIT License — free to use, modify, and distribute.

---

## Author

Built as a comprehensive systems-programming demonstration of Linux L2/L3 packet forwarding in C.
