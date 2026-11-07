#!/bin/bash
# setup_netns.sh - Set up Linux network namespaces for mini-router live testing
#
# Topology:
#
#   [ns_a: 10.0.1.100/24] ---veth_a---tap0--- [ROUTER] ---tap1---veth_b--- [ns_b: 10.0.2.100/24]
#
# The router process binds to tap0 (10.0.1.1/24) and tap1 (10.0.2.1/24).
# ns_a and ns_b are Linux network namespaces acting as hosts.
#
# Usage:
#   sudo bash scripts/setup_netns.sh
#   Then in one terminal:
#       sudo ./minirouter -c config/router.conf
#   Then test:
#       sudo ip netns exec ns_a ping -c 3 10.0.2.100
#       sudo ip netns exec ns_a ping -c 3 10.0.2.1  (ping router tap1)
#       sudo ip netns exec ns_b ping -c 3 10.0.1.100

set -euo pipefail

ROUTER_BIN="./minirouter"
NS_A="ns_a"
NS_B="ns_b"

echo "=== Mini Router: Network Namespace Setup ==="

# ── Create namespaces ─────────────────────────────────────────────────────
ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true
ip netns add "$NS_A"
ip netns add "$NS_B"
echo "[+] Namespaces $NS_A and $NS_B created"

# ── Create TAP devices that will be used by the router ───────────────────
# The router process creates/opens the TAP itself; we just pre-create them
# here so we can assign them to the right namespace context.
#
# NOTE: TAP devices opened by the router live in the default (root) namespace.
# We create a veth pair for each namespace and bridge it to the TAP.
# Alternatively, the router uses TAP directly in the root namespace and we
# add the namespace hosts via veth pairs connected to the TAP's L2.

# ── Namespace A <-> tap0 ─────────────────────────────────────────────────
ip link add veth_a0 type veth peer name veth_a1
ip link set veth_a1 netns "$NS_A"

# Configure veth_a0 as a bridge peer for tap0 (router side)
# Create tap0 manually here; the router will reuse it via IFF_TAP
ip tuntap add dev tap0 mode tap
ip link set tap0 up
ip link add br0 type bridge
ip link set tap0 master br0
ip link set veth_a0 master br0
ip link set veth_a0 up
ip link set br0 up

# Configure namespace A host
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_A" ip link set veth_a1 up
ip netns exec "$NS_A" ip addr add 10.0.1.100/24 dev veth_a1
ip netns exec "$NS_A" ip route add default via 10.0.1.1
echo "[+] Namespace A: 10.0.1.100/24, GW 10.0.1.1 via veth_a1"

# ── Namespace B <-> tap1 ─────────────────────────────────────────────────
ip link add veth_b0 type veth peer name veth_b1
ip link set veth_b1 netns "$NS_B"

ip tuntap add dev tap1 mode tap
ip link set tap1 up
ip link add br1 type bridge
ip link set tap1 master br1
ip link set veth_b0 master br1
ip link set veth_b0 up
ip link set br1 up

ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_B" ip link set veth_b1 up
ip netns exec "$NS_B" ip addr add 10.0.2.100/24 dev veth_b1
ip netns exec "$NS_B" ip route add default via 10.0.2.1
echo "[+] Namespace B: 10.0.2.100/24, GW 10.0.2.1 via veth_b1"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Start the router:"
echo "  sudo $ROUTER_BIN -c config/router.conf -l 2"
echo ""
echo "Then test connectivity:"
echo "  sudo ip netns exec $NS_A ping -c 4 10.0.2.100   # A -> B via router"
echo "  sudo ip netns exec $NS_B ping -c 4 10.0.1.100   # B -> A via router"
echo "  sudo ip netns exec $NS_A ping -c 4 10.0.2.1     # A -> router tap1"
echo ""
echo "Run teardown.sh to clean up."
