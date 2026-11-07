#!/bin/bash
# teardown_netns.sh - Clean up network namespaces and virtual interfaces

set -euo pipefail

echo "=== Mini Router: Teardown ==="

ip netns del ns_a   2>/dev/null && echo "[+] Deleted namespace ns_a"  || true
ip netns del ns_b   2>/dev/null && echo "[+] Deleted namespace ns_b"  || true

ip link del br0     2>/dev/null && echo "[+] Deleted bridge br0"      || true
ip link del br1     2>/dev/null && echo "[+] Deleted bridge br1"      || true

ip link del tap0    2>/dev/null && echo "[+] Deleted tap0"            || true
ip link del tap1    2>/dev/null && echo "[+] Deleted tap1"            || true

ip link del veth_a0 2>/dev/null && echo "[+] Deleted veth_a0"        || true
ip link del veth_b0 2>/dev/null && echo "[+] Deleted veth_b0"        || true

echo "=== Teardown complete ==="
