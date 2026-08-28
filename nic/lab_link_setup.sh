#!/usr/bin/env bash
# lab_link_setup.sh — re-apply the host-side data-plane link configuration after a reboot.
#
# Verified wiring (2026-08-28):
#   Vision enp59s0f0np0  (XXV710, 25G) ── switch 15/1 = dev_port 9    [fabric host, leaf 0]
#   Hulk   enp59s0f1np1  (XXV710, 25G) ── switch 15/2 = dev_port 10   [fabric host, leaf 1]
#   Vision enp175s0np1s0 (Agilio CX, 10G) ── Hulk enp59s0f0np0 (10G)  [direct link, Soft-RoCE]
#
# The switch legs only carry traffic when the Tofino port is out of MAC-near loopback and the
# mcp_fabric program owns the chip; the direct link is independent of the switch.
#
# netplan persists only some of this and still names a renamed interface, so this script is the
# authority. It is idempotent: run it as root after a reboot, or any time the links look wrong.
#   sudo ./lab_link_setup.sh [--check]
set -u
CHECK=${1:-}
host=$(hostname)

ensure_addr() {   # iface cidr
    ip link set "$1" up 2>/dev/null
    if ip -br addr show "$1" | grep -q "${2%%/*}/"; then echo "  ok   $1 has $2"
    elif [ "$CHECK" = "--check" ]; then echo "  MISS $1 needs $2"
    else ip addr replace "$2" dev "$1" && echo "  set  $1 -> $2"; fi
}
ensure_rxe() {    # iface
    cur=$(rdma link show 2>/dev/null | sed -n 's/.*netdev \([^ ]*\).*/\1/p' | head -1)
    if [ "$cur" = "$1" ]; then echo "  ok   rxe0 on $1 ($(rdma link show | grep -o 'state [A-Z]*' | head -1))"
    elif [ "$CHECK" = "--check" ]; then echo "  MISS rxe0 should be on $1 (is: ${cur:-none})"
    else
        modprobe rdma_rxe 2>/dev/null
        [ -n "$cur" ] && rdma link delete rxe0 2>/dev/null
        rdma link add rxe0 type rxe netdev "$1" && echo "  set  rxe0 -> $1"
    fi
}

case "$host" in
  vision)
    echo "$host: switch leg + Agilio direct link"
    ensure_addr enp59s0f0np0 10.0.1.1/24          # fabric host address, leaf 0
    ensure_addr enp175s0np1s0 192.168.100.1/24    # direct link to Hulk
    ensure_rxe  enp175s0np1s0
    ;;
  hulk)
    echo "$host: switch leg + direct link"
    ensure_addr enp59s0f0np0 192.168.100.2/24     # direct link to Vision's Agilio
    ensure_addr enp59s0f1np1 10.0.1.2/24          # fabric host address, leaf 1
    ensure_rxe  enp59s0f0np0
    ;;
  *) echo "unknown host $host — this script knows vision and hulk only"; exit 1;;
esac

echo "state:"
for i in enp59s0f0np0 enp59s0f1np1 enp175s0np1s0; do
    [ -e "/sys/class/net/$i" ] || continue
    printf "  %-16s carrier=%s speed=%-6s %s\n" "$i" \
        "$(cat /sys/class/net/$i/carrier 2>/dev/null)" \
        "$(cat /sys/class/net/$i/speed 2>/dev/null)" \
        "$(ip -br addr show $i | awk '{$1="";$2="";print}')"
done
rdma link show 2>/dev/null | sed 's/^/  /'
