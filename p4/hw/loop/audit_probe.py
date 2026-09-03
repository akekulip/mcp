#!/usr/bin/env python3
"""Send declared-audit probes from Vision: UDP dport=4792 (AUDIT_UDP_DST), sport=<token>.

Same raw-socket recipe as mcp_multicontext_probe.py (proven on this testbed); only the UDP
identity and payload differ, matching p4/ptf/gap_event/test.py's host_packet(token, 4792):
64-byte payload. The matching tbl_audit_steer entry must already be declared via gate_agent's
`U 4792 <token> <spray>`; without it the packet is ordinary production traffic.
"""
import argparse
import socket
import time

from scapy.all import Ether, IP, Raw, UDP, get_if_hwaddr

AUDIT_UDP_DST = 4792


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="enp59s0f0np0")
    ap.add_argument("--token", type=int, required=True, help="UDP source port = declared token")
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--pps", type=int, default=50)
    args = ap.parse_args()

    frame = bytes(Ether(dst=get_if_hwaddr(args.iface), src="02:00:00:00:00:06")
                  / IP(src="10.0.1.1", dst="10.0.1.3")
                  / UDP(sport=args.token, dport=AUDIT_UDP_DST)
                  / Raw(b"a" * 64))
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    interval = 1.0 / args.pps
    deadline = time.perf_counter()
    for _ in range(args.count):
        sock.send(frame)
        deadline += interval
        while time.perf_counter() < deadline:
            pass
    print(f"sent {args.count} audit frames: sport={args.token} dport={AUDIT_UDP_DST} "
          f"payload=64B at {args.pps} pps", flush=True)


if __name__ == "__main__":
    main()
