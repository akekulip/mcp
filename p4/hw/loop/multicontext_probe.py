#!/usr/bin/env python3
"""Paced raw traffic for the behavioural-sublink closed-loop hardware test.

Four DSCP classes carry the same 1428-byte IP packet, so the deployed Context
Capsule maps them to contexts 2, 6, 10, and 14 on the same physical vlink.  The
fault injector can then drop context 2 while the other three contexts remain
clean siblings for the frozen pooled baseline.
"""
import argparse
import socket
import time

from scapy.all import Ether, IP, Raw, UDP, get_if_hwaddr


TOS_VALUES = (0x00, 0x20, 0x40, 0x60)
EXPECTED_CONTEXTS = (2, 6, 10, 14)


def frames(iface, contexts):
    selected = TOS_VALUES if contexts == "all" else (TOS_VALUES[EXPECTED_CONTEXTS.index(int(contexts))],)
    return [
        bytes(Ether(dst=get_if_hwaddr(iface), src="02:00:00:00:00:06")
              / IP(src="10.0.1.1", dst="10.0.1.3", tos=tos)
              / UDP(sport=41000, dport=4449)
              / Raw(b"F" * 1400))
        for tos in selected
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="enp59s0f0np0")
    ap.add_argument("--count", type=int, required=True, help="total frames across all contexts")
    ap.add_argument("--pps", type=int, required=True, help="total offered packet rate")
    ap.add_argument("--contexts", choices=("all", "2", "6", "10", "14"), default="all")
    args = ap.parse_args()

    packets = frames(args.iface, args.contexts)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    sock.bind((args.iface, 0))
    interval = 1.0 / args.pps
    deadline = time.perf_counter()
    started = deadline
    per_context = [0] * len(packets)
    for i in range(args.count):
        which = i % len(packets)
        sock.send(packets[which])
        per_context[which] += 1
        deadline += interval
        remaining = deadline - time.perf_counter()
        if remaining > 0.0002:
            time.sleep(remaining - 0.0001)
        while time.perf_counter() < deadline:
            pass
    elapsed = time.perf_counter() - started
    labels = EXPECTED_CONTEXTS if args.contexts == "all" else (int(args.contexts),)
    print("sent %d frames in %.3fs = %.0f pps; per-context %s" %
          (args.count, elapsed, args.count / elapsed,
           dict(zip(labels, per_context))))


if __name__ == "__main__":
    main()
