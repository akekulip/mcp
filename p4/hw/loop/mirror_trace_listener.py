"""Live mirror-copy capture for the wire-reduction soak anomaly investigation
(HW-LEDGER-WIRE-REDUCTION-SOAK-ANOMALY-2026-09-02.md). Runs on Vision (the configured mirror
collector, dp9), where hw_adapter.py (pure stdlib, no SDE/bfrt dependency) can parse copies live,
with no offline round-trip needed.

Every gap event mcp_fabric_ledger.p4 detects already triggers a mirror copy to whatever collector
is configured (Ingress.set_gap_event / tbl_wit_arm) -- this listener just needs a place to catch
them. Binds a raw AF_PACKET socket to the fabric interface, filters on MIRROR_ETYPE (0x88F1), and
parses every copy with hw_adapter.parse_copy(), logging full detail for any FLAG_GAP_EVENT /
FLAG_AUDIT_RECEIPT copy -- vlink, context, epoch, gap size, arrival timestamp.

Usage (on Vision, needs root for the raw socket):
    sudo python3 mirror_trace_listener.py --iface enp59s0f0np0 --duration 300 \
        --log mirror_trace.jsonl
"""
import argparse
import json
import socket
import struct
import sys
import time

import hw_adapter as hw

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="enp59s0f0np0")
    ap.add_argument("--duration", type=float, default=300.0, help="seconds to listen")
    ap.add_argument("--log", type=str, default="mirror_trace.jsonl")
    args = ap.parse_args()

    # The switch emits mirror copies to a5:a5:a5:a5:a5:a5, NOT to Vision's NIC MAC, so the
    # NIC hardware-filters them unless the interface is in promiscuous mode. A bare AF_PACKET
    # socket does NOT enable promisc (tcpdump/Scapy do, which is why they saw the copies and an
    # earlier version of THIS listener only saw copies while a tcpdump ran alongside it). This
    # is HW-CLOSED-LOOP.md defects #1 and #4, and controller_loop.open_mirror_socket() is the
    # proven fix being copied here: bind on MIRROR_ETYPE (so the 0x0800 production stream is
    # never delivered to this socket) AND join a PACKET_MR_PROMISC membership explicitly.
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(hw.MIRROR_ETYPE))
    sock.bind((args.iface, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    membership = struct.pack("IHH8s", socket.if_nametoindex(args.iface),
                             PACKET_MR_PROMISC, 0, b"\x00" * 8)
    sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, membership)
    sock.settimeout(1.0)

    print(f"listening on {args.iface} for MIRROR_ETYPE 0x{hw.MIRROR_ETYPE:04x} copies "
          f"(promisc joined), {args.duration}s...", flush=True)

    deadline = time.monotonic() + args.duration
    n_seen = 0
    n_gap = 0
    with open(args.log, "a") as log:
        while time.monotonic() < deadline:
            try:
                buf, _addr = sock.recvfrom(2048)
            except socket.timeout:
                continue
            if len(buf) < 14:
                continue
            etype = struct.unpack_from("!H", buf, 12)[0]
            if etype != hw.MIRROR_ETYPE:
                continue
            n_seen += 1
            recv_ts = time.time()
            try:
                copy = hw.parse_copy(buf)
            except ValueError as e:
                record = {"recv_ts": recv_ts, "parse_error": str(e), "raw_len": len(buf)}
                log.write(json.dumps(record) + "\n")
                log.flush()
                print(f"  [{recv_ts:.3f}] PARSE ERROR: {e}", flush=True)
                continue
            record = {"recv_ts": recv_ts, "copy": copy}
            log.write(json.dumps(record, default=str) + "\n")
            log.flush()
            if copy.get("gap_event") or copy.get("audit_receipt"):
                n_gap += 1
                print(f"  [{recv_ts:.3f}] GAP/AUDIT COPY: vlink={copy['vlink']} "
                      f"path_id={copy['path_id']} attn={copy['attn']} flags=0x{copy['flags']:x} "
                      f"witness={copy.get('witness')} csig={copy.get('csig')}", flush=True)
            else:
                print(f"  [{recv_ts:.3f}] plain copy: vlink={copy['vlink']} flags=0x{copy['flags']:x}",
                      flush=True)

    print(f"done: {n_seen} copies seen, {n_gap} gap/audit copies, log -> {args.log}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
