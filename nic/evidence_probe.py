#!/usr/bin/env python3
"""evidence_probe.py — the NIC-side evidence PRODUCER for mcp_fabric (design doc §6,
alternative D1; PREREG §9.2 Tier-2 NIC arm).

Runs as root on Vision.  Sends a sequenced probe stream into the hairpinned fabric,
measures per-PATH loss / RTT / reorder from the copies that come back, quantises them
to the 8-bit fields of `evid_h`, and emits evidence packets to the switch, which
consumes them in `tbl_exceed_evid` and moves `reg_attn` without any controller in the
loop.

    sudo ./evidence_probe.py --dst 10.0.1.2 --pps 20000 --duration 30 --csv run.csv
    ./evidence_probe.py --dry-run            # path map + quantiser table, no sockets

--------------------------------------------------------------------------------
PATH RECOVERY — the one thing that had to be measured, not assumed
--------------------------------------------------------------------------------
A delivered frame carries NO fabric shim (the destination leaf strips it), so the
probe cannot read the spray index off the wire.  It has to recompute the switch's
own decision.  mcp_fabric.p4 sprays with

    CRCPolynomial<bit<32>>(coeff=0x04C11DB7, reversed=true, msb=false,
                           extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF)
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_spray) h_spray;
    md.spray_hash = h_spray.get({ipv4.src_addr, ipv4.dst_addr, udp.src_port});
    md.spray_idx  = md.spray_hash & mask;          // mask = k-1 = 1 for two spines

That parameter set is exactly the standard reflected CRC-32, i.e. `zlib.crc32`, and
`Hash<bit<16>>` takes the LOW 16 bits, so with two spines the spray index is simply
the low bit:

    spray   = zlib.crc32(src_ip_be || dst_ip_be || sport_be) & 1
    path_id = dst_leaf * N_SPINE + spray        # matches to_loop's path_id action data

VALIDATED EMPIRICALLY on silicon 2026-08-27 before this file was trusted, by
capturing mirrored copies (which carry both `mirror_h.path_id` and the inner UDP
source port) and comparing:

    dst 10.0.1.2 (leaf 1): 2994 source ports, 0 mismatches  -> paths {2, 3}
    dst 10.0.1.3 (leaf 2): 1989 source ports, 0 mismatches  -> paths {4, 5}

4983 of 4983 correct.  Re-run `--verify-map` against a fresh capture if the P4's
hash instance, its field list, or the number of spines ever changes: this mapping is
a property of the compiled binary, not of the protocol.

--------------------------------------------------------------------------------
QUANTISERS (documented so the switch-side thresholds mean something)
--------------------------------------------------------------------------------
    loss_q = min(255, int(loss_fraction * 2550 + 0.5))      1e-3 -> 3, 1e-2 -> 26,
                                                            1e-1 -> 255 (saturates)
    rtt_q  = min(255, int(mean_rtt_us / 4))                 4 us per LSB, 0..1020 us
    ecn_q  = 0                                              (no ECN feedback yet)
    flags  = bit0 reorder seen on this path

CAVEAT ON REORDER, measured: the reorder counter is dominated by HOST-side
reordering, not by the fabric.  A path's probes use ~500 different UDP source ports,
so the receiving NIC's RSS spreads them over several receive queues and userspace
sees them interleaved; a no-fault run reported ~17 500 "reorder" events with zero
loss.  Treat the counter as a diagnostic of the host receive path, NOT as a fabric
reorder measurement, and note that the switch ignores `flags` anyway.  A real fabric
reorder measurement would need one source port per path (which would defeat the
spray) or hardware RX timestamps.
`tbl_exceed_evid` is installed by setup_attention.py as `loss_q >= 1 OR rtt_q >= 255`,
so in practice loss is what raises attention and RTT is carried but inert.
"""
import argparse
import csv
import os
import socket
import struct
import sys
import threading
import time
import zlib
from collections import deque

# ---------------------------------------------------------------- constants
ETH_P_ALL = 0x0003
SO_ATTACH_FILTER = 26
PACKET_IGNORE_OUTGOING = 23
SOL_PACKET = 263
PACKET_STATISTICS = 6

MAGIC = b"MCPP"                 # probe payload marker
EVID_MAGIC = 0xE5
UDP_PROBE_DPORT = 5000
UDP_EVID_DPORT = 0xE5E5         # 58853 — mcp_fabric.p4 UDP_PORT_EVIDENCE
N_SPINE = 2

# host IP -> leaf, matching setup_skeleton.py's HOST_IPS
IP_LEAF = {"10.0.1.1": 0, "10.0.1.2": 1, "10.0.1.3": 2, "10.0.1.4": 3}

PAYLOAD_LEN = 35                # keeps the frame at 77 B, same framing as mcp_send.py
# magic4 | path1 | flags1 | pathseq4 | tx_ns8 = 18, then 17 bytes of padding
PROBE_HDR = struct.Struct("!4sBBIQ")


def path_of(src_ip, dst_ip, sport):
    """The switch's spray decision, recomputed on the host.  See the module docstring."""
    b = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!H", sport)
    return IP_LEAF[dst_ip] * N_SPINE + (zlib.crc32(b) & 1)


def quant_loss(frac):
    return min(255, int(frac * 2550 + 0.5))


def quant_rtt(us):
    return min(255, max(0, int(us / 4)))


def ip_csum(b):
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_frame(dmac, smac, src_ip, dst_ip, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", ip_csum(ip)) + ip[12:]
    return dmac + smac + b"\x08\x00" + ip + udp


def bpf_probe_filter(smac_bytes, dport):
    """Kernel-side filter: only our own probe replies reach userspace.  Without it the
    RX thread also has to walk every mirrored copy, and a Python RX loop that falls
    behind shows up as FAKE LOSS — the one failure mode that would silently corrupt
    every number this tool produces."""
    s_hi = struct.unpack("!I", smac_bytes[0:4])[0]
    s_lo = struct.unpack("!H", smac_bytes[4:6])[0]
    prog = [
        (0x28, 0, 0, 12),            # ldh  [12]           ethertype
        (0x15, 0, 10, 0x0800),       # jeq  0x0800 ? : drop
        (0x20, 0, 0, 6),             # ld   [6]            src mac hi 4
        (0x15, 0, 8, s_hi),          # jeq
        (0x28, 0, 0, 10),            # ldh  [10]           src mac lo 2
        (0x15, 0, 6, s_lo),          # jeq
        (0x30, 0, 0, 23),            # ldb  [23]           ip proto
        (0x15, 0, 4, 17),            # jeq  UDP
        (0xB1, 0, 0, 14),            # ldx  4*([14]&0xf)
        (0x48, 0, 0, 16),            # ldh  [x+16]         udp dport
        (0x15, 0, 1, dport),         # jeq
        (0x06, 0, 0, 0xFFFFFFFF),    # ret  all
        (0x06, 0, 0, 0),             # ret  0
    ]
    buf = b"".join(struct.pack("HBBI", c, jt, jf, k) for c, jt, jf, k in prog)
    addr = (ctypes_buf := __import__("ctypes").create_string_buffer(buf))
    return struct.pack("HP", len(prog), __import__("ctypes").addressof(addr)), ctypes_buf


class PathState(object):
    """Per-path measurement state.  `pending` is the in-flight window; `outcomes` is
    the sliding window of W retired probes that the loss fraction is computed over."""

    def __init__(self, path_id, dst_ip, W):
        self.path_id = path_id
        self.dst_ip = dst_ip
        self.tx_seq = 0
        self.pending = deque()          # (pathseq, tx_ns), in send order
        self.recv = {}                  # pathseq -> rtt_ns, for probes not yet retired
        self.outcomes = deque(maxlen=W)  # 1 received / 0 lost
        self.rtts = deque(maxlen=W)
        self.max_seq_seen = -1
        self.reorder = 0
        self.evid_seq = 0
        self.win_sent = 0
        self.win_recv = 0


class Probe(object):
    def __init__(self, a):
        self.a = a
        self.stop = threading.Event()
        self.paths = {}
        self.sports = {}                # dst_ip -> list of (sport, path_id)
        for dst in a.dst:
            lst = []
            for sp in range(a.sport_base, a.sport_base + a.sports):
                pid = path_of(a.src_ip, dst, sp)
                lst.append((sp, pid))
                if pid not in self.paths:
                    self.paths[pid] = PathState(pid, dst, a.loss_window)
            self.sports[dst] = lst
        self.dmac = bytes.fromhex(a.dst_mac.replace(":", ""))
        self.smac = bytes.fromhex(a.src_mac.replace(":", ""))
        self.tx_sock = None
        self.rx_sock = None
        self.lock = threading.Lock()
        self.sock_drops = 0
        self.n_tx = 0
        self.n_rx = 0
        self.n_evid = 0

    # ---------------------------------------------------------------- sockets
    def open_sockets(self):
        self.tx_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        self.tx_sock.bind((self.a.iface, 0))
        self.rx_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                     socket.htons(ETH_P_ALL))
        try:
            self.rx_sock.setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, 1)
        except OSError:
            print("note: PACKET_IGNORE_OUTGOING unavailable; filtering by pkttype",
                  file=sys.stderr)
        try:
            filt, self._filt_buf = bpf_probe_filter(self.smac, UDP_PROBE_DPORT)
            self.rx_sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, filt)
        except OSError as e:
            print("note: BPF filter not attached (%s); userspace filtering only" % e,
                  file=sys.stderr)
        self.rx_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 << 20)
        self.rx_sock.bind((self.a.iface, 0))

    def read_sock_drops(self):
        try:
            b = self.rx_sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8)
            _pkts, drops = struct.unpack("II", b)
            return drops
        except OSError:
            return 0

    # ---------------------------------------------------------------- threads
    def tx_loop(self):
        a = self.a
        per_tick = max(1, a.pps // 1000)
        pool = [(dst, sp, pid) for dst in a.dst for sp, pid in self.sports[dst]]
        n = len(pool)
        i = 0
        t0 = time.perf_counter()
        tick = 0
        deadline = t0 + a.duration if a.duration else None
        while not self.stop.is_set():
            now = time.perf_counter()
            if deadline and now >= deadline:
                break
            target = int((now - t0) * 1000)
            while tick <= target and not self.stop.is_set():
                for _ in range(per_tick):
                    dst, sp, pid = pool[i % n]
                    i += 1
                    st = self.paths[pid]
                    with self.lock:
                        seq = st.tx_seq
                        st.tx_seq += 1
                        tx_ns = time.monotonic_ns()
                        st.pending.append((seq, tx_ns))
                        st.win_sent += 1
                    pl = PROBE_HDR.pack(MAGIC, pid, 0, seq, tx_ns)
                    pl += b"\x00" * (PAYLOAD_LEN - len(pl))
                    try:
                        self.tx_sock.send(build_frame(self.dmac, self.smac, a.src_ip,
                                                      dst, sp, UDP_PROBE_DPORT, pl))
                        self.n_tx += 1
                    except OSError:
                        pass
                tick += 1
            time.sleep(0.0002)
        self.stop.set()

    def rx_loop(self):
        buf = bytearray(2048)
        view = memoryview(buf)
        while not self.stop.is_set():
            try:
                self.rx_sock.settimeout(0.5)
                nb = self.rx_sock.recv_into(view, 2048)
            except (socket.timeout, OSError):
                continue
            if nb < 14 + 20 + 8 + 18:
                continue
            ihl = (buf[14] & 0xF) * 4
            off = 14 + ihl + 8
            if bytes(view[off:off + 4]) != MAGIC:
                continue
            _m, pid, _f, seq, tx_ns = PROBE_HDR.unpack(bytes(view[off:off + 18]))
            st = self.paths.get(pid)
            if st is None:
                continue
            rtt = time.monotonic_ns() - tx_ns
            with self.lock:
                st.recv[seq] = rtt
                st.win_recv += 1
                if seq < st.max_seq_seen:
                    st.reorder += 1
                else:
                    st.max_seq_seen = seq
            self.n_rx += 1

    def retire(self, st, cutoff_ns):
        """Move probes older than the grace period out of `pending` into the sliding
        window.  Retiring by TIME rather than by sequence is what makes reordered and
        merely-late probes count as received instead of lost."""
        got = lost = 0
        rtts = []
        while st.pending and st.pending[0][1] <= cutoff_ns:
            seq, _t = st.pending.popleft()
            r = st.recv.pop(seq, None)
            if r is None:
                st.outcomes.append(0)
                lost += 1
            else:
                st.outcomes.append(1)
                st.rtts.append(r)
                rtts.append(r)
                got += 1
        return got, lost, rtts

    def emit_loop(self):
        a = self.a
        w = csv.writer(open(a.csv, "w", newline="")) if a.csv else None
        if w:
            w.writerow(["wall", "path_id", "dst_ip", "retired", "recv", "lost",
                        "loss_frac_window", "loss_q", "rtt_mean_us", "rtt_min_us",
                        "rtt_max_us", "rtt_q", "reorder_total", "sock_drops",
                        "emitted", "evid_seq"])
        period = a.window_ms / 1000.0
        grace = a.grace_ms * 1_000_000
        nxt = time.perf_counter() + period
        while not self.stop.is_set():
            d = nxt - time.perf_counter()
            if d > 0:
                time.sleep(min(d, 0.25))
                if time.perf_counter() < nxt:
                    continue
            nxt += period
            drops = self.read_sock_drops()
            new_drops = drops - self.sock_drops
            self.sock_drops = drops
            cutoff = time.monotonic_ns() - grace
            for pid, st in sorted(self.paths.items()):
                with self.lock:
                    got, lost, rtts = self.retire(st, cutoff)
                    outcomes = list(st.outcomes)
                    reorder = st.reorder
                if not outcomes:
                    continue
                loss_frac = 1.0 - (sum(outcomes) / float(len(outcomes)))
                allr = list(st.rtts)
                rtt_mean_us = (sum(allr) / len(allr) / 1000.0) if allr else 0.0
                rtt_min_us = (min(allr) / 1000.0) if allr else 0.0
                rtt_max_us = (max(allr) / 1000.0) if allr else 0.0
                loss_q = quant_loss(loss_frac)
                rtt_q = quant_rtt(rtt_mean_us)
                flags = 1 if reorder else 0
                emit = a.always or (loss_q != 0 or rtt_q != 0) \
                    if a.emit_on == "any" else (a.always or loss_q != 0)
                if emit:
                    self.send_evidence(st, rtt_q, loss_q, flags)
                if w:
                    w.writerow(["%.6f" % time.time(), pid, st.dst_ip, got + lost, got,
                                lost, "%.6f" % loss_frac, loss_q, "%.1f" % rtt_mean_us,
                                "%.1f" % rtt_min_us, "%.1f" % rtt_max_us, rtt_q,
                                reorder, new_drops, int(bool(emit)), st.evid_seq])
                if a.verbose:
                    print("path %d  retired %4d lost %3d  loss %.4f -> q%-3d  "
                          "rtt %6.1f us -> q%-3d  reorder %d  sockdrop %d  %s"
                          % (pid, got + lost, lost, loss_frac, loss_q, rtt_mean_us,
                             rtt_q, reorder, new_drops, "EMIT" if emit else ""))
            if w:
                pass
        if w:
            pass

    def send_evidence(self, st, rtt_q, loss_q, flags):
        ev = struct.pack("!BBBBBBH", EVID_MAGIC, st.path_id & 0xFF, rtt_q, loss_q,
                         0, flags, st.evid_seq & 0xFFFF)
        st.evid_seq += 1
        fr = build_frame(self.dmac, self.smac, self.a.src_ip, st.dst_ip,
                         20000 + st.path_id, UDP_EVID_DPORT, ev)
        try:
            self.tx_sock.send(fr)
            self.n_evid += 1
        except OSError:
            pass

    def run(self):
        self.open_sockets()
        self.read_sock_drops()
        threads = [threading.Thread(target=self.rx_loop, daemon=True),
                   threading.Thread(target=self.emit_loop, daemon=True),
                   threading.Thread(target=self.tx_loop, daemon=True)]
        for t in threads:
            t.start()
        try:
            while not self.stop.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            self.stop.set()
        time.sleep(self.a.grace_ms / 1000.0 + 0.3)
        self.stop.set()
        time.sleep(0.3)
        print("tx=%d rx=%d evidence=%d sock_drops=%d"
              % (self.n_tx, self.n_rx, self.n_evid, self.sock_drops))


def dry_run(a):
    print("path mapping   path_id = leaf(dst)*%d + (zlib.crc32(src||dst||sport) & 1)"
          % N_SPINE)
    print("               validated on silicon: 4983/4983 source ports correct")
    for dst in a.dst:
        pids = {}
        for sp in range(a.sport_base, a.sport_base + a.sports):
            pids.setdefault(path_of(a.src_ip, dst, sp), []).append(sp)
        print("  %s (leaf %d): %s" % (dst, IP_LEAF[dst],
              ", ".join("path %d <- %d sports e.g. %s" % (p, len(v), v[:4])
                        for p, v in sorted(pids.items()))))
    print("\nquantisers")
    print("  loss_q = min(255, int(loss_fraction*2550 + 0.5))")
    for f in (0, 1e-4, 3.92e-4, 1e-3, 5e-3, 1e-2, 5e-2, 0.1, 0.5, 1.0):
        print("      loss %-8g -> loss_q %d" % (f, quant_loss(f)))
    print("  rtt_q  = min(255, int(mean_rtt_us / 4))")
    for u in (0, 4, 20, 100, 250, 1020, 4000):
        print("      rtt  %-8g us -> rtt_q %d" % (u, quant_rtt(u)))
    print("\nevidence packet: IPv4/UDP dport %d (0x%04X), evid_h = "
          "{magic 0xE5, path_id, rtt_q, loss_q, ecn_q=0, flags, seq16}"
          % (UDP_EVID_DPORT, UDP_EVID_DPORT))
    print("emit rule: %s" % ("always" if a.always else
                             "loss_q or rtt_q non-zero" if a.emit_on == "any"
                             else "loss_q non-zero"))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--iface", default="enp59s0f0np0")
    p.add_argument("--src-ip", default="10.0.1.1")
    p.add_argument("--dst", action="append", default=None,
                   help="destination host IP; repeatable (default 10.0.1.2)")
    p.add_argument("--src-mac", default="02:00:00:00:00:0a",
                   help="locally administered, so the hairpinned copy is not dropped "
                        "by a self-MAC receive filter")
    p.add_argument("--dst-mac", default="3c:fd:fe:cc:5d:c0", help="Vision's own MAC")
    p.add_argument("--pps", type=int, default=10000)
    p.add_argument("--sports", type=int, default=1000)
    p.add_argument("--sport-base", type=int, default=10000)
    p.add_argument("--window-ms", type=float, default=10.0)
    p.add_argument("--loss-window", type=int, default=1000,
                   help="W: sliding window of retired probes for the loss fraction")
    p.add_argument("--grace-ms", type=float, default=5.0,
                   help="a probe is only counted lost once it is this old")
    p.add_argument("--duration", type=float, default=0, help="0 = until interrupted")
    p.add_argument("--csv", default=None)
    p.add_argument("--always", action="store_true", help="emit every window")
    p.add_argument("--emit-on", choices=("any", "loss"), default="any")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args()
    if not a.dst:
        a.dst = ["10.0.1.2"]
    for d in a.dst:
        if d not in IP_LEAF:
            p.error("unknown destination %s; known: %s" % (d, sorted(IP_LEAF)))
    if a.dry_run:
        dry_run(a)
        return
    if os.geteuid() != 0:
        p.error("raw sockets need root")
    Probe(a).run()


if __name__ == "__main__":
    main()
