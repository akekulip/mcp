#!/usr/bin/env python3
"""P3 closed loop, one running process: mirrored gap event -> GapEvent -> decision -> gate write.

Runs on the collector host (Vision, dp9). Captures mirror copies from the fabric, parses them with
the SAME `controller/hw_adapter.py` parser the unit tests use, builds a real `GapEvent`, drives the
REAL `controller/sublink_feedback.SublinkFeedback` decision core (which applies the frozen
`controller/infer.py`), and installs the resulting quarantine into `tbl_health_gate`.

The BFRT write is an RPC to `p4/hw/loop/gate_agent.py` on the switch rather than a local call,
because the bf-rt client libraries live in the SDE and this host has neither the SDE nor grpcio.
That split is also what a real deployment looks like -- a controller without vendor SDK access --
and the agent hop is MEASURED and reported separately rather than hidden inside the total.

Latency is measured with the SWITCH's own 48-bit free-running counter at both ends, so no host
clock, no PTP and no calibration enters the headline number:

    t0 = mirror_h.tstamp on the gap-event copy      (the discontinuity was observed)
    t1 = mirror_h.tstamp on the first copy whose mirror_h.vlink is the BACKUP vlink
         (a data packet has demonstrably taken the new path, i.e. the gate is LIVE)
    end-to-end = t1 - t0
"""
import argparse, ctypes, queue, socket, struct, sys, threading, time
from dataclasses import dataclass
sys.path.insert(0, "/home/decps/mcp_ctl")

from controller import hw_adapter as hw
from controller.sublink_feedback import SublinkFeedback, GapEvent

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
SO_ATTACH_FILTER = 26
IDLE_RECEIVE_TIMEOUT_S = 0.01
MIN_RECEIVE_TIMEOUT_S = 0.0001
CENSUS_SATURATION_VALUE = 0xFFFF
MAX_GATE_REPLY_BYTES = 4096


@dataclass(frozen=True)
class CensusCell:
    tx_seq: int
    observed: int


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort),
                ("instructions", ctypes.POINTER(SockFilter))]


def mirror_filter_program(backup_vlink):
    """Classic BPF: accept a gap event OR a copy naming the backup vlink."""
    if not 0 <= backup_vlink <= 0xFFFF:
        raise ValueError("backup vlink must fit the mirror header")
    return (
        (0x28, 0, 0, 22),              # BPF_LD | BPF_H | BPF_ABS: flags
        (0x45, 2, 0, 0x8),             # BPF_JMP | BPF_JSET | BPF_K: gap bit
        (0x28, 0, 0, 16),              # otherwise inspect mirror vlink
        (0x15, 0, 1, backup_vlink),     # BPF_JMP | BPF_JEQ | BPF_K
        (0x06, 0, 0, 262144),           # accept event or backup proof candidate
        (0x06, 0, 0, 0),               # reject everything else in kernel
    )


def attach_mirror_filter(capture, backup_vlink):
    """Attach the event/proof filter; Linux copies the program during setsockopt."""
    spec = mirror_filter_program(backup_vlink)
    instructions = (SockFilter * len(spec))(*(SockFilter(*row) for row in spec))
    program = SockFprog(len(spec), instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    rc = libc.setsockopt(capture.fileno(), socket.SOL_SOCKET, SO_ATTACH_FILTER,
                         ctypes.byref(program), ctypes.sizeof(program))
    if rc != 0:
        error = ctypes.get_errno()
        raise OSError(error, "could not attach mirror socket filter")


def open_mirror_socket(iface, backup_vlink):
    """Open a filtered capture socket that can receive the switch's mirror MAC.

    The switch emits mirror copies to ``a5:a5:a5:a5:a5:a5``, not to the collector
    NIC's unicast MAC.  tcpdump and Scapy happened to make early trials work by
    enabling promiscuous mode themselves; a bare AF_PACKET sender did not.  Join a
    packet-socket promiscuous membership explicitly so capture correctness does not
    depend on an unrelated process.  Closing the socket releases the membership.
    """
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                            socket.htons(hw.MIRROR_ETYPE))
    capture.bind((iface, 0))
    capture.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    membership = struct.pack("IHH8s", socket.if_nametoindex(iface),
                             PACKET_MR_PROMISC, 0, b"\x00" * 8)
    capture.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, membership)
    # The ethertype alone still admitted ~10k ordinary attention copies/s and
    # delayed a real gap by 145 ms in the userspace queue.  Push the fixed-offset
    # mirror predicate into the kernel: only gap events and possible t1 proofs
    # cross the syscall boundary.
    attach_mirror_filter(capture, backup_vlink)
    capture.settimeout(IDLE_RECEIVE_TIMEOUT_S)
    return capture


def receive_timeout(held_deadline, now=None):
    """Bound packet waiting by the loss-reordering decision deadline.

    The filtered socket is commonly idle after the one gap event.  A fixed 10 ms
    receive timeout therefore turned a configured 1 ms reorder hold into 10--11 ms
    on silicon.  Keep the ordinary idle wait, but never sleep past a pending hold.
    """
    if held_deadline is None:
        return IDLE_RECEIVE_TIMEOUT_S
    if now is None:
        now = time.monotonic()
    return max(MIN_RECEIVE_TIMEOUT_S,
               min(IDLE_RECEIVE_TIMEOUT_S, held_deadline - now))


def campaign_complete(stop_after_result, t1_switch):
    return bool(stop_after_result and t1_switch is not None)


def require_targeted_census(stop_after_result, census_sublinks):
    """Publication campaigns may not fall back to the 1,024-cell census."""
    if stop_after_result and not census_sublinks:
        raise ValueError("--stop-after-result requires --census-sublinks")


def reset_gate_entries(gate, src_leaf, context, dst_count=4, spray_count=2):
    """Idempotently clear every candidate gate row or fail the trial before capture."""
    cleared = 0
    for dst in range(dst_count):
        for spray in range(spray_count):
            gate.remove(src_leaf, dst, spray, context)
            cleared += 1
    return cleared


def parse_census_reply(payload, requested_sublinks=()):
    """Parse a complete register census; transport/protocol failure is never clean evidence."""
    if not payload or not payload.endswith(b"\n"):
        raise RuntimeError("truncated census reply")
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise RuntimeError("non-ASCII census reply") from error
    if not lines:
        raise RuntimeError("empty census reply")
    terminal = lines[-1].split()
    if len(terminal) != 2 or terminal[0] != "OK" or not terminal[1].isdigit():
        message = lines[-1] if lines[-1].startswith("ERR ") else "missing census OK terminator"
        raise RuntimeError(message)
    terminal_count = int(terminal[1])

    out = {}
    for line in lines[:-1]:
        fields = line.split()
        if len(fields) != 6 or fields[0] != "S":
            raise RuntimeError("malformed census row: %s" % line[:80])
        try:
            sublink, vlink, context, stamped, cleanrun = map(int, fields[1:])
        except ValueError as error:
            raise RuntimeError("non-integer census row: %s" % line[:80]) from error
        if not (0 <= sublink < 1024 and 0 <= context < 16 and
                sublink == (vlink << 4) | context and stamped >= 0 and cleanrun >= 0):
            raise RuntimeError("inconsistent census row: %s" % line[:80])
        if sublink in out:
            raise RuntimeError("duplicate census sublink %d" % sublink)
        out[sublink] = CensusCell(tx_seq=stamped, observed=cleanrun)
    if terminal_count != len(out):
        raise RuntimeError("census terminal count %d does not match %d rows" %
                           (terminal_count, len(out)))
    requested = set(requested_sublinks or ())
    if requested and set(out) != requested:
        missing = sorted(requested - set(out))
        extra = sorted(set(out) - requested)
        if missing:
            raise RuntimeError("missing requested census rows: %s" % missing[:8])
        raise RuntimeError("unexpected census rows: %s" % extra[:8])
    return out


def observed_delta(previous, current):
    """Conservative lower bound from the ingress observed clean-run counter."""
    if current.observed >= CENSUS_SATURATION_VALUE:
        return 0
    if previous.observed >= CENSUS_SATURATION_VALUE:
        return 0
    if current.observed >= previous.observed:
        return current.observed - previous.observed
    return current.observed


def apply_census_result(feedback, census_epoch, observations, quarantine_target):
    if census_epoch != feedback.current_epoch:
        return False
    clean = [row for row in observations
             if ((row[0] << 4) | row[1]) != quarantine_target]
    feedback.observe_clean_batch(clean, census_epoch)
    return True


def apply_gap_event(feedback, event):
    if event.epoch != feedback.current_epoch:
        return False
    return feedback.on_gap(event)


def advance_epoch(feedback, gate, epoch, expected_epoch_rows):
    gate.set_epoch(epoch, expected_epoch_rows)
    feedback.begin_epoch(epoch)


def recv_gate_line(sock, max_bytes=MAX_GATE_REPLY_BYTES):
    """Read one bounded line from the gate-agent TCP stream."""
    buf = b""
    while len(buf) < max_bytes:
        chunk = sock.recv(min(4096, max_bytes - len(buf)))
        if not chunk:
            break
        buf += chunk
        if buf.endswith(b"\n"):
            break
    if len(buf) >= max_bytes and not buf.endswith(b"\n"):
        raise RuntimeError("gate-agent reply exceeded %d bytes" % max_bytes)
    try:
        return buf.decode("ascii", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError("non-ASCII gate-agent reply") from error


class GateClient:
    """Thin remote writer. One short-lived TCP connection per operation, TCP_NODELAY."""

    def __init__(self, host, port=47100, census_sublinks=()):
        self.host, self.port = host, port
        self.census_sublinks = tuple(sorted(set(census_sublinks)))
        if any(not 0 <= sublink < 1024 for sublink in self.census_sublinks):
            raise ValueError("census sublink must fit the 1024-cell C-W4 register")
        self.write_us = []

    def _send(self, line, record_latency=True):
        t0 = time.perf_counter_ns()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(10.0)
        try:
            s.connect((self.host, self.port))
            s.sendall(line.encode())
            reply = recv_gate_line(s)
        finally:
            s.close()
        fields = reply.split()
        if len(fields) != 2 or fields[0] != "OK" or not fields[1].isdigit():
            raise RuntimeError("gate operation failed: %s" % (reply or "<empty reply>"))
        rtt = (time.perf_counter_ns() - t0) // 1000
        agent = int(fields[1])
        if record_latency:
            self.write_us.append((rtt, agent))
        return reply

    def set_epoch(self, epoch, expected_count):
        if not 0 <= epoch <= 0xFFFF:
            raise ValueError("hardware epoch must fit the 16-bit CSIG field")
        # E replies with an exact modified-row count, not agent-side write time.
        # Keeping it out of write_us prevents a topology count from contaminating
        # the gate latency result.
        reply = self._send("E %d\n" % epoch, record_latency=False)
        count = int(reply.split()[1])
        if count != expected_count:
            raise RuntimeError("epoch write modified %d rows, expected %d" %
                               (count, expected_count))
        return reply

    def verify_identity(self, expected_program, expected_build_id, expected_runtime_id):
        """Require the agent to prove its program and sealed runtime before any write."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(10.0)
        try:
            s.connect((self.host, self.port))
            s.sendall(b"V\n")
            reply = recv_gate_line(s)
        finally:
            s.close()
        fields = reply.split()
        if len(fields) != 5 or fields[0] != "IDENTITY":
            raise RuntimeError("malformed gate-agent identity: %s" % (reply or "<empty>"))
        _, program, build_id, runtime_id, switchd_pid = fields
        hexchars = frozenset("0123456789abcdef")
        if (len(build_id) != 64 or len(runtime_id) != 64 or
                not set(build_id) <= hexchars or not set(runtime_id) <= hexchars or
                not switchd_pid.isdigit()):
            raise RuntimeError("malformed gate-agent identity: %s" % reply)
        if program != expected_program:
            raise RuntimeError("gate agent serves %s, expected %s" %
                               (program, expected_program))
        if build_id != expected_build_id:
            raise RuntimeError("gate agent build %s, expected build %s" %
                               (build_id, expected_build_id))
        if runtime_id != expected_runtime_id:
            raise RuntimeError("gate agent runtime %s, expected runtime %s" %
                               (runtime_id, expected_runtime_id))
        return {"program": program, "build_id": build_id,
                "runtime_id": runtime_id, "switchd_pid": int(switchd_pid)}

    def install(self, src, dst, spray, ctx, alt):
        return self._send("Q %d %d %d %d %d\n" % (src, dst, spray, ctx, alt))

    def install_many(self, rows):
        rows = tuple(rows)
        if not rows:
            return "OK 0"
        return self._send("B %s\n" % " ".join(
            " ".join(str(value) for value in row) for row in rows))

    def remove(self, src, dst, spray, ctx):
        return self._send("D %d %d %d %d\n" % (src, dst, spray, ctx))

    def census_request(self):
        suffix = "" if not self.census_sublinks else " " + " ".join(
            str(sublink) for sublink in self.census_sublinks)
        return ("R%s\n" % suffix).encode()

    def census(self):
        """Return TX sequence diagnostics plus ingress arrival clean-run counters.

        The decision core needs a POOLED BASELINE, not just events.  controller/infer.py
        counts warm-up in observed PACKETS (BASELINE_WARMUP_PKTS = 1e5, the H28 fix), so a
        controller fed only gap events never warms up and can never alarm -- which is
        exactly what the first closed-loop run showed: one correct gap event, zero
        decisions.  In simulation the fabric supplies clean observations for every sublink
        every epoch; on hardware the equivalent is the arrival count the witness already
        keeps, polled per epoch and fed to observe_clean as deltas.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(15.0)
        buf = b""
        try:
            s.connect((self.host, self.port))
            s.sendall(self.census_request())
            while len(buf) < 256 * 1024:
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if buf.endswith(b"\n"):
                    last = buf.splitlines()[-1]
                    if last.startswith(b"OK ") or last.startswith(b"ERR "):
                        break
        finally:
            s.close()
        return parse_census_reply(buf, self.census_sublinks)


class CensusWorker(threading.Thread):
    """Poll slow BFRT registers without ever stopping the mirror receive path.

    A full 1024-cell census takes about 241 ms on this testbed.  Running it in the
    packet loop deterministically left the socket unread for most of every epoch.
    This worker emits one wrap-safe, batched fabric observation per completed read;
    the capture thread remains the sole owner of ``SublinkFeedback`` state.
    """

    def __init__(self, census, interval_s):
        super().__init__(name="mcp-census", daemon=True)
        self.census = census
        self.interval_s = interval_s
        self.results = queue.Queue()
        self.previous = {}
        self._stop_requested = threading.Event()
        self._epoch_for = lambda: 0

    def poll_once(self, epoch):
        now = self.census()
        if not self.previous:
            self.previous.update(now)
            return []
        observations = []
        for sublink, cell in sorted(now.items()):
            if sublink not in self.previous:
                continue
            delta = observed_delta(self.previous[sublink], cell)
            if delta:
                observations.append((sublink >> 4, sublink & 0xF, delta))
        self.previous.update(now)
        return observations

    def start(self, epoch_for=None):
        if epoch_for is not None:
            self._epoch_for = epoch_for
        super().start()

    def run(self):
        while not self._stop_requested.is_set():
            started = time.monotonic()
            epoch = self._epoch_for()
            try:
                observations = self.poll_once(epoch)
            except Exception as ex:
                self.results.put(("error", epoch, str(ex), time.monotonic() - started))
            else:
                self.results.put(("census", epoch, observations,
                                  time.monotonic() - started))
            remaining = self.interval_s - (time.monotonic() - started)
            if remaining > 0:
                self._stop_requested.wait(remaining)

    def stop(self):
        self._stop_requested.set()
        self.join(timeout=20.0)


def is_rerouted_probe(copy, backup_vlink, context, diffserv,
                      src_ip, dst_ip, src_port, dst_port):
    """True only for the controlled probe after it traversed the backup uplink.

    A delivery-pass mirror has already stripped the fabric capsule, so requiring
    both ``mirror.vlink == backup`` and ``fabric.pad == context`` is impossible on
    silicon.  Prefer the capsule when present; otherwise bind the plain IPv4 copy
    to the experiment's exact DiffServ value and 5-tuple.  The four campaign
    contexts deliberately share a 5-tuple and differ only in DiffServ, so omitting
    that byte can misattribute another behavioral context as the t1 proof.
    """
    if copy.get("vlink") != backup_vlink:
        return False
    fabric = copy.get("fabric") or {}
    if fabric.get("pad") == context:
        return True
    ipv4 = copy.get("ipv4") or {}
    udp = copy.get("udp") or {}
    return (ipv4.get("diffserv") == diffserv and
            ipv4.get("src") == src_ip and ipv4.get("dst") == dst_ip and
            udp.get("src_port") == src_port and udp.get("dst_port") == dst_port)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="enp59s0f0np0")
    ap.add_argument("--switch", default="10.10.54.81")
    ap.add_argument("--program", required=True,
                    help="exact P4 program identity the sealed gate agent must report")
    ap.add_argument("--build-id", required=True,
                    help="exact SHA-256 of the expected sealed build manifest")
    ap.add_argument("--runtime-id", required=True,
                    help="exact SHA-256 of the expected sealed gate-agent runtime manifest")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--h", type=float, default=6.5)
    ap.add_argument("--backup-vlink", type=int, default=1,
                    help="vlink the reroute sends traffic to; t1 is the first copy carrying it")
    ap.add_argument("--epoch-ms", type=float, default=500.0)
    ap.add_argument("--ctx", type=int, default=2,
                    help="the quarantined context; t1 requires a copy carrying THIS ctx")
    ap.add_argument("--probe-src-ip", default="10.0.1.1")
    ap.add_argument("--probe-dst-ip", default="10.0.1.3")
    ap.add_argument("--probe-src-port", type=int, default=41000)
    ap.add_argument("--probe-dst-port", type=int, default=4449)
    ap.add_argument("--probe-diffserv", type=lambda value: int(value, 0), default=0,
                    help="exact IPv4 DiffServ/TOS byte required for a plain-copy t1 proof")
    ap.add_argument("--census-every", type=int, default=1,
                    help="poll the switch arrival census every N epochs to feed the pooled baseline")
    ap.add_argument("--census-sublinks", default="",
                    help="comma-separated active C-W4 cells; empty retains the full census")
    ap.add_argument("--reorder-wait-ms", type=float, default=1.0,
                    help="hold a loss gap briefly so an immediate reorder credit can cancel it")
    ap.add_argument("--reset", action="store_true",
                    help="clear gate entries for the target before starting (runbook: reset "
                         "BEFORE the capture starts, or a trial inherits the previous trial's gate)")
    ap.add_argument("--stop-after-result", action="store_true",
                    help="exit after the first exact reroute proof (campaign mode)")
    ap.add_argument("--expected-epoch-rows", type=int, default=4,
                    help="number of tbl_final act_enter rows that must accept each epoch stamp")
    a = ap.parse_args()

    census_sublinks = tuple(int(value) for value in a.census_sublinks.split(",") if value)
    try:
        require_targeted_census(a.stop_after_result, census_sublinks)
    except ValueError as error:
        ap.error(str(error))
    gate = GateClient(a.switch, census_sublinks=census_sublinks)
    identity = gate.verify_identity(a.program, a.build_id, a.runtime_id)
    print("gate identity: program=%s build=%s runtime=%s switchd_pid=%d" %
          (identity["program"], identity["build_id"], identity["runtime_id"],
           identity["switchd_pid"]), flush=True)
    installs = []

    def do_install(src, dst, spray, ctx, alt):
        r = gate.install(src, dst, spray, ctx, alt)
        installs.append((src, dst, spray, ctx, alt))
        print("    INSTALL src=%d dst=%d spray=%d ctx=%d -> alt=%d : %s"
              % (src, dst, spray, ctx, alt, r), flush=True)

    def do_remove(src, dst, spray, ctx):
        r = gate.remove(src, dst, spray, ctx)
        print("    REMOVE  src=%d dst=%d spray=%d ctx=%d : %s" % (src, dst, spray, ctx, r),
              flush=True)

    def do_install_many(rows):
        r = gate.install_many(rows)
        installs.extend(rows)
        print("    INSTALL BATCH rows=%d : %s" % (len(rows), r), flush=True)

    if a.reset:
        # The runbook is explicit: reset BEFORE the capture starts.  Resetting afterwards
        # leaves the previous trial's state in the first seconds of every capture, which
        # once produced eight self-consistent and entirely wrong reps in this project.
        cleared = reset_gate_entries(gate, src_leaf=0, context=a.ctx)
        gate.write_us.clear()
        print("reset: verified %d gate rows absent for ctx %d" % (cleared, a.ctx), flush=True)

    fb = SublinkFeedback(install=do_install, remove=do_remove, h=a.h,
                         install_many=do_install_many)
    gate.set_epoch(0, a.expected_epoch_rows)

    # Bind to the MIRROR ethertype, not ETH_P_ALL.  The probe traffic loops back through
    # the fabric to this same NIC at ~280 kpps, so an ETH_P_ALL socket spends all its time
    # rejecting production frames and never reaches the mirror copies -- measured: 0 copies
    # parsed in a 90 s run that carried 450 k probes.  Letting the kernel filter by
    # ethertype is what the runbook meant by "a BPF-filtered socket so it only ever sees
    # events".
    s = open_mirror_socket(a.iface, a.backup_vlink)

    print("controller_loop on %s -> switch %s ; h=%.2f ; backup vlink %d ; %.0fs"
          % (a.iface, a.switch, a.h, a.backup_vlink, a.seconds), flush=True)

    fed = [0]
    quarantine_target = None      # set once we see which sublink is faulty
    t_end = time.time() + a.seconds
    epoch0 = time.time()
    epoch = 0
    copies = gaps = 0
    t0_switch = None          # switch tstamp of the gap event that caused the decision
    t1_switch = None          # switch tstamp of the first copy on the backup vlink
    decided_at = None
    held_deadline = None
    census_reads = []
    census_errors = 0

    def epoch_now():
        return int((time.time() - epoch0) * 1000.0 / a.epoch_ms)

    def report_actions(actions):
        nonlocal decided_at
        for action in actions:
            decided_at = decided_at or time.time()
            print("    DECISION: %s" % action, flush=True)

    census = CensusWorker(gate.census,
                           interval_s=a.epoch_ms * a.census_every / 1000.0)
    census.start(epoch_now)

    try:
        while time.time() < t_end:
            e = epoch_now()
            if e != epoch:
                report_actions(fb.flush_held())
                epoch = e
                advance_epoch(fb, gate, epoch, a.expected_epoch_rows)
                held_deadline = None

            # Incorporate every completed census as ONE pooled update.  The worker
            # may finish while packets are arriving, but it never mutates feedback
            # state itself, so event/census ordering remains deterministic here.
            while True:
                try:
                    kind, census_epoch, payload, duration = census.results.get_nowait()
                except queue.Empty:
                    break
                census_reads.append(duration)
                if kind == "error":
                    census_errors += 1
                    print("  census failed: %s" % payload[:60], flush=True)
                    continue
                if apply_census_result(fb, census_epoch, payload, quarantine_target):
                    fed[0] += sum(row[2] for row in payload
                                  if ((row[0] << 4) | row[1]) != quarantine_target)

            if held_deadline is not None and time.monotonic() >= held_deadline:
                report_actions(fb.flush_held())
                held_deadline = None

            s.settimeout(receive_timeout(held_deadline))
            try:
                buf = s.recv(4096)
            except socket.timeout:
                continue
            try:
                copy = hw.parse_copy(buf)
            except ValueError:
                continue
            copies += 1

            if copy.get("gap_event"):
                ev = hw.gap_event_from_copy(copy)
                if ev is None:
                    continue
                if ev.epoch != fb.current_epoch:
                    # Hardware epoch is authoritative.  Do not let a stale/future
                    # event set t0, choose the quarantine target, or suppress its
                    # census row merely because the decision core would decline it.
                    apply_gap_event(fb, ev)
                    print("  DROPPED GAP EVENT epoch=%d current=%d sublink=%d"
                          % (ev.epoch, fb.current_epoch, ev.sublink), flush=True)
                    continue
                gaps += 1
                print("  GAP EVENT t_switch=%d sublink=%d (vlink %d ctx %d) gap=0x%04X lost=%d obs=%d"
                      % (copy["tstamp_ns"], ev.sublink, ev.vlink, ev.context, ev.gap, ev.lost,
                         ev.observed_packets), flush=True)
                if t0_switch is None:
                    t0_switch = copy["tstamp_ns"]
                quarantine_target = ev.sublink
                action = apply_gap_event(fb, ev)
                report_actions([action] if action else [])
                if ev.lost > 0 and ev.sublink in fb.held:
                    held_deadline = time.monotonic() + a.reorder_wait_ms / 1000.0
            elif t0_switch is not None and t1_switch is None and installs:
                # t1 must be OUR rerouted probe, not background traffic that hashed to the
                # backup vlink anyway.  Require the backup vlink AND the quarantined context
                # (the capsule carries ctx in hdr.fabric.pad).  Without the context test this
                # fires on the first unrelated copy and yields a plausible, meaningless number.
                fab = copy.get("fabric") or {}
                if is_rerouted_probe(copy, a.backup_vlink, a.ctx,
                                     a.probe_diffserv,
                                     a.probe_src_ip, a.probe_dst_ip,
                                     a.probe_src_port, a.probe_dst_port):
                    t1_switch = copy["tstamp_ns"]
                    print("  FIRST REROUTED PACKET: vlink=%d ctx=%d spray=%d t_switch=%d"
                          % (a.backup_vlink, a.ctx, fab.get("spray", -1), t1_switch),
                          flush=True)
                    if campaign_complete(a.stop_after_result, t1_switch):
                        break
    finally:
        census.stop()
        report_actions(fb.flush_held())

    print("\n--- summary ---", flush=True)
    print("mirror copies parsed : %d" % copies)
    print("gap events           : %d" % gaps)
    print("controller summary   : %s" % fb.summary())
    print("baseline packets fed : %d (frozen layer needs ~1e5 to leave warm-up)" % fed[0])
    if census_reads:
        ordered = sorted(census_reads)
        print("census reads         : %d ; median %.1f ms ; errors %d (capture ran concurrently)"
              % (len(ordered), ordered[len(ordered) // 2] * 1000.0, census_errors))
    if gate.write_us:
        rtts = sorted(x[0] for x in gate.write_us)
        ags = sorted(x[1] for x in gate.write_us if x[1] >= 0)
        print("gate ops             : %d ; rtt median %d us ; agent-side median %d us"
              % (len(rtts), rtts[len(rtts) // 2], ags[len(ags) // 2] if ags else -1))
    if t0_switch is not None and t1_switch is not None:
        print("END-TO-END (switch clock, both ends): t0=%d t1=%d  delta=%d ns = %.3f ms"
              % (t0_switch, t1_switch, t1_switch - t0_switch, (t1_switch - t0_switch) / 1e6))
    else:
        print("END-TO-END: not measured (t0=%s t1=%s)" % (t0_switch, t1_switch))


if __name__ == "__main__":
    main()
