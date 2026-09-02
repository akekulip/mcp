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

Pass --ledger when --program is a receiver-ledger-style build (p4/witness/
mcp_fabric_ledger.p4 or a descendant). That program's `reg_wit_observed` is a bit<32>
register that never resets (the base/CLF programs' bit<16> register resets to 0 on every
gap and saturates at 0xFFFF -- see `observed_delta`), which changes two things:

1. The periodic census's saturation ceiling must be disabled (`observed_delta`'s
   `saturation=None`), or every real delta past 65535 lifetime arrivals on a sublink is
   silently discarded as "saturated".
2. A gap-event mirror's `attn` slot is no longer a self-contained since-last-gap delta
   (see `controller.hw_adapter.gap_event_from_copy`'s docstring for why an earlier
   attempt to recover one from that 16-bit mirror field was wrong at this project's own
   1e-5 sweep floor, and double-counted against the census). Instead, on every gap
   event this loop issues one synchronous, TARGETED single-sublink census read
   (`GateClient.census([sublink])`) and folds it into the exact same shared baseline
   (`CensusWorker.previous`, `CensusWorker.consume_single`) the periodic census uses --
   so the two evidence paths can never double-count, and the number is always an exact
   32-bit count, never a 16-bit heuristic that could alias.

This is NOT auto-detected from --program, because that fact is not visible in the bfrt
schema (a heuristic warning fires if the verified program name and --ledger disagree,
but it is advisory only).
"""
import argparse, ctypes, dataclasses, queue, socket, struct, sys, threading, time
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


def observed_delta(previous, current, saturation=CENSUS_SATURATION_VALUE):
    """Conservative lower bound from the ingress observed clean-run counter.

    `saturation` guards a specific 16-bit register behaviour and must be `None` when
    driving a receiver-ledger-style program (`mcp_fabric_ledger.p4`): there
    `reg_wit_observed` is `bit<32>` and never saturates within a session, so a hardcoded
    0xFFFF ceiling would misread an ordinary count in [0xFFFF, 0xFFFFFFFF) as saturated
    and silently discard every real delta once a sublink passes 65535 lifetime arrivals
    -- minutes at most, milliseconds at line rate -- which is exactly the H28 failure
    mode ("a controller fed only gap events never warms up") this census path exists to
    avoid. Pass `saturation=None` to disable the check entirely for that program.

    Returns `None`, not `0`, specifically when `saturation is None` and `current` is
    BEHIND `previous`: a never-reset lifetime counter cannot legitimately decrease. The
    dominant real cause, in `--ledger` mode, is a benign race between the periodic
    census (`CensusWorker.poll_once`) and a gap-event-triggered targeted read
    (`CensusWorker.consume_single`): the periodic poll's own switch-side snapshot can be
    NEWER than a targeted read's, so the targeted read looks "behind" a baseline the
    periodic poll has already advanced -- see `resolve_ledger_gap_event`'s retry, which
    exists specifically for this case. It is NOT caused by `gate_agent`'s `rd()`
    (`p4/hw/loop/gate_agent.py`), whose `max()` across pipes is itself monotone
    non-decreasing and cannot produce a decrease on its own. `None` tells the caller to
    REJECT the reading outright -- not advance its baseline to it -- because doing so
    would inflate the NEXT good reading's delta by the gap the bad reading introduced.
    Every other outcome, including a genuine zero-growth reading, returns an `int` and
    is safe for the caller to advance its baseline to.
    """
    if saturation is not None:
        if current.observed >= saturation:
            return 0
        if previous.observed >= saturation:
            return 0
    if current.observed >= previous.observed:
        return current.observed - previous.observed
    if saturation is None:
        return None
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

    def census_request(self, sublinks=None):
        requested = self.census_sublinks if sublinks is None else tuple(sorted(set(sublinks)))
        suffix = "" if not requested else " " + " ".join(str(sublink) for sublink in requested)
        return ("R%s\n" % suffix).encode()

    def census(self, sublinks=None):
        """Return TX sequence diagnostics plus ingress arrival clean-run counters.

        The decision core needs a POOLED BASELINE, not just events.  controller/infer.py
        counts warm-up in observed PACKETS (BASELINE_WARMUP_PKTS = 1e5, the H28 fix), so a
        controller fed only gap events never warms up and can never alarm -- which is
        exactly what the first closed-loop run showed: one correct gap event, zero
        decisions.  In simulation the fabric supplies clean observations for every sublink
        every epoch; on hardware the equivalent is the arrival count the witness already
        keeps, polled per epoch and fed to observe_clean as deltas.

        Pass `sublinks` to read a specific set instead of `self.census_sublinks` -- used
        for a targeted single-sublink read on a gap event (`--ledger` mode) regardless of
        what the periodic census is configured to watch.
        """
        requested = self.census_sublinks if sublinks is None else tuple(sorted(set(sublinks)))
        if any(not 0 <= sublink < 1024 for sublink in requested):
            raise ValueError("census sublink must fit the 1024-cell C-W4 register")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.settimeout(15.0)
        buf = b""
        try:
            s.connect((self.host, self.port))
            s.sendall(self.census_request(sublinks))
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
        return parse_census_reply(buf, requested)


class CensusWorker(threading.Thread):
    """Poll slow BFRT registers without ever stopping the mirror receive path.

    A full 1024-cell census takes about 241 ms on this testbed.  Running it in the
    packet loop deterministically left the socket unread for most of every epoch.
    This worker emits one wrap-safe, batched fabric observation per completed read;
    the capture thread remains the sole owner of ``SublinkFeedback`` state.

    `self.previous` is the single shared baseline: on a ledger-style program (`--ledger`,
    `saturation=None`) the capture thread also folds gap-event-triggered targeted reads
    into this SAME dict via `consume_single`, so the periodic poll below and a targeted
    read can never both report evidence for the same interval. `self.lock` serialises
    every read-compute-advance of `self.previous` across the two threads that touch it
    (this worker's `run()`, and the capture thread calling `consume_single`).
    """

    def __init__(self, census, interval_s, saturation=CENSUS_SATURATION_VALUE):
        super().__init__(name="mcp-census", daemon=True)
        self.census = census
        self.interval_s = interval_s
        self.saturation = saturation
        self.results = queue.Queue()
        self.previous = {}     # NEVER read or write this outside `self.lock`
        self.lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._epoch_for = lambda: 0

    def poll_once(self, epoch):
        now = self.census()
        with self.lock:
            if not self.previous:
                self.previous.update(now)
                return []
            observations = []
            for sublink, cell in sorted(now.items()):
                baseline = self.previous.get(sublink)
                if baseline is None:
                    self.previous[sublink] = cell
                    continue
                delta = observed_delta(baseline, cell, self.saturation)
                if delta is None:
                    continue    # rejected reading: baseline left exactly as it was
                self.previous[sublink] = cell
                if delta:
                    observations.append((sublink >> 4, sublink & 0xF, delta))
            return observations

    def consume_single(self, sublink, cell):
        """Fold one targeted, out-of-band reading into the shared baseline.

        Thread-safe: called from the CAPTURE thread on a gap event, while `poll_once`
        (this worker's own thread) may be mutating the same `self.previous` dict
        concurrently. Returns the delta since the previous baseline for `sublink`, or
        `None` if there is no prior baseline yet (first-ever reading for this sublink)
        or the reading was rejected as a bad/racy decrease (`observed_delta`). In both
        `None` cases the caller must treat this occurrence as having no evidence, not a
        zero -- a reading that means "we don't yet know" is not the same claim as a
        reading that means "we know zero packets arrived".
        """
        with self.lock:
            baseline = self.previous.get(sublink)
            if baseline is None:
                self.previous[sublink] = cell
                return None
            delta = observed_delta(baseline, cell, self.saturation)
            if delta is None:
                return None    # rejected reading: baseline left exactly as it was
            self.previous[sublink] = cell
            return delta

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


def resolve_ledger_gap_event(gate, census, ev, retries=1):
    """Replace a gap event's `observed_packets` with an exact 32-bit reading (`--ledger`
    mode only; do not call this for a base/CLF program, whose mirror-derived value from
    `hw.gap_event_from_copy` is already exact and self-contained).

    Issues one synchronous, targeted single-sublink census read for `ev.sublink` and
    folds it into `census`'s shared baseline via `CensusWorker.consume_single`, so this
    reading and the periodic census can never both report evidence for the same
    interval. Returns `(event, rpc_seconds, None)` with `observed_packets` replaced, or
    `(None, rpc_seconds, reason)` if nothing was decidable, `reason` one of
    `"rpc_error"`, `"no_baseline"`, `"race_exhausted"` -- the caller should count
    `"race_exhausted"` separately and prominently: it means real loss evidence
    (`ev.lost`) was discarded, a missed-detection risk, not merely an imprecise count.
    `rpc_seconds` is the time spent in
    the RPC(s) this call made -- IMPORTANT: this is real network latency the caller adds
    to whatever timing it measures around this call, unlike every other program this
    loop drives, where `observed_packets` comes for free out of the mirror copy already
    in hand. Callers computing the event-to-reroute latency headline number MUST report
    this time explicitly and separately; folding it silently into that number changes
    what the number means relative to every non-ledger measurement in this project.

    A rejected reading (`CensusWorker.consume_single` returning `None`) is retried up to
    `retries` times ONLY when a baseline already existed for this sublink: the dominant
    cause is a benign race with the periodic census (it read a snapshot taken LATER on
    the switch and advanced the baseline before this targeted read's slightly-earlier
    snapshot was consumed) -- a second attempt, moments later, is virtually always ahead
    of whatever the periodic poll last advanced to. A missing baseline (first-ever
    reading for this sublink) is never retried; the read has already seeded it for next
    time, and retrying cannot produce a baseline that does not yet exist.

    `None` must be treated as "no evidence this occurrence", never as an event with
    `observed_packets=0`: dropping the event silently would hide a real detection, and
    fabricating a delivered count callers thought they didn't have would reintroduce
    exactly the failure mode this design replaces. Every drop path prints why.
    """
    t0 = time.perf_counter()
    for attempt in range(retries + 1):
        try:
            fresh = gate.census([ev.sublink])[ev.sublink]
        except (OSError, RuntimeError) as error:
            # Transport (OSError) and protocol (RuntimeError, from parse_census_reply)
            # failures only. A ValueError (malformed sublink) or KeyError here would be
            # a programming error, not a transient hiccup, and must propagate.
            print("  GAP EVENT sublink=%d: targeted census read failed (%s); dropped"
                  % (ev.sublink, error), flush=True)
            return None, time.perf_counter() - t0, "rpc_error"
        # Diagnostic-only, deliberately unlocked: a stale read only mislabels the log
        # line below ("no baseline" vs "rejected"), never the data path, which goes
        # through consume_single's own lock regardless.
        had_baseline = ev.sublink in census.previous
        delta = census.consume_single(ev.sublink, fresh)
        if delta is not None:
            return (dataclasses.replace(ev, observed_packets=delta),
                    time.perf_counter() - t0, None)
        if not had_baseline:
            print("  GAP EVENT sublink=%d: no census baseline yet; dropped, seeded for "
                  "next time" % ev.sublink, flush=True)
            return None, time.perf_counter() - t0, "no_baseline"
    print("  GAP EVENT sublink=%d: rejected census reading after %d attempt(s); LOSS "
          "EVIDENCE DROPPED (lost=%d)" % (ev.sublink, retries + 1, ev.lost), flush=True)
    return None, time.perf_counter() - t0, "race_exhausted"


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
    ap.add_argument("--ledger", action="store_true",
                    help="pass when --program is a receiver-ledger-style build "
                         "(mcp_fabric_ledger.p4 or a descendant): reg_wit_observed is "
                         "bit<32> and never resets, so a gap event's observed_packets is "
                         "derived from a targeted single-sublink census read instead of "
                         "the mirror's attn field, and the periodic census's 16-bit "
                         "saturation ceiling is disabled -- see the module docstring")
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
    # Heuristic only, not authoritative -- the switch-confirmed program name is the best
    # signal this process has of "receiver ledger" without a capability round trip to
    # gate_agent.py (which already resolves reg_rx_frontier's presence at its own
    # startup, gate_agent.py:70-82, but does not expose that fact over the wire). A
    # false positive/negative here is a print, not a block, because a future descendant
    # program's name is not guaranteed to contain "ledger".
    looks_ledger = "ledger" in identity["program"].lower()
    if looks_ledger != a.ledger:
        print("WARNING: program=%r %s 'ledger' but --ledger=%s; a mismatch either derives "
              "observed_packets from an unreliable mirror field on the ledger program, or "
              "runs an unnecessary targeted census read per gap event on a program that "
              "did not need it -- see the module docstring" %
              (identity["program"], "contains" if looks_ledger else "does not contain",
               a.ledger), flush=True)
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
    ledger_rpc_seconds = []     # per-gap-event targeted-read latency (--ledger only)
    ledger_races = 0            # gap events dropped after exhausting the reject-retry

    def epoch_now():
        return int((time.time() - epoch0) * 1000.0 / a.epoch_ms)

    def report_actions(actions):
        nonlocal decided_at
        for action in actions:
            decided_at = decided_at or time.time()
            print("    DECISION: %s" % action, flush=True)

    census_worker = CensusWorker(gate.census,
                           interval_s=a.epoch_ms * a.census_every / 1000.0,
                           saturation=None if a.ledger else CENSUS_SATURATION_VALUE)
    if a.ledger:
        # Seed the shared baseline BEFORE capture starts (a one-time cost outside the
        # measured campaign window), so the first gap event of the run is not
        # unconditionally dropped for lack of a prior reading (consume_single returns
        # None on first sight for every sublink -- see its docstring). This does not
        # help a sublink excluded from --census-sublinks; that sublink's first event
        # still drops, now with a printed reason instead of silently.
        try:
            census_worker.poll_once(epoch=epoch_now())
        except Exception as error:
            print("WARNING: could not seed the census baseline before capture (%s); "
                  "the first gap event on each sublink this run will be dropped for "
                  "lack of a baseline" % error, flush=True)
    census_worker.start(epoch_now)

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
                    kind, census_epoch, payload, duration = census_worker.results.get_nowait()
                except queue.Empty:
                    break
                census_reads.append(duration)
                if kind == "error":
                    census_errors += 1
                    print("  census failed: %s" % payload[:60], flush=True)
                    continue
                # In --ledger mode, quarantine_target's exclusion is unnecessary AND
                # harmful: resolve_ledger_gap_event already makes double-counting
                # structurally impossible via the shared baseline (CensusWorker.
                # consume_single), so this crude single-sublink filter only discards
                # legitimate clean evidence for the sublink under investigation, for
                # the rest of the run (nothing in this script currently clears
                # quarantine_target on restore). On base/CLF programs the filter is
                # unchanged: the register resets on gap, so the two streams were
                # already disjoint and this exclusion, while now also unnecessary
                # there, is at least not harmful, and is out of scope to touch here.
                exclude = None if a.ledger else quarantine_target
                if apply_census_result(fb, census_epoch, payload, exclude):
                    fed[0] += sum(row[2] for row in payload
                                  if a.ledger or ((row[0] << 4) | row[1]) != quarantine_target)

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
                    # Checked BEFORE any --ledger targeted census read: apply_gap_event
                    # short-circuits without calling on_gap for a mismatched epoch, so
                    # resolving observed_packets first would spend a synchronous RPC
                    # and consume the shared baseline for evidence nothing uses.
                    apply_gap_event(fb, ev)
                    print("  DROPPED GAP EVENT epoch=%d current=%d sublink=%d"
                          % (ev.epoch, fb.current_epoch, ev.sublink), flush=True)
                    continue
                if a.ledger:
                    ev, rpc_seconds, reason = resolve_ledger_gap_event(gate, census_worker, ev)
                    ledger_rpc_seconds.append(rpc_seconds)
                    if ev is None:
                        if reason == "race_exhausted":
                            ledger_races += 1
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
        census_worker.stop()
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
    if a.ledger:
        # --ledger's per-gap-event targeted census read runs SYNCHRONOUSLY inside the
        # decision path, unlike every other program this loop drives, where
        # observed_packets comes free out of the mirror copy already in hand. This
        # latency is real and is included in the measured END-TO-END number below --
        # it must never be reported as, or compared against, a non-ledger run's number
        # without accounting for it explicitly.
        if ledger_rpc_seconds:
            ordered = sorted(ledger_rpc_seconds)
            print("ledger targeted reads: %d ; median %.1f ms ; INCLUDED in END-TO-END below"
                  % (len(ordered), ordered[len(ordered) // 2] * 1000.0))
        print("ledger evidence drops: %d gap event(s) with LOSS EVIDENCE DISCARDED "
              "after exhausting the reject-retry (missed-detection risk)" % ledger_races)
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
