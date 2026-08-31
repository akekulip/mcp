#!/usr/bin/env python3
"""Repeated CLF trials with a verified reset, for rates rather than anecdotes.

Every step here is checked, because each unchecked step has already produced a wrong number:

* the bank is ZEROED and the zero is VERIFIED.  An earlier version of this driver documented
  ``quiesce -> zero -> quiesce -> generate -> settle -> read`` and then never zeroed at all.
  The frozen bank carried residue from every previous run, and a stale RX bit makes
  ``TX & ~RX`` come out zero for the very sublink under test -- a real blackhole read as
  HEALTHY.  Residue does not merely add noise; it silently deletes detections.
* the PROBE's exit status and packet count are checked.  ``capture_output=True`` with a
  discarded returncode turns a probe that never ran into a clean-looking miss.
* the INJECTOR is confirmed armed, and its drop counter is reported next to every verdict, so
  a detection claim always sits beside the measured number of packets actually dropped.
* the bank is FROZEN before it is read: traffic marks bank B, then the source flips to 1-B and
  we guard before reading B.  TX and RX then describe the same set of packets.

Coverage: CLF observes both directed links in the emulated path.  The exact tbl_eg_vlink
readback is a precondition: without it both hops alias into vlink 0 and plausible-looking counts
lose their link identity.
"""
import argparse, socket, subprocess, sys, time

sys.path.insert(0, "/home/decps/mcp_ctl")  # runs ON Vision: the agent allowlist
                                            # admits 10.10.54.166 and 127.0.0.1 only
from sim.clf.verdict import verdict, verdict_counts, Verdict

SWITCH = "10.10.54.81"
PORT = 47100
EXPECTED_ACT_ENTER_ROWS = 4
DEFAULT_PROBE_PACKETS = 40
DEFAULT_PROBE_GAP = 0.01
MAX_AGENT_REPLY_BYTES = 256 * 1024


class HarnessError(RuntimeError):
    """A trial whose own preconditions failed. Never averaged into a rate."""


def _reply_complete(buf):
    lines = [line for line in buf.splitlines() if line.strip()]
    if not lines:
        return False
    last = lines[-1]
    return (last.startswith(b"OK ") or last.startswith(b"ERR ") or
            last.startswith(b"IDENTITY "))


def agent(cmd, timeout=25):
    s = socket.create_connection((SWITCH, PORT), timeout)
    s.settimeout(timeout)
    try:
        s.sendall((cmd + "\n").encode())
        buf = b""
        while len(buf) < MAX_AGENT_REPLY_BYTES and not _reply_complete(buf):
            c = s.recv(min(65536, MAX_AGENT_REPLY_BYTES - len(buf)))
            if not c:
                break
            buf += c
        if len(buf) >= MAX_AGENT_REPLY_BYTES and not _reply_complete(buf):
            raise HarnessError("agent reply exceeded %d bytes" % MAX_AGENT_REPLY_BYTES)
        return buf.decode(errors="replace")
    finally:
        s.close()


def require_ok_count(reply, command, expected=None, positive=False):
    lines = [line.strip() for line in reply.splitlines() if line.strip()]
    if not lines:
        raise HarnessError("%s reply was empty" % command)
    if any(line.startswith("ERR") for line in lines):
        raise HarnessError("%s failed: %s" % (command, lines[-1]))
    ok = [line for line in lines if line.startswith("OK ")]
    if not ok:
        raise HarnessError("%s reply missing OK terminator" % command)
    try:
        count = int(ok[-1].split()[1])
    except (IndexError, ValueError):
        raise HarnessError("%s reply has malformed OK count: %r" % (command, ok[-1]))
    if positive and count <= 0:
        raise HarnessError("%s modified %d act_enter rows" % (command, count))
    if expected is not None and count != expected:
        raise HarnessError("%s modified %d act_enter rows, expected %d"
                           % (command, count, expected))
    return count


def mutate_ok(command, expected=None, positive=False):
    return require_ok_count(agent(command), command, expected=expected, positive=positive)


def require_blackhole_arm(reply, sublink):
    command = "K %d" % sublink
    require_ok_count(reply, command, expected=1)
    detail = [line.strip() for line in reply.splitlines()
              if line.strip() and not line.startswith("OK ")]
    expected = "BLACKHOLED %d [0..65535]" % sublink
    if detail != [expected]:
        raise HarnessError("%s returned malformed arm detail: %r" %
                           (command, reply.strip()[:120]))


def require_agent_identity(expected_program, expected_build_id, expected_runtime_id):
    reply = agent("V")
    fields = reply.strip().split()
    if len(fields) != 5 or fields[0] != "IDENTITY":
        raise HarnessError("malformed gate-agent identity: %r" % reply[:120])
    _, program, build_id, runtime_id, switchd_pid = fields
    hexchars = frozenset("0123456789abcdef")
    if (len(build_id) != 64 or len(runtime_id) != 64 or
            not set(build_id) <= hexchars or not set(runtime_id) <= hexchars or
            not switchd_pid.isdigit()):
        raise HarnessError("malformed gate-agent identity: %r" % reply[:120])
    if program != expected_program:
        raise HarnessError("gate agent serves %s, expected %s" %
                           (program, expected_program))
    if build_id != expected_build_id:
        raise HarnessError("gate agent build %s, expected build %s" %
                           (build_id, expected_build_id))
    if runtime_id != expected_runtime_id:
        raise HarnessError("gate agent runtime %s, expected runtime %s" %
                           (runtime_id, expected_runtime_id))
    return program, build_id, runtime_id, int(switchd_pid)


def set_bank(bank, expected_act_enter_rows=EXPECTED_ACT_ENTER_ROWS):
    return mutate_ok("N %d" % bank, expected=expected_act_enter_rows, positive=True)


def clear_injectors():
    mutate_ok("C")


def zero_frontiers():
    mutate_ok("Z")


def parse_frontiers(reply):
    require_ok_count(reply, "F")
    out = []
    for line in reply.splitlines():
        f = line.split()
        if not f or f[0] == "OK":
            continue
        if len(f) != 6 or f[0] != "F":
            raise HarnessError("malformed F row: %r" % line[:120])
        out.append((int(f[1]), int(f[2]), int(f[3], 16), int(f[4], 16)))
    return out


def frontiers():
    return parse_frontiers(agent("F"))


def parse_count_frontiers(reply):
    require_ok_count(reply, "X")
    out = []
    for line in reply.splitlines():
        f = line.split()
        if not f or f[0] == "OK":
            continue
        if len(f) != 6 or f[0] != "X":
            raise HarnessError("malformed X row: %r" % line[:120])
        out.append(tuple(int(x) for x in f[1:]))
    return out


def count_frontiers():
    return parse_count_frontiers(agent("X"))


def rows_for_sublink(rows, bank, sublink):
    vlink, ctx = sublink >> 4, sublink & 0xF
    return [row for row in rows if row[0] == bank and row[1] == vlink and row[2] == ctx]


def zero_frontiers_for_sublink(bank, sublink, attempts=3, settle=0.3):
    measured_residue = []
    for _ in range(attempts):
        zero_frontiers()
        time.sleep(settle)
        residue = count_frontiers()
        measured_residue = (rows_for_sublink(residue, bank, sublink)
                            if sublink is not None else residue)
        if not measured_residue:
            return
    raise HarnessError("zero did not take on sublink %s, %d rows remain: %s" %
                       (sublink, len(measured_residue), measured_residue[:3]))


def injector_rows():
    reply = agent("I")
    require_ok_count(reply, "I")
    return [l.strip() for l in reply.splitlines() if l.startswith("I ")]


def injector_drops():
    """Total packets the post-TM fault injector actually discarded."""
    n = 0
    for row in injector_rows():
        f = row.split()
        if len(f) >= 5:
            n += int(f[4])
    return n


def probe(script, packets=DEFAULT_PROBE_PACKETS, gap=DEFAULT_PROBE_GAP):
    """Local: this driver already runs on the probe host. Failure is raised, never swallowed."""
    if not 0 < packets < 255:
        raise ValueError("probe packet budget must be positive and below the 255-count saturation value")
    if gap <= 0:
        raise ValueError("probe gap must be positive")
    r = subprocess.run(["python3", script, str(packets), str(gap)],
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise HarnessError("probe exited %d: %s" % (r.returncode, (r.stderr or "").strip()[:200]))
    sent = 0
    for tok in (r.stdout or "").split():
        if tok.isdigit():
            sent = int(tok)
            break
    if sent != packets:
        raise HarnessError("probe reported %d packets sent, expected %d: %r" %
                           (sent, packets, (r.stdout or "")[:200]))
    return sent


def classify_presence(rows):
    """Frozen-bank rows -> per-sublink verdicts.

    gap_seen is unknown for every sublink: the frontier registers carry presence bits, not
    sequence continuity, so this explicit historical mode only compares blackhole vs
    not-blackhole. Partial loss is C-W4's job and is measured separately.
    """
    v = {}
    for _bank, vl, tx, rx in rows:
        for ctx in range(4):
            t, r = bool(tx >> ctx & 1), bool(rx >> ctx & 1)
            if t or r:
                v[(vl, ctx)] = verdict(t, r, None)
    return v


def classify_counts(rows):
    """Frozen-bank X rows -> per-sublink verdicts from saturating counts."""
    v = {}
    for _bank, vl, ctx, tx, rx in rows:
        if tx or rx:
            v[(vl, ctx)] = verdict_counts(tx, rx)
    return v


classify = classify_presence


def trial(target_sublink, guard, arm_settle=1.0, bank=0, observe_sublink=None,
          expected_act_enter_rows=EXPECTED_ACT_ENTER_ROWS,
          packets=DEFAULT_PROBE_PACKETS, probe_gap=DEFAULT_PROBE_GAP):
    """One trial: quiesce -> arm -> zero -> verify -> probe -> freeze -> guard -> read.

    Raises HarnessError if any precondition fails, so a broken trial is reported and excluded
    rather than being averaged in as a miss.
    """
    clear_injectors()                           # clear injectors
    set_bank(bank, expected_act_enter_rows)     # make B the active bank
    time.sleep(guard)                           # quiesce: prior in-flight lands

    # ARM BEFORE ZEROING.  The reverse order leaves the target sublink live between the reset
    # and the arm, and a single stray background packet arriving in that window sets RX=1 --
    # which masks the blackhole exactly the way stale residue did, reporting HEALTHY for a
    # sublink that is dark.  Observed directly: a fault trial with 401 packets dropped read
    # HEALTHY.  Arming first means nothing can mark RX for the target after the zero.
    if target_sublink is not None:
        reply = agent("K %d" % target_sublink)
        require_blackhole_arm(reply, target_sublink)
        time.sleep(arm_settle)

    measured_sublink = target_sublink if target_sublink is not None else observe_sublink
    zero_frontiers_for_sublink(bank, measured_sublink)  # zero and verify the measured slot

    sent = probe("/tmp/probe_spray0.py", packets=packets, gap=probe_gap)
                                                # marks bank B; raises if it did not run

    set_bank(1 - bank, expected_act_enter_rows) # freeze B by flipping away
    time.sleep(guard)                           # in-flight B packets land in B, then quiet
    drops = injector_drops()
    if target_sublink is not None and drops <= 0:
        raise HarnessError("injector reported no drops for armed sublink %d" % target_sublink)
    rows = [r for r in count_frontiers() if r[0] == bank]   # read ONLY the frozen bank
    return classify_counts(rows), sent, drops


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--guard", type=float, default=2.0)
    ap.add_argument("--arm-settle", type=float, default=1.0,
                    help="pause after arming before probing; 0 reproduces the race")
    ap.add_argument("--sublink", type=int, default=2, help="vlink 0, ctx 2")
    ap.add_argument("--act-enter-rows", type=int, default=EXPECTED_ACT_ENTER_ROWS,
                    help="exact positive act_enter row count required from N")
    ap.add_argument("--packets", type=int, default=DEFAULT_PROBE_PACKETS,
                    help="packets per trial; must stay below the 255-count saturation value")
    ap.add_argument("--probe-gap", type=float, default=DEFAULT_PROBE_GAP,
                    help="seconds between probe packets")
    ap.add_argument("--program", default="mcp_fabric_clf_eg",
                    help="expected P4 program served by the switch-side gate agent")
    ap.add_argument("--build-id", required=True,
                    help="exact SHA-256 of the expected sealed build manifest")
    ap.add_argument("--runtime-id", required=True,
                    help="exact SHA-256 of the expected sealed gate-agent runtime manifest")
    a = ap.parse_args()
    program, build_id, runtime_id, switchd_pid = require_agent_identity(
        a.program, a.build_id, a.runtime_id)
    print("agent identity: program=%s build=%s runtime=%s switchd_pid=%d" %
          (program, build_id, runtime_id, switchd_pid), flush=True)
    tgt = (a.sublink >> 4, a.sublink & 0xF)

    res = {"fault": [], "control": []}
    broken = []
    for i in range(a.trials):
        for arm, sub in (("fault", a.sublink), ("control", None)):
            try:
                v, sent, drops = trial(sub, a.guard, a.arm_settle, bank=i % 2,
                                       observe_sublink=a.sublink,
                                       expected_act_enter_rows=a.act_enter_rows,
                                       packets=a.packets, probe_gap=a.probe_gap)
            except HarnessError as e:
                broken.append((i + 1, arm, str(e)))
                print("  trial %2d %-7s HARNESS-ERROR %s" % (i + 1, arm, e), flush=True)
                continue
            hit = v.get(tgt) == Verdict.BLACKHOLE
            starved = v.get(tgt) == Verdict.STARVED
            false_bh = sum(1 for k, x in v.items() if x == Verdict.BLACKHOLE and k != tgt)
            false_starved = sum(1 for k, x in v.items() if x == Verdict.STARVED and k != tgt)
            imp = sum(1 for x in v.values() if x == Verdict.IMPOSSIBLE)
            res[arm].append((hit, starved, false_bh, false_starved, imp, len(v)))
            note = ""
            if arm == "fault" and not (hit or starved):
                tv = v.get(tgt)
                note = "  MISS verdict=%s" % (tv.value if tv else "ABSENT")
            print("  trial %2d %-7s blackhole=%-5s starved=%-5s false_bh=%d "
                  "false_starved=%d impossible=%d observed=%d sent=%d dropped=%d%s"
                  % (i + 1, arm, hit, starved, false_bh, false_starved, imp, len(v),
                     sent, drops, note), flush=True)
    agent("C")

    print("\n=== CLF detection rates (guard %.1fs, %d trials/arm requested) ===" % (a.guard, a.trials))
    for arm in ("fault", "control"):
        r = res[arm]
        n = len(r)
        if not n:
            print("  %-8s n=0 -- every trial failed its preconditions; no rate reported" % arm)
            continue
        det = sum(1 for x in r if x[0])
        starved = sum(1 for x in r if x[1])
        fbh = sum(x[2] for x in r)
        fst = sum(x[3] for x in r)
        imp = sum(x[4] for x in r)
        obs = sum(x[5] for x in r)
        print("  %-8s n=%d  target BLACKHOLE %d/%d (%.0f%%)  target STARVED %d/%d (%.0f%%)  "
              "false blackholes %d  false starved %d  IMPOSSIBLE %d  sublink-observations %d"
              % (arm, n, det, n, 100.0 * det / n, starved, n, 100.0 * starved / n,
                 fbh, fst, imp, obs))
    if broken:
        print("\n  %d trial(s) EXCLUDED for failed preconditions (not counted as misses):" % len(broken))
        for i, arm, e in broken[:10]:
            print("    trial %d %s: %s" % (i, arm, e))

    print("\n  PREREG rule 1 needs >=95%% detection on the fault arm and 0%% on control.")
    print("  PREREG rule 5 needs IMPOSSIBLE == 0.")
    print("  Default mode uses X count rows and verdict_counts(); F presence masks are kept only")
    print("  for explicit historical blackhole comparison.")
    print("  Scope: CLF localizes both directed links when tbl_eg_vlink passes exact readback.")


if __name__ == "__main__":
    main()
