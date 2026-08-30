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

Coverage: CLF currently observes the FIRST directed link (source leaf -> spine).  The spine's
egress commits no TX because the destination leaf records no arrival -- csig is removed at
LAST_HOP -- and committing a link whose arrivals cannot be seen would report a permanent
blackhole.  A verdict here is a statement about link 1, not about the whole path.
"""
import argparse, socket, subprocess, sys, time

sys.path.insert(0, "/home/decps/mcp_ctl")  # runs ON Vision: the agent allowlist
                                            # admits 10.10.54.166 and 127.0.0.1 only
from sim.clf.verdict import verdict, Verdict

SWITCH = "10.10.54.81"
PORT = 47100


class HarnessError(RuntimeError):
    """A trial whose own preconditions failed. Never averaged into a rate."""


def agent(cmd, timeout=25):
    s = socket.create_connection((SWITCH, PORT), timeout)
    s.settimeout(timeout)
    try:
        s.sendall((cmd + "\n").encode())
        buf = b""
        while b"OK " not in buf and b"ERR" not in buf and b"BLACKHOLED" not in buf:
            c = s.recv(65536)
            if not c:
                break
            buf += c
        return buf.decode(errors="replace")
    finally:
        s.close()


def frontiers():
    out = []
    for line in agent("F").splitlines():
        f = line.split()
        if len(f) == 6 and f[0] == "F":
            out.append((int(f[1]), int(f[2]), int(f[3], 16), int(f[4], 16)))
    return out


def injector_rows():
    return [l.strip() for l in agent("I").splitlines() if l.startswith("I ")]


def injector_drops():
    """Total packets the post-TM fault injector actually discarded."""
    n = 0
    for row in injector_rows():
        f = row.split()
        if len(f) >= 5:
            n += int(f[4])
    return n


def probe(script):
    """Local: this driver already runs on the probe host. Failure is raised, never swallowed."""
    r = subprocess.run(["python3", script], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise HarnessError("probe exited %d: %s" % (r.returncode, (r.stderr or "").strip()[:200]))
    sent = 0
    for tok in (r.stdout or "").split():
        if tok.isdigit():
            sent = int(tok)
            break
    if sent == 0:
        raise HarnessError("probe reported no packets sent: %r" % (r.stdout or "")[:200])
    return sent


def classify(rows):
    """Frozen-bank rows -> per-sublink verdicts.

    gap_seen is False for every sublink: the frontier registers carry presence bits, not
    sequence continuity, so this driver cannot distinguish HEALTHY from PARTIAL_LOSS. It
    decides blackhole vs not-blackhole, which is what the CLF rules are about. Partial loss
    is C-W4's job and is measured separately.
    """
    v = {}
    for _bank, vl, tx, rx in rows:
        for ctx in range(4):
            t, r = bool(tx >> ctx & 1), bool(rx >> ctx & 1)
            if t or r:
                v[(vl, ctx)] = verdict(t, r, False)
    return v


def trial(target_sublink, guard, arm_settle=1.0, bank=0):
    """One trial: quiesce -> arm -> zero -> verify -> probe -> freeze -> guard -> read.

    Raises HarnessError if any precondition fails, so a broken trial is reported and excluded
    rather than being averaged in as a miss.
    """
    agent("C")                                  # clear injectors
    agent("N %d" % bank)                        # make B the active bank
    time.sleep(guard)                           # quiesce: prior in-flight lands

    # ARM BEFORE ZEROING.  The reverse order leaves the target sublink live between the reset
    # and the arm, and a single stray background packet arriving in that window sets RX=1 --
    # which masks the blackhole exactly the way stale residue did, reporting HEALTHY for a
    # sublink that is dark.  Observed directly: a fault trial with 401 packets dropped read
    # HEALTHY.  Arming first means nothing can mark RX for the target after the zero.
    if target_sublink is not None:
        reply = agent("K %d" % target_sublink)
        if "BLACKHOLED" not in reply:
            raise HarnessError("arm refused: %r" % reply.strip()[:120])
        time.sleep(arm_settle)

    agent("Z")                                  # zero the frontiers; safe only while quiet
    time.sleep(0.3)
    residue = frontiers()
    if residue:
        raise HarnessError("zero did not take, %d rows remain: %s" % (len(residue), residue[:3]))

    sent = probe("/tmp/probe_spray0.py")        # marks bank B; raises if it did not run

    agent("N %d" % (1 - bank))                  # freeze B by flipping away
    time.sleep(guard)                           # in-flight B packets land in B, then quiet
    drops = injector_drops()
    rows = [r for r in frontiers() if r[0] == bank]   # read ONLY the frozen bank
    return classify(rows), sent, drops


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--guard", type=float, default=2.0)
    ap.add_argument("--arm-settle", type=float, default=1.0,
                    help="pause after arming before probing; 0 reproduces the race")
    ap.add_argument("--sublink", type=int, default=2, help="vlink 0, ctx 2")
    a = ap.parse_args()
    tgt = (a.sublink >> 4, a.sublink & 0xF)

    res = {"fault": [], "control": []}
    broken = []
    for i in range(a.trials):
        for arm, sub in (("fault", a.sublink), ("control", None)):
            try:
                v, sent, drops = trial(sub, a.guard, a.arm_settle, bank=i % 2)
            except HarnessError as e:
                broken.append((i + 1, arm, str(e)))
                print("  trial %2d %-7s HARNESS-ERROR %s" % (i + 1, arm, e), flush=True)
                continue
            hit = v.get(tgt) == Verdict.BLACKHOLE
            false_bh = sum(1 for k, x in v.items() if x == Verdict.BLACKHOLE and k != tgt)
            imp = sum(1 for x in v.values() if x == Verdict.IMPOSSIBLE)
            res[arm].append((hit, false_bh, imp, len(v)))
            note = ""
            if arm == "fault" and not hit:
                tv = v.get(tgt)
                note = "  MISS verdict=%s" % (tv.value if tv else "ABSENT")
            print("  trial %2d %-7s detected=%-5s false_bh=%d impossible=%d observed=%d "
                  "sent=%d dropped=%d%s"
                  % (i + 1, arm, hit, false_bh, imp, len(v), sent, drops, note), flush=True)
    agent("C")

    print("\n=== CLF detection rates (guard %.1fs, %d trials/arm requested) ===" % (a.guard, a.trials))
    for arm in ("fault", "control"):
        r = res[arm]
        n = len(r)
        if not n:
            print("  %-8s n=0 -- every trial failed its preconditions; no rate reported" % arm)
            continue
        det = sum(1 for x in r if x[0])
        fbh = sum(x[1] for x in r)
        imp = sum(x[2] for x in r)
        obs = sum(x[3] for x in r)
        print("  %-8s n=%d  target detected %d/%d (%.0f%%)  false blackholes %d  IMPOSSIBLE %d  "
              "sublink-observations %d" % (arm, n, det, n, 100.0 * det / n, fbh, imp, obs))
    if broken:
        print("\n  %d trial(s) EXCLUDED for failed preconditions (not counted as misses):" % len(broken))
        for i, arm, e in broken[:10]:
            print("    trial %d %s: %s" % (i, arm, e))

    print("\n  PREREG rule 1 needs >=95%% detection on the fault arm and 0%% on control.")
    print("  PREREG rule 5 needs IMPOSSIBLE == 0.")
    print("  Scope: these verdicts are about the first directed link (source leaf -> spine).")


if __name__ == "__main__":
    main()
