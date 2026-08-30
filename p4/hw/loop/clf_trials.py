#!/usr/bin/env python3
"""Repeated CLF trials with a proper guard-interval reset, for rates rather than anecdotes.

Every CLF reading so far is n=1 and every per-trial reset used a bare zero, which the epoch-race
finding showed can leave RX marks from packets that straddled it (docs/review/artifacts/
HW-CLF-CONGESTION-RACE.md). This driver enforces the discipline the frontier design requires:

    quiesce -> zero -> quiesce -> generate -> settle -> read

so a rate measured here reflects the mechanism and not the reader.
"""
import argparse, socket, subprocess, sys, time

sys.path.insert(0, "/home/decps/mcp_ctl")  # runs ON Vision: the agent allowlist
                                            # admits 10.10.54.166 and 127.0.0.1 only
from sim.clf.verdict import verdict, Verdict

SWITCH = "10.10.54.81"
PORT = 47100


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


def probe(script):
    """Local: this driver already runs on the probe host."""
    subprocess.run(["python3", script], capture_output=True, timeout=300)


def classify(rows):
    v = {}
    for _bank, vl, tx, rx in rows:
        for ctx in range(4):
            t, r = bool(tx >> ctx & 1), bool(rx >> ctx & 1)
            if t or r:
                v[(vl, ctx)] = verdict(t, r, False)
    return v


def trial(target_sublink, guard, arm_settle=1.0):
    """One trial. target_sublink None = healthy control."""
    agent("C")                      # clear injectors
    time.sleep(guard)               # quiesce BEFORE zeroing
    agent("Z")
    time.sleep(guard)               # let in-flight packets land before we start counting
    if target_sublink is not None:
        agent("K %d" % target_sublink)
        # SETTLE AFTER ARMING. The gate write takes ~2 ms and the probe starts immediately,
        # so early packets can cross a sublink whose injector entry has not yet landed --
        # they arrive, RX is set, and the verdict reads HEALTHY on a link that is about to
        # go dark. That is a race in the HARNESS, not a missed detection, and it inflates
        # the miss count. Diagnosed from 9/100 misses all reading verdict=HEALTHY with
        # target_seen=True, i.e. packets demonstrably arrived on the blackholed sublink.
        time.sleep(arm_settle)
    probe("/tmp/ctx_pilot.py")
    time.sleep(guard)               # settle before reading
    inj = [l for l in agent("I").splitlines() if l.startswith("I ")]
    return classify(frontiers()), inj


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
    for i in range(a.trials):
        for arm, sub in (("fault", a.sublink), ("control", None)):
            v, inj = trial(sub, a.guard, a.arm_settle)
            hit = v.get(tgt) == Verdict.BLACKHOLE
            false_bh = sum(1 for k, x in v.items() if x == Verdict.BLACKHOLE and k != tgt)
            imp = sum(1 for x in v.values() if x == Verdict.IMPOSSIBLE)
            res[arm].append((hit, false_bh, imp, len(v)))
            note = ""
            if arm == "fault" and not hit:
                # A miss must be diagnosable, not averaged away. The usual cause is that the
                # probe delivered no packets of the target context in this window, so the
                # source never committed it and TX=0 -- which is IDLE, not a missed detection.
                tv = v.get(tgt)
                note = "  MISS verdict=%s injector=[%s]" % (
                    tv.value if tv else "ABSENT", " ".join(inj) or "NO-ENTRY")
            print("  trial %2d %-7s detected=%-5s false_bh=%d impossible=%d observed=%d%s"
                  % (i + 1, arm, hit, false_bh, imp, len(v), note), flush=True)
    agent("C")

    print("\n=== CLF detection rates (guard %.1fs, %d trials/arm) ===" % (a.guard, a.trials))
    for arm in ("fault", "control"):
        r = res[arm]
        n = len(r)
        det = sum(1 for x in r if x[0])
        fbh = sum(x[1] for x in r)
        imp = sum(x[2] for x in r)
        obs = sum(x[3] for x in r)
        print("  %-8s n=%d  target detected %d/%d (%.0f%%)  false blackholes %d  IMPOSSIBLE %d  "
              "sublink-observations %d" % (arm, n, det, n, 100.0 * det / n if n else 0, fbh, imp, obs))
    print("\n  PREREG rule 1 needs >=95%% detection on the fault arm and 0%% on control.")
    print("  PREREG rule 5 needs IMPOSSIBLE == 0 with a guard interval.")


if __name__ == "__main__":
    main()
