"""Directly tests the idle-then-first-burst hypothesis from
HW-LEDGER-WIRE-REDUCTION-SOAK-ANOMALY-2026-09-02.md: all three confirmed anomalies so far were the
first traffic burst after a gap (fresh bring-up, or several idle minutes), with one exception.

Sends a burst with NO preceding idle (control condition), then a deliberate idle gap, then another
burst (test condition -- itself now "first after idle"), and reports whether the anomaly rate
differs between the two conditions. Not a statistical proof on n=1 either way, but directly
informative: reproducing it after idle and not before is exactly what the hypothesis predicts.
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from overnight_ledger_soak import census_after_settle, deltas_since, mismatches_vs, read_census, send_clean_traffic


def burst(label, baseline, count_per_context, pps, settle_s, recheck_s):
    send_clean_traffic(count_per_context, pps)
    after = census_after_settle(settle_s)
    first = mismatches_vs(baseline, after)
    recheck = None
    if first:
        time.sleep(recheck_s)
        after = read_census()
        recheck = mismatches_vs(baseline, after)
    mismatches = recheck if recheck is not None else first
    print(f"{label}: mismatches={mismatches}", flush=True)
    return after, mismatches


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--count-per-context", type=int, default=20)
    ap.add_argument("--pps", type=int, default=100)
    ap.add_argument("--settle-s", type=float, default=1.0)
    ap.add_argument("--recheck-s", type=float, default=2.0)
    ap.add_argument("--idle-s", type=float, default=90.0)
    ap.add_argument("--trials", type=int, default=3)
    ap.add_argument("--log", type=str, default="docs/review/artifacts/P3-IDLE-GAP-PROBE-2026-09-02.jsonl")
    args = ap.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    control_mismatches = 0
    test_mismatches = 0
    baseline = read_census()

    for trial in range(1, args.trials + 1):
        print(f"--- trial {trial}/{args.trials} ---", flush=True)
        baseline, m_control = burst(f"trial{trial} CONTROL (no preceding idle)", baseline,
                                    args.count_per_context, args.pps, args.settle_s, args.recheck_s)
        if m_control:
            control_mismatches += 1

        print(f"idling {args.idle_s}s with zero traffic...", flush=True)
        time.sleep(args.idle_s)

        baseline, m_test = burst(f"trial{trial} TEST (first burst after {args.idle_s}s idle)", baseline,
                                 args.count_per_context, args.pps, args.settle_s, args.recheck_s)
        if m_test:
            test_mismatches += 1

        with log_path.open("a") as handle:
            handle.write(json.dumps({"trial": trial, "timestamp": time.time(),
                                     "control_mismatches": m_control,
                                     "test_mismatches": m_test}) + "\n")

    print(f"\nSUMMARY: control (no idle) mismatches: {control_mismatches}/{args.trials}; "
          f"test (after {args.idle_s}s idle) mismatches: {test_mismatches}/{args.trials}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
