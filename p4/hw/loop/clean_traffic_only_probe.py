"""Discriminator for the wire-reduction soak anomaly (HW-LEDGER-WIRE-REDUCTION-SOAK-ANOMALY-2026-09-02.md):
does the "extra stamp, no matching arrival" pattern ever occur with ZERO live injector table
writes nearby, or only ever adjacent to an arm_injector()/clear_injector() call?

Both of the two confirmed anomalies happened immediately next to a tbl_eg_fail/tbl_eg_bern write
(arm or clear). This sends clean traffic in a tight loop with NO injector activity at all, reusing
overnight_ledger_soak.py's own helpers so the comparison is apples to apples.
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from overnight_ledger_soak import (
    CENSUS_SUBLINKS, census_after_settle, deltas_since, mismatches_vs,
    read_census, send_clean_traffic,
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cycles", type=int, default=100)
    ap.add_argument("--count-per-context", type=int, default=20)
    ap.add_argument("--pps", type=int, default=100)
    ap.add_argument("--settle-s", type=float, default=1.0)
    ap.add_argument("--recheck-s", type=float, default=2.0)
    ap.add_argument("--log", type=str,
                    default="docs/review/artifacts/P3-CLEAN-ONLY-PROBE-2026-09-02.jsonl")
    args = ap.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    baseline = read_census()
    for cycle in range(1, args.cycles + 1):
        send_clean_traffic(args.count_per_context, args.pps)
        after = census_after_settle(args.settle_s)
        first = mismatches_vs(baseline, after)
        recheck = None
        if first:
            time.sleep(args.recheck_s)
            after = read_census()
            recheck = mismatches_vs(baseline, after)
        baseline = after
        mismatches = recheck if recheck is not None else first
        record = {"cycle": cycle, "timestamp": time.time(),
                  "mismatches": mismatches, "mismatches_first_read": first if recheck is not None else None}
        with log_path.open("a") as handle:
            handle.write(json.dumps(record) + "\n")
        status = "OK" if not mismatches else "MISMATCH"
        print(f"cycle {cycle}/{args.cycles} {status} mismatches={len(mismatches)}", flush=True)
        if mismatches:
            print(f"  detail: {mismatches}", flush=True)
            print("STOPPING: first mismatch, not continuing blind", flush=True)
            return 1
    print(f"all {args.cycles} cycles clean, zero injector activity throughout", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
