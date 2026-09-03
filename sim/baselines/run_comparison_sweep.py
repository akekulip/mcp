"""Head-to-head sweep: the ledger's own mechanism vs faithful SprayCheck-Z and
FlowPulse-theta replay arms, plus the zero-byte CounterPair-0B arm at several
controller read-skew levels, on identical simulated traffic (see
`comparison.py` for the fairness argument, the exact scenario, and the
read-skew model). Writes a JSON report and prints a summary table.

Packets-to-detect is counted from the fault's ONSET (post-onset origin). The
2026-09-02 sweep folded the 10 clean warm-up epochs (20 M packets) into every
cost; it is kept for provenance and superseded by this output.

Run from the repo root: `python3 -m sim.baselines.run_comparison_sweep`
"""
import json

from sim.baselines.comparison import (
    SprayCheckDetectorCalibration, summarize, summarize_counterpair, sweep,
)

OUTPUT_PATH = "docs/review/artifacts/BASELINE-COMPARISON-SWEEP-2026-09-03.json"

# Loss rates: the original five, then three below the sweep's former floor to
# locate the ledger's own wall against the 1e-5 background (a referee's
# request: locate the boundary rather than stop short of it).
LOSS_RATES = [0.015, 0.01, 0.005, 1e-3, 1e-4, 5e-5, 2e-5, 1e-5]

# CounterPair-0B read skew as a fraction of the epoch. 0 = idealized (same
# information as the witness, read at one instant). 2.6e-2 = the best case
# measured on the Tofino (2.6 ms per-sublink pairwise read against a 100 ms
# epoch, READ-LOOP-BENCH-2026-09-03.md); the measured full-fabric census is
# 350 ms, i.e. 3.5 epochs, which no epoch of 100 ms can absorb at all.
COUNTERPAIR_SKEWS = (0.0, 1e-4, 1e-3, 1e-2, 2.6e-2, 1e-1)


def main() -> None:
    s = SprayCheckDetectorCalibration.get(2_500_000)
    print("calibrated s =", s, flush=True)

    # packets_per_epoch = 2,000,000 (250,000/spine at k=8): an earlier choice
    # of 200,000 made a single epoch's own i.i.d.-spraying sampling noise
    # (relative std ~0.6%) close enough to FlowPulse's fixed 1% threshold
    # that a healthy spine crossed it ~7-13% of the time from pure noise,
    # independent of any real fault -- confirmed by isolating the
    # single-spine, single-epoch FPR against an exact (non-estimated)
    # baseline swept over scale; verified FPR -> 0.0000 at 2,000,000,
    # matching the paper's own <1% claim. Disclosed here, not silently fixed.
    results = sweep(LOSS_RATES, k=8, healthy_rate=1e-5, packets_per_epoch=2_000_000,
                    bootstrap_epochs=10, max_post_onset_epochs=80, trials=50,
                    spraycheck_calibration_lam=2_500_000,
                    counterpair_skews=COUNTERPAIR_SKEWS)

    report = {}
    for p, trial_results in results.items():
        report[p] = {
            "mcp": summarize(trial_results, "mcp_epoch"),
            "spraycheck": summarize(trial_results, "spraycheck_epoch"),
            "flowpulse": summarize(trial_results, "flowpulse_epoch"),
            "mcp_packets": summarize(trial_results, "mcp_packets"),
            "spraycheck_packets": summarize(trial_results, "spraycheck_packets"),
            "flowpulse_packets": summarize(trial_results, "flowpulse_packets"),
            "counterpair": {str(sk): {
                "epoch": summarize_counterpair(trial_results, sk, "epoch"),
                "packets": summarize_counterpair(trial_results, sk, "packets"),
            } for sk in COUNTERPAIR_SKEWS},
            "packets_origin": "post_onset",
        }
        print(f"p={p}:", flush=True)
        for method in ("mcp", "spraycheck", "flowpulse"):
            r = report[p][method]
            pk = report[p][method + "_packets"]
            ci_lo, ci_hi = r["action_rate_ci95"]
            print(f"  {method}: action_rate={r['action_rate']:.2f} "
                  f"(95% CI [{ci_lo:.2f}, {ci_hi:.2f}], n={r['n']}) "
                  f"median_epoch={r['median']} "
                  f"median_packets={pk['median']} iqr_packets={pk['iqr']} "
                  f"fpr={r['false_positive_rate']:.2f}", flush=True)
        for sk in COUNTERPAIR_SKEWS:
            r = report[p]["counterpair"][str(sk)]["epoch"]
            pk = report[p]["counterpair"][str(sk)]["packets"]
            print(f"  counterpair skew={sk:g}: action_rate={r['action_rate']:.2f} "
                  f"median_packets={pk['median']} fpr={r['false_positive_rate']:.2f}",
                  flush=True)

    with open(OUTPUT_PATH, "w") as f:
        json.dump({str(k): v for k, v in report.items()}, f, indent=2)
    print(f"done -> {OUTPUT_PATH}", flush=True)


if __name__ == "__main__":
    main()
