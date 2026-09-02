"""Head-to-head sweep: MCP's own mechanism vs faithful SprayCheck-Z and
FlowPulse-theta replay arms, on identical simulated traffic (see
`comparison.py` for the fairness argument and exact scenario). Writes a JSON
report and prints a summary table.

Run from the repo root: `python3 -m sim.baselines.run_comparison_sweep`
"""
import json

from sim.baselines.comparison import SprayCheckDetectorCalibration, sweep, summarize

OUTPUT_PATH = "docs/review/artifacts/BASELINE-COMPARISON-SWEEP-2026-09-02.json"


def main() -> None:
    s = SprayCheckDetectorCalibration.get(2_500_000)
    print("calibrated s =", s, flush=True)

    loss_rates = [0.015, 0.01, 0.005, 1e-3, 1e-4]
    # packets_per_epoch = 2,000,000 (250,000/spine at k=8): an earlier choice
    # of 200,000 made a single epoch's own i.i.d.-spraying sampling noise
    # (relative std ~0.6%) close enough to FlowPulse's fixed 1% threshold
    # that a healthy spine crossed it ~7-13% of the time from pure noise,
    # independent of any real fault -- confirmed by isolating the
    # single-spine, single-epoch FPR against an exact (non-estimated)
    # baseline swept over scale; verified FPR -> 0.0000 at 2,000,000,
    # matching the paper's own <1% claim. This combination (FlowPulse's
    # LearnedLoadModel's own bootstrap-estimation noise, not just the
    # detector's threshold logic against a known-exact baseline) was never
    # exercised by the original per-module fidelity check in
    # `tests/test_flowpulse_theta.py` -- disclosed here, not silently fixed
    # without a trace.
    results = sweep(loss_rates, k=8, healthy_rate=1e-5, packets_per_epoch=2_000_000,
                    bootstrap_epochs=10, max_post_onset_epochs=80, trials=50,
                    spraycheck_calibration_lam=2_500_000)

    report = {}
    for p, trial_results in results.items():
        report[p] = {
            "mcp": summarize(trial_results, "mcp_epoch"),
            "spraycheck": summarize(trial_results, "spraycheck_epoch"),
            "flowpulse": summarize(trial_results, "flowpulse_epoch"),
            "mcp_packets": summarize(trial_results, "mcp_packets"),
            "spraycheck_packets": summarize(trial_results, "spraycheck_packets"),
            "flowpulse_packets": summarize(trial_results, "flowpulse_packets"),
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

    with open(OUTPUT_PATH, "w") as f:
        json.dump({str(k): v for k, v in report.items()}, f, indent=2)
    print(f"done -> {OUTPUT_PATH}", flush=True)


if __name__ == "__main__":
    main()
