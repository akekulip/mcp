"""Floor sweep: where does the ledger's own detection wall sit, and does it
track the background loss rate f?

The proposition in the paper: a count-deficit (passive) test needs
lambda > s^2 / p^2 packets per spine to separate a loss fraction p from spray
noise; the witness, which counts drops directly against a background floor f,
needs about lambda > s^2 f / p^2 in the Gaussian regime (and ~ 1/(p log(p/f))
when floor drops per epoch are few). Both fall as 1/p^2; the witness divides
the constant by f. Its wall therefore sits at p of order a few times f, not
at a fixed p. This sweep runs the ledger arm alone over p in a grid scaled by
f, for three floors, and reports the action rate per cell.

Run from the repo root: `python3 -m sim.baselines.run_floor_sweep`
"""
import json

from sim.baselines.comparison import SprayCheckDetectorCalibration, run_one_trial, summarize

OUTPUT_PATH = "docs/review/artifacts/FLOOR-SWEEP-2026-09-03.json"
FLOORS = (1e-6, 1e-5, 1e-4)
MULTIPLES = (1.0, 2.0, 5.0, 10.0, 50.0)
TRIALS = 50


def main() -> None:
    s = SprayCheckDetectorCalibration.get(2_500_000)
    report = {}
    for f in FLOORS:
        report[str(f)] = {}
        for m in MULTIPLES:
            p = f * m
            if p >= 0.02:
                continue
            trials = [run_one_trial(8, p, f, 2_000_000, 10, 80, seed, s)
                      for seed in range(TRIALS)]
            cell = {"p": p, "floor": f, "multiple": m,
                    "mcp": summarize(trials, "mcp_epoch"),
                    "mcp_packets": summarize(trials, "mcp_packets"),
                    "spraycheck": summarize(trials, "spraycheck_epoch")}
            report[str(f)][str(m)] = cell
            print(f"floor={f:g} p={p:g} (x{m:g}): ledger action={cell['mcp']['action_rate']:.2f} "
                  f"fpr={cell['mcp']['false_positive_rate']:.2f} median_epoch={cell['mcp']['median']} "
                  f"| spraycheck action={cell['spraycheck']['action_rate']:.2f}", flush=True)
    with open(OUTPUT_PATH, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"done -> {OUTPUT_PATH}", flush=True)


if __name__ == "__main__":
    main()
