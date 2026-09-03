# Packets-to-detect scaling curve — closing attack A3 (2026-09-03)

Reviewer attack A3 (`CONTRIBUTION-FRAMING-2026-09-02.md`): *"Why not run SprayCheck
longer / size it bigger?"* — the strongest technical attack on the detection
result. The answer the memo asks to make airtight is a **cost-scaling** statement,
not a capability one: passive-inference cost scales with 1/loss-rate while the
in-fabric witness's does not. This artifact turns the frozen 50-seed sweep into
that curve and the paper's headline technical figure.

- **Figure (paper-ready, IEEE single-column):** `figures/scaling_curve.pdf` /
  `figures/scaling_curve.png`
- **Figure source:** `figures/scaling_curve.py` (reads the sweep JSON; no re-run)
- **Plotted numbers:** `figures/scaling_curve_data.csv`
- **Raw sweep (reused, not re-run):** `BASELINE-COMPARISON-SWEEP-2026-09-02.json`
  (50 seeds/rate, Wilson 95% CI on action rate, IQR on packets-to-detect)

## Findings first

Median packets-to-detect (fleet total, k=8 spines) and action rate (fraction of
50 seeds detecting the true faulty spine within the 160 M-packet budget):

| loss rate p | MCP median / action | SprayCheck-Z median / action | FlowPulse-θ median / action |
|---|---|---|---|
| 1.5%  | 22.0 M / **1.00** | 24.0 M / 1.00 | 22.0 M / 1.00 |
| 1.0%  | 22.0 M / **1.00** | 26.0 M / 1.00 | 22.0 M / 1.00 |
| 0.5%  | 22.0 M / **1.00** | 32.0 M / 1.00 | 88.0 M / **0.38** |
| 1e-3  | 22.0 M / **1.00** | 114.0 M / **0.78** | — / **0.00** |
| 1e-4  | 22.0 M / **1.00** | — / **0.00** | — / **0.00** |

FP = 0.00 for all three arms at every rate (confirmed in the sweep, not assumed).

1. **MCP is Θ(1) in loss rate.** Median packets-to-detect is flat at 22.0 M
   (IQR 22–24 M) across four orders of magnitude, action rate 1.00 throughout.
   MCP detects on the **first post-onset epoch** at every rate (median epoch 10,
   onset at epoch 10): its per-link witness observes each directed link's own
   (tx, rx), so the quantity it tests is a **loss ratio relative to the fleet
   floor**, and a fault at p ≫ floor (1e-5) clears the ratio-grid alternative in
   one epoch's worth of that link's traffic regardless of the absolute p. Cost is
   set by per-epoch volume, not by p.

2. **The passive arms' cost grows as the fault gets rarer, and their action rate
   collapses.** SprayCheck-Z's median rises 24 M → 26 M → 32 M → 114 M as p falls
   1.5% → 1e-3, and its action rate collapses 100% → 78% → 0%. FlowPulse-θ fails a
   full order earlier (partial at 0.5%, gone by 1e-3). This is the mechanism a Z-test
   on arrival counts cannot escape: to separate a p-fraction arrival deficit from
   i.i.d.-spray sampling noise, the per-spine count must satisfy λ·p > s·√λ, i.e.
   λ > s²/p² — **packets-to-detect grows at least like 1/p** (the Z-test SNR
   argument gives 1/p²). MCP's does not grow at all.

3. **This is a scaling law, not a budget artifact.** The separation is visible
   *within* the fixed budget: at 1e-3 SprayCheck already needs a median 114 M
   packets (5× MCP) to catch the 78% it catches at all; the 22% it misses and the
   entire 1e-4 column are the same 1/p² wall pushing the requirement past 160 M.

## Honest framing (the claim A3 lets us make, and only that)

- **Cost, not capability.** A passive detector sized for an *unbounded* budget
  could eventually detect at 1e-4 — nothing here says it cannot. The claim is that
  its **cost scales with 1/loss-rate while the witness's is constant**, and that
  within any fixed operational budget the passive action rate therefore collapses
  as faults get rarer. The figure states the budget (160 M packets = 80 epochs)
  explicitly as a dotted ceiling and marks every non-detection as an X on it, not
  as a missing point.
- **The conditional median is survivorship-biased, and the figure says so.** For
  SprayCheck at 1e-3 the 114 M median is over the **78% that detected**; the 22%
  that never did are not in it. That is why every reduced-action point is drawn as
  a hollow marker annotated with its detection rate — the action-rate collapse
  (100→78→0), not the exact slope of a censored median, is the load-bearing signal.
- **The headline is the flat-vs-growing separation**, per the memo's instruction
  to lead with detection cost-scaling and not the definitional localization 1.00.

## Threats to validity

- **k=8, i.i.d.-uniform spray, one independent spine fault.** Matches SprayCheck's
  own Table 1 topology and the PREREG v1.9 scope. The 1/p² SNR wall is a property
  of any count-deficit test and is topology-robust in direction; the exact crossover
  rate is not a universal constant. The correlated / common-mode regime is the
  separate A4 gate (`CORRELATED-FAULT-STRESS-2026-09-03.md`).
- **SprayCheck's `s` is calibrated under the paper's own i.i.d. Poisson model**,
  which its real JSQ(2) spraying beats; a JSQ-tuned `s` would shift its curve down
  by a constant factor but not change the 1/p² slope. Disclosed in `spraycheck_z.py`.
- **Budget = 80 post-onset epochs (160 M packets).** A larger budget moves the
  passive action-rate floor rightward (rarer p still detectable) but cannot flatten
  the curve; MCP's flat line is budget-independent.

## Reproduce

```bash
python3 -m pytest sim/baselines/tests -q                      # harness fidelity
$RESEARCH_PYTHON docs/review/artifacts/figures/scaling_curve.py  # rebuild figure + CSV
# (raw sweep, only if regenerating from scratch — data already in hand:)
python3 -m sim.baselines.run_comparison_sweep
```
