# Correlated / multi-link fault stress gate — attack A4 (2026-09-03)

Reviewer attack A4 (`CONTRIBUTION-FRAMING-2026-09-02.md`), the single largest
evidence gap: *every committed head-to-head injects one independent single-link
fault (PREREG v1.9).* This artifact runs the correlated regime the venue ceiling
depends on and reports the honest verdict. **It is a gate, not a pass/fail on the
paper:** if MCP's advantage collapses under correlation, that bounds the headline
claims to the independent-fault regime (already the PREREG scope) — it is not fatal,
but we must know, and now we do.

- **Harness:** `sim/baselines/correlated.py` (generator, fabric-wide FlowPulse,
  multi-fault scorer), `sim/baselines/run_correlated_stress.py` (sweep)
- **Tests:** `sim/baselines/tests/test_correlated.py` (9 tests; the full baseline
  suite is 58 tests, all passing)
- **Raw output:** `CORRELATED-FAULT-STRESS-SWEEP-2026-09-03.json`
- **Config:** n_leaves=4, k=8, healthy floor 1e-5, 2 M packets/ordered-pair/epoch,
  10 bootstrap epochs, **40 post-onset epochs**, 50 seeds/cell, SprayCheck s=3.24.

## Regimes and fairness

The same shared-stream discipline as the single-fault head-to-heads
(`localization.py`): ONE 2-hop spray/survival draw per epoch feeds all three arms;
each arm sees only its own switch's view (MCP: per-directed-link (tx, rx);
SprayCheck-Z: RX-only per-flow arrivals + full §3.6 cross-leaf intersection;
FlowPulse-θ: per-(sender, ingress-port) RX vs a learned baseline, now applied at
**every** (spine, dst) port, not one victim port). One generator drives three
regimes by setting each directed link's loss to `faulty_rate` if faulty else a
`base_rate` background:

- **R1 multi-independent** — M∈{2,3} distinct directed links faulty, healthy
  background. Ground truth = that set. *Does the per-link advantage survive
  multiplicity?*
- **R2 common-mode shock** — every directed link elevated to a shock level, **no
  single culprit**. Ground truth = ∅; any link named is a false localization.
  *Can each arm tell a shared-cause shift from per-link faults?*
- **R3 shock + culprit** — the shock PLUS one link worse than the shifted
  background. Ground truth = that culprit. *Is a real fault still isolable against
  a correlated background?*

Two anchors are reported alongside (repo cross-check #4): **do-nothing** (never
acts: FP 0, recall 0) and **oracle** (returns exactly the true set). Both a
UNION-over-window score (ever named this link in the 40 epochs — the safety-relevant
"ever took this action") and a FINAL-epoch score (steady state) are reported, so a
transient false-positive burst is separated from a persistent latch.

Cross-checks applied before trusting any row: **injected loss verified in the data,
not the flags** (realized faulty vs background loss printed per cell — R1 0.005 vs
1e-5, R3 0.05/0.01 vs 0.005/0.001, all correct); **MCP's all-64 false-flag column
audited** (it is not a scoring artifact — MCP flags only the faulty links in R1 and
isolates the culprit's true link in R3, so its indiscriminate behavior is specific
to the shock, and it matches the independently root-caused Q1 failure documented in
`controller/decision_loop.py`).

## Findings first

Recall = fraction of true faults named; FP rate = fraction of seeds naming ≥1
non-faulty link; mean-false = mean count of non-faulty links named; UNION = ever in
window, FINAL = last epoch. n=50/cell.

### R1 — multiple simultaneous INDEPENDENT faults (healthy background)

| cell | arm | recall | exact-all | FP (union / final) | mean-false (union) |
|---|---|---|---|---|---|
| M=2, 0.5% | **MCP** | **1.00** | **1.00** | **0.00 / 0.00** | 0.00 |
| | SprayCheck-Z | 1.00 | 0.28 | 0.72 / 0.00 | 1.20 |
| | FlowPulse-θ | 0.00 | 0.00 | 0.00 / 0.00 | 0.00 |
| M=3, 0.5% | **MCP** | **1.00** | **1.00** | **0.00 / 0.00** | 0.00 |
| | SprayCheck-Z | 1.00 | 0.18 | 0.82 / 0.02 | 1.44 |
| | FlowPulse-θ | 0.00 | 0.00 | 0.02 / 0.00 | 0.02 |
| M=2, 1e-3 | **MCP** | **1.00** | **1.00** | **0.00 / 0.00** | 0.00 |
| | SprayCheck-Z | 0.75 | 0.00 | 0.98 / 0.52 | 2.54 |
| | FlowPulse-θ | 0.00 | 0.00 | 0.00 / 0.00 | 0.00 |
| M=3, 1e-3 | **MCP** | **1.00** | **1.00** | **0.00 / 0.00** | 0.00 |
| | SprayCheck-Z | 0.63 | 0.00 | 0.96 / 0.54 | 2.58 |
| | FlowPulse-θ | 0.00 | 0.00 | 0.00 / 0.00 | 0.00 |

**MCP's advantage HOLDS and widens under multiplicity.** It names every one of 2–3
simultaneous independent faults on the first post-onset epoch, with zero false
links, at both 0.5% and 1e-3 — no degradation from having several faults at once,
because its per-link (tx, rx) + e-BH FDR judges each directed link on its own
evidence. SprayCheck-Z gets *worse* with multiplicity: multiple simultaneous
failure reports create spurious §3.6 cross-leaf intersections, so it recalls the
true faults (at high loss) but adds 1.2–2.6 false links per trial (exact-all only
0.18–0.28), and at 1e-3 its recall itself falls to 0.63–0.75 with a persistent
false-link rate of ~0.5. FlowPulse-θ misses at these rates, as in the single-fault
sweep. This is a new, previously-unreported limitation of the passive localizers
that MCP does not share.

### R2 — common-mode shock, NO single culprit (ground truth = ∅)

| cell | arm | FP rate (union / final) | mean-false (union / final) | max simultaneous false |
|---|---|---|---|---|
| shock 0.5% | **MCP** | **1.00 / 1.00** | **64.0 / 64.0** | **64 (all links)** |
| | SprayCheck-Z | 0.20 / 0.02 | 0.48 / 0.04 | 2 |
| | FlowPulse-θ | 1.00 / 1.00 | 64.0 / 33.3 | 48 |
| | *do-nothing (correct)* | 0.00 | 0.00 | 0 |
| shock 0.1% | **MCP** | **1.00 / 1.00** | **64.0 / 64.0** | **64 (all links)** |
| | SprayCheck-Z | 0.28 / 0.02 | 0.68 / 0.04 | 2 |
| | FlowPulse-θ | 0.00 / 0.00 | 0.00 / 0.00 | 0 |

**MCP FAILS the common-mode gate: it false-localizes the entire fabric,
persistently.** Under a shared-cause shock with no individual culprit, MCP flags
all 64 directed links every epoch through to the end of the window — worse than a
do-nothing detector, and exactly the CRITICAL already root-caused in
`controller/decision_loop.py`: the leave-one-out floor lags a fleet-wide shift, so
each link's ratio-relative e-process reads the shifted-but-not-faulty rate as strong
evidence, e-BH rejects nearly every link, rejected links drop out of the healthy
pool, and the fleet latches at `w_min`. This is an independently predicted,
mechanistically understood failure, not a harness surprise.

**SprayCheck-Z is the robust arm here** (FP 0.02 at steady state): its per-flow
Z-test normalizes by that flow's own observed N, which drops with the shock, so a
uniform shift self-cancels. FlowPulse-θ fails when the shock's 2-hop arrival deficit
exceeds its fixed 1% threshold (0.5% shock → ~1% deficit → flags ~all ports) and is
merely blind, not robust, when it falls below (0.1% shock → ~0.2% deficit → fires on
nothing).

### R3 — one culprit embedded in a common-mode shock (ground truth = 1 link)

| cell | arm | recall (culprit) | exact-all | FP rate (union / final) | mean-false (union) |
|---|---|---|---|---|---|
| shock 0.1%, culprit 1% | MCP | 1.00 | 0.00 | 1.00 / 1.00 | 63.0 |
| | **SprayCheck-Z** | **1.00** | **0.86** | **0.14 / 0.00** | 0.22 |
| | FlowPulse-θ | 1.00 | 0.00 | 1.00 / 0.50 | 3.0 |
| shock 0.5%, culprit 5% | MCP | 1.00 | 0.00 | 1.00 / 1.00 | 63.0 |
| | **SprayCheck-Z** | **1.00** | **0.98** | **0.02 / 0.00** | 0.02 |
| | FlowPulse-θ | 1.00 | 0.00 | 1.00 / 1.00 | 33.9 |

**Under a shock + culprit, MCP's localization advantage INVERTS.** MCP does find the
culprit (recall 1.00, first epoch), but it drowns it in all 63 other links
(exact-all 0.00) — operationally useless, since "all 64 links are faulty" is not an
actionable localization. **SprayCheck-Z isolates the culprit cleanly against the
shifted background** (exact-all 0.86–0.98, FP ≤0.14 and 0.00 at steady state),
precisely because its relative normalization cancels the shock. The exact
directed-link localization that is MCP's headline advantage in the independent
regime becomes SprayCheck's advantage once a correlated background is present.

## Verdict

**Holds for independent multiplicity; fails for common-mode correlation. Scope the
paper's headline claims to the independent-fault regime (= PREREG v1.9).**

1. **HOLDS (and widens):** MCP's detection + exact single-directed-link
   localization survives *multiple simultaneous independent* faults intact
   (recall 1.00, exact-all 1.00, FP 0.00, M up to 3, down to 1e-3), while the
   passive localizers degrade further (SprayCheck adds spurious intersections;
   FlowPulse misses). The independent-fault story is stronger than a single fault,
   not merely as strong.
2. **FAILS (common-mode):** under a shared-cause shock with no culprit, MCP
   false-localizes the whole fabric and stays latched — worse than do-nothing —
   because its leave-one-out floor cannot distinguish a fleet-wide shift from 64
   per-link faults. This is the root-caused `decision_loop.py` Q1 defect, now
   measured head-to-head. SprayCheck-Z's relative test is robust here.
3. **INVERTS (shock + culprit):** MCP still detects a real culprit but cannot
   isolate it (63 false links); SprayCheck-Z isolates it cleanly. MCP's
   localization advantage is specific to a stationary, uncorrelated background.

**Consequence for the paper.** This does not sink the measurement paper — it draws
its boundary, and the boundary is exactly the pre-registered one. The honest claim
is: *on a stationary fabric with independent per-directed-link faults (one or
several at once), the in-fabric witness gives flat-cost detection and exact
directed-link localization the passive baselines cannot match; under correlated
common-mode load its absolute-floor test is not robust, and a relative passive test
(SprayCheck-Z) is the better tool there.* Reporting the common-mode failure — and
that a baseline beats MCP in it — is the fair framing A4 demands and materially
raises the paper's credibility (cross-check #4: an FP number reported next to the
action rate). It does **not**, on its own, lift the ToN/IMC ceiling; robust
common-mode handling (a floor-staleness guard / Q4 corroboration gate,
`decision_loop.py`) would be new design work and its own result.

## Threats to validity

- **The common-mode shock is uniform across all links.** A partial correlated
  shock (a subset of links, a shared spine) is untested; it would sit between R1 and
  R2. The uniform case is the cleanest stress and the one MCP's own root-cause
  analysis predicts it fails, so it is the right gate, but "degrades-to-failure" is
  demonstrated for the uniform shock specifically.
- **MCP's controller (`decision_loop.py`) is the wiring, not the frozen
  `infer.py`.** No frozen code was edited; the failure reproduces the module's own
  documented CRITICAL on fresh seeds, corroborating it rather than discovering it.
- **n_leaves=4, k=8, 40-epoch window.** MCP's common-mode latch is persistent within
  40 epochs (FINAL FP = 1.00); a longer window would not clear it (the pool stays
  collapsed). SprayCheck's robustness and FlowPulse's threshold-crossing behavior are
  topology-robust in direction; exact FP counts are fabric-specific.
- **UNION-over-window counts a transient false action as a false positive.** This is
  the strict, safety-relevant reading; the FINAL column is reported beside it so the
  reader sees MCP's common-mode FP is persistent (not transient) and SprayCheck's
  R1 false links are largely transient.

## Reproduce

```bash
python3 -m pytest sim/baselines/tests -q              # 58 tests incl. 9 correlated
python3 -m sim.baselines.run_correlated_stress        # ~5 min; writes the JSON above
```
