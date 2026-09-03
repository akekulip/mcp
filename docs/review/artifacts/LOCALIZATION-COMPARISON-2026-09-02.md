# Localization-accuracy head-to-head: MCP vs SprayCheck-Z and FlowPulse-theta (2026-09-02)

Companion to the detection head-to-head (`BASELINE-COMPARISON-2026-09-02.md`). Detection answers
"is something wrong?"; this answers "which exact directed link?" -- the question a repair action
actually needs, and the one both baseline papers state a single RX-only vantage cannot answer.
Code: `sim/baselines/localization.py` (mechanisms + scoring), `sim/baselines/run_localization_sweep.py`
(this sweep), tests `sim/baselines/tests/test_localization.py`, raw output
`docs/review/artifacts/LOCALIZATION-COMPARISON-SWEEP-2026-09-02.json`. 50 seeds per (fault family,
loss rate), Wilson 95% CIs on every rate, percentile-bootstrap 95% CIs on mean ambiguous-set size,
and paired exact McNemar tests (all three arms score the SAME per-seed stream).

## The claim under test

MCP localizes to exactly one directed link where the passive baselines degrade to an ambiguous set.
The result below supports that claim **in the low-loss and uplink regimes**, and reports an **honest
null at high loss for SprayCheck** (it ties MCP there). It is not manufactured: the baselines are
given their FULL, paper-faithful localizers and a budget that is generous to them, and where they
succeed it is reported as plainly as where they fail.

## Why a single RX-only vantage is ambiguous (both papers' own words, verified this session)

A packet from leaf L_a to leaf L_b via spine S_i crosses TWO directed links: the uplink L_a->S_i and
the downlink S_i->L_b. Any arrival deficit at L_b is the PRODUCT of the two hops' survival; an RX-only
counter aliases them.

- **SprayCheck** (arXiv:2605.03702 v1, §3.6): a failure report "flags the entire path ... This path
  consists of two links: the uplink from the source leaf to the spine (link 1), and the downlink from
  the spine to the destination leaf (link 2)"; a single link is named only by cross-leaf intersection:
  "a link is considered failed when it is in the intersection of multiple failure reports that include
  a different leaf switch."
- **FlowPulse** (HotNets'25, §5.3, verbatim): "Reduced traffic at a given ingress port can indicate
  either a fault on the local link ... or a fault on a remote link ... If traffic from all senders is
  equally affected, the local link is marked as failed. However, if only one sender is affected, the
  link between the spine switch and the leaf switch of the sender is marked as failed." It needs >=2
  senders on the port (one as a clean control).
- **MCP** carries a per-hop witness stamp, so its receiver ledger holds each directed link's OWN
  (tx, rx) and factors the product from a single vantage, with no cross-referencing.

## Fairness of the harness

One shared per-(source, dest, spine) spray/survival draw feeds all three arms every epoch -- the same
i.i.d.-uniform-spray + independent-per-hop-survival model as the detection harness, extended to a
2-hop fabric (`sim/baselines/localization.py:simulate_epoch`). Topology: a full mesh of n_leaves=4
leaves and k=8 spines; exactly one directed link is degraded, all others healthy (1e-5). Each arm is
given ONLY what its own switch sees, and its STRONGEST honest localizer:

- **MCP**: per-directed-link (tx, rx) from its ledger; its own frozen decision loop (`make_mcp_loop`,
  unchanged) run over all 64 directed links; localized set = the links e-BH rejects.
- **SprayCheck-Z**: per-flow per-spine RX arrival counts, accumulated across epochs exactly as the
  detection harness accumulates them (RX-only cumulative N), PLUS its full §3.6 cross-leaf
  intersection over a completed round-robin cycle of measured flows. Never TX.
- **FlowPulse-theta**: per-(sender, spine-port) RX volumes and its full §5.3 per-sender rule,
  predicted from a bootstrapped `LearnedLoadModel`. Never TX. Per-sender visibility is GIVEN to it
  (its own paper assumes it) -- this is the charitable, not the weakened, reading.

Two fault families, run separately -- the two cases the papers' own rules distinguish:
- **down**: faulty link = S_0->L_0 (a downlink). All sources to L_0 via S_0 are equally affected.
- **up**: faulty link = L_1->S_0 (an uplink). Only source L_1's traffic via S_0 is affected.

**Budget disclosure (generous to the baselines).** Each trial runs up to 60 post-onset epochs of
2,000,000 packets per ordered pair. That is a far larger accumulation than the detection sweep's
budget, deliberately: it gives SprayCheck the fullest chance to complete a corroborating round-robin
cycle and FlowPulse the fullest chance to clear its threshold. This is why SprayCheck's raw detection
reach here extends below where the detection sweep (a tighter budget) placed its action-rate floor --
the two sweeps ask different questions. Even with this generous budget the baselines degrade as shown.

## Results -- fault family "down" (a downlink fault, S_0->L_0)

Exact = named the true directed link and only it. Ambiguous/wrong = detected but the returned set
contains a non-faulty link (an ambiguous set that would misdirect a repair). Miss = no localization.
Mean set size counts only detections. Paired diff = MCP exact-rate minus the baseline's, same seeds.

| loss | arm | exact (95% CI) | ambig/wrong | miss | mean set size (95% CI) |
|---|---|---|---|---|---|
| 1.5% | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1.5% | SprayCheck-Z | 1.00 [0.93,1.00] | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1.5% | FlowPulse-theta | 0.94 [0.84,0.98] | 0.06 | 0.00 | 1.18 [1.00,1.42] |
| 1.0% | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1.0% | SprayCheck-Z | 0.96 [0.87,0.99] | 0.04 | 0.00 | 1.04 [1.00,1.10] |
| 1.0% | FlowPulse-theta | 0.22 [0.13,0.35] | 0.78 | 0.00 | 2.74 [2.32,3.16] |
| 0.5% | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 0.5% | SprayCheck-Z | 0.34 [0.22,0.48] | 0.66 | 0.00 | 1.70 [1.54,1.86] |
| 0.5% | FlowPulse-theta | 0.00 [0.00,0.07] | 0.00 | 1.00 | -- |
| 1e-3 | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1e-3 | SprayCheck-Z | 0.00 [0.00,0.07] | 1.00 | 0.00 | 2.00 [2.00,2.00] |
| 1e-3 | FlowPulse-theta | 0.00 [0.00,0.07] | 0.00 | 1.00 | -- |
| 1e-4 | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1e-4 | SprayCheck-Z | 0.00 [0.00,0.07] | 0.26 | 0.74 | 2.00 [2.00,2.00] |
| 1e-4 | FlowPulse-theta | 0.00 [0.00,0.07] | 0.00 | 1.00 | -- |

Paired exact McNemar, MCP vs each baseline (exact-rate difference, exact two-sided p, discordant n):
1.5% SC +0.00 (p=1.0, 0); 1.0% SC +0.04 (p=0.50, 2), FP +0.78 (p=3.6e-12, 39); 0.5% SC +0.66
(p=2.3e-10, 33), FP +1.00 (p=1.8e-15, 50); 1e-3 SC +1.00 (p=1.8e-15, 50), FP +1.00 (p=1.8e-15, 50);
1e-4 SC +1.00 (p=1.8e-15, 50), FP +1.00 (p=1.8e-15, 50).

## Results -- fault family "up" (an uplink fault, L_1->S_0)

| loss | arm | exact (95% CI) | ambig/wrong | miss | mean set size (95% CI) |
|---|---|---|---|---|---|
| 1.5% | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1.5% | SprayCheck-Z | 1.00 [0.93,1.00] | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1.5% | FlowPulse-theta | 0.00 [0.00,0.07] | 0.00 | 1.00 | -- |
| 1.0% | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1.0% | SprayCheck-Z | 1.00 [0.93,1.00] | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1.0% | FlowPulse-theta | 0.00 [0.00,0.07] | 0.00 | 1.00 | -- |
| 0.5% | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 0.5% | SprayCheck-Z | 0.26 [0.16,0.40] | 0.74 | 0.00 | 1.78 [1.64,1.94] |
| 0.5% | FlowPulse-theta | 0.00 [0.00,0.07] | 0.00 | 1.00 | -- |
| 1e-3 | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1e-3 | SprayCheck-Z | 0.02 [0.00,0.10] | 0.92 | 0.06 | 1.98 [1.94,2.00] |
| 1e-3 | FlowPulse-theta | 0.00 [0.00,0.07] | 0.00 | 1.00 | -- |
| 1e-4 | MCP | **1.00 [0.93,1.00]** | 0.00 | 0.00 | 1.00 [1.00,1.00] |
| 1e-4 | SprayCheck-Z | 0.00 [0.00,0.07] | 0.26 | 0.74 | 2.00 [2.00,2.00] |
| 1e-4 | FlowPulse-theta | 0.00 [0.00,0.07] | 0.00 | 1.00 | -- |

Paired exact McNemar: 1.5% SC +0.00 (p=1.0, 0), FP +1.00 (p=1.8e-15, 50); 1.0% SC +0.00 (p=1.0, 0),
FP +1.00 (p=1.8e-15, 50); 0.5% SC +0.74 (p=1.5e-11, 37), FP +1.00 (p=1.8e-15, 50); 1e-3 SC +0.98
(p=3.6e-15, 49), FP +1.00 (p=1.8e-15, 50); 1e-4 SC +1.00 (p=1.8e-15, 50), FP +1.00 (p=1.8e-15, 50).

## What the numbers say (findings first)

1. **MCP localizes to exactly one directed link at every loss rate and in both fault families**:
   exact = 1.00 (Wilson CI [0.93, 1.00], n=50), mean set size exactly 1.00, wrong = 0.00 throughout.
   This is a direct consequence of two facts already on record -- MCP detects in 100% of trials at
   every rate, with a false-positive rate of 0.00 (detection sweep) -- combined with the per-link
   (tx, rx) it observes: the rejected sublink IS the named directed link, and only the faulty link's
   loss ratio is anomalous. The advantage is real but it is an advantage **by construction**: MCP is
   the only arm that sees each directed link's own transmit count, which is exactly the contribution.

2. **SprayCheck-Z ties MCP at high loss and degrades to the ambiguous 2-link set at low loss.** At
   1.5% (both families) and 1.0% (up), SprayCheck's full §3.6 intersection resolves the fault to a
   single directed link as well as MCP does (paired diff +0.00, p=1.0) -- reported as an honest null,
   not hidden. At 0.5% its exact rate falls to 0.34 (down) / 0.26 (up); at 1e-3 it collapses to 0.00
   / 0.02 with a mean set size of exactly 2.00 -- the {uplink, downlink} pair the paper says a
   single, uncorroborated report is left with. At those rates its Z-test flags the faulty spine on
   too few DISTINCT leaves to complete the cross-leaf intersection, so it can name the spine but not
   the directed link. Every such 2-set contains one healthy link, which is why "ambiguous/wrong"
   reaches 1.00 there: acting on that set would repair the wrong hop half the time.

3. **FlowPulse-theta cannot localize -- and for an uplink fault cannot even detect -- once the signal
   is diluted or below its 1% floor.** For downlink faults it is exact at 1.5% (0.94) but drops to
   0.22 at 1.0% (mean set size 2.74: the per-sender "all/one" test lands in neither branch and
   returns the whole port's candidate set) and misses entirely at 0.5% and below. For uplink faults
   it MISSES at every rate, including 1.5%: a single sender's loss moves the aggregate ingress-port
   load by only ~1/(senders) of the drop rate (here ~0.5% for a 1.5% uplink loss across 3 senders),
   which never clears the paper's fixed 1% detection threshold. This is faithful to FlowPulse's own
   design: in its native single-sender-per-port Ring-AllReduce setup an uplink fault is 100% of the
   port and it detects; under multi-sender sprayed ports it is diluted below threshold. The gap is a
   property of the sprayed fabric MCP targets, reproduced, not a handicap imposed on the baseline.

## Threats to validity (honest caveats)

- **MCP's perfect score is partly definitional.** Given per-link (tx, rx) and a detector already
  shown to be 100%/FP-0 on this scenario, exact single-link localization is close to guaranteed. The
  contribution is that MCP HAS that per-link signal cheaply in the dataplane, not that a clever
  inference beats a hard baseline on equal information -- the arms do not have equal information, by
  design, and that is the point. This should be framed as "the witness ledger removes the
  uplink/downlink aliasing the passive baselines cannot," not as an algorithmic-cleverness win.
- **The budget is generous to the baselines**, not to MCP; a tighter budget would only worsen the
  baselines' miss rates. SprayCheck's detection reach here is therefore not comparable to the
  detection sweep's action-rate floor (different budgets, different questions) and should not be
  quoted as a detection result.
- **Single independent per-link fault**, matching PREREG v1.9 scope and the detection sweep exactly.
  Multi-link, common-mode, and non-stationary regimes are out of scope here (the open gap tracked in
  `STATS-LAYER-STATUS-2026-09-02.md`); no claim is made about them.
- **n_leaves=4, k=8, i.i.d.-uniform spray.** FlowPulse's uplink dilution scales with senders-per-port
  (worse at larger radix); SprayCheck's cross-leaf resolution improves with more leaves but costs a
  longer round-robin. The qualitative ordering is robust to these, but the exact crossover rates are
  topology-dependent and are reported as measured on this fabric, not as universal constants.
- Localization is measured at each arm's first successful localization within the budget; a per-epoch
  "set size over time" curve (the ambiguous window before SprayCheck's cycle completes) is not
  reported here and would strengthen the cost story.

## Bottom line

The claim "MCP localizes exactly where the baselines degrade to an ambiguous set" is **supported**,
with the boundaries stated: MCP is exact (set size 1) at every rate and both families; SprayCheck-Z
ties it at 1.0-1.5% loss (honest null) and degrades to the ambiguous 2-link set at <=0.5% and below;
FlowPulse-theta degrades to an ambiguous port-set or a miss below 1.5% for downlinks and misses
uplink faults entirely under multi-sender spraying. The measured localization gap on a sprayed
fabric is a genuine, previously unreported contribution.

## Reproduce

```bash
python3 -m pytest sim/baselines/tests -q          # 49 tests incl. localization fidelity
python3 -m sim.baselines.run_localization_sweep   # ~3 min; writes the JSON above
```
