# PREREG — Pre-registered evaluation protocol

**Project:** MCP — "The data plane decides what to measure"
**Version:** 1.1, 2026-08-25 (v1.0 frozen 2026-08-25 pre-review; v1.1 amends it in place in
response to `docs/PRE-REVIEW.md` before any block has run — every change is logged in §14. From
v1.1 on, changes are amendments appended in §14 with date and reason, never edits in place)
**Plan of record:** `~/.claude/plans/we-have-to-do-spicy-patterson.md`; hurdle register `HURDLES.md`
**Status of the numbers herein:** every claim below is a commitment, not a result. No experiment
in §10–§11 has been run at freeze time except as stated in §14.

---

## 0. Thesis under test and what would falsify it

**Thesis.** A two-timescale measurement controller — a per-path attention-weight loop in the
switch data plane (fast loop) plus a constrained contextual bandit with shadow prices in the
control plane that sets per-resource budgets and re-prices the fast loop each epoch (slow loop) —
localizes gray failures on packet-sprayed AI fabrics faster than fixed-policy measurement at
equal measurement budget, while keeping collective completion time (CCT) overhead negligible.

**The thesis is falsified** if any of the following holds on the Tier-1 evaluation (§9):
(a) H1 fails — MCP's time-to-localize is not at least 30 % lower than the best tuned
fixed-policy baseline at equal budget; (b) H6 fails — CCT overhead exceeds 1 %; or (c) H3 and
H4 both fail — neither shadow prices nor context contribute, in which case the two-timescale
design is not what produces the benefit and the paper must be reframed as a fast-loop-only
result; or (d) **fast-loop falsification condition (PRE-REVIEW R1):** ablation A7 (slow-loop
only, attention gating disabled) is within the 95 % CI of full MCP on H1 — in which case the
data-plane loop is *not* the contribution, the paper may not claim that "the data plane
decides", and the contribution is restated as a controller-side budgeted scheduler. The same
verdict follows if H7 fails on silicon (the gate does not react to a loss step without
controller involvement, or reacts no faster than the slow loop). Outcomes (a)–(d) are reported,
not suppressed.

**Claim (2) conditionality (PRE-REVIEW §4).** The plan's claim (2) — localization on *lossy*
fabrics — is asserted only if MCP beats B7' SprayCheck-L (baseline-loss-aware) on H1 at every
non-zero level of the background-loss sweep of §4.2; beating only as-published SprayCheck (B7)
at non-zero background loss is a straw-man win and is reported as such.

**What is not claimed.** GPU-scale CCT numbers, lossless (PFC/DCQCN) fabrics, hardware RDMA,
and multi-switch skew are outside the claim set (§9).

---

## 1. Hypotheses, success criteria, and tests

All comparisons are at *equal measurement budget* (§2.3) after *equal tuning budget* (§3.2).
Primary hypothesis is H1; the rest are secondary. Family-wise error is controlled with Holm's
step-down over the six *tested* hypotheses {H1, H2, H3, H4, H6, H7} at α = 0.05 (§6.4); H5 is
descriptive and outside the family (amended v1.1). Effect sizes are reported for every
hypothesis regardless of significance. The "best baseline" set for H1 excludes any arm reported
as "infeasible at $B$" at the operating point in question (in practice B1 at $B$ < its fixed
tag overhead); an infeasible arm cannot be the best baseline at a budget it cannot meet.

| ID | Hypothesis (H1 = alternative) | Pre-specified success criterion | Primary test | Effect size |
|---|---|---|---|---|
| **H1** Faster localization | MCP's time-to-localize (TTL) is lower than every fixed-policy baseline at equal budget | Median TTL reduction ≥ 30 % vs the *best* baseline on the fault catalogue (§5), AND Holm-adjusted p < 0.05, AND 95 % bootstrap CI of the median ratio excludes 0.70 from above | Log-rank (Mantel–Cox) on right-censored TTL, stratified by fault type; confirmatory paired Wilcoxon on log-TTL per seed | Hazard ratio with 95 % CI; Cliff's δ on uncensored pairs; median ratio with BCa CI |
| **H2** Pareto dominance (restated v1.1, PRE-REVIEW R3) | On the two-dimensional plane (localization F1, $\beta_{probe}+\beta_{tag}$) MCP's curve Pareto-dominates every baseline's curve, with all arms sharing the common inference layer of §3.3 | For every budget level in the sweep {0.5, 1, 2, 5, 10, 20} %, MCP's F1 ≥ best baseline's F1 at ≤ its $\beta_{probe}+\beta_{tag}$ (weak dominance), with strict dominance (F1 higher by more than the paired CI, or bandwidth lower by more than the CI at equal F1) in ≥ 4 of 6 budget levels. SRAM/stages, NIC reads/s and host CPU are **side constraints, reported not tested**: each arm's value is tabulated next to its point, and any arm that exceeds the §2.3 side-constraint cap is marked on the plot but not excluded. Zero-SRAM arms (B3, B11) therefore no longer make H2 unpassable | Per-budget-level paired comparison of F1 (Wilcoxon signed-rank across seeds) at matched $\beta_{probe}+\beta_{tag}$ | Hypervolume gain of the dominated region on the 2-D plane (normalized), with bootstrap CI |
| **H3** Shadow prices are necessary | Removing shadow prices (ablation A1) degrades TTL or violates budgets | Ablation A1 has median TTL ≥ 15 % higher than full MCP OR budget-violation rate ≥ 5× full MCP, Holm-adjusted p < 0.05 | Log-rank (TTL); two-proportion z-test on violation rate | HR; risk ratio of violation |
| **H4** Context is necessary | Removing the context vector (ablation A2) degrades TTL under non-stationary workloads | On the held-out parallelism configurations (§8.3), A2 median TTL ≥ 15 % higher than full MCP, Holm-adjusted p < 0.05 | Log-rank on TTL, stratified by parallelism config | HR; Cliff's δ |
| **H5** Near-oracle — **DESCRIPTIVE (demoted v1.1, PRE-REVIEW §4)** | MCP's cumulative regret against the *dynamic* oracle (§8.2) is small relative to the oracle's cumulative reward | No pass/fail threshold (the former "≥ 70 % of oracle" bar was arbitrary). Normalized regret is reported with its 95 % BCa CI, alongside the static-oracle gap, for each learner of §8.1 | None (not in the Holm family) | Normalized regret with CI |
| **H6** Simulated CCT overhead (renamed v1.1, PRE-REVIEW §3) | In the htsim simulation, MCP's measurement traffic and actions do not slow the collective | Simulated CCT overhead ≤ 1 % (median over seeds and traces) relative to the no-measurement run, AND p99 straggler lag overhead ≤ 2 %, with the upper 95 % CI bound ≤ 1.5 % and ≤ 3 % respectively. Stated as a *simulation* result throughout the paper; no GPU-scale CCT claim is made and the near-tautological character of the test at $B$ ≤ 2 % is acknowledged in the text | Equivalence test (TOST) with margin 1 % on log-CCT ratio | Median CCT ratio with CI |
| **H7** Fast-loop reaction latency (added v1.1, PRE-REVIEW R1) | On Tofino silicon, the attention gate reacts to an injected loss step on a sprayed path without controller involvement, in microseconds, and at least 100× faster than the slow loop's decision→install latency | **Measurement.** Fault F1 ★ (or F6 ★) is switched on at a known instant on one virtual link while the controller's write path to `reg_attn`/`reg_thresh` is *frozen* (bfrt writes disabled for the run). Reaction time $\tau_{fast}$ = time from the first dropped packet on the faulty path to the first gated mirror / tag emitted for that path, both timestamped by the switch's own ingress global timestamp (mirrored copies carry `ig_intr_md.ingress_mac_tstamp`; the fault onset is timestamped by the packet generator's TX timestamp cross-calibrated to the switch clock via a pre-run loopback, residual ≤ 1 µs). The slow-loop install latency $\tau_{slow}$ = time from the controller's epoch tick that first observes the fault to the completed bfrt table/register write, measured by the same clock. **Success:** median $\tau_{fast}$ ≤ 100 µs across ≥ 10 reps × 2 faults, AND the 95 % BCa CI of the paired ratio $\tau_{slow}/\tau_{fast}$ lies entirely above 100, AND in the frozen-controller runs the gate fires on the faulty path but not on ≥ 90 % of healthy paths (specificity check). **Failure:** any of the above not met, or no gated sample within $T$ when the controller is frozen (the gate is then shown to depend on the controller, and §0(d) applies) | One-sample sign test on $\log_{10}(\tau_{slow}/\tau_{fast}) > 2$ over reps; two-proportion z-test faulty vs healthy paths for specificity | Median $\tau_{fast}$ and $\tau_{slow}$ with CIs; paired ratio with BCa CI |

Falsification of H1 by the *best* baseline is a stricter bar than by the *mean* baseline; we
commit to the stricter one. If a baseline ties MCP within CI on H1, the paper reports it as a
tie and the contribution shifts to H2–H4 and H7. H7 is the only hypothesis whose primary
evidence is Tier-2 (silicon); Tier-1 cannot test it (§9.2).

---

## 2. Metrics — definitions and units

### 2.1 Detection and localization (time-based, right-censored)

Let a fault be injected at simulation time $t_0$ on element $e^*$ (a virtual link, spine port,
or NIC). Time is measured in seconds of simulated (Tier-1) or wall-clock (Tier-2) time.

- **Time-to-detect (TTD)** = $t_d - t_0$, where $t_d$ is the first time the controller's anomaly
  state (a single global bit derived only from observations, §7) becomes 1 and stays 1 for at
  least one epoch. Unit: s.
- **Time-to-localize (TTL)** = $t_\ell - t_0$, where $t_\ell$ is the first time $e^*$ appears in
  the controller's top-$k$ suspect list with $k = 1$ (single fault) or $k$ = number of injected
  faults (multi-fault), and stays there for one epoch. Unit: s.
- **Censoring.** A run ends at horizon $T$ (default 120 s simulated, 600 s hardware). If
  localization has not occurred by $T$, TTL is right-censored at $T - t_0$ and recorded with a
  censor flag. Censored observations are *never* dropped and never imputed; survival analysis
  (Kaplan–Meier + log-rank) is the primary summary, medians are reported from the KM curve,
  and the fraction censored is reported per arm.
- **CDFs** of TTD/TTL are plotted per fault type with 95 % pointwise bootstrap bands.

### 2.2 Localization quality

- **Precision@k / Recall@k** against the injected fault set at the localization epoch and at
  the end of the run: $P@k = |S_k \cap F| / k$, $R@k = |S_k \cap F| / |F|$, where $S_k$ is the
  top-$k$ suspects and $F$ the injected set. Reported for $k \in \{1, 3, 5\}$.
- **Localization F1** = harmonic mean of $P@|F|$ and $R@|F|$ at the end of the run, so that a
  method that never localizes scores 0 rather than being excluded.
- **False alarms per hour** on *no-fault* runs: number of epochs in which any element enters
  the top-1 suspect list with anomaly bit = 1, divided by run length in hours. Unit: h⁻¹.
  Each configuration gets ≥ 30 no-fault seeds (§6.1). A baseline is disqualified from the H1
  comparison at a given operating point if its false-alarm rate exceeds 6 h⁻¹ (one per 10 min);
  the operating point is then moved along its threshold knob until it complies.

### 2.3 Overhead — five common units, always reported together

Every arm's overhead is reported in all five units so that "equal budget" is checkable in each:

| Unit | Definition | Symbol |
|---|---|---|
| Probe bytes | Bytes of injected probe packets on the fabric per second, summed over all links, divided by total fabric link capacity | $\beta_{probe}$, fraction of capacity |
| INT/tag/evidence bytes | Bytes of INT headers, CSIG-style tags, mirrored/truncated copies, **NIC evidence packets** (the NIC→switch reflected per-path evidence of the fast loop, and any NIC→controller evidence export in B11), and **mirror bytes on the collector port** — counted wherever they traverse a fabric link *or* a collector link, per second, same normalization (amended v1.1, PRE-REVIEW R3) | $\beta_{tag}$, fraction of capacity |
| Tofino SRAM and stages | SRAM (in 16 KB units) and MAU stages consumed by the measurement primitives, from the bf-p4c resource report (`*.resources.json`); Tier-1 uses the cost model calibrated from that report | SRAM units; stages |
| NIC reads/s | Counter/register reads issued to the NIC per second (Agilio: XDP map lookups or firmware counter reads; simulated equivalently) | reads/s |
| Host CPU | Fraction of one core consumed by the collector/controller per 1k monitored endpoints, measured with `perf stat` (Tier-2) or by the calibrated cost model (Tier-1) | core-fraction |

**Budget.** The "measurement budget" $B$ that all arms share is defined as $\beta_{probe} + \beta_{tag} \le B$ (bandwidth), where $\beta_{tag}$ **includes NIC evidence packets and
collector-port mirror bytes** as defined above, so that no arm can move cost off-budget by
routing it through the NIC or the collector link. Collector-link bytes are normalized by the
same fabric capacity so that a collector port is not "free" capacity. SRAM/stages/NIC-reads/CPU
are reported as side constraints that no arm may exceed by more than 10 % of MCP's usage (for
H1); for H2 they are reported next to each point and not tested (§1). Sweep values: $B \in$
{0.5, 1, 2, 5, 10, 20} % of fabric capacity. Default $B$ = 2 %.

**Budget-violation rate** = fraction of epochs in which any resource exceeds its cap by more
than 5 %. Unit: fraction of epochs.

### 2.4 Coverage vs budget

**Link coverage** at budget $B$ = fraction of virtual links for which at least one valid
measurement sample (probe, tag, or NIC counter delta) was received in the last epoch. Reported
as mean over epochs with 95 % CI, per budget level.

### 2.5 Workload impact

- **CCT** = time from the first packet of a collective to the last acknowledgement, per
  collective, from the workload trace's collective boundaries. **CCT overhead** = median over
  collectives of $CCT_{arm} / CCT_{no\text{-}measurement}$ − 1, for identical seed and trace.
- **p99 straggler lag** = 99th percentile over training iterations of (slowest rank's
  iteration end − fastest rank's iteration end). Overhead defined as for CCT.

### 2.6 Learning metrics

- **Regret** at epoch $t$: $R_t = \sum_{\tau \le t} \big( r(a^*_\tau) - r(a_\tau) \big)$ where
  $a^*_\tau$ is the *dynamic oracle* action (§8.2) and $r$ is the observation-only reward of §7.
  **Normalized regret** = $R_T / \sum_\tau r(a^*_\tau)$.
- **Exploration rate** = fraction of epochs in which the chosen action differs from the greedy
  action (for reporting only).

---

## 3. Baselines

### 3.1 The comparison set

Each baseline is implemented in the same htsim fork against the same measurement hooks and
the same budget accounting. "Decides" = what the arm chooses each epoch or per packet.

| # | Baseline | Stands in for | What it decides | Tunable knobs | Notes |
|---|---|---|---|---|---|
| B1 | Fixed INT, all flows | HPCC-style always-on INT | Nothing; every packet carries a tag | Tag size (8/12 B); which fields | Overhead is what it is; will exceed small budgets and is then reported as "infeasible at $B$" rather than silently scaled. **An infeasible B1 is excluded from the H1 "best baseline" set at that $B$** (v1.1, PRE-REVIEW §4); it is still plotted on H2 |
| B2 | INT 1/N | Sampled INT | Nothing adaptive; tags every N-th packet per port | $N$ (set so $\beta_{tag} = B$) | Sampling is uniform over packets, hence proportional to load |
| B3 | Uniform probe mesh | R-Pingmesh / Hostmesh | Nothing adaptive; every NIC probes a fixed pinglist at a fixed rate | Probe rate (set to $B$), payload (50 B as R-Pingmesh), timeout (500 ms as R-Pingmesh), pinglist density, anomaly threshold | Localization by probe-path intersection as in Pingmesh |
| B4 | Sketch-only | Switch sketch telemetry | Nothing adaptive; per-port count/loss sketch exported every epoch | Sketch width/depth (within SRAM cap), export epoch | No probes, no tags |
| B5 | Rule-based threshold-adaptive sampling | ChameleMon-style stand-in (renamed v1.1: CPRANT's mechanism is not verified, so its name is not attached to this arm) | Raises sampling rate on ports whose sketch deviation exceeds a threshold, lowers elsewhere, controller-side at epoch cadence | Deviation threshold, up/down multipliers, min/max rate, epoch | The strongest "adaptive but not learned" comparator |
| B6 | FlowPulse | FlowPulse (Technion) | Per-iteration symmetry check of collective flow pairs; flags asymmetric pairs | Asymmetry threshold, window | Uses the iteration clock; no budget knob, overhead reported |
| B7 | SprayCheck round-robin (as-published) | SprayCheck (arXiv 2605.03702) | Round-robins one prioritized flow across spray paths on a fixed schedule; flags a path on *any* loss (as-published threshold, designed for a lossless fabric) | Schedule period, number of paths per round | Extended to 3-level topologies and lossy fabrics exactly as its paper says it does not support. On lossy fabrics this arm is expected to false-alarm; it is kept so the reader sees the as-published behaviour, but it is **not** the arm claim (2) must beat. **Run in both tiers** (v1.1, PRE-REVIEW R2) |
| B7' | SprayCheck-L (baseline-loss-aware) | SprayCheck, made fair for lossy fabrics (added v1.1, PRE-REVIEW §4) | As B7, but the per-path loss threshold is set relative to an estimated background loss rate: over the first $M$ collective iterations of the run (no-fault warm-up) it estimates the fabric-wide loss rate $\hat\ell_0$ and its per-path spread, then flags a path only when its measured loss exceeds $\hat\ell_0$ by $z$ standard errors; localizes by path-set difference | $M$ (warm-up iterations), $z$, schedule period, paths per round | The arm claim (2) must beat at every non-zero background-loss level (§0, §4.2). **Run in both tiers** |
| B8 | DynATOS+-style scheduler | DynATOS/DynATOS+ | Time-divides switch resources among measurement tasks to meet per-task accuracy targets, controller-side | Accuracy targets, epoch, task set | No spraying awareness |
| B9 | Random at equal budget | — | Picks a random subset of paths/ports to measure each epoch, spending exactly $B$ | Subset size (from $B$), epoch | Sanity floor |
| B10 | Round-robin at equal budget | — | Cycles through paths/ports in fixed order, spending exactly $B$ | Cycle order, epoch | Sanity floor; also the "no learning" ablation of the slow loop |
| B11 | NIC-only, **aggregating** (restated v1.1, PRE-REVIEW §4) | NIC-side per-path telemetry pooled at a controller, as Meta's fleet does | Per-path RTT/ECN/PSN-gap counters on every NIC, always on; each NIC exports per-path evidence to a controller every epoch; the controller **pools evidence per path across all NICs** (a path's statistic is the union of all NICs' samples on it) and localizes on the pooled statistic through the common inference layer of §3.3; **no switch state at all** | Per-path window, number of paths tracked, export epoch | Tests claim (3): is the NIC alone, with fleet-wide aggregation, sufficient? A non-aggregating per-NIC variant is *not* run — it would be a straw man. Evidence export bytes count in $\beta_{tag}$ (§2.3). On hardware it is **not** called "MetaRoCE-like": it has RTT (host XDP) and reorder-confounded PSN gaps only, no ECN (§9.2) |
| B12 | Oracle | — | Knows the injected fault and measures exactly the elements needed; upper bound on what the budget can buy | None | Used for H5 regret and as the ceiling on all plots; the *dynamic* oracle re-solves each epoch (§8.2) |
| B13 | OPP-style probe duplication (added v1.1, PRE-REVIEW §2 housekeeping) | OmniPath Ping (SIGCOMM'26) — **reimplemented from the published abstract only; the full paper was not available at v1.1** | Each NIC's probe is duplicated at the first hop onto *every* spray path toward its destination (full path coverage per probe), and copies are de-duplicated in-network at the last hop so that the receiver sees one probe per (src, dst) while every path is exercised; per-path loss is inferred from which copies survived (a per-path bitmap carried by the surviving copy or by the dedup switch's counter) | Probe rate (set so $\beta_{probe}$ = $B$, counting *all duplicates* on every link), dedup table size (within the SRAM side constraint) | Labelled "OPP-style (abstract-only reimplementation)" in every figure and table. **Decision rule:** if the full OPP paper becomes available before the tuning block starts and its mechanism differs materially from the above, B13 is re-implemented to match and the change is logged in §14; if it cannot be obtained before tuning starts, B13 is retained as "OPP-style" and the paper's claim (1) is worded to compare against "OPP-style probe duplication" rather than OPP itself. Duplicated probes are charged to $\beta_{probe}$ on every link they traverse, so at $B$ = 2 % the per-source rate is $1/N_{paths}$ of B3's |

### 3.2 Equal tuning budget

- Every baseline with knobs and MCP itself get the **same tuning budget**: 64 configurations
  drawn by Latin-hypercube sampling from the knob ranges above, each evaluated on 5 seeds of a
  **tuning split** (one fat-tree size and two Chakra traces that are *excluded* from the
  evaluation split), selecting the configuration with the best median TTL subject to the false-
  alarm cap of §2.2. Total: 320 runs per arm.
- MCP's tuning knobs are: exploration coefficient, shadow-price step size, discount/window
  (§8.1), attention-weight update gain. These are the *only* MCP knobs tuned; everything else is
  fixed before tuning and listed in `conf/mcp/default.yaml`.
- The selected configuration per arm is frozen and recorded (`conf/tuned/<arm>.yaml`, with the
  tuning-run manifest) before any evaluation-split run starts.
- Baselines B1, B12 have nothing to tune; B9/B10 tune only epoch. B7' additionally tunes
  ($M$, $z$); B13 tunes probe rate and dedup table size.
- **Tuning covers the localizer-independent knobs only.** The common inference layer of §3.3
  is frozen before tuning starts and is not a per-arm knob.

### 3.3 Common inference layer (added v1.1, PRE-REVIEW R3)

**Problem addressed.** In v1.0 each arm localized with its own rule (MCP: Beta-Binomial /
Normal-Gamma + CUSUM; B3: probe-path intersection; B7: path-set difference; B2/B4:
unspecified). A TTL difference could then come from the *localizer*, not from which samples the
measurement policy delivered. That confound is removed as follows.

**One frozen localizer, shared by every arm.** All arms — MCP, A1–A7, B1–B13 — feed their
samples into the *same* inference module, `controller/infer.py`, frozen (hash recorded in
`conf/infer/frozen.yaml`) before the tuning block starts:

1. **Per-element posterior.** For every measurable element $e$ (virtual link, spine port, NIC,
   and each sprayed path as a composite), a Beta-Binomial posterior on the loss rate from
   (delivered, lost) sample counts and a Normal-Gamma posterior on latency from RTT / one-way
   samples. A probe, a tag, a mirrored copy, a sketch delta and a NIC counter delta are all
   converted to the same `(element, delivered, lost, latency_samples)` record by the arm's
   *sample adapter*, which is the only per-arm code. Path-level samples are attributed to
   links by the known path→link map with the uniform-prior de-aggregation already used for
   Pingmesh-style intersection (so B3's "intersection" becomes a special case).
2. **Change detection.** A two-sided CUSUM per element on the posterior-mean loss (and
   latency) against that element's own running baseline; the CUSUM constants ($k$, $h$) are
   shared and frozen.
3. **Ranking.** Elements are ranked by CUSUM statistic; the anomaly bit (§2.1) is 1 when the
   top-ranked element's CUSUM exceeds $h$; the top-$k$ suspect list is the top-$k$ of that
   ranking.

**What differs across arms is only which samples arrive** — their elements, count, timing and
cost. An arm's tunable knobs (§3.1) affect the sample stream, never the localizer. The
false-alarm operating-point knob of §2.2 is $h$ **per arm**, the one exception, because arms
with different sample rates need different $h$ to meet the 6 h⁻¹ cap; the selected $h$ per arm
is recorded and the sweep of $h$ is plotted in the appendix.

**Verification.** `controller/tests/test_common_inference.py` asserts that (i) every arm's
localization call resolves to the same `infer.localize` function object, (ii) the module hash
at run time equals the frozen hash in the manifest, and (iii) feeding two arms the identical
sample stream yields identical suspect lists. The paper states this design in the Evaluation
setup and reports, in the appendix, each arm's *published* localizer as an exploratory
comparison (B3 with Pingmesh intersection, B7 with path-set difference) so the reader can see
how much the common layer changed each baseline.

---

## 4. Ablations and sensitivity sweeps

### 4.1 Ablations (each = full MCP minus one component, same tuned configuration otherwise)

| ID | Ablation | What is removed | Supports |
|---|---|---|---|
| A1 | No shadow prices | Per-resource prices fixed at their initial value; budget enforced only by hard clipping | H3 |
| A2 | No context | Bandit context vector replaced by a constant; policy becomes a non-contextual bandit | H4 |
| A3 | No exploration | Exploration coefficient = 0 (pure greedy on posterior mean) | Learning is doing work |
| A4 | No memory | Posterior reset every epoch (no carry-over of estimates) | Cumulative occupancy model matters |
| A5 | Single modality (switch only) | NIC evidence not reflected in-band; fast loop uses switch counters only | Claim (3) |
| A5' | Single modality (NIC only) | = B11 with MCP's slow loop on top | Claim (3) |
| A6 | Fast-loop only | Slow loop disabled; budgets and prices fixed at tuned initial values | Two timescales matter |
| A7 | Slow-loop only | Attention-weight gating disabled; the controller's chosen budgets are spent uniformly per path | Two timescales matter |

### 4.2 Sensitivity sweeps (one factor at a time from the default point; defaults in bold)

| Factor | Values |
|---|---|
| Measurement budget $B$ | 0.5, 1, **2**, 5, 10, 20 % |
| Slow-loop epoch | 10 ms, 100 ms, **1 s**, 10 s |
| Spray paths per source–destination | 8, **16**, 32, 64 |
| Silent loss rate on faulty element | 1e-5, **1e-4**, 1e-3, 1e-2 |
| **Background loss, fabric-wide** (added v1.1, PRE-REVIEW §4) | **0**, 1e-5, 1e-4, 1e-3 — applied as i.i.d. Bernoulli drops on *every* link (random-drop mode) and, as a second variant, as congestion-induced drops from raising offered load until the tail-drop rate on the busiest 10 % of links reaches the same nominal value (congestion mode); the faulty element's excess loss is *added* to the background |
| Concurrent faults | **1**, 2, 4 |
| Offered load | 30, **60**, 90 % of bisection |

Each sweep point: 30 seeds, full baseline set on the H1 metric only (TTL) plus overhead in all
five units. A full-factorial design is *not* run; interactions are exploratory (§12).

**Exception — background loss × fault loss.** The background-loss factor is crossed with the
faulty-element loss rate (4 × 4 = 16 points, the F1 ★ fault) because claim (2) is *about* that
interaction: a 1e-4 fault on a 1e-4 background is the hard case. At every non-zero
background-loss point the arms of record are MCP, B7 (as-published), B7' (SprayCheck-L), B11
(aggregating) and B3; claim (2) requires MCP to beat B7' on H1 (log-rank, Holm within the
sweep-point family) at each of the three non-zero levels, and B7's false-alarm rate is reported
alongside so the straw-man gap is visible. The no-fault F0 runs are repeated at each
background-loss level for the false-alarm cap of §2.2, which is applied per level.

---

## 5. Fault catalogue

Each fault is defined by (element, mechanism, magnitude, onset, duration). Rates and durations
are drawn from the sources below; **V** = number read this session from the authors' own PDF
or arXiv HTML via `pdftotext`/direct read; **S** = extracted by a fetch summariser from the
arXiv HTML (spot-check against the PDF before citing a page number); **U** = unverified.

### 5.1 Source evidence

| Source | Evidence | Status |
|---|---|---|
| Alibaba HPN, SIGCOMM'24, §2.3 | "0.057 % of NIC-ToR links fail each month, and about 0.051 % of ToR switches encounter critical errors and crashes"; "a single LLM training job would encounter 1-2 crashes each month"; "5K-60K link flapping cases happen each day" (cluster-wide, cluster size not stated in that sentence) | V (authors' PDF) |
| Meta RoCE@Scale, SIGCOMM'24, §5.1, §4 | Go-back-N used "for rare packet drops due to unhealthy network elements or link flap/down"; ACK/NACK drops cause Local ACK Timeout "on the order of milliseconds"; ECMP hash collisions degraded training "up to more than 30 %"; E-ECMP + QP scaling improved AllReduce up to 40 %. No numeric flap or loss *rate* is given | V (authors' PDF) |
| R-Pingmesh, SIGCOMM'24, §4, §6 | ToR-mesh probing 10 pkt/s per RNIC "to detect anomalous RNICs at 100 ms granularity"; ≥ 10 probes/s per direction per link above ToR; probe timeout 500 ms; probe payload 50 B; service-tracing interval 10 ms; per-RNIC probe load < 150 pkt/s; detects, categorizes and locates problems "in 20 s"; one-month audit: 85 % of located problems accurate, all 157 switch-network problems accurate; Fig. 1: a single flapping RNIC or switch port degrades cluster-average training throughput | V (authors' PDF) |
| Meta "Revisiting Reliability" (arXiv 2410.21680) | 6.50 (RSC-1) and 2.34 (RSC-2) failures per 1000 node-days; IB links the dominant failure source in the studied period; MTTF 7.9 h at 1024 GPUs, projected 1.8 h at 16k; health checks every 5 min; 4 M jobs, 150 M A100-hours | S |
| ByteRobust (arXiv 2509.16293), Table 1, Table 3 | Over 778,135 jobs in three months: InfiniBand error 2.9 % of incidents, job hang 9.9 %, MFU decline 0.8 %, CUDA error 36.1 %; network issues (NIC crash, port flapping) detected in 30 s by real-time inspection vs ~10 min default timeout | S |
| ByteDance straggler study, OSDI'25 (arXiv 2505.05713) | 3,079 jobs over five months; 42.5 % of jobs straggle; the 10 % worst jobs waste ≥ 21.3 % GPU-hours (≥ 1.27× slowdown); 10.4 % GPU-hour waste overall; computation imbalance dominates; only 1.7 % of straggling jobs attributable to problematic workers; stragglers are persistent within a job rather than transient | S |

Consequence for scope: the OSDI'25 study says *most* stragglers are not network-caused. The
paper claims faster localization of the *network* faults that do occur, not a reduction of
overall straggler incidence, and states this explicitly.

### 5.2 Injected faults (Tier-1; Tier-2 subset marked ★)

| ID | Fault | Mechanism in htsim / P4 | Magnitude | Onset | Duration | Grounding |
|---|---|---|---|---|---|---|
| F1 ★ | Silent gray loss on a spine uplink | Per-packet Bernoulli drop on one link | 1e-4 (sweep 1e-5–1e-2) | Uniform in [10, 30] s after warm-up | Persistent to horizon | R-Pingmesh §2.2 (in-network drops on lossless fabrics); Meta §5.1 |
| F2 ★ | Silent gray loss on a NIC-ToR link | Same, on an access link | 1e-4 | Same | Persistent | HPN §2.3 link failure ratio; R-Pingmesh RNIC drops |
| F3 ★ | Link flap | Link down/up toggling | Down for U[0.5, 3] s, up for U[5, 30] s, 3–10 cycles | Same | Bounded (≤ 60 s) | HPN "5K-60K flaps/day"; R-Pingmesh flapping RNIC/port; ByteRobust port flapping |
| F4 ★ | One-direction asymmetry | Drop/latency applied only in one direction of a spine link | 1e-3 loss or +50 µs | Same | Persistent | Plan M3 failure-injection list; FlowPulse symmetry premise |
| F5 | Congestion hotspot from hash polarization | Force a subset of flows onto one spine (ECMP collision) | Extra load to 100–120 % of link | At a collective boundary | Duration of 3 collective phases | Meta §4 "up to more than 30 %" degradation; HPN §2.2 |
| F6 ★ | Black-hole (silent 100 % loss) | Route entry removed for one destination prefix on one spine | 100 % | Same | Persistent | HPN ToR critical errors; Meta unhealthy elements |
| F7 | NIC slowdown (host-side straggler) | One NIC's egress rate capped at 50 % | 50 % | Same | Persistent | OSDI'25 worker hardware 1.7 %; ByteRobust NIC crash |
| F8 ★ | Corruption (ICRC failure) | Per-packet payload corruption ⇒ receiver drop + NAK | 1e-4 | Same | Persistent | Plan M3; Meta go-back-N on drops |
| F9 | Latency inflation | Extra 20–100 µs on one link (recirc loop on hardware) | +20/50/100 µs | Same | Persistent | R-Pingmesh "high RTT" category |
| F0 | No fault (control) | — | — | — | Whole run | Required for false-alarm rate (§2.2) |

Multi-fault runs (2 and 4 concurrent) draw without replacement from F1–F9 with onsets
staggered by U[0, 10] s.

Fault *incidence* in the sweeps is one injection per run (not Poisson arrivals), because TTL is
per-fault; a separate "operational" run set uses Poisson arrivals at the HPN monthly rates
scaled to the simulated fabric size to produce the false-alarm and budget-violation numbers
under realistic incidence (reported in the appendix only).

---

## 6. Seeds, trials, confidence intervals, tests, and power

### 6.1 Replication

- **Tier-1 (htsim):** ≥ 30 seeds per (arm × fault × sweep point); 30 no-fault seeds per arm.
- **Tier-2 (hardware):** ≥ 10 repetitions per (arm × fault ★); ≥ 10 no-fault repetitions.
- The seed list is fixed in advance: seeds 1000–1029 (Tier-1), 2000–2009 (Tier-2). Additional
  seeds are appended (never substituted) if the power re-estimate in §6.5 calls for them, and
  the amendment is logged in §14.

### 6.2 Four independent RNG streams

Each run derives four independent generators from (master seed, stream id) via
`numpy.random.SeedSequence(master).spawn(4)` (Tier-1) / equivalent seeded PRNGs in htsim:

1. **Topology and placement stream** — job placement, rank-to-NIC mapping, initial ECMP seeds.
2. **Fault stream** — fault element choice, onset time, per-packet drop decisions.
3. **Policy stream** — MCP exploration draws, Thompson samples, baseline random choices.
4. **Noise stream** — link-latency jitter, probe RTT jitter, counter-read latency draws
   (from the calibrated distributions of §9.3).

Paired comparisons between arms use the *same* master seed so that streams 1, 2 and 4 are
identical across arms and only stream 3 differs. This is what makes the per-seed paired test
in §6.4 valid.

### 6.3 Confidence intervals

- All point estimates carry 95 % **BCa bootstrap** CIs over seeds (10,000 resamples, bootstrap
  RNG seeded with 7).
- Survival curves: Kaplan–Meier with Greenwood pointwise 95 % bands; medians read from KM.
- Ratios (TTL ratio, CCT ratio) are bootstrapped on the paired per-seed log-ratio.

### 6.4 Tests

- **TTL/TTD (H1, H3, H4):** primary = log-rank stratified by fault type, with censoring at
  horizon; confirmatory = Wilcoxon signed-rank on paired per-seed log-TTL (censored pairs
  excluded from the confirmatory test and counted). Effect size = hazard ratio (Cox, fault type
  as stratum) and Cliff's δ on uncensored pairs.
- **Proportions (budget violation, false alarm):** two-proportion z-test; risk ratio with CI.
- **CCT overhead (H6):** TOST equivalence on log-ratio with margin ln(1.01).
- **Regret (H5, descriptive):** normalized regret with BCa CI; no test (demoted v1.1).
- **Fast-loop latency (H7, Tier-2):** one-sample sign test on $\log_{10}(\tau_{slow}/\tau_{fast}) > 2$
  over reps; two-proportion z-test faulty vs healthy paths for specificity (§1).
- **Multiple comparisons:** Holm step-down over the six tested hypotheses (family = {H1, H2,
  H3, H4, H6, H7}; H5 is descriptive and outside the family). Within H1,
  MCP-vs-each-baseline comparisons are a second family, Holm-adjusted separately, and the
  headline H1 p-value is the one against the best baseline.
- **Sweeps** are descriptive (CIs only); no tests are run on sweep points to avoid a 36-way
  multiplicity problem.

### 6.5 Power calculation (for the H1 primary test)

Target: detect a 30 % reduction in median TTL (hazard ratio HR = 1/0.7 ≈ 1.43 under
proportional hazards) at 80 % power.

**Assumptions stated:** (i) proportional hazards between MCP and the best baseline; (ii) TTL
approximately log-normal with coefficient of variation CV; (iii) within-seed correlation ρ
between arms because streams 1, 2 and 4 are shared; (iv) at most 10 % censoring at the
default operating point (checked in the gate experiment, §10).

*Unpaired log-rank (Schoenfeld):* total events needed
$d = 4 (z_{1-\alpha/2} + z_{1-\beta})^2 / (\ln HR)^2$.
At α = 0.05: d ≈ 247 events; at the Holm-adjusted α = 0.05/6: d ≈ 381 events (90 % power: 330
and 483). With 9 fault types × 30 seeds = 270 fault events per arm (540 total), the stratified
log-rank is powered above 80 % even at the Holm-adjusted level. Per single fault type
(30 events per arm) it is **not**; per-fault-type results are therefore reported with CIs and
not tested individually.

*Paired confirmatory test on log-TTL:* required seeds
$n = (z_{1-\alpha/2} + z_{1-\beta})^2 / d_z^2$ with
$d_z = \ln(1/0.7) / \sqrt{2\sigma^2(1-\rho)}$, $\sigma = \sqrt{\ln(1+CV^2)}$, at the Holm-adjusted α:

| CV | ρ = 0.3 | ρ = 0.5 |
|---|---|---|
| 0.3 | 12 seeds | 9 seeds |
| 0.5 | 30 seeds | 22 seeds |
| 0.8 | 66 seeds | 48 seeds |

**Commitment:** 30 seeds is sufficient if CV ≤ 0.5 and ρ ≥ 0.3. The gate experiment (§10)
estimates CV and ρ from its uniform-vs-random arms; if CV > 0.5 or ρ < 0.3, seeds are
increased to the table value for the observed (CV, ρ) rounded up to the next multiple of 10,
before any MCP evaluation run, and the change is logged in §14.

*Tier-2 (10 reps)* is under-powered for a 30 % effect under any plausible CV and is therefore
used **only** to establish that the hardware loop behaves as the calibrated simulator predicts
(§9.2), never for H1–H6 inference (it is the primary evidence for H7 only).

---

## 7. Reward-function integrity

### 7.1 Requirement

The slow-loop reward must be computable from what the controller observed in the epoch and
nothing else. In particular it must not read the injected fault set, the fault stream, the
oracle, or any per-element ground-truth loss/latency from the simulator.

### 7.2 Formula template (final constants fixed in `conf/mcp/reward.yaml` before evaluation)

For epoch $t$, path set $P$, resource set $R$:

$$
r_t = \sum_{p \in P} \Big[ \underbrace{\log \hat\sigma^2_p(t-1) - \log \hat\sigma^2_p(t)}_{\text{uncertainty reduction}}
\;+\; \beta \cdot \underbrace{\min\!\big(1,\; C_p(t) / \kappa\big)}_{\text{anomaly evidence}} \Big]
\;-\; \sum_{r \in R} \lambda_r(t) \cdot \max\!\big(0,\; c_r(t) - B_r\big)
$$

where $\hat\sigma^2_p(t)$ is the posterior variance of the per-path loss/latency estimate
computed from the *samples received* for path $p$ up to epoch $t$ (Beta-Binomial for loss,
Normal-Gamma for latency), $C_p(t)$ is a CUSUM statistic of received samples against the
path's own running baseline, $c_r(t)$ is the *measured* consumption of resource $r$ (bytes
counted, reads issued, CPU sampled), $B_r$ its cap, and $\lambda_r(t)$ the current shadow price.
$\beta$, $\kappa$ are constants. Every term is a function of the `Observation` record only.

The first term rewards *reducing uncertainty*, the second rewards *following evidence*, the
third *charges for resource overuse*. Nothing rewards "being right about the fault" because
the controller cannot know it was right.

### 7.3 Unit test (committed as `controller/tests/test_reward_no_leakage.py`)

```python
"""Reward must be a pure function of Observation; it must not touch fault ground truth."""
import ast, inspect, dataclasses
import controller.reward as reward_mod
from controller.reward import compute_reward
from controller.types import Observation
from sim.faults import FaultSet, FaultLabel   # ground-truth types


def test_reward_module_has_no_fault_imports():
    tree = ast.parse(inspect.getsource(reward_mod))
    banned = {"sim.faults", "sim.oracle", "sim.groundtruth"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
            assert not any(n.startswith(b) for n in names for b in banned), node


def test_observation_carries_no_fault_field():
    fields = {f.name for f in dataclasses.fields(Observation)}
    assert not (fields & {"fault", "faults", "fault_set", "label", "ground_truth", "oracle"})


def test_reward_invariant_to_ground_truth(make_observation, make_prices):
    """Same observations, different injected faults -> identical reward."""
    obs = make_observation(seed=1)
    prices = make_prices()
    r_a = compute_reward(obs, prices, ground_truth=FaultSet([FaultLabel("spine3-up2", "loss", 1e-4)]))
    r_b = compute_reward(obs, prices, ground_truth=FaultSet([]))
    assert r_a == r_b  # compute_reward must ignore ground_truth if it even accepts it


def test_reward_raises_on_oracle_access(monkeypatch, make_observation, make_prices):
    """Any read of the simulator's fault oracle during reward computation is a test failure."""
    import sim.oracle as oracle
    def _trip(*a, **k):
        raise AssertionError("reward touched the fault oracle")
    monkeypatch.setattr(oracle, "injected_faults", _trip)
    monkeypatch.setattr(oracle, "true_loss", _trip)
    compute_reward(make_observation(seed=2), make_prices())
```

The test runs in CI on every commit; a red run blocks any evaluation run (the `make eval`
target depends on `make test-integrity`).

### 7.4 In-switch attention update rule — TO BE FIXED BEFORE P4 STEP 5 (see HURDLES H22)

**Status: PLACEHOLDER (v1.1, PRE-REVIEW R1).** As of v1.0 the only in-data-plane decision was
`rnd < attn` with `attn` written by the controller each epoch; per-path statistics were
computed off-chip (P4-DESIGN-SPACE §5.2, §5.7, §11). That is controller-set rate sampling, and
under it ablation A6 (fast-loop only) is undefined and H7 cannot hold. The rule below is the
**candidate** form from the review; it is *not yet pre-registered*. It must be fixed — one
rule, with constants — and logged in §14 before P4 implementation step 5 begins, and before
any Tier-2 run. Until then A6, A7 and H7 are pending on this section.

*Candidate rule (from PRE-REVIEW R1; feasible under bf-p4c constraint classes N8/N9 — one
SALU per stage, one register access per packet, 32-bit ALU):* per (dst-leaf, spine) register
`reg_attn[p]` in $[0, A_{max}]$,

- on a **threshold exceedance** observed in the data plane for path $p$ (e.g. `deq_qdepth`
  above $q_{thr}$ on the egress toward $p$, or a per-path sequence/ICRC anomaly counter crossing
  $c_{thr}$), **or on arrival of a NIC evidence packet** for $p$ whose quantized RTT/PSN-gap
  field exceeds its threshold: `attn[p] = min(attn[p] + k_up, A_max)`;
- on every $N$-th **clean** sample for $p$ (a per-path clean-sample counter in the same SALU
  word, upper 16 bits, wraps at $N$): `attn[p] = max(attn[p] - 1, A_min)`;
- the gate remains `rnd < attn[p]`, so the *controller* only sets $A_{min}$, $A_{max}$,
  $k_{up}$, $N$ and the thresholds once per epoch (the re-pricing of §0), and the switch moves
  `attn[p]` between those bounds on its own, per packet.

*Open decisions to close before step 5:* (i) which data-plane signal(s) count as
"exceedance" on Tofino 1 (queue depth is available in egress only; the anomaly counter must be
in the same SALU as `attn` or one stage earlier); (ii) packing of `attn` and the clean counter
into one 32-bit register so a single SALU op does both; (iii) the constants $k_{up}$, $N$,
$A_{min}$, $A_{max}$ — the update gain $k_{up}$ is the "attention-weight update gain" tuning
knob of §3.2, the others are fixed; (iv) whether the NIC evidence packet is itself gated (it
must not be, or the loop can starve). The frozen rule replaces this section verbatim in the
next amendment, with the P4 source hash.

---

## 8. Non-stationarity protocol

### 8.1 Comparators inside the learner family

MCP is evaluated with three slow-loop learners, each tuned with the §3.2 budget:
(i) standard LinUCB / Thompson (stationary); (ii) **discounted** LinUCB (discount γ ∈
{0.9, 0.99, 0.999}); (iii) **sliding-window** LinUCB (window ∈ {10, 100, 1000} epochs). The
paper reports all three; the headline uses whichever was selected on the tuning split, named.

### 8.2 Dynamic oracle for regret

Regret is measured against the **dynamic oracle**: at each epoch it re-solves the budgeted
measurement allocation with full knowledge of the current fault set and traffic matrix
(a per-epoch knapsack over paths). A *static* oracle (best single fixed allocation in
hindsight) is also reported so the reader can see the non-stationarity gap.

### 8.3 Held-out parallelism configurations

Workload non-stationarity comes from the collective schedule. The tuning split uses two
Chakra traces (one data-parallel, one tensor+pipeline). The evaluation split adds **held-out**
parallelism configurations never seen in tuning: (DP-only, TP+PP, DP+TP+PP with expert
parallelism from the Mixtral trace, and a two-job multi-tenant mix). H4 is tested on these.

### 8.4 Regime-shift runs

A dedicated run set switches the trace mid-run (job A → job B at 50 % of horizon) with a fault
injected 5 s after the switch, to measure TTL under a fresh regime. Reported descriptively.

---

## 9. Two-tier scope statement and calibration

### 9.1 Tier-1 — htsim, 1k–4k NICs

**Claims supported:** H1–H6 (H7 is Tier-2 only); all baselines; all ablations and sweeps; coverage vs budget;
regret; multi-fault; 3-level topologies (fat-tree k = 16 → 1024 NICs, k = 24 → 3456 NICs).
**Fidelity limits:** switch cost model calibrated from the bf-p4c resource report, not
measured on Tier-1; host CPU from the cost model; PFC/DCQCN cross-checked on one scenario in
`ns-3-alibabacloud` (reported as a fidelity note, not a result).

### 9.2 Tier-2 — one Tofino 1 + Agilio CX + two hosts, Soft-RoCE, lossy

**Claims supported (and only these):** (a) the measured per-primitive resource cost (SRAM,
stages, PHV) from the compiler report; (b) **fast-loop reaction time** $\tau_{fast}$ — the
time from an injected loss step on a sprayed path to the first gated mirror/tag for that path,
with the controller's write path frozen — and slow-loop decision→install latency
$\tau_{slow}$ on silicon, both by the switch ingress timestamp as specified in H7 (§1); this
is the primary evidence for H7 and for §0(d) (amended v1.1, PRE-REVIEW R2); (c) the
calibration distributions of §9.3; (d) that injected faults F1, F2, F3, F4, F6, F8 on the
virtual sprayed fabric are localized by the hardware loop with TTL inside the calibrated
simulator's 95 % prediction band, **and** that on the same silicon, same virtual fabric, same
budget and same common inference layer, MCP's TTL on F1 ★ and F4 ★ is lower than B7
(SprayCheck as-published) and B7' (SprayCheck-L) — reported with CIs, not as an H1 test (10
reps are under-powered, §6.5); (e) budgets are respected on silicon (violation rate).
**Not claimed:** coverage at scale, CCT with real GPUs, multi-switch skew (HURDLES H8),
lossless-fabric behaviour, 3-level topologies (simulation only). The paper states in the first
paragraph of the Implementation section: software-RDMA, lossy, single-chip *emulation* (never
"testbed"), `rdma_rxe`, no PFC/DCQCN, single traffic manager, virtual switches via
recirculation (as SprayCheck did).

**NIC evidence channels that exist on the hardware (stated explicitly, v1.1, PRE-REVIEW §4).**
On the Agilio CX / Hulk hosts the NIC arm and MCP's NIC-evidence path have exactly these
signals: (i) **per-path RTT**, measured by a host XDP program from probe/ACK timestamps — this
is the only clean channel; (ii) **PSN gaps**, read from `rdma_rxe` — **reorder-confounded**
under per-packet spraying, because go-back-N reports a gap on every reorder as well as on every
loss, so PSN-gap evidence is used only after subtracting the no-fault floor measured by the
pre-test below, and is reported as such; (iii) **no ECN** — there is no DCQCN/ECN marking on
the lossy fabric, so the ECN evidence field is absent on hardware (zero) and exists only in
Tier-1. Hardware results that depend on the NIC channel are therefore labelled "RTT + PSN-gap
(reorder-floor-corrected)" and never "MetaRoCE-like".

**Prerequisite pre-test — `rdma_rxe` under per-packet spraying (HURDLES H20; v1.1,
PRE-REVIEW R2).** Before any hardware result that uses NIC evidence is reported, a no-fault run
on the sprayed virtual fabric (16 paths, default load, F0) establishes the **NAK/retransmit
floor**: NAK rate, retransmitted-bytes fraction, and PSN-gap events per 10⁴ packets, over
≥ 10 reps × 60 s, plus whether the Gloo/`perftest` all-reduce completes. Pass: the all-reduce
completes in every rep AND the NAK rate is stable across reps (CV ≤ 0.3) so it can be
subtracted as a floor. Fail: all-reduce does not complete, or the floor is not stable — then
spray fan-out is reduced (32 → 16 → 8) or flowlet mode is used for `rdma_rxe`, the change is
logged in §14, and if no configuration passes, **no NIC-evidence claim is made from hardware**
and claim (3) rests on Tier-1 plus ablation A5/C3 only. The measured floor is published as a
table and fed into Tier-1's noise stream (§6.2, stream 4) as the PSN-gap noise model.

### 9.3 Sim→hardware calibration procedure

1. On the direct Agilio↔Hulk 10 G link (no switch needed, S-DOWN) and later through the Tofino
   (S-UP), measure **probe RTT** (≥ 10⁵ probes, 50 B, 10 pkt/s per pinglist entry as R-Pingmesh)
   and **counter-read latency** (≥ 10⁴ bfrt register reads and ≥ 10⁴ NIC map reads) as
   empirical distributions; store as `sim/calib/{probe_rtt,ctr_read}_{link|tofino}.npy` with
   SHA256.
2. Feed the empirical distributions into htsim's noise stream (§6.2, stream 4) by inverse-CDF
   sampling; no parametric fit.
3. Run the ★ faults on the hardware and on htsim configured with the hardware topology
   (same virtual-switch count, same spray fan-out, same load).
4. Report the two-sample **Kolmogorov–Smirnov distance** between hardware and simulated
   distributions of: probe RTT, counter-read latency, and TTL per ★ fault, with the KS
   p-value and n. Acceptance for using the simulator's numbers as representative: KS distance
   ≤ 0.15 for RTT and read latency; TTL hardware medians inside the simulator's 95 % prediction
   band for ≥ 5 of 6 ★ faults. Failure of acceptance is reported and the affected Tier-1
   claims are marked "uncalibrated".

---

## 10. Gate experiment (must run before any MCP evaluation)

**Purpose:** confirm the benchmark is not trivially solved, and estimate CV and ρ for §6.5.

| Item | Specification |
|---|---|
| Topology | One 3-level fat-tree, k = 16 (1024 NICs, 128 leaves, 64 spines... exact counts from the htsim topology file, recorded) |
| Workload | One Chakra trace: NeMo Mixtral (Zenodo record id and SHA256 recorded) through ATLAHS |
| Fault | F1: silent 1e-4 Bernoulli loss on one spine uplink, onset U[10, 30] s |
| Arms | Uniform probe mesh (B3), Random at equal budget (B9), Oracle (B12); budget B = 2 % |
| Seeds | 30 (1000–1029); horizon 120 s |
| Outputs | TTL KM curves; censor fraction; CV of log-TTL per arm; ρ between B3 and B9 log-TTL; overhead in all five units |
| **Abort / tighten rule** | If uniform (B3) localizes in ≤ 2 epochs (median TTL ≤ 2 s at the 1 s epoch), the benchmark is too easy: reduce budget to 0.5 % and/or loss to 1e-5 and re-run; repeat until uniform median TTL ≥ 5 epochs or a floor of 0.5 % / 1e-5 is reached. If uniform is censored in > 50 % of seeds at the floor, the fault is too hard for *any* method and the default operating point is loosened one step. The final default operating point is frozen and recorded in §14 before MCP runs. |
| Reproduction | `make gate SEED=<n>` regenerates one seed; `make gate-all` regenerates the figure |

---

## 11. Experiment matrix summary

| Block | Arms | Faults | Seeds | Runs (approx.) |
|---|---|---|---|---|
| Gate | 3 | F1 | 30 | 90 |
| Tuning | 14 arms × 64 configs | F1, F3 | 5 | 4,480 |
| Main (H1, H2, H6) | 14 baselines (B1–B13 incl. B7') + MCP ×3 learners | F0–F9 | 30 | 5,100 |
| Ablations (H3, H4) | 8 | F0–F9 | 30 | 2,400 |
| Sweeps | MCP + best 3 baselines | F1 (+F0) | 30 × 25 points | 3,000 |
| Background-loss × fault-loss (claim 2) | MCP, B3, B7, B7', B11 | F1 (+F0 per level) | 30 × 16 points (+ 4 F0 levels) | 3,000 |
| Non-stationarity (H4, H5) | MCP ×3 + oracles | held-out configs × F1, F3, F5 | 30 | 720 |
| Tier-2 hardware | MCP, B3, B7, B7', B9, B11 | ★ faults + F0 | 10 | 420 |
| Tier-2 H7 (frozen controller) | MCP | F1 ★, F6 ★ | 10 | 20 |
| Tier-2 rxe pre-test (H20) | no measurement | F0 | 10 | 10 |

Total ≈ 18,400 simulated runs (v1.1; was 14,350 at v1.0). At an estimated 2–6 min per run on the lab servers this is
~1,300 core-hours; feasible on Vision/Hulk (72 cores each), subject to HURDLES H18 (the
per-seed cost of the Llama trace is unmeasured and may exceed the 6 min estimate).

---

## 12. Analysis plan (fixed before data collection)

1. Gate experiment → CV, ρ, censor fraction → confirm or amend seed count (§6.5).
2. Tuning → freeze `conf/tuned/*.yaml`.
3. Main block → H1 (log-rank vs best baseline, then vs each), H2 (dominance per budget level),
   H6 (TOST). Holm across {H1, H2, H3, H4, H6, H7} once all six p-values exist (H7 arrives from Tier-2, step 7).
4. Ablations → H3, H4.
5. Non-stationarity block → H5 (descriptive regret), H4 confirmation.
6. Sweeps → descriptive figures; background-loss × fault-loss block → claim (2) test vs B7'.
7. Tier-2 → rxe pre-test floor first (gates all NIC-evidence claims); then H7 (fast-loop
   reaction time, frozen controller); then calibration KS, prediction-band check, MCP vs
   B7/B7' on-silicon CIs, primitive cost table.
8. Everything not listed above is **exploratory** and labelled as such in the paper.

Analysis is implemented in `paper/analysis/analysis.ipynb` and `paper/analysis/*.py`; every
figure and table in the paper is regenerated by `make figures` from the run logs with no manual
step. Numbers in the paper text are pulled from `paper/analysis/results.json` by macro.

---

## 13. Reproducibility checklist

Every reported number is traceable to (config, seed, commit). The following are recorded in
`outputs/<block>/<run>/manifest.json` at run start and checked by `make verify-manifests`:

- [ ] `mcp` repository commit hash; `git status` clean (dirty tree aborts the run)
- [ ] htsim fork commit hash; ATLAHS and Chakra converter commit hashes
- [ ] Chakra trace file name, Zenodo record id, and SHA256
- [ ] Resolved config (`conf/*.yaml` after overrides) and the tuned-config hash
- [ ] Master seed and the four stream ids
- [ ] Python version, `uv.lock` hash, `pip freeze` snapshot
- [ ] Hostname, CPU model, kernel version
- [ ] Calibration distribution files and their SHA256 (Tier-1 runs after calibration)
- [ ] Common inference layer hash (`conf/infer/frozen.yaml`) equal to the frozen value (§3.3)
- [ ] **Tier-2 only:** rxe-under-spraying pre-test result file and its SHA256 (§9.2); the
      §7.4 update rule's P4 source hash (must be non-placeholder before any Tier-2 run)
- [ ] **Tier-2 only:** Intel SDE version (9.13.2 expected), `bf-p4c` version string, P4 source
      SHA256 and compiled `*.tofino` bundle SHA256, resource report archived, bfrt control
      script hash, Tofino firmware/`bf_switchd` build id, Agilio firmware version and driver
      (`ethtool -i`), `rdma_rxe` kernel module version, `perftest` version, DPDK/TRex version,
      NIC observer (XDP object) SHA256, host kernel versions on Vision and Hulk
- [ ] Run start/end timestamps and wall-clock duration
- [ ] `paper/analysis/analysis.ipynb` executes end-to-end (`make figures`) from the logs and
      reproduces every figure and `results.json` byte-identically (bootstrap RNG seeded)
- [ ] Released artifacts: htsim fork, P4 program, controller, RoCEv2 collective pcaps, and the
      run manifests, each with a version tag matching the paper's stated commit

---

## 14. Amendment log

| Date | Section | Change | Reason |
|---|---|---|---|
| 2026-08-25 | — | Document frozen at v1.0 | Initial pre-registration (M1) |
| 2026-08-25 | header | Version 1.1; in-place amendment permitted once, pre-build | All v1.1 changes respond to `docs/PRE-REVIEW.md` before any block has run; no result existed to be biased |
| 2026-08-25 | §0 | Added falsification condition (d): A7 within CI of full MCP on H1 ⇒ data-plane loop is not the contribution; H7 failure triggers the same verdict | PRE-REVIEW R1 |
| 2026-08-25 | §0 | Added claim (2) conditionality: must beat B7' SprayCheck-L at every non-zero background-loss level | PRE-REVIEW §4 |
| 2026-08-25 | §1 | Added H7 "fast-loop reaction latency" (µs on silicon, ≥ 100× faster than slow-loop install, frozen-controller measurement, specificity check) | PRE-REVIEW R1 |
| 2026-08-25 | §1 | H2 restated as Pareto dominance on the (F1, $\beta_{probe}+\beta_{tag}$) plane; SRAM/stages/NIC-reads/CPU reported as side constraints, not tested | PRE-REVIEW R3 |
| 2026-08-25 | §1, §6.4, §12 | H5 demoted to descriptive (arbitrary 70 % bar removed); Holm family now {H1, H2, H3, H4, H6, H7} | PRE-REVIEW §4 |
| 2026-08-25 | §1 | H6 renamed "Simulated CCT overhead"; stated as a simulation-only result | PRE-REVIEW §3 |
| 2026-08-25 | §1, §3.1 | B1 excluded from the H1 "best baseline" set wherever it is infeasible at $B$ | PRE-REVIEW §4 |
| 2026-08-25 | §2.3 | Budget $B$ redefined: $\beta_{tag}$ includes NIC evidence packets and collector-port mirror bytes wherever they traverse a fabric or collector link | PRE-REVIEW R3 |
| 2026-08-25 | §3.1 | B5 renamed to drop CPRANT's name (mechanism unverified) | PRE-REVIEW §4 |
| 2026-08-25 | §3.1, §11 | B7 split into B7 (as-published) and B7' SprayCheck-L (background-loss-aware threshold, warm-up estimate over $M$ iterations); both run in Tier-1 and Tier-2 | PRE-REVIEW R2, §4 |
| 2026-08-25 | §3.1 | B11 NIC-only restated as an aggregating arm (per-path evidence pooled across all NICs at a controller, no switch state); "MetaRoCE-like" label dropped on hardware | PRE-REVIEW §4 |
| 2026-08-25 | §3.1 | Added B13 OPP-style probe duplication with in-network dedup, labelled "abstract-only reimplementation", with a decision rule: re-implement if the full paper appears before tuning, else claim (1) is worded against "OPP-style" not OPP | PRE-REVIEW §2 housekeeping |
| 2026-08-25 | §3.3 (new), §3.2, §13 | Common inference layer: one frozen Beta-Binomial/Normal-Gamma + CUSUM top-$k$ localizer shared by all arms; arms differ only in which samples arrive; test file and manifest hash added | PRE-REVIEW R3 |
| 2026-08-25 | §4.2, §11 | Background-loss sweep factor (0, 1e-5, 1e-4, 1e-3; random-drop and congestion modes), crossed with fault loss for F1; per-level F0 runs | PRE-REVIEW §4 |
| 2026-08-25 | §7.4 (new) | Placeholder for the in-switch attention update rule with the review's candidate SALU form; marked BLOCKING before P4 step 5 (HURDLES H22); A6/A7/H7 pending on it | PRE-REVIEW R1 |
| 2026-08-25 | §9.2 | (b) now the fast-loop reaction-time measurement; on-silicon MCP vs B7/B7' added to (d); "3-level" and "testbed" excluded from hardware claims; NIC evidence channels on hardware stated (RTT via host XDP; PSN gaps reorder-confounded; no ECN) | PRE-REVIEW R2, §3, §4 |
| 2026-08-25 | §9.2, §12, §13 | rxe-under-spraying pre-test (NAK/retx floor, all-reduce completion) made a prerequisite for any NIC-evidence claim from hardware (HURDLES H20) | PRE-REVIEW R2 |
| 2026-08-25 | §11 | Run counts updated for the added arms and blocks (≈ 18,400 runs) | consequence of the above |
| 2026-08-26 | §10 (v1.2) | Gate as run: ATLAHS MoE8x8B-64 trace, 1024-NIC htsim fat tree, 100 ms epoch / one-iteration horizon, budget 4 % after 2 % was TOO HARD, faulty uplink randomized per seed, TTL_obs from first observable drop (H27), probe evidence window and transport RTO stated | see Amendment v1.2 below |
| 2026-08-26 | §7.4 (v1.3) | In-switch attention update rule FROZEN (H22): per-path {attn, clean} SALU word, saturating exceedance bump by k_up (a_max = 65535), decay by 1 every n_clean clean samples down to a_min, probabilistic gate attn/65536 quantized to attn[15:8]/256 via a 256-row TCAM table (a gateway cannot compare two runtime fields); exceedance sources = NIC evidence (loss_q/rtt_q thresholds) and previous-hop CSIG worst_qdepth threshold; P4 source sha256 232b7355fe58c67c (p4/reports/step5.md) | see Amendment v1.3 below |
| 2026-08-27 | §1 H7 (v1.4) | τ_fast redefined as the ramp back-extrapolation (attention rises exactly k_up per exceeding packet, so the first exceeding packet's time is recovered from the attn-vs-time ramp in the mirrored copies); τ_slow = a FULL-SWEEP epoch (read all reg_attn slots from hw + counter sync/read + write all slots). The v1.1 τ_fast ("first gated mirror after the first dropped/exceeding packet") is 0 by construction for CSIG evidence because the evidence packet is itself gated post-update. **Post-hoc for F6** (12 reps already collected under v1.1 and re-analysed); pre-registered for F1 (not yet run) | see Amendment v1.4 below |
| 2026-08-27 | §1 H7 status | H7 measured on silicon for BOTH faults under v1.4 (p4/reports/h7-timing-F6.md, h7-timing-F1.md, 12 reps each): F6 supported (τ_fast 97 µs, ratio 907, CI 452–1143); **F1 fails** (τ_fast 10.1 ms, CI 10.10–10.13; ratio 8.8, CI 8.6–9.1; specificity 0/15) because silent loss leaves no in-band evidence — the F1 fast loop is the NIC-side producer (nic/evidence_probe.py, RTT-tail-bounded window ≥ 2 ms). H7 as pre-registered ("≥ 10 reps × 2 faults, ratio > 100") is therefore NOT met; the paper reports the split result (§0 outcome (d) applies to F1 only) | reported, not suppressed |
| 2026-08-27 | §3.3 (frozen localizer constants, v1.5-draft) | controller/infer.py implemented (sha256 f1957bc9…): Beta(1,1)/Normal-Gamma posteriors with a per-epoch forgetting factor ρ = 0.9 (a fully cumulative posterior cannot act as a change detector), two-sided CUSUM with k_loss = 2.5e-4, k_lat = 10 µs, h = 4.0, baseline EWMA γ = 0.05 after a 10-observation warm-up, uniform-prior fractional de-aggregation path→links, atomic elements only in the suspect ranking. First co-simulation runs show the per-element warm-up makes sparse-probing arms (budget 4/128) blind on a 55-epoch trace while budget 32 detects at epoch 49; a pooled (fabric-wide) baseline is being added as a config switch. The localizer is NOT yet frozen (freeze happens before the tuning block); this row records the candidate constants | pre-tuning, not yet frozen |
| 2026-08-27 | §10 → §14 operating point FROZEN (v1.2 gate, 90/90 runs) | MoE8x8B-64 on the 1024-NIC fat tree, 100 ms epochs, one-iteration horizon (36 epochs), budget 4 % (41/1024), F1 = 1e-4 silent loss on a per-seed random agg→core uplink, onset U[0.3, 0.9] s, seeds 1000–1029. Results: oracle TTL 8 [5, 9] (TTL_obs 0), uniform 15 [10, 22] 3 % censored (TTL_obs 9 [2, 16]), random 23 [16, 27] 37 % censored (TTL_obs 14 [7, 21]); §6.5 inputs: CV(log TTL) uniform 0.18 (onset) / 0.51 (obs), ρ(uniform, random) = 0.05 (n = 18 / 15). Verdict OK under both TTL definitions; this point is the Tier-1 default until the tuning block | sim/gate/results_real_v12_summary.txt; runs at 62 min / 21.5 GB each |
| 2026-08-27 | §3.3 localizer constants (pre-freeze) | Loss change detector = upper-sided binomial-LLR CUSUM; `delta_loss` (minimum detectable shift) set to the frozen F1 rate 1e-4 (a larger delta makes the LLR drift negative at the fault rate and the fault can never alarm; measured on the Tier-1 pilot); h = 6.5 nats; pooled baseline. Consequence: a single observed drop (4.6 nats) cannot alarm — ≥ 2 drops in a probe window are required, which busy Tier-1 links provide (~3 expected per 30k-packet epoch). The LULESH-128 rehearsal (COSIM-RESULTS.md) was run at delta 1e-3 and is not comparable | pre-tuning, not yet frozen |
| 2026-08-27 | Tier-1 PILOT at the frozen §14 point (NOT the pre-registered main block; 30 seeds paired with the gate arms) | cusum (localizer suspects + round-robin) ≡ uniform per seed (15 [10, 22]); MCP with the LULESH-tuned configuration (dlinucb, α 0, coverage floor 0.75; no Tier-1 tuning) 18 [14, 24], slower than uniform in 23/30 seeds (sign test p = 0.005); oracle 8. H1 (≥ 30 % lower median TTL than the best baseline) is NOT met by this configuration. Reading: with one stationary silent-loss fault, time-to-localize is decided by the first probe of the faulty link after onset; a learner must beat coverage per probe slot. The §3.2 Tier-1 tuning block has not been run (≈ 64 configs × 5 seeds × 1 h). Localizer provenance: infer.py 116ffc9f with delta_loss 1e-4, pooled | sim/gate/results_tier1_cosim_summary.md; reported, not suppressed |
| 2026-08-27 | v1.5 — detector provenance, budget currency, retirements, replacement hypotheses H8/H9 (panel review, docs/review/) | Every published TTL was computed by the simulator's ratio rule (`mcp.cpp:133-152`), not the frozen localizer §3.3 names; re-issued under the pre-registered detector (MCP 19.0 KM vs cusum/uniform-schedule 20.0, paired 11/19, p = 0.20 — the arms are indistinguishable and no arm meets H1). Medians now read off the KM curve (§2.1). One budget currency. H1, H3, H5, H7-for-F1 and the 18,400-run matrix retired on the record; H8/H9 added | see Amendment v1.5 below |
| 2026-08-28 | v1.6 — §3.3 warm-up defined in observed evidence; replay determinism and success semantics | The frozen localizer held an element in warm-up for `baseline_warmup_epochs = 10` **update calls**. Warm-up is a statement about how much evidence stands behind the baseline, so counting calls penalised any schedule that reads less often while carrying the same packets per read: the H8 in-band arm collecting every 4th epoch saw 11 drops in 99,704 packets and still reported CUSUM 0.00. Warm-up is now `baseline_warmup_packets = 1e5` observed packets (= 10/δ, so the baseline's own noise ~1/N = 1e-5 is an order below the shift under test) and `baseline_warmup_latency_samples = 10` latency samples. infer.py sha256 `0a989aaf…`; every replay result re-issued under it | see Amendment v1.6 below |

Amendments are appended only. An amendment after the corresponding block has started running
is flagged "post-hoc" in the paper.

### Amendment v1.2 — 2026-08-26 — §10 gate experiment as actually run (gate rehearsal + real gate)

**Reason.** The §10 specification could not be executed as written: no "NeMo Mixtral" Chakra
trace exists in the ATLAHS collection; the available Mixtral-class GOAL traces are one training
iteration long (3.5 s), so a 120 s horizon with a 1 s epoch is not reachable; and htsim's
memory (21.5 GB per run, HURDLES H26) bounds the fleet width. Two confounds surfaced in the
first runs and are corrected here (HURDLES H27 and the sweep-order artifact).

| §10 item | v1.1 text | v1.2 (as run) |
|---|---|---|
| Topology | k = 16 fat tree, 1024 NICs | htsim `fat_tree_1024_1os.topo`: 1024 NICs, 16 pods × 8 agg × 8 core, 1024 agg→core uplinks, 200 G links |
| Workload | NeMo Mixtral Chakra trace (Zenodo) | ATLAHS `MoE8x8B_N16_GPU64_TP1_PP8_DP8_EP1_7B_BS32` GOAL trace (`moe.bin`, 523 239 908 B, SHA256 `b00e6c76…17b7f7`, `sim/traces/moe8x8b_n16/SOURCE`); 64 ranks spread over all 16 pods with rank stride 16; one iteration = 3.52 s |
| Fault | F1 on one spine uplink, onset U[10, 30] s | F1 silent 1e-4 Bernoulli loss on **one agg→core uplink drawn per seed** (deterministic from the seed; recorded in `seed<N>.fault`), onset U[0.3, 0.9] s per seed (`seed<N>.onset`) — same 8–25 % position in the horizon as v1.1 |
| Arms / budget | B3, B9, B12 at B = 2 % | same arms; **B = 4 % (41 of 1024 uplinks)** after the v1.1 point (2 %) was TOO HARD by the §10 rule (uniform censored 15/15 — its 52-epoch sweep exceeds the horizon) |
| Epoch / horizon | 1 s / 120 s | **100 ms / one iteration (≈ 36 epochs)** |
| Seeds | 30 (1000–1029) | unchanged |
| TTL definition | from fault onset | reported **both** from onset and from the first *observable* drop on the faulty link (`TTL_obs`, from the per-epoch link counters); the abort/tighten rule is applied to `TTL_obs`, because the MoE iteration is compute-dominated and the fabric is idle outside three communication bursts (896 of 1024 uplinks carry no packets in epoch 10), so from-onset TTL measures the collective schedule, not the policy (H27) |
| Probe evidence window | (unspecified) | a probed link's drop/tx ratio is computed over the interval since that link was last probed; verdict = argmax over the probed set if ratio > 1e-5 |
| Transport | (unspecified) | UEC, per-packet oblivious spraying, min RTO 300 µs (`-rto_min_us`; H25 — the queue-derived default disables retransmission at the gate's queue size) |
| Outputs | as v1.1 | as v1.1 plus `TTL_obs`; overhead units deferred to the main block |

**Evidence so far (n = 15 per arm at 4 %, faulty link fixed at US0→CS0, from-onset TTL):**
oracle 11 [10, 12] epochs, random 27 [17, 29] (33 % censored), uniform 20 [19, 21] (0 % censored),
ρ(B3, B9) = 0.20. The v1.2 run (randomized link, `TTL_obs`) supersedes these numbers for §6.5.

### Amendment v1.3 — 2026-08-26 — §7.4 in-switch attention update rule, frozen (closes HURDLES H22)

The candidate rule of §7.4 is fixed as follows and implemented in `p4/mcp_fabric.p4` step 5
(source sha256 `232b7355fe58c67c…`, compiled 0 errors on SDE 9.13.1 and on the switch's 9.13.2,
8 ingress stages; `p4/reports/step5.md`). Per path $p$ (index = path id, 256 slots) one 32-bit
SALU word holds `attn[p]` (16 bit) and `clean[p]` (16 bit). Exactly one update runs per packet:

- **Exceedance packet** for $p$ (a NIC evidence packet whose `loss_q` or `rtt_q` is in the
  controller-installed exceedance range, or a data packet whose previous-hop CSIG tag carries
  `worst_qdepth` in the exceedance range): `attn = attn |+| k_up` (saturating add), `clean = 0`,
  so $A_{max} = 65535$ is fixed by construction (a register's actions share four parameter
  slots; a separate cap parameter did not fit).
- **Clean sample** (every other packet on $p$): `if (clean >= n_clean−1 && attn > a_min)
  {clean = 0; attn −= 1} else if (clean >= n_clean−1) {clean = 0} else {clean += 1}`.
- **Gate:** measure the packet iff `rnd_attn < attn`, evaluated as a 256-row TCAM table on
  `attn[15:8]` (bf-p4c does not allow a gateway compare of two runtime fields), i.e. with
  probability $\lfloor attn/256 \rfloor / 256$.
- **Controller-set constants** (`RegisterParam`s, written once per epoch at most): `k_up` = the
  attention-gain tuning knob of §3.2; `a_min`, `n_clean` fixed for the study at 256, 4096 unless
  the tuning block (§3.2) says otherwise, and the two exceedance ranges. (Corrected the same day,
  before any run: an earlier wording of this amendment named a `bump_cap` parameter.)
  Initial `attn` per path is seeded by the controller (`A0`, §5.7).
- **Evidence packets are ungated** (open decision iv): they update attention and are dropped at
  the switch; they never enter the fabric.

Open decisions (i)–(iv) of §7.4 are thereby closed: (i) signals = NIC evidence + previous-hop
CSIG queue depth (Tofino 1 has no ingress queue depth); (ii) packing = one 32-bit word, two
16-bit halves; (iii) constants as above; (iv) ungated. Ablation A6 and hypothesis H7 are now
defined against this rule.

### Amendment v1.4 — 2026-08-27 — H7 timing definitions (Philip's decision; F6 post-hoc, F1 pre-registered)

**Reason.** The first silicon run of H7 for F6 (`p4/reports/h7-timing-F6.md`, 12 reps) showed the
v1.1 definition of $\tau_{fast}$ to be degenerate on the implemented pipeline: the ingress order is
`tbl_exceed_csig → tbl_attn → tbl_gate`, so the packet carrying threshold-exceedance evidence is
gated under the attention its own evidence just raised — evidence and reaction are the same packet
and $t_{react} - t_{evid} \le 0$ in 12/12 reps.

**Definitions from v1.4 on.**

- $\tau_{fast}$ **(ramp back-extrapolation).** Attention on a path rises by exactly `k_up` per
  exceeding packet (§7.4), so `mirror_h.attn` in the switch-timestamped mirrored copies is a
  counter of exceeding packets. Fit the attn-vs-`tstamp` ramp on the faulty path between the first
  copy with `attn > A0` and saturation; $t_{evid}$ is the back-extrapolated time at which the ramp
  crosses $A_0$ (the first exceeding packet); $t_{react}$ is the first copy with `attn > A0`;
  $\tau_{fast} = t_{react} - t_{evid}$. All timestamps are the switch's `ingress_mac_tstamp`
  (no host-clock calibration). For F1 the first dropped packet's fault-mirror timestamp (sid 3)
  is reported alongside as a check.
- $\tau_{slow}$ **(full-sweep epoch).** From the switch's own control plane: read every
  `reg_attn` slot from hardware (all pipes) + `SyncCounters` and read of `tbl_vlink`/`tbl_fail`
  + the decision + write every `reg_attn` slot, timed end to end. The minimal single-slot
  read/write latency is reported as a secondary figure but is not the H7 comparator.
- Success criterion, reps, specificity and the sign test are unchanged from v1.1.

**Status.** F6: supported under v1.4 — median $\tau_{fast}$ 97.4 µs (BCa 95 % CI 67.9–215.1 µs),
$\tau_{slow}$ 88.8 ms (86.4–92.1), paired ratio median 907 (452–1143), sign test 12/12
($p = 2.4\times10^{-4}$), specificity 0/13 healthy path-instances reacted. **Post-hoc**: these 12
reps were collected before this amendment. F1: pending the NIC evidence producer (`nic/`), to be
run under v1.4.

### Amendment v1.5 — 2026-08-27 — detector provenance, budget currency, retirements, replacement hypotheses

Following an eight-reviewer panel with a literature sweep and an adversarial pass
(`docs/review/PANEL-REPORT.md`, `PLAN.md`, `EDITOR-NOTES.md`, `LITERATURE.md`), the following
are amended **before** any further data collection.

**1. Detector provenance (defect, corrected).** §3.3 requires one frozen localizer for every arm.
That held for what the *policies* consumed and failed for what the *metric* used: `analyze_real.py`
read the simulator's `correct` column, written by an argmax(drop/tx) ratio rule in
`sim/htsim/htsim/sim/mcp.cpp:133-152`. `analyze_real.py` now computes TTL from the frozen
localizer's own verdict (`--detector localizer`, from `<seed>.bridge.csv`), and reports the ratio
rule beside it. Re-issued pilot (`sim/gate/results_tier1_cosim_summary.md`, 30 paired seeds):

| arm | ratio rule (as published) | frozen localizer (§3.3) |
|---|---|---|
| MCP | KM 19.0, 1/30 censored | **KM 19.0, 2/30** |
| cusum (≡ uniform schedule) | KM 16.0, 1/30 | **KM 20.0, 6/30** |
| paired MCP vs uniform schedule | 7 faster / 23 slower, p = 0.005 | **11 / 19, p = 0.20** |

The correct statement is that the arms are **statistically indistinguishable** and **no arm meets
H1**; the earlier "MCP is significantly slower" was an artifact of the wrong detector. Open-loop
arms (uniform, random, oracle) have no localizer verdict recorded and require offline replay.

**2. Medians.** All medians are now read off the Kaplan–Meier curve as §2.1 requires; the raw
median is reported beside it (they differ by up to 1 epoch here).

**3. Budget currency.** The tested budget is **one** unit: $\beta_{probe} + \beta_{tag}$ in bytes
over fabric capacity (§2.3). SRAM KB, MAU stages, mirror/collector bytes and control-plane reads/s
are reported beside every arm as side constraints. "4 % = 41 of 1024 uplinks" (v1.2) is retired as a
*budget*: link count is not one of the §2.3 units. Arms that inject no packets report zero.

**4. Replay soundness (new finding, verified).** The per-link counter logs are byte-identical
across all five arms for every seed (120/120 arm-seed pairs). At Tier-1 the measurement policy does
not perturb the fabric: $\beta_{probe} = \beta_{tag} = 0$ for every budgeted arm, H6 (CCT overhead)
is untestable for probe-free arms at Tier-1, and **offline replay of any read schedule against the
recorded counters is exact**, not an approximation. The 18,400-run matrix therefore existed largely
to regenerate a trace that is identical for every arm.

**5. Retired on the record** (reported as outcomes, per §0's "outcomes (a)–(d) are reported, not
suppressed"):
- **H1 as stated** — not met by any arm under either detector at the frozen point; the operating
  point is evidence- and coverage-bound (§0 outcome (a) applies).
- **H3** — the shadow price is provably pinned at zero in htsim (usage ≤ cap is enforced before the
  dual step) and there is no multi-resource wiring on the hardware path: no valid test exists on
  either tier.
- **H5** (already descriptive) and the **18,400-run matrix** (§11), superseded by replay + one
  measured figure.
- **H7 for F1** — structural: silent loss has no in-band evidence in the built system, so its "fast
  loop" is a host timer (10.115 ms, ratio 8.8). H7 stands **only** for the congestion class, and
  the run labelled F6 was a TM max-rate shaper, i.e. §5.2's **F5 congestion hotspot** — the
  supported result is relabelled accordingly.
- From the **contribution set**: "attention", "bandit", "shadow prices", the CSIG-style tag and the
  NIC evidence producer. They remain in the artifact and the appendix, not in the claims.

**6. Replacement hypotheses.** The H1–H7 namespace is full; these are **H8** and **H9** (the
HURDLES file's H-numbers are a separate namespace):
- **H8 (coverage-gap attainment).** Detection delay decomposes into evidence time plus coverage
  time. A link-local in-band invariant (per-link sequence gap, or an RFC 9341 alternate-marking
  counter diff) removes the coverage term: median TTL_obs ≤ 1 epoch and packets-on-the-faulty-link
  to localization within a factor 2 of the $1/p$ information floor, at $p \in \{10^{-4}, 10^{-3},
  5\times10^{-3}, 1.5\times10^{-2}\}$, with false-localization rate below the fault event rate.
  *Fails if* the false-gap rate at F0 exceeds the fault event rate, or the invariant needs more than
  the §8 stage/SRAM budget.
- **H9 (no counter-computable schedule closes the gap).** Over the recorded per-link counters, no
  schedule computable from those counters (uniform, load-gated, threshold-gated, greedy-information,
  LinUCB, Thompson/random) reaches within 30 % of the oracle's delay, across a five-point budget
  sweep and under single, multiple and moving faults. *Fails if* any such schedule closes ≥ 30 % of
  the oracle gap with paired p < 0.05 — in which case the allocation thesis is revived and H1 reopens.
- **H7′ (reaction, restated).** The in-switch gate's reaction is one pipeline pass; the reported
  metrics are ADD versus pre-change duty cycle at a fixed false-alarm rate, with $\tau_{slow}$
  reported for **both** the minimal single-slot controller path (2.20 ms) and the full-sweep epoch
  (88.8 ms). The v1.4 ratio is retained only with both denominators stated.

**7. Hygiene.** `conf/infer/frozen.yaml` records `baseline_mode: per_element` while every run passes
`pooled`; the runs' mode is authoritative and the file is corrected. The LULESH rehearsal
(`sim/gate/COSIM-RESULTS.md`) was produced with localizer hash `116ffc9f` and `delta_loss = 1e-3`,
neither reproducible from HEAD: those results are marked **superseded** and are not cited in the paper.

### Amendment v1.6 — 2026-08-28 — warm-up is evidence, not cadence

**Reason.** §3.3 froze `baseline_warmup_epochs = 10`: the CUSUM stayed at zero until the baseline
owner (the pool, in the `pooled` mode every run uses) had been *updated* ten times. An update call
is not a unit of evidence. A schedule that reads every fourth epoch accumulates four epochs of
packets per read, so it carried the same evidence per call and four times the evidence per warm-up
— yet it was held in warm-up four times as long. The defect is not neutral across arms: it
penalises exactly the low-cadence collection that the H8 in-band invariant proposes, and it was
found because the `inband_sync` arm (per-link verdicts collected every 4th epoch) reported CUSUM
0.00 after observing 11 drops in 99,704 packets on the faulty link.

**Change.** Warm-up is counted in observed evidence:

| knob | v1.5 | v1.6 |
|---|---|---|
| loss | `baseline_warmup_epochs: 10` (update calls) | `baseline_warmup_packets: 1e5` (packets the baseline owner has observed) |
| latency | the same 10 update calls | `baseline_warmup_latency_samples: 10` (individual latency samples) |

`1e5 = 10/δ` at the frozen `delta_loss = 1e-4`: the baseline's own estimation noise (~1/N = 1e-5)
is then an order of magnitude below the shift the LLR is asked to detect. `ElementState` gained
`n_pkt_loss` and `n_samp_lat`; `n_obs_loss`/`n_obs_lat` remain and still gate
`alarm_min_observations`. Localizer hash `be12e7b2…` → `0a989aaf…`.

**Effect on the published replay results** (30 gate seeds, frozen budget 41, h = 6.5, KM median TTL
from onset, censored in parentheses):

| schedule | v1.5 (call-counted warm-up) | v1.6 (packet-counted) |
|---|---|---|
| uniform | 20.0 (6) | **18.0 (4)** |
| random | 22.0 (13) | 22.0 (13) |
| load-gated | 24.0 (3) | 24.0 (3) |
| threshold-gated | 20.0 (1) | 20.0 (1) |
| greedy-information | 22.0 (7) | 22.0 (7) |
| oracle | 10.0 (0) | **9.0 (0)** |
| in-band (H8) | 10.0 (0) | **9.0 (0)** |
| in-band, collected every 4th epoch | never localized (blind) | **10.0 (0)** |

Every arm gains 0–2 epochs of warm-up that was previously wasted, and the low-cadence in-band arm
stops being an artifact. Wrong-link alarms remain 0/30 seeds for every arm at h = 6.5 on these
clean-background runs; the F0 background-loss block (BG_LOSS = 1e-4, no fault) is the false-alarm
test and is still running. **The conclusions are unchanged**: no counter-computable schedule closes
any of the oracle gap (H9 not tripped), and the link-local in-band invariant closes all of it.

**Replay determinism and success semantics (same date, same commit).** Three defects in
`sim/gate/replay.py` fixed alongside, because they affect what the H8/H9 numbers mean:

1. Semi-synthetic fault identities were drawn from `random.Random(hash(stem))`. Python salts
   `hash` of a string per process, so the multi-fault scenarios were not reproducible between runs
   of the same command. They now use `scenario_seed()` = CRC-32 of the stem and role.
2. Multi-fault success was implicitly "the recorded fault ranked first, distractors ignored".
   The objective is now explicit and reported in the header: `any` (top-ranked element is any
   injected fault), `all` (every injected fault has been top-ranked), `original` (the recorded
   fault only, semi-synthetic ones are distractors). Moving-fault semantics are deterministic and
   the vacated link becomes healthy at the move epoch.
3. The oracle-gap summary named the best arm among *all* non-oracle arms, which let the in-band
   arm answer a question about counter-computable **schedules**. The H9 gate now ranks only
   counter-computable schedules; the in-band arms are reported separately as a different
   observability class.

A wrong-link false-alarm count (anomaly epochs whose top-ranked element is no injected fault) is
now recorded per arm, so the ADD/false-alarm axis M4 needs is produced by the replay itself.

