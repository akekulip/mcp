# PREREG — Pre-registered evaluation protocol

**Project:** MCP — "The data plane decides what to measure"
**Version:** 1.0, 2026-08-25 (frozen at commit `<fill at freeze>`; any later change is an
amendment appended in §14 with date and reason, never an edit in place)
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
result. Outcomes (a)–(c) are reported, not suppressed.

**What is not claimed.** GPU-scale CCT numbers, lossless (PFC/DCQCN) fabrics, hardware RDMA,
and multi-switch skew are outside the claim set (§9).

---

## 1. Hypotheses, success criteria, and tests

All comparisons are at *equal measurement budget* (§2.3) after *equal tuning budget* (§3.2).
Primary hypothesis is H1; the rest are secondary. Family-wise error is controlled with Holm's
step-down over the six hypotheses at α = 0.05 (§6.4). Effect sizes are reported for every
hypothesis regardless of significance.

| ID | Hypothesis (H1 = alternative) | Pre-specified success criterion | Primary test | Effect size |
|---|---|---|---|---|
| **H1** Faster localization | MCP's time-to-localize (TTL) is lower than every fixed-policy baseline at equal budget | Median TTL reduction ≥ 30 % vs the *best* baseline on the fault catalogue (§5), AND Holm-adjusted p < 0.05, AND 95 % bootstrap CI of the median ratio excludes 0.70 from above | Log-rank (Mantel–Cox) on right-censored TTL, stratified by fault type; confirmatory paired Wilcoxon on log-TTL per seed | Hazard ratio with 95 % CI; Cliff's δ on uncensored pairs; median ratio with BCa CI |
| **H2** Pareto dominance | On the (F1, overhead) plane, MCP's curve dominates every baseline's curve | For every budget level in the sweep {0.5, 1, 2, 5, 10, 20} %, MCP's localization F1 ≥ best baseline's F1 at ≤ its overhead in each of the five overhead units of §2.3 (weak dominance), with strict dominance in ≥ 4 of 6 budget levels | Per-budget-level paired comparison of F1 (Wilcoxon signed-rank across seeds); dominance declared only if no unit shows MCP overhead higher than baseline by more than the CI | Hypervolume gain of the dominated region (normalized), with bootstrap CI |
| **H3** Shadow prices are necessary | Removing shadow prices (ablation A1) degrades TTL or violates budgets | Ablation A1 has median TTL ≥ 15 % higher than full MCP OR budget-violation rate ≥ 5× full MCP, Holm-adjusted p < 0.05 | Log-rank (TTL); two-proportion z-test on violation rate | HR; risk ratio of violation |
| **H4** Context is necessary | Removing the context vector (ablation A2) degrades TTL under non-stationary workloads | On the held-out parallelism configurations (§8.3), A2 median TTL ≥ 15 % higher than full MCP, Holm-adjusted p < 0.05 | Log-rank on TTL, stratified by parallelism config | HR; Cliff's δ |
| **H5** Near-oracle | MCP attains ≥ 70 % of the oracle's regret-free reward | Cumulative regret vs the *dynamic* oracle (§8.2) ≤ 30 % of the oracle's cumulative reward over the run, averaged over seeds, with the upper 95 % CI bound also ≤ 30 % | One-sided bootstrap test on mean normalized regret | Normalized regret with CI |
| **H6** Negligible CCT overhead | MCP's measurement traffic and actions do not slow the collective | CCT overhead ≤ 1 % (median over seeds and traces) relative to the no-measurement run, AND p99 straggler lag overhead ≤ 2 %, with the upper 95 % CI bound ≤ 1.5 % and ≤ 3 % respectively | Equivalence test (TOST) with margin 1 % on log-CCT ratio | Median CCT ratio with CI |

Falsification of H1 by the *best* baseline is a stricter bar than by the *mean* baseline; we
commit to the stricter one. If a baseline ties MCP within CI on H1, the paper reports it as a
tie and the contribution shifts to H2–H4.

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
| INT/tag bytes | Bytes of INT headers, CSIG-style tags, or mirrored/truncated copies added to production packets per second, same normalization | $\beta_{tag}$, fraction of capacity |
| Tofino SRAM and stages | SRAM (in 16 KB units) and MAU stages consumed by the measurement primitives, from the bf-p4c resource report (`*.resources.json`); Tier-1 uses the cost model calibrated from that report | SRAM units; stages |
| NIC reads/s | Counter/register reads issued to the NIC per second (Agilio: XDP map lookups or firmware counter reads; simulated equivalently) | reads/s |
| Host CPU | Fraction of one core consumed by the collector/controller per 1k monitored endpoints, measured with `perf stat` (Tier-2) or by the calibrated cost model (Tier-1) | core-fraction |

**Budget.** The "measurement budget" $B$ that all arms share is defined as $\beta_{probe} + \beta_{tag} \le B$ (bandwidth), with SRAM/stages/NIC-reads/CPU reported as side constraints
that no arm may exceed by more than 10 % of MCP's usage. Sweep values: $B \in$
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
| B1 | Fixed INT, all flows | HPCC-style always-on INT | Nothing; every packet carries a tag | Tag size (8/12 B); which fields | Overhead is what it is; will exceed small budgets and is then reported as "infeasible at $B$" rather than silently scaled |
| B2 | INT 1/N | Sampled INT | Nothing adaptive; tags every N-th packet per port | $N$ (set so $\beta_{tag} = B$) | Sampling is uniform over packets, hence proportional to load |
| B3 | Uniform probe mesh | R-Pingmesh / Hostmesh | Nothing adaptive; every NIC probes a fixed pinglist at a fixed rate | Probe rate (set to $B$), payload (50 B as R-Pingmesh), timeout (500 ms as R-Pingmesh), pinglist density, anomaly threshold | Localization by probe-path intersection as in Pingmesh |
| B4 | Sketch-only | Switch sketch telemetry | Nothing adaptive; per-port count/loss sketch exported every epoch | Sketch width/depth (within SRAM cap), export epoch | No probes, no tags |
| B5 | Rule-based adaptive sampling | CPRANT / ChameleMon stand-in | Raises sampling rate on ports whose sketch deviation exceeds a threshold, lowers elsewhere, controller-side at epoch cadence | Deviation threshold, up/down multipliers, min/max rate, epoch | The strongest "adaptive but not learned" comparator |
| B6 | FlowPulse | FlowPulse (Technion) | Per-iteration symmetry check of collective flow pairs; flags asymmetric pairs | Asymmetry threshold, window | Uses the iteration clock; no budget knob, overhead reported |
| B7 | SprayCheck round-robin | SprayCheck | Round-robins one prioritized flow across spray paths on a fixed schedule; localizes by path-set difference | Schedule period, number of paths per round | Extended to 3-level topologies and lossy fabrics exactly as its paper says it does not support, to test claim (2) of the plan |
| B8 | DynATOS+-style scheduler | DynATOS/DynATOS+ | Time-divides switch resources among measurement tasks to meet per-task accuracy targets, controller-side | Accuracy targets, epoch, task set | No spraying awareness |
| B9 | Random at equal budget | — | Picks a random subset of paths/ports to measure each epoch, spending exactly $B$ | Subset size (from $B$), epoch | Sanity floor |
| B10 | Round-robin at equal budget | — | Cycles through paths/ports in fixed order, spending exactly $B$ | Cycle order, epoch | Sanity floor; also the "no learning" ablation of the slow loop |
| B11 | NIC-only | MetaRoCE-like | Per-path RTT/ECN/PSN-gap counters on every NIC, always on; localizes by per-path statistics only, no switch involvement | Per-path window, anomaly threshold, number of paths tracked | Tests claim (3): is the NIC sufficient? |
| B12 | Oracle | — | Knows the injected fault and measures exactly the elements needed; upper bound on what the budget can buy | None | Used for H5 regret and as the ceiling on all plots; the *dynamic* oracle re-solves each epoch (§8.2) |

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
- Baselines B1, B12 have nothing to tune; B9/B10 tune only epoch.

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
| Concurrent faults | **1**, 2, 4 |
| Offered load | 30, **60**, 90 % of bisection |

Each sweep point: 30 seeds, full baseline set on the H1 metric only (TTL) plus overhead in all
five units. A full-factorial design is *not* run; interactions are exploratory (§12).

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
- **Regret (H5):** one-sided bootstrap on mean normalized regret against 0.30.
- **Multiple comparisons:** Holm step-down over the six hypotheses (family = H1–H6). Within H1,
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
(§9.2), never for H1–H5 inference.

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

**Claims supported:** H1–H6; all baselines; all ablations and sweeps; coverage vs budget;
regret; multi-fault; 3-level topologies (fat-tree k = 16 → 1024 NICs, k = 24 → 3456 NICs).
**Fidelity limits:** switch cost model calibrated from the bf-p4c resource report, not
measured on Tier-1; host CPU from the cost model; PFC/DCQCN cross-checked on one scenario in
`ns-3-alibabacloud` (reported as a fidelity note, not a result).

### 9.2 Tier-2 — one Tofino 1 + Agilio CX + two hosts, Soft-RoCE, lossy

**Claims supported (and only these):** (a) the measured per-primitive resource cost (SRAM,
stages, PHV) from the compiler report; (b) fast-loop decision latency and slow-loop
decision→install latency on silicon; (c) the calibration distributions of §9.3; (d) that
injected faults F1, F2, F3, F4, F6, F8 on the virtual sprayed fabric are localized by the
hardware loop with TTL inside the calibrated simulator's 95 % prediction band; (e) budgets are
respected on silicon (violation rate). **Not claimed:** coverage at scale, CCT with real GPUs,
multi-switch skew (HURDLES H8), lossless-fabric behaviour. The paper states in the
Implementation section: lossy fabric, software RDMA (`rdma_rxe`), no PFC/DCQCN, single traffic
manager, virtual switches via recirculation (as SprayCheck did).

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
| Tuning | 12 arms × 64 configs | F1, F3 | 5 | 3,840 |
| Main (H1, H2, H6) | 12 baselines + MCP ×3 learners | F0–F9 | 30 | 4,500 |
| Ablations (H3, H4) | 8 | F0–F9 | 30 | 2,400 |
| Sweeps | MCP + best 3 baselines | F1 (+F0) | 30 × 21 points | 2,520 |
| Non-stationarity (H4, H5) | MCP ×3 + oracles | held-out configs × F1, F3, F5 | 30 | 720 |
| Tier-2 hardware | MCP, B3, B9, B11 | ★ faults + F0 | 10 | 280 |

Total ≈ 14,350 simulated runs. At an estimated 2–6 min per run on the lab servers this is
~1,000 core-hours; feasible on Vision/Hulk (72 cores each).

---

## 12. Analysis plan (fixed before data collection)

1. Gate experiment → CV, ρ, censor fraction → confirm or amend seed count (§6.5).
2. Tuning → freeze `conf/tuned/*.yaml`.
3. Main block → H1 (log-rank vs best baseline, then vs each), H2 (dominance per budget level),
   H6 (TOST). Holm across H1–H6 once all six p-values exist.
4. Ablations → H3, H4.
5. Non-stationarity block → H5, H4 confirmation.
6. Sweeps → descriptive figures.
7. Tier-2 → calibration KS, prediction-band check, primitive cost table.
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

Amendments are appended only. An amendment after the corresponding block has started running
is flagged "post-hoc" in the paper.
