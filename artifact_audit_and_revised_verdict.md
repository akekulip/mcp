# Referee Report, Addendum: Artifact Audit and Revised Verdict

**Manuscript:** "What a Two-Byte Witness Buys on a Sprayed Fabric"
**Artifact:** `github.com/akekulip/mcp` @ `428080c` (210 commits pushed 2026-09-03)
**Supersedes:** parts of `review_two_byte_witness.md`; read that first for anything not restated here.

---

## 0. Headline of this audit

**The paper is substantially weaker than the work behind it.**

The repository contains a rigorous, pre-registered, adversarially self-gated research program: 31,656 lines of Python with a 295/295 test suite, a pre-registration document at v1.9 that explicitly fences the claim boundary *before* the gate was run, six separate novelty gates with recorded FAIL/NARROW verdicts, and an anomaly investigation that ran four discriminating experiments after the manuscript's account stops. This is better practice than most accepted ToN papers and it is largely invisible in the submission.

At the same time, the manuscript omits two findings from that same repository that decisively change how a reviewer should read it. One would *help* the paper. The other is a new top-level blocker. Both are in the artifact; neither is in the PDF.

**Revised recommendation: still major revision, but the path is now clear and the underlying work is more credible than the manuscript conveys.** Six of my seven original findings are confirmed at line level; one is withdrawn; two new blockers are added.

---

## 1. NEW BLOCKER — the application-impact result is NULL, and the paper does not mention it

`docs/review/artifacts/APP-IMPACT-HTSIM-MAKEBREAK-2026-09-03.md`:

> **Verdict: NULL.** At 1e-3 on a fully-loaded uplink, with RTO-dominated recovery at τ = 40 ms, the do-nothing CCT slowdown is **+1.362%** (3.58752 s → 3.63638 s). That is below the 5% promotion bar and, because it is measured at the *largest* RTO (the worst case for do-nothing), it bounds every smaller-τ regime too.

I grepped the entire manuscript source (`paper/ton/sections/*.tex`, `main.tex`) for `CCT`, `collective.completion`, `1.36`, `application.impact`, `slowdown`. **Zero hits.**

This is the single most dangerous omission in the submission, because it undercuts the motivation for the exact regime that is the paper's whole contribution. Section I motivates the work by asserting grayholes "can be costly for synchronous training jobs whose collective operations wait for the slowest packet [6]." The authors then measured that cost with htsim, at 10⁻³ — the informative rate, where the witness's advantage over SprayCheck is largest — and found 1.4%, below their own promotion bar. The paper spends thirteen pages establishing detection capability in a regime its own unpublished measurement says is nearly performance-invisible.

A reviewer does not need the repo to ask this question. "You detect 6 lost packets in 60,000 — so what?" is the first thing an operator reviewer asks, and the paper has no answer in it. Right now the answer exists and is unfavourable.

**This must be in the paper, and it must be reframed rather than buried.** The legitimate reframings, in descending strength:

1. **Detection is for repair economics, not CCT recovery.** A 10⁻³ link is a link that is degrading. The value of naming it is preventive replacement before it becomes a 10⁻² link or a blackhole, plus vendor attribution and RMA. Cite CorrOpt, which is precisely a repair-economics paper.
2. **Fleet-scale aggregation.** 1.4% on one collective, across thousands of directed links and continuous training, is not 1.4% of a fleet's cost. Compute it.
3. **The gray-to-black progression.** If physical-layer causes persist and worsen until repaired (which Section II-C already assumes, citing [5]), early naming has option value that a single-point CCT measurement cannot capture.
4. **Honest scoping.** State that the contribution is a measurement instrument, that the application-level value of low-loss detection is an open question, and that your own htsim gate bounds it at ~1.4% at 10⁻³ under RTO-dominated recovery.

Note also the harness limitation the gate document itself records: htsim's MCP layer has no mitigation actuator, so `uniform`, `random`, and `oracle` finish at the identical picosecond and CLEAN is the only available mitigation ceiling. Disclose that too — it bounds how much the 1.36% figure can be read as "mitigation would recover 1.36%."

Handled well, this becomes a strength: a paper that measures its own motivation and reports it as weaker than assumed is the same paper that ran the correlated-fault gate. Handled by omission, it is the finding that gets the work retracted from the record after someone else measures it.

---

## 2. CONFIRMED at line level — the packets-to-detect bug

My first report deduced this from arithmetic. It is a real bug, and the code's own docstring contradicts its implementation.

`sim/baselines/comparison.py`, module docstring:

> Detection delay is measured in epochs AND in packets, from the epoch the fault actually starts, **not from epoch 0**

`run_one_trial`, same file:

```python
cumulative_packets = 0
...
for _ in range(bootstrap_epochs):          # 10 clean epochs
    ...
    cumulative_packets += packets_per_epoch   # ← counts warmup into the metric
    epoch += 1
for _ in range(max_post_onset_epochs):
    ...
    cumulative_packets += packets_per_epoch
    if decision.fleet_rejected: mcp_packets = cumulative_packets
```

With `bootstrap_epochs=10, packets_per_epoch=2_000_000` (`run_comparison_sweep.py`), the warmup contributes a fixed 20 M to every reported cost. The output JSON confirms it exactly:

| p | arm | `median_epoch` | `median_packets` | post-onset epochs | **corrected packets** |
|---|---|---|---|---|---|
| 1.5% | ledger | 10.0 | 22,000,000 | 1 | **2 M** |
| 1.5% | spraycheck | 11.0 | 24,000,000 | 2 | **4 M** |
| 0.5% | spraycheck | 15.0 | 32,000,000 | 6 | **12 M** |
| 10⁻³ | ledger | 10.0 | 22,000,000 | 1 | **2 M** |
| 10⁻³ | spraycheck | 56.0 | 114,000,000 | 47 | **94 M** |

`median_epoch = 10.0` for the ledger at every rate is the first post-onset epoch (epochs 0–9 are bootstrap), which is exactly what Section V claims in words. The packets column simply does not measure what the paper says it measures.

Three consequences:

1. **The 160 M budget and the reported costs are on different origins.** The budget is 80 post-onset epochs = 160 M post-onset packets; the costs include 20 M of pre-onset. Figure 2 plots them against a common ceiling.
2. **The bug understates your headline by ~9×.** At 10⁻³ the true separation is 94 M vs 2 M = **47×**, not the 114/22 = 5× the paper reports. Fixing the metric strengthens the central result by an order of magnitude.
3. **The IQR is currently degenerate** (`[22 M, 22 M]`) because the constant offset dominates the variance. Post-onset, the ledger's IQR is genuinely 1–1 epoch and SprayCheck's is 31–64 epochs — a far more informative figure.

Fix: initialize `cumulative_packets = 0` after the bootstrap loop, regenerate the JSON, regenerate Figure 2, and restate every number in Table I and Section V.

---

## 3. CONFIRMED missing — but you already have the analysis

My §1.2 asked why a zero-byte TX/RX counter pair is not an arm. `sim/baselines/` contains exactly two baseline modules: `spraycheck_z.py` and `flowpulse_theta.py`. There is no counter-pair arm.

But `docs/review/RELATED-WORK-COMPARISON-2026-09-03.md` already states the argument, correctly and in the right terms:

> | RFC 6374 counter pair | TX/RX loss counters, per-link or per-class ME | ... | `TX>0 & RX==0` sees a dark context; **epoch-boundary skew** (packets in flight) fabricates/hides at low counts — **Θ(1) but skew-limited** |

You have identified that the counter pair is Θ(1) in `p` — i.e. it matches the witness on the paper's headline axis — and that what distinguishes the witness is skew. That is the thesis. It is in an internal comparison table and in one cell of Table VII, and it is nowhere in the argument of the paper.

This makes my original recommendation much cheaper than I assumed. You do not need new analysis, only:

1. **`CounterPair-0B` as a fourth arm** in `comparison.py` and `localization.py`. `simulate_epoch` already returns `{spine: (tx, rx)}` — the arm is a few dozen lines: feed the same `(tx, rx)` through the same `FleetDecisionLoop`, but perturb `tx` by an in-flight/skew term drawn from a measured skew distribution. Sweep skew from 0 (idealized bound) upward.
2. **A measured skew number from your own switch.** How long does `controller/hw_adapter.py` take to read all sublinks? You have `bench_feedback_path.py` already. That single number is the paper's justification for spending two bytes.
3. **Retitle around it.** What the two bytes buy is in-band epoch alignment. Say so in the abstract.

Until this arm exists, Reviewer C's objection — "per-link TX/RX counters do this for free and you did not test them" — stands, and it is the objection that determines acceptance.

---

## 4. CONFIRMED — no formal cost-scaling treatment, and the floor is never swept

`paper/THEORY.md` (184 lines) is a rigorous document, but it formalizes a **different and now-retired result**: the Bellman/Blackwell batched coverage-delay lemma for a probing scheduler at `(n, B) = (1024, 41)`. None of that framing appears in the ToN manuscript. Grepping THEORY.md for `1/p`, `p^2`, `Poisson`, `scaling` returns nothing relevant to Section II-B's claim.

So the paper's central analytical claim — passive cost Θ(1/p), witness cost Θ(1) — has no formal statement anywhere in the paper or the artifact. My first report's derivation stands: both arms are Θ(1/p²), and the witness divides the constant by the background floor `f`.

And the floor is hardcoded. `healthy_rate=1e-5` appears as a default in `comparison.py:186` and as a literal in `run_comparison_sweep.py:33`. **It is never swept, in any runner.** The paper's most load-bearing constant — the one that sets where the ledger's own wall sits, and therefore whether "flat" is true — is a single unexamined harness setting.

Add: the proposition with its two-line proof; a sweep to 10⁻⁵/10⁻⁶ locating the ledger's wall; and a sweep over `f` showing `p_min` tracking it. All three are cheap in this harness.

---

## 5. WITHDRAWN — the e-process criticism was about the paper, not the science

I flagged the decision rule as unspecified. The machinery is in fact rigorous and well-built. `controller/absolute_eprocess.py` implements a convex mixture of e-processes over a log-spaced grid of loss-rate alternatives approximating a log-uniform (GRO-style) mixture, against a **previsible** leave-one-out null from `floor_estimator.py`, with the martingale-validity argument for a moving null stated explicitly in the docstring, and censored epochs contributing a factor of exactly one with no alpha-spending restarts. There are dedicated tests for the absolute, relative, and ratio variants.

`α = 0.05` and `ratios=(2.0, 5.0, 10.0, 50.0, 200.0)` are set in `comparison.py:make_mcp_loop`.

So this is purely a write-up gap, and a serious one: `03_ledger.tex` gives the whole rule three sentences and says "a chosen false discovery rate," never stating 0.05. **You are hiding your most defensible technical asset.** Give it a subsection with the mixture, the previsibility condition, the censoring convention, and `α` stated numerically. This is the part of the paper a statistics reviewer would respect, and right now they cannot see it.

---

## 6. UPGRADED — the anomaly investigation is far ahead of the paper, and it found a design defect

The manuscript's Section X account stops at "the cause is not known," having ruled out physical-layer drops and ambient noise. `WORKING_NOTES.md:1932–2011` and `docs/review/artifacts/HW-LEDGER-WIRE-REDUCTION-SOAK-ANOMALY-2026-09-02.md` go four experiments further:

1. **Matched-binary comparison.** A byte-identical copy of the pre-wire-reduction source, deployed via the same pipeline, run with the same script immediately after: **0/100 anomalies on the four-byte binary vs 2/57 on the two-byte binary.** This isolates the anomaly to the wire-reduction build.
2. **Injector-write hypothesis ruled out** with a purpose-built zero-injector probe, which reproduced the anomaly on cycle 1 with the identical `Δseq=21, Δobs=20` signature.
3. **Idle-then-first-burst trigger confirmed**, probabilistically: 3 of 5 first-after-gap bursts reproduced it, against 0 of many dozens of steady-state bursts. Cycle 56 remains an exception to the pattern.
4. **A second, structural finding.** Contexts 0 and 3 show phantom arrivals with no matching stamps, reproduced across two bring-ups, explained as: bring-up's port-verification traffic defaults `spray=0`, and **the new reconstruction maps `spray=0` to vlink 0 regardless of which leaf sent it.**

Two things follow, pulling in opposite directions.

**In your favour:** the paper's disclosure is *weaker than the evidence*. Replace "the cause is not known" with the matched-binary result and the confirmed idle-burst trigger. A reviewer reading "we isolated it to the two-byte build with a byte-identical control at 0/100 vs 2/57, and confirmed idleness elevates it at 3/5 vs 0/dozens" sees a competent investigation with a bounded open mechanism. A reviewer reading the current text sees an unexplained hardware mystery next to a zero-false-positive claim. Same facts, opposite impressions.

**Against you, and this is the harder one:** finding 4 is a **correctness defect of the wire reduction, and the paper omits it entirely.** Section III celebrates removing the 16-bit link identifier because "the receiving hop already knows its own ingress port, and because the spray field is already on the wire, the identifier is redundant," and Section IX reports the cost of that removal purely in pipeline stages. The repo shows the removal also introduced an aliasing hole: any packet arriving with `spray=0` that is not part of the stamped stream is attributed to vlink 0. The internal note dismisses it as never touching a measured sublink — true in the testbed, false in a production fabric, which carries abundant untagged and control traffic.

Combined with finding 1, Table VI now has data pointing the other way on the central design choice: the four-byte version has 0/100 plus ~3,200 clean historical cycles and no aliasing hole; the two-byte version has a confirmed reproducible anomaly and a known `spray=0` collision. Section X already concedes "a reviewer who weights pipeline stages over wire bytes can reasonably prefer the four-byte version." **You now have evidence that they should.** Report it.

---

## 7. NEW — the sequence wrap figure in the paper is wrong by 2×

`WORKING_NOTES.md:137–140`:

> the witness sequence **advances 2.0 values per packet** (`reg_wit_seq` 13859->13959 for 50 packets), since it is stamped on each fabric pass. So a sequence-range fault covers half the packets its width suggests, and the 16-bit space wraps every **32768 packets per sublink, not 65536** — PREREG's `wrap` scenario uses the wrong figure.

The manuscript inherits the wrong figure. Section III says the registers advance "by `Δseq`, taken modulo 2¹⁶," and Section IV says "every cell also keeps `Δseq` below 2¹⁶, so that the sequence wraps at most once." The measured effective period is 2¹⁵ packets per sublink.

Two corrections needed, and the second matters more than the first:

- **State the effective wrap period as measured**, and say why it is 2× (both hops on a two-hop path stamp at egress). If that doubling is an artifact of the loopback emulation rather than a property of the design, say that instead — but say which.
- **Halve the epoch bound.** My first report computed that at 25 Gb/s a sublink exhausts 2¹⁶ in roughly 120 ms, constraining the controller's read loop. At the measured 2¹⁵ that becomes ~60 ms, for a controller that must read 1024 sublinks × 2 registers. The paper never states the silicon epoch in wall-clock time and never benchmarks the read loop. `controller/bench_feedback_path.py` exists; use it. If the loop cannot close in 60 ms, the two-byte width is not viable at line rate and the four-byte version is the only deployable one — which again converges with §6.

Related: the silicon evaluation runs at 20 kpps, ~1% of a 25 Gb/s port. `docs/P4-DESIGN-SPACE.md:1163` lists "`dp68` recirculation line rate — pktgen ramp, find the drop knee" as an open item. It is still open. A title promising silicon measurement needs it closed.

---

## 8. Figure 2's "MCP" label — exact root cause

The new ToN figure module is correct. `paper/ton/figures/_common.py:15`:

```python
LABELS = {"mcp": "Ledger", "spraycheck": "SprayCheck-Z", "flowpulse": r"FlowPulse-$\theta$"}
```

But `paper/ton/sections/05_detection.tex:8` includes `scaling_curve.pdf`, which is built by `docs/review/artifacts/figures/scaling_curve.py:37`:

```python
LABELS = {"mcp": "MCP (in-fabric witness)", ...}
```

`scaling_curve.pdf` was **copied** into `paper/ton/figures/` rather than regenerated during the ToN figure pass (commit `23fd8ea`, "one data figure per objective from the collected sweeps"). It is the only figure in the paper not rebuilt from `_common.py`. Since you must regenerate it anyway for §2, port it onto `_common.py` at the same time.

Underlying cause, worth fixing before artifact release: the mechanism is named `mcp` throughout the code — `make_mcp_loop`, `mcp_epoch`, `mcp_packets`, the `"mcp"` arm key, `mcp_policy.py` — inherited from the retired measurement-control-plane project that still sits in `legacy/`. Either rename, or put a mapping note in the README. A reviewer who downloads the artifact and finds the paper's "Ledger" called "MCP" everywhere in the code, alongside a `legacy/` directory containing a different paper with the same name, will spend their time on archaeology instead of on your result.

---

## 9. What the artifact adds to my confidence — credit where it is due

These should be *cited in the paper*, because they are the reasons a reviewer should trust the numbers, and none of them is currently visible:

- **`paper/PREREG.md` at v1.9** pre-registers the claim boundary before the gate ran: grayhole-only scope, headline restricted to independent per-directed-link faults, common-mode degradation entered as a *disclosed limitation*, and its fix (the relative-discriminator gate, "Q4") explicitly logged as **H13 — DEFERRED, not tested**, with a note that it sits outside the Holm family so the scope boundary is visible in the numbering. Section VIII's framing ("it is a gate rather than a pass... which is the pre-registered scope") is *true*, and the paper should cite the pre-registration by name so a reviewer can verify it rather than take it on trust.
- **Six recorded novelty gates** with honest adverse verdicts: `NOVELTY-GATE-2` (FAIL as novelty, NARROW as engineering), `NOVELTY-GATE-3` (per-(link,class) loss measurement is prior art), `NOVELTY-GATE-4` (SERIOUS not FATAL, and the contract argued against the wrong baseline), `NOVELTY-GATE-DSHARK` ("it does not kill the project, it kills one framing of it"), `NOVELTY-GATE-HEALING` (FAIL), `NOVELTY-GATE-IDENTIFIABILITY` (FAIL). A research program that ran six novelty gates against itself and published the failures has earned the "we claim no novelty for the primitive" framing.
- **A 295/295 test suite** re-run clean after each change, including regression tests written against specific past defects (`test_ratio_eprocess`, `test_reward_no_leakage`, the `_restoration_grid` floor-coupling regression).
- **Adverse findings recorded rather than quietly fixed**, with the reason: `THEORY.md §4` — "An earlier draft argued that per-packet spraying collapses the pooled-test design space... **That argument is wrong and has been removed.**" Also the FlowPulse volume artifact, disclosed in a 12-line code comment explaining exactly which fidelity check failed to catch it.
- **The 1000/1000-cycle soak across the 16-bit sequence wrap** (`MAIN3`), which validates the wrap arithmetic on hardware even though the paper cites the wrong period for it.

My first report said the honesty was "better than most accepted papers." Having read the artifact, that was an understatement. The problem is not the research. **The problem is that the manuscript is a lossy compression of it, and the lossy parts are load-bearing.**

---

## 10. Revised checklist

Ordered by effect on the outcome. Items marked ⚠ are new since the first report.

1. ⚠ **Report the app-impact NULL and reframe the motivation.** +1.36% CCT at 10⁻³, htsim's missing mitigation actuator, and one of the four reframings in §1. *Cannot ship without this.*
2. **Add `CounterPair-0B`** and a measured read-skew number; retitle around in-band epoch alignment. You already have the analysis in `RELATED-WORK-COMPARISON-2026-09-03.md`.
3. **Fix `cumulative_packets`**, regenerate the JSON and Figure 2, restate Table I and Section V. Your headline separation goes from 5× to 47×.
4. **State the cost-scaling proposition**; sweep to 10⁻⁵/10⁻⁶; sweep `healthy_rate`.
5. ⚠ **Rewrite Section X's anomaly paragraph** with the matched-binary result (0/100 vs 2/57) and the idle-burst trigger (3/5 vs 0/dozens) — *and disclose the `spray=0` → vlink 0 aliasing hole* as a correctness cost of the wire reduction.
6. **Add regime R4: congestion/incast.** `docs/P4-DESIGN-SPACE.md:304` notes the virtual links produce genuine queueing and expose `deq_qdepth`, so the testbed can already do this.
7. **Promote the e-process to a proper subsection**, with the mixture, previsibility, censoring convention, and `α = 0.05`.
8. ⚠ **Correct the wrap period to the measured 2¹⁵**, state why, halve the epoch bound, and benchmark the read loop with `bench_feedback_path.py`.
9. **Close the line-rate item** (`P4-DESIGN-SPACE.md:1163`) or scope the silicon claim explicitly to 20 kpps.
10. **Report the stage budget inside a production-representative pipeline**, or on Tofino 2/3 — and reconsider the 2 B vs 4 B choice in light of items 5 and 8.
11. **Cite `PREREG.md` v1.9 and the novelty gates** in the methodology so the scope discipline is verifiable rather than asserted.
12. **Regenerate `scaling_curve.pdf` from `_common.py`**; rename `mcp` → `ledger` in code, or add a README mapping; move or clearly label `legacy/`.
13. Fill affiliation, date, acknowledgment, biography; report added load as a range over packet sizes; note the blackhole-reads-as-zero and duplicate-cancels-loss cases.

Items 1–5 separate reject from major revision. Items 6–8 separate major from minor. Items 9–13 are what a reviewer will list regardless.

---

## 11. One closing note on process

The repo shows a pattern worth naming, because it is the actual risk here and it will recur on the next paper. Every gate that could have killed the project was run, recorded, and honoured — novelty, healing, identifiability, correlated faults, application impact. But when the manuscript was assembled, **two of those gate outcomes did not make it into the paper**: the app-impact NULL (unfavourable, omitted entirely) and the anomaly investigation's four follow-ups (favourable, truncated to "cause is not known").

The selection is not in the same direction, so this does not look like spin. It looks like the manuscript was written from the *design* documents rather than from the *gate* documents, and the gates that landed after the paper spine was fixed on 2026-09-03 never got folded back in. `PAPER-SPINE-2026-09-03.md` and the evidence-mapping commit (`26b57a5`) are dated the same day as the app-impact gate (`d51cbfa`, `2a42768`), which is consistent with that.

The fix is mechanical: before submission, diff the claim set in `PREREG.md` against every gate verdict in `docs/review/`, and require that each verdict appears in the paper or is explicitly scoped out with a reason. You built the infrastructure to do this — the pre-registration log already has a verdict column. Use it as a submission checklist.
