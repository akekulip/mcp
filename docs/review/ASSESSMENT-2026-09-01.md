# Whole-repo assessment — 2026-09-01

Scope: the entire repository as of commit `8675b08` plus the 19 uncommitted doc changes. Method: I read
the working notes, plan, verification ledger, campaign plan, the NSDI sealed-evidence spec and plan, the
five novelty gates and the panel report myself, then ran five independent audits in parallel (code vs
claims; results artifacts vs claims; an NSDI/SIGCOMM-style adversarial review; a literature and
creative-directions pass with primary sources; a methodology and statistics critique). Every number
below was either recomputed from a committed artifact or is marked as unbacked. Test suites were run
fresh: 433 tests pass, 0 fail (controller 129, sim 159, p4/control 36, p4/hw 99, p4/witness 10).

## 1. Verdict

The engineering is real, unusually honest, and green. The research is not yet a paper, and the reason
is not missing experiments. It is that the project has changed its thesis four times in eight days
(generic measurement control plane → counterfactual observability → Behavioral Sublinks → sealed
evidence epochs) and each pivot carried the evidence of the previous one forward without re-basing
the claim on it. The current spec (`docs/superpowers/specs/2026-08-31-nsdi-sealed-evidence-campaign-design.md`)
and its 2,775-line plan (14 tasks, 108 checkboxes, 0 done, the `experiments/` package does not exist)
build the next three months on the weakest of the four framings.

Three findings are load-bearing and should be resolved before any more campaign code is written:

1. **The mechanism as built cannot operate at the rate it claims to target.** The frontier is two
   8-bit saturating counters per sublink (`p4/witness/mcp_fabric_clf_eg.p4:1139,1414`). The silicon
   results were taken at 40 packets per epoch, 200 packets per second, with a 2.0 s guard that was never
   measured (`p4/hw/loop/sequential_trials.py:62,218,238`). A 25G link at 1500 B carries 255 packets in
   about 120 µs; the fastest exact read is 7.7 ms. At production rate every epoch saturates and is
   censored. That is the "perfectly safe, perfectly useless" shape the repo's own rule 4 warns about.
2. **The preregistered null contradicts the stated target.** The e-process null is delivery ≥ 0.99
   (`sim/clf/SEQUENTIAL-PREREG.md:20`, `p4/hw/loop/sequential_trials.py:66`), so 1 % loss is healthy by
   definition. The campaign plan foregrounds a 1e-3 to 1e-5 loss target "two to four orders of magnitude"
   below SprayCheck (`docs/review/CAMPAIGN-PLAN.md:43-45`). Measured power of the mixture within 50
   epochs: 51 % at 98 % survival, 8 % at 98.5 %, 0 % at 99.5 % and 99.9 %. One of the two statements has
   to go.
3. **The calibrated detector is not the one that acts.** `controller/evidence_ledger.py` (the
   anytime-valid mixture) is imported only by the offline trial harness and the simulation sweep
   (`p4/hw/loop/sequential_trials.py:23`, `sim/clf/sequential_eval.py:12`). The closed-loop quarantine
   decision at `controller/sublink_feedback.py:453` uses the CUSUM in `controller/infer.py` with the tuned
   knob `h = 6.5`, which `conf/infer/frozen.yaml` itself describes as a per-arm knob. The paper's
   false-alarm guarantee therefore covers a path the system does not take.

## 2. What is wrong — ranked

### 2.1 Framing and positioning

- **No spine.** Framing 1 (Behavioral Sublinks) has an object, an action, and a decision rule for
  whether it matters. Framing 2 (sealed evidence) is a manifest of hashes and typed censor reasons
  wrapped around seven fixed harness bugs (D1–D7). A PC member will read
  "the seven repaired defects establish why the validity contract matters" (spec §2) as generalising
  one prototype's bugs into a thesis. Prior art the gates never searched: RFC 9341 §5 already
  specifies the in-flight guard as a validity condition; Namkung et al. (SOSR'21) recommend
  alternating duplicated counter instances per epoch, which is the bank parity; Speedlight gives
  consistent cross-switch cuts; Panorama (OSDI'18) already has an observation-to-verdict separation
  with a three-valued PENDING status, which falsifies `GATE2-VERDICT.md:77-80`.
- **The premise of Framing 1 is unmeasured.** Conditional faults are conditional on silicon only
  because the injector drops by `md.sublink` range, the same label the detector uses. The motivating
  `>1 KB` bin is unreachable at MTU 1500 (`WORKING_NOTES.md:129-131`). The physical size-selectivity
  bench proposed in `CAMPAIGN-PLAN.md:128-135` was never run. FANcY (SIGCOMM'22), which keys
  in-network loss evidence and fast reroute on the same identity in Tofino, is still rated "abstract
  only" in `docs/NOVELTY-MATRIX.md:53`. dDrops is unverified. Those two full reads are the last open
  fatal vectors for Framing 1.
- **The verification ledger describes a program that is no longer the subject.**
  `VERIFICATION-2026-08-29.md` licenses claims for `mcp_fabric_gate_event` (11 ingress / 4 egress, 36
  tables) and contains zero mentions of CLF, the frontier, or e-values. Every result from 2026-08-30
  onward ran `mcp_fabric_clf_eg` (11/5, 42 tables). The ledger has no superseded banner.
- **There is no manuscript.** `paper/` contains PREREG.md (v1.1, the abandoned bandit thesis,
  unmarked at the top) and THEORY.md. Three preregistration documents now exist for three theses.

### 2.2 Mechanism and controller defects (all with file:line evidence)

- **Probation is a dead state.** `PROBATION` is defined at `controller/sublink_feedback.py:49` and
  referenced nowhere else; `on_clean_epoch` goes `QUARANTINED → HEALTHY` directly (`:562`).
- **The probation confidence statement is not what the code computes.** `probation_packets_required`
  (`:57-69`) derives N from N consecutive clean packets, but `clean_packets` accumulates (`:555`) and is
  never reset when the CUSUM sees losses without alarming (`:454-457`). The log line at `:566-568`
  claims a bound the accumulator does not support.
- **The ledger wedges permanently on 16-bit epoch wrap.** `evidence_ledger.py:139-143` returns STALE
  for `epoch ≤ last_epoch` without invalidating; the trial harness feeds `(epoch + offset) & 0xFFFF`
  (`sequential_trials.py:185,236`). After 65535 every epoch is STALE forever. No test covers it.
- **Censor reasons the code cannot produce.** `BOUNDARY_RACE` and `COUNTER_RESET`
  (`evidence_ledger.py:39-40`) are never derived (`_censor_reason`, `:192-201`). The boundary race is
  the phenomenon the whole "sealed" argument rests on, and it is unimplemented as a detector output.
  `EpochRecord.gap_seen` (`:62`) is never read.
- **"Frozen" is self-certifying.** `infer.py:6-7` says the hash is verified at start-up; no runtime path
  calls `module_hash()` except `freeze.py` (which rewrites it) and one test. `frozen.yaml` records three
  retunes by comment.
- **Three detectors, one of them hand-rolled.** `sim/sublink/feedback.py:44-56` claims to be "the same
  sequential test the rest of the project uses" and is an analytic approximation with 6.5 hardcoded;
  `sim/clf/verdict.py` duplicates the ledger's verdict enum with different semantics.
- **Reorder-tolerant witness not on the chip** (HURDLES H33). The deployed witness infers loss from a
  single adjacent swap, and reordering is the normal state of a sprayed fabric. The 20/20 latency
  trials used 655 consecutive sequence values: a burst, with no reordering present.
- **Default spray mode contradicts the paper's own argument.** `mcp_fabric_base.p4:407` and
  `setup_skeleton.py:236` default to hash-of-entropy spraying, the exact regime where a host can pin a
  path. CAMPAIGN-PLAN §0 says to run the headline under random or round-robin; not done.
- **Alpha is spent wrong.** `_sequence_alpha` (`evidence_ledger.py:189-190`) gives the first sequence
  α/2, so the realised threshold is 40, not 20; halving wastes half the budget on a rare restart.
- Smaller: `multicontext_probe.py` is not in the deploy manifest (`gate_agent.py:48`);
  `nic/evidence_probe.py` re-implements the spray CRC with no test pinning it to `poly_spray`;
  `mcp_policy.py` and `sim_bridge.py` have zero tests; `p4/ptf/PTF-MODEL.md:61-100` documents two
  P4 files that do not exist; the four vendored simulators have no `.gitmodules` pin.

### 2.3 Evidence record

| claim | n | artifact | status |
|---|---|---|---|
| 4.998 ms median event-to-reroute | 20 | CSV + raw + hashes | **verified**, recomputed exactly; but t1 resolution is 0.5 ms, so "4.998" is one quantisation bin |
| sequential sweep (100 % @ 0.95, 0.4 % @ 0.99) | 2000/pt | code only, no CSV | reproduced by re-running; IID loss only |
| silicon sequential triad | **1 run per condition, 11 epochs** | prose only | existence proof, not a result |
| 17/17 identities; 1/17 selective detection | 1 run | md table | self-declared "no CI" |
| 1.990 ms gate write | 20 ops, 1 config | none | "no repetition and no intervals" |
| 249x–8407x readout ratio | 3 | none; mirroring column is arithmetic | not citable |
| "~250 ms for all 1,024 cells" | — | none; only measured full census is 32 ms | unsourced, repeated in four docs |
| +25 pp safe delivered demand | analytic | closed form | must be labelled analytic |
| 60 ms / 106.6 ms cliff | 5 seeds | sim | under-powered |
| CLF vs C-W4 `201→201→45` | 1 | md | quoted in FINAL-COMPARISON without the n |

Contradictions left standing: Capsule 9/3 (`CAPSULE-RESULT.md:16`, unmarked) vs the retracted-to-9/4
ruling in VERIFICATION; 9/3 silicon counts still in `EDITOR-NOTES.md:5` and `PANEL-REPORT.md:37`;
CLF build 11/4 in `CLF-COMPILE-GATE.md:10-13` vs 11/5 everywhere else; the measured 2.0-per-packet
sequence advance (`WORKING_NOTES.md:137-140`) is not propagated to `HW-CLOSED-LOOP.md:26,56`
("655-packet" is a sequence width, about 327 packets), `HW-SELECTIVE-DETECTION.md:64-67`, or either
sim PREREG's `wrap` scenario; "zero wire bytes" is unqualified in six places against the ledger's own
qualification; `README.md:26-92` describes directories that no longer exist and presents CICIDS
tables as current results; `BRIEF.md` redirects to `PLAN.md`, which is itself superseded.

### 2.4 Statistics and evaluation design

- **Bursty loss breaks the false-alarm bound.** The null is packetwise-conditional, far stronger than
  "99 % average delivery". Monte Carlo against the real ledger (n = 32, 50 epochs, 2,000 runs):
  IID 0.99 → 0.2 % alarms; Gilbert–Elliott at 99.5 % mean survival with burst length 5 → **11.3 %**;
  burst length 10 → **16.1 %**. `sequential_eval.py:36-37` only generates IID Bernoulli.
- **30 silicon reps per cell cannot test the primary endpoints.** 0/30 gives an exact-binomial 95 %
  upper bound of 11.6 %; the 5 % gate needs 59 zero-event trials. `HW-CLF-RATES.md` did n = 100; the
  spec regresses.
- **Censoring is informative.** SATURATED depends on load; IMPOSSIBLE correlates with reordering and
  fault presence. Conditional rates are biased. Report the three-way outcome
  `P(alarm ≤ H) + P(censored) + P(valid & silent) = 1` as competing risks, with unconditional
  false-alarm (censor = no alarm) as the safety metric and unconditional sensitivity (censor = miss) as
  the usefulness metric, side by side.
- **Holm is incoherent as declared** (four primaries in CAMPAIGN-PLAN, five plus one in the spec, six in
  PREREG); most endpoints are bound checks without p-values. Wilson-over-sublink-epochs is still in
  `sim/dynamic/PREREG.md:71,74` after CAMPAIGN-PLAN §3 rejected it.
- **"Matched safety" is not operationalised.** Define per-run unsafe exposure U and a bound B, admit a
  seed only if both arms satisfy U ≤ B, report the inadmissible fraction as a co-primary, then paired
  log-ratio of CCT with BCa bootstrap over seeds; the CI must exclude ln(0.95) to claim ≥ 5 %.
- **One chip, same clock, same TM.** The epoch-boundary race the sealed-evidence story is about is
  trivially small on this testbed and largest in the two-switch regime it cannot produce. The
  0 IMPOSSIBLE / 200 result is conditional on that.
- **Deterministic gray loss on silicon.** The injector kills a fixed sequence range, so 38/40 is the
  same record every epoch; repetitions measure harness noise, not detector variance. A hash-based
  probabilistic drop in `tbl_eg_fail` is needed for any sim-to-silicon comparison.
- **The htsim MoE block cannot answer a mitigation question as planned.** On MoE-64 the faulty uplink
  carries traffic in two bursts at 6–7 % load (H27) and CCT under loss is RTO-dominated (H25); whole-link
  and sublink quarantine will tie for the wrong reason. Use a communication-bound trace or a synthetic
  load matrix and report the loaded-fraction denominator.

## 3. What is genuinely good and must be kept

- The closed-loop microbenchmark: switch-clock stamps at both ends, one-batch actuation, validity
  conditions retained by rule, hashes on disk. This is the one paper-grade artifact.
- The CLF-vs-C-W4 retroactivity observation (a sequence witness is blind for exactly as long as a
  blackhole lasts) is clean, mechanistic, and quotable.
- The D1–D7 record, the "cheap, clean and decisive is suspicious" rule, the retract-don't-edit
  convention, and the primary-source novelty gates. Reviewers reward this; keep it visible.
- The e-process implementation is correct for the composite one-sided null (monotone likelihood
  ratio, verified by derivation and by exact reproduction of the silicon e-values).
- `sim/dynamic` drives the real controller objects; `gen_variants.py` fails hard on ambiguous
  substitution; `sim/gate/replay.py` is exact because counters are byte-identical across arms.
- The identifiability argument in CAMPAIGN-PLAN §0 (host measurement on a switch-sprayed fabric is
  rank-deficient to bundle granularity) is correct and unclaimed as a sentence, but it is two lines
  of linear algebra and holds only under switch-local spraying. Use it as motivation, never as a
  contribution bullet.

## 4. Recommendation: one paper, one spine

Keep `(directed link, source-declared context)` as the unit. Demote "sealed evidence" to one Design
subsection (post-TM TX, ingress RX, bank in the dead shim byte, typed censoring) plus one table of
censor rate versus packet rate. Drop "evidence validity contract" and "failure taxonomy" from the
contribution list. Build the paper on two results the literature does not yet hold:

**Result A — attribution beats distribution below 1 % and is invariant to the spray policy.**
A post-spray directed-link witness detects 1e-3 to 1e-4 loss in O(1/p) packets with an anytime-valid
bound, whatever the spray policy; spray-distribution detectors (SprayCheck, FlowPulse) need O(k/p²)
packets and state adaptive/weighted spraying as a limitation. That stated limitation is the opening.
Requirements: widen the CLF counters to 16 or 32 bits (2–4 KiB, trivial), or state that the 16-bit
sequence witness is the sub-1 % detector and CLF is liveness only; move the null to 0.999 with
200-packet epochs; measure the maximum uncensored exact-count rate; implement SprayCheck's Z-test and
FlowPulse's temporal-symmetry test as replay arms over the recorded counters (a few hundred lines
each); run four spray modes × loss {1e-2, 1e-3, 1e-4} in htsim and validate 1e-3 on the loopback
fabric. LinkGuardian detects 1e-3 with a link-local sequence, so the comparison is "per-context
attribution at LinkGuardian's floor without retransmission buffers".

**Result B — half-open sublinks: exposure-bounded restoration.**
Quarantine destroys the passive evidence needed to lift it (the restoration-lifecycle run already
shows steps 3 and 4 are IDLE whether the link is broken or repaired). Restoration therefore needs an
authorized counterfactual channel with a priced exposure. The literature has only timeouts
(BFD, route-flap damping), CorrOpt's enable-and-watch, and the circuit-breaker half-open pattern,
which must be cited. Requirements: fix the dead PROBATION state and the consecutiveness bug; put the
mixture ledger, not the CUSUM knob, on the restore decision; run persistent / repaired / flapping
faults × probation budget with a running controller; report false restorations, time-to-restore,
audit bytes, and production packets exposed, against "three clean rounds" and enable-and-watch,
always with the action rate beside the safety rate.

**The context dimension is promoted only if the physics says so.** Run the size/class-selectivity
bench (`CAMPAIGN-PLAN.md:128-135`): p(loss | frame size) on a physically degraded 25G link with the
SDE's pre/post-FEC counters as covariate. If the curve shows real selectivity, Behavioral Sublinks
become the headline and the +5 pp / 5 % CCT gate is worth running. If it does not, context stays as
the granularity of the object and the paper is A + B. The loopback DAC may not produce a marginal
link; an attenuator or a deliberately mis-seated transceiver on a real cable is the honest way to get
one, and that is a day of work.

## 5. Creative directions, with honest threat levels

1. **Spray-policy-invariant attribution at sub-1 % loss** (strong; Result A above).
2. **Half-open sublinks / exposure-bounded restoration** (strong; Result B above; cite circuit-breaker).
3. **Audit in the gaps.** H27 is treated as a nuisance: the faulty uplink is idle most of the
   iteration. Turn it around: the collective schedule tells the controller when a quarantined link
   carries no production traffic, so probation traffic can be steered through it at zero production
   exposure. Restoration exposure goes from bounded to zero whenever the schedule is known
   (ATLAHS/Chakra gives it). Cheap in htsim; unclaimed as far as this session's search found;
   threat is that it is a scheduling trick rather than a mechanism, so it belongs inside Result B.
4. **Workload-declared context.** The 4-bit context is source-declared and the class dimension is
   already DSCP. Let the collective library stamp the collective phase (AllReduce ring step,
   AlltoAll, parameter broadcast) into DSCP; the sublink becomes `(link, collective phase)` and
   conditional health becomes phase-conditional, which is the form an AI-fabric operator actually
   wants ("this link is bad for AlltoAll bursts"). No NCCL integration needed on the testbed: a
   UDP generator with per-phase DSCP suffices. Threat: OptCC and UCCL already schedule around
   asymmetric bandwidth at the host; the claim must stay on the evidence side. Speculative, cheap.
5. **False health under benign stress as a measurement result** (medium). Naive TX/RX and presence
   detectors declare false health at rate X under epoch races, TM placement, residue, background
   packets, uninstalled tables; typed censoring drives it to zero at censor rate Y. Publishable as a
   taxonomy with numbers inside the paper, not as a headline. Threat: SOSR'21 makes the same
   argument for sketches.
6. **Two-vantage attention** (medium). Host-side XDP per-QP counters are bundle-limited; a
   demand-targeted census reads only the sublinks the host implicates. Threat: R-Pingmesh already
   separates RNIC from in-network drops. Worth one figure, not a section.
7. **FEC physics of size-conditional faults** (weak on this testbed unless a marginal link is
   built). Aegis's `>1 KB` total drop is a threshold, which points at MTU or buffer, not FEC.
8. **Iteration-synchronous health snapshots** — FAIL. FlowPulse owns per-iteration temporal symmetry.
   Absorb it as a trigger for the census; do not claim it.

## 6. Cheapest fixes, by credibility gained per hour

1. Guard-interval sweep {0, 10, 100, 500, 2000 ms} × IMPOSSIBLE rate, and 60 healthy epochs at fixed
   k for the stray-packet floor. One switch session. Every silicon number rests on both.
2. Add Gilbert–Elliott loss to `sequential_eval.py`; state the null as packetwise-conditional;
   reconcile 0.99 with the 1e-3 target. One afternoon.
3. Widen the frontier counters; measure the maximum uncensored rate; put a censor-rate-vs-rate table
   in the design section. One compile plus one session.
4. Wire `evidence_ledger` into the online quarantine and restore path; delete the CUSUM knob from
   the action path or label it a baseline; fix PROBATION, the consecutiveness reset, the epoch-wrap
   wedge, and the alpha schedule (first sequence gets most of α; print the realised threshold).
5. Read FANcY and dDrops in full and write the delta in one paragraph each.
6. Mark stale documents (CAPSULE-RESULT, EDITOR-NOTES, PANEL-REPORT stage counts, README body,
   PREREG header, BRIEF→PLAN chain) and add a superseded banner to VERIFICATION-2026-08-29 pointing
   at the 11/5 program. Propagate the 2-per-packet sequence advance. Commit the sequential sweep
   CSV and the silicon sequential logs the way the closed-loop campaign did.
7. Present the preregistration as a registered-report table: hypothesis, original wording, status,
   triggering evidence, date, and whether the amendment preceded outcome data. Almost all amendments
   are retirements or corrections; say so, and name v1.4 (F6) as the disclosed post-hoc exception.
8. Replace the 108-task plan with a plan for A + B + the selectivity bench. Preregister the
   censor-aware three-way endpoint and the matched-safety paired endpoint on one page before any
   result run.

## 7. Sources consulted outside the repo this session

FANcY (SIGCOMM'22), dDrops (Computer Networks 2022), LinkGuardian (SIGCOMM'23), CorrOpt (SIGCOMM'17),
NetBouncer (NSDI'19), 007 (NSDI'18), R-Pingmesh (SIGCOMM'24), SprayCheck (arXiv 2605.03702), FlowPulse
(HotNets'25), Aegis (NSDI'25), RFC 9341/9342, Namkung et al. SOSR'21 (counter retrieval
inconsistency), Speedlight (SIGCOMM'18), Panorama (OSDI'18), dShark (NSDI'19), LossRadar (CoNEXT'16),
FlowRadar (NSDI'16), NetSeer (SIGCOMM'20), ITU-T Y.1731, US 9,161,259 B2, Ghost in the Datacenter
(arXiv 2603.03736), SuperBench (ATC'24), OptCC (arXiv 2606.01680), UCCL (arXiv 2504.17307), Meta RoCE
(SIGCOMM'24), Spectrum-X adaptive routing, Ramdas et al. game-theoretic statistics / safe anytime-valid
inference. Full URLs are in the literature agent's output and should be copied into
`docs/review/LITERATURE.md` when the related-work section is drafted.
