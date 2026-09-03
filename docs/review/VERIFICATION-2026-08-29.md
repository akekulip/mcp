# Behavioral Sublinks verification and claim ledger — 2026-08-29, updated 2026-08-30

## Verdict

The repository contains a real **mechanism prototype** and a repeated partial-loss
detection-to-quarantine silicon loop. It does **not yet contain the restoration lifecycle or
statistically supported application result needed for a best-systems-journal claim**.

| question | verdict | evidence boundary |
|---|---|---|
| Is the behavioral-sublink abstraction implemented? | **PASS** | Context Capsule, context-indexed W4 state, selective health gate, attributed event, and audit steering exist in the generated P4 |
| Does it fit Tofino 1? | **PASS** | current event program: 11 ingress / 4 egress stages, 36 allocated tables |
| Do selective detection and mitigation work on silicon? | **PASS** | the integrated loop quarantined context 2; an independent check kept contexts 6/10/14 on the primary and moved only context 2 to the backup |
| Is downstream-event to source-gate feedback closed and measured? | **PASS for partial loss** | 20/20 valid hardened trials; 4.998 ms median event-to-first-rerouted packet, 3.998–5.499 ms range |
| Is restoration safe and demonstrated? | **NO** | evidence-sized probation exists in controller code, but audit injection, receipt processing, and removal have not run as one silicon lifecycle |
| Is the headline performance contribution proved? | **NO** | no matched-safety Ring-AllReduce/MoE result with paired seeds and confidence intervals |
| Is the novelty broad? | **NO** | the ingredients are occupied prior art; the defensible novelty is the exact systems composition and capability below |

## Defensible claim now

> Behavioral Sublinks represent a directed physical link as conditionally healthy over a small,
> source-declared packet context. The same context key indexes post-TM delivery evidence and
> selective forwarding mitigation, allowing a failing context to be rerouted while contexts
> proven safe continue using the physical link. The context reuses existing witness-header space.

This is a **mechanism and capability claim**, not yet a workload-benefit or completed-lifecycle
claim. “Zero extra wire bytes” is only relative to the existing W4 witness header, not relative to
an uninstrumented fabric.

## Claims that are not currently licensed

- first-ever sequence-gap witness, downstream notification, active probe, fast reroute, per-class
  OAM, lease, probation, or restoration mechanism;
- a complete in-network telemetry answer for arbitrary faults;
- detection of a context that becomes a total black hole using passive C-W4 alone;
- a sub-3.998 ms end-to-end feedback latency or a 4.998 ms production-overhead result (the t1
  observation probability was deliberately elevated during measurement);
- safe automated restoration on hardware;
- application capacity or collective-completion-time improvement;
- production readiness or a publication-ready evaluation.

Absence of an identical system in the reviewed literature is not proof that none exists. The paper
must use a scoped composition claim and compare directly with per-CoS OAM, programmable loss
localization/notification, selective protection, and recent path-observability work.

## Why the novelty is narrow but potentially real

| closest occupied idea | what it removes from our novelty claim | remaining distinction to test |
|---|---|---|
| [ITU-T G.8013/Y.1731](https://www.itu.int/rec/T-REC-G.8013) | per-service/per-CoS loss OAM and active loss measurement are not new | one source-declared context key coupling post-TM evidence to selective packet forwarding inside a sprayed fabric |
| [dDrops](https://posco.github.io/publication/qian-2022-ddropsplane/) | downstream sequence discontinuity and upstream loss notification are not new | evidence and mitigation are indexed by the same behavioral-sublink identity, without per-packet feature buffering |
| [CorrOpt](https://people.csail.mit.edu/ghobadi/papers/corropt_sigcomm_2017.pdf) | detect/disable/repair/re-enable lifecycle and capacity-constrained mitigation are not new | retain the demonstrably safe contexts of the same directed physical link rather than disable the resource |
| [Aegis](https://www.usenix.org/system/files/nsdi25-dong.pdf) | size-conditioned faults and varied-size probing are published motivation, not our discovery | enforce a conditional health state after detection, instead of using size only to broaden diagnosis |

The likely contribution is therefore not a new detector or lifecycle primitive. It is a
**new controlled-resource contract**—the same `(directed link, context)` identity names evidence
and forwarding—and the empirical result that this contract preserves useful capacity at equal
safety. The implementation proves the contract is expressible; the application experiment must
still prove that it matters.

## Fresh implementation evidence

### Current P4 identity and placement

| item | value |
|---|---|
| source | `p4/witness/mcp_fabric_gate_event.p4` |
| source SHA-256 | `5f55380eb32d4dbf067c4bba1b21762e6a6ccfa49187ecad740594d85e2850fa` |
| checked-in BFRT schema SHA-256 | `92302aee7d5ce20c59af9e89e49ece96ed0b820269bd5bb5b2b5395cd372b4a3` |
| bf-p4c | 9.13.1, compile exit 0 |
| placement | **11 ingress / 4 egress**, 36 tables |
| table-summary SHA-256 | `42b8e91fc78da3ae57348a9d9344b86692f3f09d2323c67e13374387ca278958` |

The comparison programs remain: armed W4 9/3, C-W4 9/4, Context Capsule 9/4, and Capsule +
health gate 10/4. The old 9/3 Capsule and 10/3 gate rows were invalid because an 8-to-16-bit parser
copy contaminated the context with the adjacent byte.

### Model and controller semantics

- Fresh repository suites pass: **117 controller**, **34 P4 control/generator**,
  **27 hardware-loop/protocol**, and **137 simulation** tests.
- The current-source Tofino model run passes both gap-event/audit scenarios after recompiling the
  36-table program. The runner refuses pre-existing model/switch processes and cleans up only the
  exact PIDs it launched; the verified run left no matching process behind.
- The generator reproduces the checked-in event source, including audit-source authorization and
  the post-stamp fault injector.
- The model runner recompiles the current source instead of loading the obsolete 35-table artifact.
- The gap-event tests prove one attributed event per discontinuity and fail-closed audit behavior:
  only an authorized source can bypass quarantine; downstream arrival produces the receipt.
- The BFRT audit writer uses the current three-key schema
  `(md.audit_src, UDP dst, UDP src)`.
- The setup audit derives all 50 BFRT objects from the schema and reports zero required,
  unplanned match-action tables.
- `git diff --check`, targeted Python byte-compilation, Bash syntax checks, and ShellCheck pass.
  Deploy and bring-up dry-runs perform no SSH, SCP, or local writes.

### Silicon evidence already in the repository

- forwarding: 400/400 host frames and matching hardware counters;
- behavioral identity: 17/17 demanded sublinks synchronized across seven directed links and three
  contexts;
- selective detection: exactly one of 17 sublinks reported the injected conditional fault;
- integrated partial-loss feedback: 20/20 one-gap hardened trials produced one quarantine and one
  strict four-row batch; switch-clock event-to-first-rerouted-packet median 4.998 ms, range
  3.998–5.499 ms;
- demand-targeted census: four active cells read in 7.7 ms median instead of roughly 250 ms for all
  1,024 cells, with zero census errors in the campaign;
- selective mitigation: 2,000 bad-context packets moved to the backup while three healthy contexts
  each kept 2,000 packets on the original link (plus one background packet on context 14);
- 16-bit injector wrap: a live canary split a 655-packet fault into `[65303..65535]` and `[0..421]`;
- isolated gate-write cost: median 1.990 ms.

The 1.990 ms isolated number is retained only as a component reference; the 4.998 ms result is the
integrated feedback/actuation measurement. Neither includes fault-onset-to-detection time.

## Important negative results

1. **Passive black-hole blindness.** C-W4 needs a later survivor in the same context. Selective and
   all-context 100% loss emit no gap.
2. **Reordering defect in the deployed witness.** The present witness can infer loss under
   within-sublink reordering. An advance-only SALU plus controller reorder credit passed simulation
   and compiles at the same 11/4 stage cost, but it has not been adopted on the chip.
3. **Restoration rule failure.** The preregistered three-clean-round rule restored persistently
   faulty sublinks. Evidence-sized probation is implemented in the controller/simulator correction
   but has not been exercised as a silicon lifecycle.
4. **Latency cliff.** In dynamic replay, 60 ms feedback held or staled audits and 106.6 ms staled
   gap events before quarantine. A rule that never acts is not evidence of safety.
5. **Evaluation incompleteness.** The frozen 92,160-run grid was not completed and should be
   replaced by the preregistered tuning/confirmatory split in `CAMPAIGN-PLAN.md`, not quoted
   selectively.

## What must be implemented next

1. Drive authorized audit packets through the quarantined primary, consume receipts, accumulate
   evidence-sized probation, remove the gate, and test persistent/repaired/flapping faults.
2. Adopt and revalidate the advance-only/reorder-credit mechanism or narrow the operating contract
   to ordered sublinks.
3. Treat total black holes with a separately priced liveness mechanism or explicitly exclude them.
4. Run matched-safety baselines and the trace-driven Ring-AllReduce/MoE block with paired seeds,
   cluster bootstrap confidence intervals, and the preregistered stop rule.

## Publication decision rule

Promote the mechanism to a full contribution only if, at the same unsafe-packet bound, Behavioral
Sublinks retain at least five percentage points more safe primary demand or improve median
collective completion time by at least 5% over directed-link quarantine, with a confidence interval
excluding zero. Otherwise publish the mechanism/negative characterization narrowly and do not
claim application benefit.
