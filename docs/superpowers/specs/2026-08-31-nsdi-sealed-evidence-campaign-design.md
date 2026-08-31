# NSDI Sealed-Evidence Campaign

**Status:** Architecture approved 2026-08-31; specification pending review

**Repository:** `/home/philip/Projects/mcp`

**Target:** an evidence-backed Traditional Research Track submission, with an honest stop verdict if the campaign does not clear the required gates

## 1. Outcome

Build, evaluate, and compare a programmable grayhole/blackhole detection mechanism whose decisions are valid only when the traffic evidence is complete, contemporaneous, and tied to the exact deployed system identity.

The paper's central question is:

> What evidence contract is required before programmable telemetry may safely declare a path healthy, gray, or blackholed?

The proposed answer is a **sealed evidence epoch**: a health decision is admissible only when the sender and receiver observations, epoch and repair generation, exact trial configuration, and deployed program identities agree. Missing, stale, saturated, contaminated, or boundary-raced evidence is censored rather than interpreted as health.

The target result is not merely a detector with a higher point estimate. It is a measured validity boundary that:

1. prevents malformed observations from becoming false health;
2. detects partial and total non-delivery across a declared operating range;
3. supports selective mitigation without converting uncertainty into a destructive action;
4. has bounded switch, control-plane, and evidence-bandwidth cost; and
5. compares fairly with executable prior systems and matched decision baselines.

## 2. Repository-grounded starting point

The project already has a strong implementation base:

- the P4 program compiles for Tofino 1 and has fresh model, PTF, and silicon evidence;
- the evidence ledger rejects stale, incomplete, saturated, impossible, or boundary-raced records;
- the sequential detector uses a preregistered six-alternative mixture and anytime-valid evidence;
- the silicon harness records exact program, build, setup, runtime, process, epoch, and packet-count identity;
- healthy, 95% survival, and total-blackhole controls have been reproduced sequentially on silicon;
- the current implementation costs 1 KiB of on-chip state, with compile and control-plane costs already measured; and
- class-selective mitigation has been demonstrated on the one-switch virtual fabric.

The seven repaired defects establish why the validity contract matters. D1--D6 were different ways for an RX bit that did not belong to the measured traffic to become health evidence. D7 showed that even a correct detector can be evaluated against a topology table that was never installed. The campaign treats both data-plane evidence and deployment identity as parts of the same validity boundary.

The current evidence is not yet sufficient for an NSDI claim because it lacks a randomized multi-condition silicon campaign, matched decision baselines, benign calibration, complete ablations, and an end-to-end reproducibility audit. A paired workload-level effect and compatible upstream-system runs would materially strengthen the result, but are secondary extensions rather than prerequisites for validating the mechanism.

## 3. Thesis and contribution boundary

### 3.1 Gated thesis

Programmable failure telemetry has treated visibility as sufficient: if a counter or bit can be read, it can be used. Grayhole and blackhole decisions instead require **validity**. A sealed evidence epoch makes provenance, completeness, and temporal consistency explicit and fail closed, while a mixture sequential test extracts useful decisions from the sealed counts at low bandwidth and fixed on-chip state.

### 3.2 Candidate contributions

1. **Evidence Validity Contract.** A cross-layer contract joining data-plane observations, epoch closure, repair generation, exact packet accounting, controller state, and deployment identity. Invalid evidence yields a typed censor reason, not a health verdict.
2. **Unified gray/blackhole decision surface.** Immediate total-non-delivery handling plus anytime-valid mixture inference for partial loss, evaluated against fixed and standardized baselines on identical sealed observations.
3. **Tofino implementation and evaluation.** A resource-priced implementation with randomized silicon trials, benign calibration, selective mitigation, and reproducible evidence manifests.
4. **Failure taxonomy and negative evidence.** An empirical account of how plausible implementation, epoch, parser, and setup defects can create the expected answer for the wrong reason, together with tests that make those failures inadmissible.

Each contribution remains gated by the results. The paper must not claim that the Evidence Validity Contract, mixture test, or individual implementation primitive is novel until the final primary-source prior-art review supports that wording.

### 3.3 Explicit non-claims

Do not claim:

- the first gray-failure, silent-drop, alternate-marking, sequential, or programmable-data-plane detector;
- physical root-cause classification from non-delivery evidence;
- multi-switch silicon validation;
- production-scale deployment;
- arbitrary-topology or all-pipe support from the current pipe-0 loopback configuration;
- application improvement without paired workload evidence and confidence intervals;
- restoration or safe reintroduction unless the complete lifecycle is implemented and measured;
- superiority over prior work from published points measured in different environments; or
- a detector result from any censored, identity-mismatched, saturated, or count-inexact epoch.

## 4. Design principles

### 4.1 Seal before inference

Inference receives only a sealed record. Sealing checks:

- program name and source revision;
- build, setup, and runtime hashes;
- switch identity and `bf_switchd` process identity;
- gate-agent/runner version and trial manifest hash;
- sublink, epoch, bank parity, and repair generation;
- configured packet count, rate, context count, survival rule, and loss pattern;
- exact sender count, receiver count, programmed drops, and measured drops;
- saturation, wrap, duplicate, stale, transition, and boundary-race conditions; and
- single-owner BFRT binding during the trial.

A mismatch returns `CENSORED(reason)`. It never falls back to a presence bit, zero, prior epoch, or partial observation.

### 4.2 Separate closure, observation, decision, and action

The implementation and artifacts keep four layers distinct:

1. **Closure:** determine whether the epoch has ended and all required observations belong to it.
2. **Observation:** construct the exact TX/RX/drop record.
3. **Decision:** apply presence, fixed threshold, alternate marking, or sequential inference to the same record.
4. **Action:** monitor, selectively quarantine, or quarantine the whole link.

This separation makes baseline comparison meaningful and prevents action code from changing the evidence being evaluated.

### 4.3 Condition-based readiness

The campaign first measures the existing guard interval. Where the platform exposes a stable completion condition, the runner waits for that condition with a bounded timeout rather than sleeping for an arbitrary fixed delay. The old guard remains a conservative fallback and an ablation. Timing optimization must never weaken exact-count or epoch-closure checks.

### 4.4 Blackhole is non-delivery, not cause

A total-blackhole verdict means the sealed sender evidence records expected transmissions and the matching receiver evidence records no deliveries. It does not identify whether the cause was optics, queueing, configuration, a disconnected host, or the injected fault.

## 5. Evaluation architecture

The campaign has five linked lanes. All lanes consume an immutable scenario manifest and emit the common result schema in Section 10.

### 5.1 Deterministic correctness lane

Unit, property, model, and PTF tests establish invariants before statistical runs:

- no unsealed record reaches any detector;
- all known D1--D7 regressions have a failing counterexample and a passing fixed test;
- exact counts, wrap, saturation, parity, duplicate, stale epoch, repair-generation change, and transition races censor correctly;
- the six-alternative default is identical in simulation, controller, hardware runner, preregistration, and artifact metadata;
- immediate blackhole handling and partial-loss inference cannot overwrite one another; and
- setup manifests prove that all required forwarding and egress-vlink tables are installed.

### 5.2 Statistical simulation lane

Simulation provides broad, paired coverage that would be prohibitively expensive on silicon.

Primary dimensions:

- survival probability: `1.0, 0.999, 0.995, 0.99, 0.98, 0.95, 0.90, 0.75, 0.50, 0.10, 0.0`;
- loss process: IID, burst loss, and correlated multi-sublink loss;
- packets per epoch: `40, 100, 200`;
- detector: monitor, presence, fixed threshold, Alternate Marking count comparison, and sealed mixture;
- fault cardinality: one sublink, concurrent independent failures, and shared-fate failures;
- epoch transition: clean, delayed observation, duplicate, stale, and repair-generation change; and
- saturation/censor path: valid, exact saturation, overflow, count mismatch, and missing side.

Use at least 2,000 paired campaigns per primary survival point. The seed schedule is committed before the result run and shared by all detectors.

### 5.3 Focused silicon lane

The silicon campaign exercises the mechanism and matched local baselines on the existing one-switch 4x2 virtual fabric.

Required matrix:

- representative sublinks from each leaf/uplink position: `2, 6, 10, 14` unless preflight proves a mapping change;
- survival: `1.0, 0.99, 0.95, 0.75, 0.50, 0.10, 0.0`;
- loss pattern: dispersed and contiguous burst;
- packet rates: one conservative host-driven rate and the highest stable exact-count rate found by preflight;
- packets per epoch: 200 for resolution when counters permit, with the current 40-packet trial retained as a smoke/control case;
- at least 30 valid repetitions per primary cell; and
- randomized cell order with interleaved healthy controls.

Every trial records invalid attempts. Replacement trials increase the valid sample count but never erase the original censor rate.

Before the result matrix, a calibration phase determines:

- maximum exact-count packet rate;
- minimum safe condition-based or timed guard;
- counter and epoch-wrap limits;
- host buffering and output-flush behavior; and
- whether trial order creates detectable thermal, queue, or controller drift.

The final silicon matrix is frozen after calibration and before result collection.

### 5.4 Benign-stress lane

Healthy evidence must be tested under conditions that could resemble loss or incomplete closure:

- no injected loss at low and high stable load;
- a delivered 99% boundary condition matching the preregistered healthy null;
- bursty offered load and host scheduling pauses;
- reordered controller reads and delayed record assembly;
- back-to-back epoch transitions;
- duplicate read/update delivery;
- unrelated sublink faults; and
- intentional one-trial contamination as a negative control.

Primary outputs are false-alarm rate, censor rate, censor reason, and time-to-seal. A censor is not counted as either a correct negative or a false positive.

### 5.5 Action lane and workload extension

Selective action is part of the primary mechanism evaluation. A trace-driven workload is a secondary extension: implement it after the validity, silicon, and action microbenchmark gates pass, using paired seeds and identical injected failures. Prefer the existing MoE AlltoAll or Ring-AllReduce path that requires the least new simulator surface; add the second workload only after the first passes its correctness gate.

Compare:

- no mitigation;
- whole-link quarantine;
- class-selective quarantine driven by sealed evidence; and
- an oracle action time as a bound.

Required action metrics are bad packets exposed before action, healthy capacity removed, action latency, false-action rate, and residual loss. If the workload extension runs, also report job/collective completion time, tail completion time, and goodput. Restoration is excluded unless a separately reviewed lifecycle implementation passes its own safety tests.

## 6. Baseline contract

Baselines are divided into matched decision baselines and external system baselines. Recovery systems and detectors are never ranked on a single mixed metric.

### 6.1 Matched decision baselines

These consume the same sealed TX/RX record and differ only in decision logic:

- monitor/no action;
- presence/absence;
- fixed `1/8` loss threshold;
- standardized Alternate Marking count difference; and
- the six-alternative anytime-valid mixture.

This comparison isolates the contribution of inference from the contribution of valid evidence.

### 6.2 Best-effort external compatibility experiments

Attempt the smallest defensible executable set after pinning each upstream revision and proving that its environment, fault model, and metrics support a meaningful comparison:

- **FANcY:** closest released in-network gray-failure baseline, using its upstream simulator/Tofino artifact where compatible;
- **dDrops:** released programmable silent-drop baseline, using its upstream artifact where compatible; and
- **Alternate Marking:** standards-based passive counter baseline, with RFC 9341 as the semantic authority.

NetBouncer is added only if the final claim includes active-probe localization. LinkGuardian is added only to a mitigation/recovery comparison. SprayCheck remains related work unless a reproducible artifact becomes available. Full LossRadar remains historical/partial-artifact context unless a faithful implementation can be validated.

External-system runs are not a core acceptance prerequisite. If an artifact cannot be retrieved, built, validated, or made compatible without changing its semantics, record the exact blocker and keep that system in related-work or published-point context. External code is run in an isolated environment and is not copied into this repository. License, compiler, topology, and version differences are disclosed.

### 6.3 Fairness labels

Every comparison cell is labelled exactly one of:

- `matched-reimplementation`;
- `upstream-artifact`;
- `semantic-reimplementation`;
- `replay-only`; or
- `published-point`.

Only matched or meaningfully compatible runs support a superiority statement. Published points provide context, not a head-to-head win.

### 6.4 Metric separation

Detection/localization:

- probability of alarm within the declared horizon;
- epochs and packets to alarm;
- false alarms and misses;
- top-1/top-k localization; and
- censor rate reported separately.

Telemetry/implementation:

- switch stages, SRAM, map RAM, stateful ALUs, PHV, and tables;
- evidence and probe bytes;
- controller read/write rate and CPU time; and
- maximum exact-count throughput.

Mitigation:

- residual loss and bad packets exposed;
- capacity removed;
- action and recovery latency; and
- workload median and tail completion time.

## 7. Ablations

The minimum ablation matrix is:

1. sealed versus deliberately unsealed/legacy-compatible evidence handling;
2. presence versus fixed threshold versus sealed mixture;
3. each mixture alternative removed in turn and the complete six-point mixture;
4. packets per epoch and decision horizon;
5. fixed guard versus condition-based closure;
6. censoring enabled versus a negative-control analysis that demonstrates the bias caused by treating censored evidence as zero or healthy;
7. saturation limit and count resolution;
8. per-element versus pooled localizer baseline;
9. one versus multiple contexts where the implementation supports both; and
10. selective versus whole-link quarantine.

The negative-control implementation must be contained in analysis/test code and must never be deployable as the production default.

## 8. Statistical contract

The primary endpoints and seed schedules are preregistered before result collection.

Primary detection endpoints:

- false-alarm probability under the healthy null;
- alarm probability within four sealed epochs at preregistered gray-loss points;
- immediate-alarm probability for total blackholes;
- median sealed epochs and packets to alarm; and
- censor probability by condition.

Secondary workload endpoint, if the extension runs:

- paired change in job or collective completion time under the same failure trace, subject to no increase in false-action rate.

Analysis rules:

- pair seeds and scenarios across detectors/actions;
- bootstrap over campaigns/runs, not individual packets;
- report 95% confidence intervals for rates and paired differences;
- use exact binomial intervals where event counts are small;
- apply Holm correction across the declared primary comparisons;
- report all frozen cells, including null and adverse results;
- never tune a threshold, mixture, epoch, or guard on the result partition; and
- distinguish invalid/censored trials from missing files and detector misses.

Calibration data, development trials, and the frozen result partition live in separate artifact directories and carry separate manifest hashes.

## 9. Overhead and efficiency contract

Measure incremental cost against the closest compiled program without sealed-evidence functionality:

- ingress and egress stages;
- SRAM blocks and bytes;
- map RAM, TCAM, stateful ALUs, PHV, and table count;
- fixed and per-sublink state scaling;
- evidence bytes per epoch and per detected fault;
- controller reads, writes, CPU time, and BFRT operation latency;
- guard/closure latency;
- stable exact-count packets per second; and
- selective gate-install latency.

Raw compiler output is the authority for placed resources. Arithmetic extrapolation is labelled separately from measured bytes or timings. Any throughput optimization must preserve the evidence seal and reproduce the correctness suite before entering the result campaign.

## 10. Result and evidence schema

### 10.1 Immutable scenario manifest

```text
scenario_id
campaign_version
seed
sublink
epoch
repair_generation
packets
pps
contexts
survival
loss_pattern
burst_parameters
guard_policy
detectors
action_policy
```

### 10.2 Trial record

```text
scenario_id
program
source_revision
build_id
setup_id
runtime_id
switch_id
switchd_pid
runner_id
gate_agent_id
manifest_hash
started_at
completed_at
tx
rx
programmed_drops
measured_drops
seal_status
censor_reason
detector
verdict
e_value
decision_epoch
action
action_latency
cleanup_status
```

### 10.3 Campaign summary

```text
condition
valid_runs
invalid_runs
censor_rate
alarm_rate
false_alarm_rate
miss_rate
median_epochs
median_packets
confidence_interval
paired_effect
corrected_p_value
```

Raw JSONL is append-only. Derived CSV tables and plots record the input manifest hash and analysis revision. A summary without its raw-trial and manifest hashes is not authoritative.

## 11. Testbed and reproducibility boundary

The active hardware is one Tofino switch configured as a loopback 4x2 virtual fabric. All wired ports are in pipe 0. Vision supplies the active host path; Hulk is not presently part of forwarding. One BFRT client owns the configuration binding.

Therefore:

- silicon claims are limited to this switch, topology, pipe, compiler/SDE, and host path;
- model/PTF fault injection may validate cross-component or logically distributed behavior but is not multi-switch silicon evidence;
- a controller running on a second host does not convert the experiment into a two-switch deployment; and
- physical cross-switch validation remains a future/external requirement, not a hidden success criterion.

Safe hardware execution order is immutable artifact deployment, exact-manifest bring-up, ownership verification, calibration, randomized result campaign, cleanup verification, and evidence export. No result run begins while a foreign owner or mismatched process is present.

## 12. Implementation boundaries

The implementation plan may introduce one cohesive experiment package, but it must reuse the existing detector, evidence ledger, simulation, hardware runner, manifest, and analysis surfaces before adding abstractions.

Expected ownership boundaries:

- scenario and preregistration definitions;
- pure baseline decision functions;
- broad simulation campaign runner;
- resumable silicon campaign orchestration around the existing safe runner;
- append-only result validation and statistical analysis;
- workload/action adapter; and
- paper figures/tables generated only from sealed artifacts.

No new runtime dependency is permitted unless the implementation plan demonstrates that the existing environment cannot satisfy the requirement. External baseline repositories remain isolated and pinned by revision.

## 13. Deliverables

1. Approved design and execution plan.
2. Frozen preregistration, scenario matrix, and seed manifests.
3. Regression, property, model, and PTF verification results.
4. Calibration report and frozen silicon campaign manifest.
5. Raw silicon, simulation, and benign-stress artifacts with hashes, plus workload artifacts if the secondary extension runs.
6. Reproducible analysis scripts, tables, and publication-quality figures.
7. Incremental compile/resource and runtime-overhead report.
8. Prior-work implementation matrix with fairness labels and primary-source citations.
9. A new paper/evaluation surface centered on sealed evidence rather than the stale legacy MCP paper.
10. An adversarial completion audit and final NSDI-readiness verdict.

## 14. Acceptance gates

The campaign clears its result gate only if all of the following hold:

1. all D1--D7 classes and the declared seal invariants have regression coverage;
2. model/PTF and current-source compile checks pass from fresh artifacts;
3. the randomized silicon matrix completes with exact identities and a disclosed censor rate;
4. the healthy/benign false-alarm result satisfies the preregistered bound;
5. partial-loss and total-blackhole results satisfy their preregistered detection endpoints;
6. all matched decision baselines are evaluated; every candidate external system is either run from a pinned compatible artifact or retained as context with exact blocker evidence;
7. selective action is correct, bounded, and no less safe than whole-link quarantine in the declared microbenchmarks;
8. resource, evidence-bandwidth, controller, and action costs are freshly measured;
9. every headline claim maps to a raw artifact, manifest, and analysis revision; and
10. an independent adversarial review finds no blocking mismatch between code, configuration, artifacts, statistics, comparison text, and paper claims.

## 15. Stop and narrowing conditions

Do not force a positive paper conclusion. Narrow or stop the Traditional Research Track claim if:

- benign calibration violates the false-alarm gate;
- gray-loss coverage depends on unsealed or post-hoc-selected evidence;
- the silicon result is not reproducible across the declared representative sublinks;
- censored trials dominate a primary condition;
- matched baselines remove the claimed benefit;
- the primary validity/mitigation result disappears under paired analysis;
- overhead is materially worse than the value delivered;
- an upstream artifact or primary paper already implements the same validity contract and contribution; or
- the strongest result requires describing the one-switch loopback as a distributed silicon fabric.

If the workload extension does not produce a benefit, the paper is explicitly scoped to trustworthy failure evidence and selective action microbenchmarks. If only correctness survives, publish the repaired implementation/evidence methodology as an artifact or engineering result rather than overstating an NSDI systems contribution.
