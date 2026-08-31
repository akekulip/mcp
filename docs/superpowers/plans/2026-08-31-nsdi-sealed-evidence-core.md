# NSDI Sealed-Evidence Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and execute the reproducible core campaign that tests whether sealed evidence improves the validity, grayhole/blackhole coverage, and selective-action safety of the Tofino mechanism against matched baselines.

**Architecture:** Keep raw observation, sealing, decision, and action as separate layers. A small stdlib-only experiment package owns canonical manifests, append-only trial records, paired simulation, statistics, and artifact validation; the existing evidence ledger remains the only sequential detector, while a resumable wrapper drives the existing silicon trial harness. The primary acceptance axis is validity plus selective mitigation; workload evaluation remains a separately planned extension after the core result gate.

**Tech Stack:** Python 3.8-compatible stdlib, `pytest`/`unittest`, P4_16/TNA, Intel Tofino 1 switch with SDE 9.13.2, local model/compiler with SDE 9.13.1, BFRT, existing PTF/model runners, Bash deployment runbooks, Markdown/JSON/JSONL/CSV artifacts

**Spec:** `docs/superpowers/specs/2026-08-31-nsdi-sealed-evidence-campaign-design.md`

## Global Constraints

- Preserve all unrelated modified and untracked files; stage and commit only paths named by the current task.
- Add no repository dependency. Statistical, manifest, and analysis code stays Python-stdlib-only.
- The authoritative gray-loss null remains `healthy_delivery = 0.99`, per-repair-generation `alpha = 0.05`, and alternatives `(0.01, 0.10, 0.50, 0.75, 0.90, 0.97)`.
- A count is valid only when `0 <= rx <= tx < 255`; saturation, missing evidence, identity mismatch, stale/gapped epochs, cleanup failure, and injector mismatch are censored, never converted into health or loss.
- Hardware claims are limited to the current single-Tofino, pipe-0, 4x2 loopback fabric with one BFRT owner. Model/PTF is not multi-switch silicon evidence.
- The result partition is immutable after freezing. Development and calibration records cannot enter result summaries.
- Invalid attempts remain in append-only JSONL. Replacement attempts increase valid-attempt counts without deleting or relabelling invalid attempts.
- The statistical unit is one four-epoch attempt of one frozen condition cell inside one randomized `block_index`. JSONL remains epoch-granular. A valid attempt contains exactly the frozen horizon of sealed epoch records; any censor, crash-truncated sequence, or cleanup failure invalidates the whole attempt, and all of its records remain stored but are excluded together from detector-rate denominators.
- Matched detector comparisons consume the same sealed observation and packet budget. External-system results carry a provenance/compatibility label and cannot create a head-to-head claim across incompatible environments.
- No restoration or workload-benefit claim enters the core acceptance result.
- Every task follows red-green-refactor, runs the named focused tests, and commits only after fresh passing evidence.
- A bad outcome triggers the failure-driven improvement protocol below; it never authorizes tuning and reusing the same frozen result partition.

## Failure-driven improvement protocol

Apply this loop after simulation, calibration, silicon result, action, or overhead gates fail:

1. Reproduce the adverse result and audit raw records, identities, censor reasons, implementation state, and the claim-to-metric mapping before editing code.
2. Classify it with an independent review as exactly one of:
   - `PROVEN-DEFECT`: a violated preregistered invariant, implementation error, measurement error, or avoidable inefficiency with a concrete failing regression;
   - `VALID-UNDERPERFORMANCE`: the implementation and evidence contract are correct, but the mechanism does not meet a gate; or
   - `EXPECTED-CENSOR`: a preregistered invalid attempt, which remains in the censor rate and receives only a replacement attempt.
3. For `PROVEN-DEFECT`, add the failing regression first, implement the smallest root-cause fix, rerun offline/model/calibration gates, mark every affected result partition `INVALIDATED`, preserve its raw artifacts, increment `campaign_version`, freeze a new manifest/source closure with disjoint holdout seeds, and rerun all affected confirmatory cells. Never merge old and new result versions.
4. For `VALID-UNDERPERFORMANCE`, preserve and report the adverse result. Mechanism redesign or efficiency work occurs only in development/calibration, with a new preregistered hypothesis and thresholds where scientifically justified; evaluation then uses a new version and disjoint result holdout. If no independently defensible redesign remains, narrow the claim instead of iterating for significance.
5. Record every diagnosis, regression, code/source hash, invalidated artifact hash, design change, new seed range, and reviewer verdict in `docs/review/artifacts/nsdi27/IMPROVEMENT-LEDGER.md`. The final comparison shows all campaign versions, including adverse or invalidated predecessors.

Stop the loop only when the current version passes its frozen gates, or independent review confirms that no contract defect or in-scope mechanistic improvement remains and the honest outcome is a narrower/negative result.

---

## File and responsibility map

### New core experiment package

- `experiments/__init__.py` — package marker only.
- `experiments/nsdi27/__init__.py` — exports the frozen campaign version.
- `experiments/nsdi27/schema.py` — immutable deployment, campaign, scenario, decision, and trial record types plus validation.
- `experiments/nsdi27/codec.py` — canonical JSON, SHA-256 identities, append-only JSONL, and typed decode.
- `experiments/nsdi27/frozen.py` — confirmatory matrix, detector set, seeds, and acceptance constants.
- `experiments/nsdi27/baselines.py` — matched monitor/no-action, presence, fixed-threshold, Alternate-Marking fixed-horizon, and sealed-mixture decisions.
- `experiments/nsdi27/simulate.py` — paired IID/burst/shared-fate simulation using one realized observation stream per scenario.
- `experiments/nsdi27/analysis.py` — exact/Wilson intervals, clustered/paired bootstrap, exact paired tests, Holm adjustment, summaries, and gates.
- `experiments/nsdi27/ablations.py` — frozen exploratory ablation families and non-deployable negative controls.
- `experiments/nsdi27/overhead.py` — compiler/resource and runtime-cost extraction with measured/derived provenance.
- `experiments/nsdi27/external.py` — pinned external-artifact inventory and comparison compatibility validation.
- `experiments/nsdi27/PREREG.md` — frozen confirmatory questions, matrices, endpoints, exclusions, and exploratory split.
- `experiments/nsdi27/tests/` — focused tests for each module above.

### Existing controller and hardware surfaces

- `controller/evidence_ledger.py` — unchanged authoritative sequential inference unless a regression test exposes a contract defect.
- `controller/tests/test_seal_invariants.py` — exhaustive/property-style seal invariants built without an added property-testing dependency.
- `p4/hw/loop/gate_agent.py` — verify and expose applied setup identity; add exact dispersed-loss command.
- `p4/hw/loop/gate_agent_core.py` — SDK-independent setup-receipt and sealed-identity helpers.
- `p4/hw/loop/injector_ranges.py` — pure burst and evenly dispersed modular range generation.
- `p4/hw/loop/sequential_trials.py` — consume setup identity and selected loss pattern while preserving exact epoch semantics.
- `p4/hw/loop/nsdi_campaign.py` — freeze, run, resume, validate, and summarize calibration/result silicon manifests.
- `p4/hw/loop/nsdi_action_trials.py` — no-action, selective-context, and whole-link action microbenchmarks.
- `p4/hw/loop/test_*.py` — protocol, injector, trial, campaign, and action contract tests.
- `p4/hw/deploy.sh`, `p4/hw/bringup.sh` — seal runtime closure and write an applied-setup receipt only after exact setup succeeds.
- `p4/hw/test_setup_manifest_contract.py` — deployment/bring-up receipt ordering contract.

### Generated and reviewed artifacts

- `docs/review/artifacts/nsdi27/calibration/` — append-only calibration manifests, raw trials, and calibration selection.
- `docs/review/artifacts/nsdi27/ablation/` — separately hashed exploratory simulation and calibration-only ablations.
- `docs/review/artifacts/nsdi27/result/` — frozen result manifest, raw trials, validation receipt, and summaries.
- `docs/review/artifacts/nsdi27/overhead/` — raw compiler/resource/runtime inputs and parsed deltas.
- `docs/review/artifacts/nsdi27/external/` — pinned revisions, commands, compatibility verdicts, and result/blocker receipts.
- `docs/review/NSDI-FINAL-COMPARISON.md` — final measured implementation comparison and claim-to-evidence ledger.

---

### Task 1: Canonical scenario and append-only trial contract

**Files:**
- Create: `experiments/__init__.py`
- Create: `experiments/nsdi27/__init__.py`
- Create: `experiments/nsdi27/schema.py`
- Create: `experiments/nsdi27/codec.py`
- Create: `experiments/nsdi27/tests/__init__.py`
- Create: `experiments/nsdi27/tests/test_schema.py`
- Create: `experiments/nsdi27/tests/test_codec.py`

**Interfaces:**
- Produces: `DeploymentIdentity`, `ScenarioManifest`, `CampaignStage`, `CampaignManifest`, `ArmDecision`, `TrialRecord`, `Partition`, `LossPattern`, `SealStatus`, `ComparisonProvenance`.
- Produces: `trial_identity(campaign_hash, manifest, block_index, attempt, epoch_offset) -> str`, `canonical_bytes(value) -> bytes`, `sha256_identity(value) -> str`, `write_new(path, value) -> None`, `read_campaign(path) -> CampaignManifest`, `append_trial(path, trial) -> None`, `read_trials(path) -> Tuple[TrialRecord, ...]`.
- Consumes: Python dataclasses, enums, JSON, SHA-256, and filesystem primitives only.

- [ ] **Step 1: Write failing schema tests**

```python
from dataclasses import replace
import pytest

from experiments.nsdi27.schema import (
    ArmDecision, CampaignManifest, CampaignStage, DeploymentIdentity, LossPattern,
    Partition, ScenarioManifest, SealStatus, TrialRecord,
)

HEX_A = "a" * 64
HEX_B = "b" * 64


def identity():
    return DeploymentIdentity(
        program="mcp_fabric_clf_eg", switch_id=HEX_B, source_revision=HEX_A,
        build_id=HEX_A, setup_id=HEX_B, runtime_id=HEX_A,
        runner_id=HEX_B, gate_agent_id=HEX_A,
    )


def scenario():
    return ScenarioManifest(
        scenario_id="result/s2/seed7", campaign_version="nsdi27-v1",
        partition=Partition.RESULT,
        seed=7, sublink=2, start_epoch=100, repair_generation=0,
        packets_per_epoch=200, horizon=4, pps=200, contexts="2",
        survival=0.95, loss_pattern=LossPattern.DISPERSED,
        fault_model="single", epoch_condition="clean", evidence_condition="valid",
        burst_length=0, guard_seconds=0.5, closure_mode="fixed-guard",
        alpha=0.05, healthy_delivery=0.99,
        alternatives=(0.01, 0.10, 0.50, 0.75, 0.90, 0.97),
        deployment=identity(), action_policy="monitor",
    )


def stage(*scenario_ids):
    return CampaignStage(
        stage_id="result", depends_on=(), scenario_ids=scenario_ids,
        valid_target=30 * len(scenario_ids), attempt_cap=60 * len(scenario_ids),
        selection_rule="all-cells-30-valid",
    )


def test_result_manifest_rejects_non_result_partition():
    with pytest.raises(ValueError, match="result manifest"):
        replace(scenario(), partition=Partition.CALIBRATION).require_result()


def test_campaign_manifest_rejects_mixed_partitions():
    manifest = CampaignManifest(
        campaign_id="nsdi27-result", campaign_version="nsdi27-v1",
        partition=Partition.RESULT, selection_rule="all-cells-30-valid",
        source_closure=(("p4/witness/mcp_fabric_clf_eg.p4", HEX_A),),
        scenarios=(scenario(), replace(scenario(), scenario_id="cal/1",
                                       partition=Partition.CALIBRATION)),
        stages=(stage("result/s2/seed7", "cal/1"),),
    )
    with pytest.raises(ValueError, match="partition"):
        manifest.validate()


def test_campaign_manifest_rejects_unsealed_or_ambiguous_source_closure():
    manifest = CampaignManifest(
        campaign_id="nsdi27-result", campaign_version="nsdi27-v1",
        partition=Partition.RESULT, selection_rule="all-cells-30-valid",
        source_closure=(("p4/witness/mcp_fabric_clf_eg.p4", HEX_A),
                        ("p4/witness/mcp_fabric_clf_eg.p4", HEX_B)),
        scenarios=(scenario(),), stages=(stage("result/s2/seed7"),),
    )
    with pytest.raises(ValueError, match="source closure"):
        manifest.validate()


def test_campaign_stage_cannot_reference_an_unknown_scenario():
    manifest = CampaignManifest(
        campaign_id="nsdi27-result", campaign_version="nsdi27-v1",
        partition=Partition.RESULT, selection_rule="all-cells-30-valid",
        source_closure=(("p4/witness/mcp_fabric_clf_eg.p4", HEX_A),),
        scenarios=(scenario(),), stages=(stage("not-frozen"),),
    )
    with pytest.raises(ValueError, match="stage scenario coverage"):
        manifest.validate()


def test_hardware_trial_requires_every_identity_and_exact_counts():
    manifest = scenario()
    with pytest.raises(ValueError, match="setup_id"):
        replace(manifest, deployment=replace(identity(), setup_id="")).validate()


def test_only_simulation_may_use_a_preregistered_leave_one_out_mixture():
    reduced = (0.01, 0.10, 0.50, 0.75, 0.90)
    replace(scenario(), partition=Partition.SIMULATION, alternatives=reduced).validate()
    with pytest.raises(ValueError, match="frozen six-point mixture"):
        replace(scenario(), alternatives=reduced).validate()


@pytest.mark.parametrize("changes, message", (
    ({"guard_seconds": -0.1}, "guard_seconds"),
    ({"contexts": "2,99"}, "contexts"),
    ({"alpha": 0.0}, "alpha"),
    ({"action_policy": "quarantine-everything"}, "action_policy"),
))
def test_manifest_rejects_invalid_operating_parameters(changes, message):
    with pytest.raises(ValueError, match=message):
        replace(scenario(), **changes).validate()


def test_censored_trial_is_not_a_detector_miss():
    record = TrialRecord.censored(
        campaign_hash=HEX_A, manifest=scenario(), block_index=0,
        attempt=0, epoch_offset=0,
        switchd_pid=123, reason="identity-mismatch", cleanup_status="not-mutated",
    )
    assert record.seal_status is SealStatus.CENSORED
    assert all(decision.verdict == "CENSORED" for decision in record.decisions)
    assert {decision.observation_id for decision in record.decisions} == {record.trial_id}


def test_censored_trial_cannot_omit_a_matched_arm():
    record = TrialRecord.censored(
        campaign_hash=HEX_A, manifest=scenario(), block_index=0,
        attempt=0, epoch_offset=0,
        switchd_pid=123, reason="identity-mismatch", cleanup_status="not-mutated",
    )
    with pytest.raises(ValueError, match="frozen detector set"):
        replace(record, decisions=record.decisions[:-1]).validate()
```

- [ ] **Step 2: Run the schema tests and confirm the package is absent**

Run: `python3 -m pytest experiments/nsdi27/tests/test_schema.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'experiments.nsdi27'`.

- [ ] **Step 3: Implement the immutable types and validation**

```python
class Partition(str, Enum):
    DEVELOPMENT = "development"
    CALIBRATION = "calibration"
    RESULT = "result"
    SIMULATION = "simulation"


class LossPattern(str, Enum):
    IID = "iid"
    BURST = "burst"
    DISPERSED = "dispersed"
    SHARED_FATE = "shared-fate"


class SealStatus(str, Enum):
    SEALED = "sealed"
    CENSORED = "censored"


class ComparisonProvenance(str, Enum):
    MATCHED_REIMPLEMENTATION = "matched-reimplementation"
    UPSTREAM_ARTIFACT = "upstream-artifact"
    SEMANTIC_REIMPLEMENTATION = "semantic-reimplementation"
    REPLAY_ONLY = "replay-only"
    PUBLISHED_POINT = "published-point"


@dataclass(frozen=True)
class DeploymentIdentity:
    program: str
    switch_id: str
    source_revision: str
    build_id: str
    setup_id: str
    runtime_id: str
    runner_id: str
    gate_agent_id: str

    def validate(self) -> None:
        for name, value in dataclasses.asdict(self).items():
            if name == "program":
                if not value:
                    raise ValueError("program is required")
            elif len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("%s must be a lowercase SHA-256" % name)


@dataclass(frozen=True)
class ScenarioManifest:
    scenario_id: str
    campaign_version: str
    partition: Partition
    seed: int
    sublink: int
    start_epoch: int
    repair_generation: int
    packets_per_epoch: int
    horizon: int
    pps: int
    contexts: str
    survival: float
    loss_pattern: LossPattern
    fault_model: str
    epoch_condition: str
    evidence_condition: str
    burst_length: int
    guard_seconds: float
    closure_mode: str
    alpha: float
    healthy_delivery: float
    alternatives: Tuple[float, ...]
    deployment: DeploymentIdentity
    action_policy: str

    def validate(self) -> None:
        self.deployment.validate()
        if not self.scenario_id or not self.campaign_version:
            raise ValueError("scenario_id and campaign_version are required")
        if not 0 <= self.sublink < 1024:
            raise ValueError("sublink must lie in 0..1023")
        if not 0 <= self.start_epoch <= 0xFFFF:
            raise ValueError("start_epoch must fit 16 bits")
        if not 0 < self.packets_per_epoch < 255:
            raise ValueError("packets_per_epoch must lie in 1..254")
        if self.horizon <= 0 or self.pps <= 0:
            raise ValueError("horizon and pps must be positive")
        if self.seed < 0 or self.repair_generation < 0:
            raise ValueError("seed and repair_generation must be non-negative")
        if not math.isfinite(self.guard_seconds) or self.guard_seconds < 0.0:
            raise ValueError("guard_seconds must be finite and non-negative")
        if self.burst_length < 0:
            raise ValueError("burst_length must be non-negative")
        if (self.loss_pattern is LossPattern.BURST and self.survival < 1.0
                and self.burst_length <= 0):
            raise ValueError("non-healthy burst loss requires a positive burst_length")
        if self.loss_pattern is not LossPattern.BURST and self.burst_length != 0:
            raise ValueError("only burst loss may set burst_length")
        try:
            contexts = tuple(int(value) for value in self.contexts.split(","))
        except ValueError:
            raise ValueError("contexts must be comma-separated integers")
        if (not contexts or contexts != tuple(sorted(contexts))
                or len(set(contexts)) != len(contexts)
                or any(value not in (2, 6, 10, 14) for value in contexts)):
            raise ValueError("contexts must be a canonical active-context subset")
        if self.fault_model not in ("single", "concurrent-independent", "shared-fate"):
            raise ValueError("unknown fault_model")
        if self.epoch_condition not in (
                "clean", "delayed", "duplicate", "stale", "repair-change"):
            raise ValueError("unknown epoch_condition")
        if self.evidence_condition not in (
                "valid", "saturation", "overflow", "count-mismatch", "missing-side"):
            raise ValueError("unknown evidence_condition")
        if self.fault_model == "single" and len(contexts) != 1:
            raise ValueError("single fault_model requires one context")
        if self.fault_model != "single" and len(contexts) <= 1:
            raise ValueError("multi-fault models require multiple contexts")
        if ((self.fault_model == "shared-fate")
                != (self.loss_pattern is LossPattern.SHARED_FATE)):
            raise ValueError("shared-fate fault and loss models must agree")
        if (self.partition is not Partition.SIMULATION
                and (self.fault_model != "single" or self.epoch_condition != "clean"
                     or self.evidence_condition != "valid")):
            raise ValueError("synthetic fault/evidence conditions are simulation-only")
        if not 0.0 <= self.survival <= 1.0:
            raise ValueError("survival must lie in [0, 1]")
        if self.alpha != 0.05 or self.healthy_delivery != 0.99:
            raise ValueError("alpha and healthy_delivery differ from preregistration")
        if self.action_policy not in ("monitor", "none", "selective", "whole-link"):
            raise ValueError("unknown action_policy")
        if self.closure_mode not in ("fixed-guard", "injected-receipt"):
            raise ValueError("unknown closure mode")
        if (self.closure_mode == "injected-receipt"
                and self.partition is not Partition.CALIBRATION):
            raise ValueError("injected-receipt closure is calibration-only")
        frozen = (0.01, 0.10, 0.50, 0.75, 0.90, 0.97)
        if self.partition is Partition.SIMULATION:
            if (not self.alternatives or len(set(self.alternatives)) != len(self.alternatives)
                    or any(value not in frozen for value in self.alternatives)):
                raise ValueError("simulation alternatives must be a nonempty frozen subset")
        elif tuple(self.alternatives) != frozen:
            raise ValueError("alternatives differ from the frozen six-point mixture")

    def require_result(self) -> "ScenarioManifest":
        if self.partition is not Partition.RESULT:
            raise ValueError("result manifest contains a non-result scenario")
        if self.closure_mode != "fixed-guard":
            raise ValueError("result manifest requires deployable fixed-guard closure")
        self.validate()
        return self


@dataclass(frozen=True)
class CampaignStage:
    stage_id: str
    depends_on: Tuple[str, ...]
    scenario_ids: Tuple[str, ...]
    valid_target: int
    attempt_cap: int
    selection_rule: str


@dataclass(frozen=True)
class CampaignManifest:
    campaign_id: str
    campaign_version: str
    partition: Partition
    selection_rule: str
    source_closure: Tuple[Tuple[str, str], ...]
    scenarios: Tuple[ScenarioManifest, ...]
    stages: Tuple[CampaignStage, ...]

    def validate(self):
        if (not self.campaign_id or not self.selection_rule or not self.scenarios
                or not self.campaign_version or not self.source_closure or not self.stages):
            raise ValueError(
                "campaign id, selection rule, source closure, scenarios, and stages are required"
            )
        closure_paths = tuple(path for path, _ in self.source_closure)
        if (closure_paths != tuple(sorted(closure_paths))
                or len(set(closure_paths)) != len(closure_paths)
                or any(not path or len(digest) != 64
                       or any(char not in "0123456789abcdef" for char in digest)
                       for path, digest in self.source_closure)):
            raise ValueError("source closure must be sorted, unique, and SHA-256 sealed")
        scenario_ids = tuple(scenario.scenario_id for scenario in self.scenarios)
        if len(set(scenario_ids)) != len(scenario_ids):
            raise ValueError("campaign scenario ids must be unique")
        for scenario in self.scenarios:
            scenario.validate()
            if scenario.partition is not self.partition:
                raise ValueError("campaign and scenario partition differ")
            if scenario.campaign_version != self.campaign_version:
                raise ValueError("campaign version differs from scenario")
        if len({scenario.deployment for scenario in self.scenarios}) != 1:
            raise ValueError("campaign scenarios have different deployment identities")
        known_stages = []
        staged_scenarios = []
        for stage in self.stages:
            if (not stage.stage_id or stage.stage_id in known_stages
                    or not stage.scenario_ids or stage.valid_target < 0
                    or stage.attempt_cap <= 0
                    or stage.valid_target > stage.attempt_cap
                    or not stage.selection_rule):
                raise ValueError("campaign stage is incomplete or duplicated")
            if any(dependency not in known_stages for dependency in stage.depends_on):
                raise ValueError("campaign stage dependency is missing or out of order")
            known_stages.append(stage.stage_id)
            staged_scenarios.extend(stage.scenario_ids)
        if (len(set(staged_scenarios)) != len(staged_scenarios)
                or set(staged_scenarios) != set(scenario_ids)):
            raise ValueError("stage scenario coverage differs from frozen scenarios")

    def require_result(self):
        if self.partition is not Partition.RESULT:
            raise ValueError("result manifest contains a non-result campaign")
        self.validate()
        for scenario in self.scenarios:
            scenario.require_result()
        return self


DETECTOR_NAMES = (
    "monitor-no-action",
    "presence",
    "fixed-1-in-8",
    "alternate-marking-exact",
    "sealed-mixture",
)


@dataclass(frozen=True)
class ArmDecision:
    observation_id: str
    detector: str
    verdict: str
    e_value: Optional[float]
    p_value: Optional[float]
    statistical_alarm: bool
    reason: str
    provenance: ComparisonProvenance


@dataclass(frozen=True)
class TrialRecord:
    trial_id: str
    scenario_id: str
    campaign_hash: str
    scenario_hash: str
    block_index: int
    attempt: int
    epoch_offset: int
    switch_id: str
    switchd_pid: int
    started_ns: int
    completed_ns: int
    tx: Optional[int]
    rx: Optional[int]
    programmed_drops: Optional[int]
    measured_drops: Optional[int]
    seal_status: SealStatus
    censor_reason: Optional[str]
    cleanup_status: str
    decisions: Tuple[ArmDecision, ...]

    @classmethod
    def censored(cls, campaign_hash, manifest, block_index, attempt, epoch_offset,
                 switchd_pid, reason, cleanup_status, *, started_ns=0, completed_ns=0,
                 tx=None, rx=None, programmed_drops=None, measured_drops=None):
        from experiments.nsdi27.codec import sha256_identity
        scenario_hash = sha256_identity(manifest)
        trial_id = trial_identity(
            campaign_hash, manifest, block_index, attempt, epoch_offset,
        )
        decisions = tuple(
            ArmDecision(
                observation_id=trial_id, detector=name, verdict="CENSORED",
                e_value=None, p_value=None, statistical_alarm=False,
                reason=reason,
                provenance=ComparisonProvenance.MATCHED_REIMPLEMENTATION,
            )
            for name in DETECTOR_NAMES
        )
        result = cls(
            trial_id=trial_id, scenario_id=manifest.scenario_id,
            campaign_hash=campaign_hash, scenario_hash=scenario_hash,
            block_index=block_index, attempt=attempt,
            epoch_offset=epoch_offset, switch_id=manifest.deployment.switch_id,
            switchd_pid=switchd_pid,
            started_ns=started_ns, completed_ns=completed_ns,
            tx=tx, rx=rx, programmed_drops=programmed_drops,
            measured_drops=measured_drops,
            seal_status=SealStatus.CENSORED, censor_reason=reason,
            cleanup_status=cleanup_status, decisions=decisions,
        )
        result.validate()
        return result

    @classmethod
    def sealed(cls, campaign_hash, manifest, block_index, attempt, epoch_offset,
               switchd_pid, tx, rx, programmed_drops, measured_drops, decisions,
               cleanup_status,
               *, started_ns=0, completed_ns=0):
        from experiments.nsdi27.codec import sha256_identity
        scenario_hash = sha256_identity(manifest)
        trial_id = trial_identity(
            campaign_hash, manifest, block_index, attempt, epoch_offset,
        )
        result = cls(
            trial_id=trial_id, scenario_id=manifest.scenario_id,
            campaign_hash=campaign_hash, scenario_hash=scenario_hash,
            block_index=block_index, attempt=attempt,
            epoch_offset=epoch_offset, switch_id=manifest.deployment.switch_id,
            switchd_pid=switchd_pid,
            started_ns=started_ns, completed_ns=completed_ns,
            tx=tx, rx=rx, programmed_drops=programmed_drops,
            measured_drops=measured_drops, seal_status=SealStatus.SEALED,
            censor_reason=None, cleanup_status=cleanup_status,
            decisions=tuple(decisions),
        )
        result.validate()
        return result

    def validate(self):
        for name, value in (("trial_id", self.trial_id),
                            ("campaign_hash", self.campaign_hash),
                            ("scenario_hash", self.scenario_hash),
                            ("switch_id", self.switch_id)):
            if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError("%s must be a lowercase SHA-256" % name)
        if (not self.scenario_id or self.block_index < 0 or self.attempt < 0
                or self.epoch_offset < 0
                or self.switchd_pid < 0 or self.started_ns < 0
                or self.completed_ns < self.started_ns):
            raise ValueError("trial identity, attempt, PID, or timestamps are invalid")
        if tuple(d.detector for d in self.decisions) != DETECTOR_NAMES:
            raise ValueError("trial does not contain the frozen detector set")
        if any(d.observation_id != self.trial_id for d in self.decisions):
            raise ValueError("detectors did not score the same sealed observation")
        if self.seal_status is SealStatus.CENSORED:
            if not self.censor_reason or any(d.verdict != "CENSORED" for d in self.decisions):
                raise ValueError("censored trials require censored decisions and a reason")
            return
        if self.cleanup_status != "clean":
            raise ValueError("cleanup failure must censor the trial")
        if self.tx is None or self.rx is None or not 0 <= self.rx <= self.tx < 255:
            raise ValueError("sealed counts must satisfy 0 <= rx <= tx < 255")
        measured = self.tx - self.rx
        if self.programmed_drops != measured or self.measured_drops != measured:
            raise ValueError("programmed, measured, and counter-derived drops differ")


def trial_identity(campaign_hash, manifest, block_index, attempt, epoch_offset):
    if block_index < 0 or attempt < 0 or epoch_offset < 0:
        raise ValueError("block_index, attempt, and epoch_offset must be non-negative")
    return hashlib.sha256(
        ("%s/%s/%d/%d/%d" %
         (campaign_hash, manifest.scenario_id, block_index, attempt,
          epoch_offset)).encode("utf-8")
    ).hexdigest()
```

Import `dataclasses`, `hashlib`, `math`, `Enum`, `Optional`, and `Tuple` explicitly. Keep the local codec import inside the two constructors so `codec.py` can decode schema types without an import cycle.

- [ ] **Step 4: Write failing codec tests**

```python
import json
import pytest

from experiments.nsdi27.codec import (
    append_trial, canonical_bytes, read_campaign, read_trials, sha256_identity,
    write_new,
)
from experiments.nsdi27.schema import CampaignManifest, Partition, TrialRecord
from experiments.nsdi27.tests.test_schema import HEX_A, scenario, stage


def test_canonical_hash_is_order_and_process_stable(tmp_path):
    manifest = scenario()
    assert sha256_identity(manifest) == sha256_identity(manifest)
    assert canonical_bytes(manifest).endswith(b"\n")
    decoded = json.loads(canonical_bytes(manifest))
    assert decoded["partition"] == "result"
    assert decoded["loss_pattern"] == "dispersed"
    assert decoded["deployment"]["program"] == "mcp_fabric_clf_eg"


def test_jsonl_append_preserves_invalid_attempts(tmp_path):
    output = tmp_path / "trials.jsonl"
    first = TrialRecord.censored(
        HEX_A, scenario(), 0, 0, 0, 123, "count-mismatch", "clean",
    )
    second = TrialRecord.censored(
        HEX_A, scenario(), 0, 1, 0, 123, "identity-mismatch", "not-mutated",
    )
    append_trial(output, first)
    append_trial(output, second)
    assert read_trials(output) == (first, second)


def test_campaign_manifest_is_created_once_and_round_trips(tmp_path):
    path = tmp_path / "manifest.json"
    value = CampaignManifest(
        campaign_id="nsdi27-result", campaign_version="nsdi27-v1",
        partition=Partition.RESULT, selection_rule="all-cells-30-valid",
        source_closure=(("p4/witness/mcp_fabric_clf_eg.p4", HEX_A),),
        scenarios=(scenario(),),
        stages=(stage("result/s2/seed7"),),
    )
    write_new(path, value)
    assert read_campaign(path) == value
    with pytest.raises(FileExistsError):
        write_new(path, value)
```

- [ ] **Step 5: Implement canonical encoding and durable append**

```python
def _json_value(value):
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical JSON mappings require string keys")
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise TypeError("unsupported canonical JSON type: %s" % type(value).__name__)


def canonical_bytes(value) -> bytes:
    payload = _json_value(value)
    return (json.dumps(payload, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def sha256_identity(value) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def write_new(path: pathlib.Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(canonical_bytes(value))
        handle.flush()
        os.fsync(handle.fileno())


def append_trial(path: pathlib.Path, trial: TrialRecord) -> None:
    trial.validate()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as handle:
        handle.write(canonical_bytes(trial))
        handle.flush()
        os.fsync(handle.fileno())
```

Import `Enum` in `codec.py`. Decode enums, tuples, nested `DeploymentIdentity`, `CampaignStage`, `CampaignManifest`, `ScenarioManifest`, and nested `ArmDecision` explicitly in `read_campaign`/`read_trials`; reject unknown fields and malformed lines instead of silently dropping them.

- [ ] **Step 6: Run focused tests**

Run: `python3 -m pytest experiments/nsdi27/tests/test_schema.py experiments/nsdi27/tests/test_codec.py -q`

Expected: all tests PASS.

- [ ] **Step 7: Commit the contract**

```bash
git add experiments/__init__.py experiments/nsdi27/__init__.py experiments/nsdi27/schema.py experiments/nsdi27/codec.py experiments/nsdi27/tests/__init__.py experiments/nsdi27/tests/test_schema.py experiments/nsdi27/tests/test_codec.py
git commit -m "feat: define sealed campaign records"
```

---

### Task 2: Freeze confirmatory matrices, seeds, and acceptance rules

**Files:**
- Create: `experiments/nsdi27/frozen.py`
- Create: `experiments/nsdi27/PREREG.md`
- Create: `experiments/nsdi27/tests/test_frozen.py`

**Interfaces:**
- Consumes: `ScenarioManifest`, `DeploymentIdentity`, `Partition`, `LossPattern` from Task 1.
- Produces: `simulation_scenarios(identity) -> Tuple[ScenarioManifest, ...]`, `silicon_cells(identity, partition, packets_per_epoch=200, pps=200, guard_seconds=2.0, closure_mode="fixed-guard") -> Tuple[ScenarioManifest, ...]`, `scenario_order(scenarios, seed) -> Tuple[ScenarioManifest, ...]`, `scenario_blocks(scenarios, repetitions, seed) -> Tuple[Tuple[ScenarioManifest, ...], ...]`.
- Produces constants: `CAMPAIGN_VERSION`, `DEFAULT_ALTERNATIVES`, `SIMULATION_SURVIVAL`, `SIMULATION_PACKET_COUNTS`, `SIMULATION_PRIMARY_REPETITIONS`, `PRIMARY_SUBLINKS`, `PRIMARY_SURVIVAL`, `PRIMARY_PATTERNS`, `PRIMARY_REPETITIONS`, `PRIMARY_HORIZON`, `PRIMARY_DETECTORS`, `PRIMARY_ACTION_MODES`.

- [ ] **Step 1: Write failing frozen-matrix tests**

```python
def test_primary_matrix_is_exact_and_uses_four_representative_sublinks():
    assert SIMULATION_SURVIVAL == (
        1.0, 0.999, 0.995, 0.99, 0.98, 0.95,
        0.90, 0.75, 0.50, 0.10, 0.0,
    )
    assert SIMULATION_PACKET_COUNTS == (40, 100, 200)
    assert SIMULATION_PRIMARY_REPETITIONS == 2000
    assert PRIMARY_SUBLINKS == (2, 6, 10, 14)
    assert PRIMARY_SURVIVAL == (1.0, 0.99, 0.95, 0.75, 0.50, 0.10, 0.0)
    assert PRIMARY_PATTERNS == (LossPattern.DISPERSED, LossPattern.BURST)
    assert PRIMARY_REPETITIONS == 30
    assert PRIMARY_HORIZON == 4
    assert PRIMARY_DETECTORS == (
        "monitor-no-action", "presence", "fixed-1-in-8",
        "alternate-marking-exact", "sealed-mixture",
    )
    assert PRIMARY_ACTION_MODES == ("none", "selective", "whole-link")
    assert tuple(DEFECT_REGRESSION_TESTS) == ("D1", "D2", "D3", "D4", "D5", "D6", "D7")


def test_randomized_order_is_reproducible_and_not_source_order():
    cells = silicon_cells(identity(), Partition.RESULT)
    blocks = scenario_blocks(cells, PRIMARY_REPETITIONS, 20260831)
    assert blocks == scenario_blocks(cells, PRIMARY_REPETITIONS, 20260831)
    assert len(blocks) == PRIMARY_REPETITIONS
    assert all(set(block) == set(cells) for block in blocks)
    assert len({tuple(cell.scenario_id for cell in block) for block in blocks}) > 1


def test_every_result_block_contains_healthy_controls():
    cells = silicon_cells(identity(), Partition.RESULT)
    blocks = scenario_blocks(cells, PRIMARY_REPETITIONS, 20260831)
    assert all(any(cell.survival == 1.0 for cell in block) for block in blocks)
```

- [ ] **Step 2: Run tests and confirm imports fail**

Run: `python3 -m pytest experiments/nsdi27/tests/test_frozen.py -q`

Expected: FAIL because `experiments.nsdi27.frozen` does not exist.

- [ ] **Step 3: Implement exact frozen constants and deterministic CRC-32 seeds**

```python
CAMPAIGN_VERSION = "nsdi27-v1"
DEFAULT_ALTERNATIVES = (0.01, 0.10, 0.50, 0.75, 0.90, 0.97)
SIMULATION_SURVIVAL = (
    1.0, 0.999, 0.995, 0.99, 0.98, 0.95,
    0.90, 0.75, 0.50, 0.10, 0.0,
)
SIMULATION_PACKET_COUNTS = (40, 100, 200)
SIMULATION_PRIMARY_REPETITIONS = 2000
PRIMARY_SUBLINKS = (2, 6, 10, 14)
PRIMARY_SURVIVAL = (1.0, 0.99, 0.95, 0.75, 0.50, 0.10, 0.0)
PRIMARY_PATTERNS = (LossPattern.DISPERSED, LossPattern.BURST)
PRIMARY_PACKET_COUNTS = (40, 200)
PRIMARY_REPETITIONS = 30
PRIMARY_HORIZON = 4
PRIMARY_DETECTORS = DETECTOR_NAMES
PRIMARY_ACTION_MODES = ("none", "selective", "whole-link")
MAX_HEALTHY_FALSE_ALARM_UCL = 0.05
MIN_GRAY_ALARM_RATE = {0.95: 0.80, 0.75: 0.95, 0.50: 0.95}
MIN_GRAY_ALARM_LCL = {0.95: 0.70, 0.75: 0.85, 0.50: 0.85}
MIN_BLACKHOLE_FIRST_EPOCH_RATE = 0.99
MIN_BLACKHOLE_FIRST_EPOCH_LCL = 0.90
MAX_AGGREGATE_CENSOR_UCL = 0.05
MAX_PER_CELL_CENSOR_RATE = 0.10
DEFECT_REGRESSION_TESTS = {
    "D1": ("p4/hw/loop/test_sequential_trials.py::SequentialTrialTest::test_zero_readback_rejects_persistent_target_residue",),
    "D2": ("p4/ptf/test_w4_witness.py::Test13EndToEndPostStampLoss",),
    "D3": ("p4/ptf/test_cw4_sublinks.py::Test23EgressClassifiesAndStampsSublinks",),
    "D4": ("p4/hw/loop/test_sequential_trials.py::SequentialTrialTest::test_sealed_epoch_orders_commands_and_cleans_injector",),
    "D5": ("p4/ptf/test_w4_witness.py::Test12StampNamesTheDirectedLink",),
    "D6": ("p4/hw/loop/test_clf_trials.py::ClassifierTest::test_count_rows_drive_verdict_counts_by_default",),
    "D7": ("p4/control/tests/test_setup_attention.py::EgVlinkVerificationTest::test_exact_eg_vlink_verification_rejects_missing_row",),
}


def stable_seed(*parts: object) -> int:
    encoded = "/".join(str(part) for part in parts).encode("utf-8")
    return zlib.crc32(encoded) & 0x7fffffff


def scenario_order(scenarios, seed):
    ordered = list(scenarios)
    random.Random(seed).shuffle(ordered)
    return tuple(ordered)


def scenario_blocks(scenarios, repetitions, seed):
    if repetitions <= 0:
        raise ValueError("repetitions must be positive")
    return tuple(
        scenario_order(scenarios, stable_seed(seed, block_index))
        for block_index in range(repetitions)
    )
```

Each `ScenarioManifest` represents one immutable condition cell, not one repetition. Give it a stable human-readable `scenario_id` containing partition, sublink, survival, pattern, packet count, rate, guard, and closure mode; its `seed` is the cell's frozen base seed. `scenario_blocks` creates one reproducible randomized permutation of all cells per repetition, and the emitted `TrialRecord.block_index` preserves that cluster/pairing identity. Include the 40-packet smoke cells only in calibration; use 200 packets in the result partition when calibration selects them as exact-count safe. `silicon_cells` must refuse `Partition.DEVELOPMENT` and `Partition.SIMULATION`; its explicit packet/rate/guard/closure arguments are the only way calibration choices flow into generated cells, and `CampaignManifest.require_result()` still rejects non-fixed closure. `CampaignStage.valid_target` counts complete valid attempts and `attempt_cap` bounds all attempts; neither counts epoch records.

- [ ] **Step 4: Write the preregistration beside the code**

Record these confirmatory endpoints verbatim:

```markdown
1. Statistical false-alarm probability at survival 0.99 and 1.0.
2. Alarm probability within four sealed epochs at survival 0.95, 0.75, and 0.50.
3. First-epoch operational blackhole probability at survival 0.0.
4. Kaplan-Meier median sealed epochs and packets to alarm at every non-healthy
   survival point, treating horizon-complete misses as right-censored and reporting
   `not reached` when the estimated event probability does not cross 0.5.
5. Censor probability, reported separately for every cell and reason.
6. Selective-action bad packets, removed capacity, false actions, residual loss, and install latency.

Confirmatory detector comparisons: sealed mixture vs monitor/no action; sealed mixture
vs presence; sealed mixture vs fixed 1/8; sealed mixture vs fixed-horizon Alternate
Marking. Confirmatory action comparisons: selective vs no action and selective vs
whole-link quarantine. All other matrix contrasts are exploratory. Holm correction
applies within the four-detector and two-action comparison families separately.

Acceptance bounds: the sealed mixture's one-sided 95% healthy false-alarm upper
bound is at most 0.05; four-epoch gray alarm point estimates are at least 0.80,
0.95, and 0.95 at survival 0.95, 0.75, and 0.50, with corresponding lower 95%
bounds at least 0.70, 0.85, and 0.85; first-epoch blackhole alarm is at least
0.99 with lower 95% bound at least 0.90; the aggregate censor upper 95% bound is
at most 0.05 and no primary cell's censor point estimate exceeds 0.10. Median
Kaplan-Meier median sealed epochs and packets to alarm are always reported but are not independently
thresholded. Detection and false-alarm gates aggregate only across the frozen
sublink/pattern cells at the same survival point and bootstrap whole repetitions;
every individual cell remains visible. Failure of any gate produces a narrowing
verdict rather than tuning.
```

- [ ] **Step 5: Run tests and commit**

Run: `python3 -m pytest experiments/nsdi27/tests/test_frozen.py -q`

Expected: all tests PASS.

```bash
git add experiments/nsdi27/frozen.py experiments/nsdi27/PREREG.md experiments/nsdi27/tests/test_frozen.py
git commit -m "docs: freeze NSDI campaign matrix"
```

---

### Task 3: Seal the applied setup identity into the hardware protocol

**Files:**
- Modify: `p4/hw/loop/gate_agent_core.py`
- Modify: `p4/hw/loop/gate_agent.py`
- Modify: `p4/hw/loop/sequential_trials.py`
- Modify: `p4/hw/loop/test_gate_agent_core.py`
- Modify: `p4/hw/loop/test_sequential_trials.py`
- Modify: `p4/hw/bringup.sh`
- Modify: `p4/hw/test_setup_manifest_contract.py`

**Interfaces:**
- Produces: `compute_switch_id(machine_id, hostname, device_id) -> str` and `verify_loaded_setup(root, program, switch_identity, setup_identity, switchd_pid) -> None` in `gate_agent_core.py`.
- Produces protocol command `V2` and reply `SEALED_IDENTITY <program> <switch_id> <build_id> <setup_id> <runtime_id> <switchd_pid>`.
- Extends: `TrialConfig.expected_switch_id: str`, `TrialConfig.expected_setup_id: str`, and `require_identity(..., expected_switch_id, expected_setup_id) -> dict`.
- Preserves: legacy `V` reply for `clf_trials.py` and `controller_loop.py`; campaign code uses only `V2`.

- [ ] **Step 1: Write failing setup-receipt and V2 tests**

```python
def test_loaded_setup_receipt_must_match_live_build_owner(tmp_path):
    receipt = tmp_path / "prog.loaded-setup.sha256"
    receipt.write_text("123 %s %s\n" % ("a" * 64, "b" * 64))
    verify_loaded_setup(tmp_path, "prog", "a" * 64, "b" * 64, 123)
    with self.assertRaisesRegex(RuntimeError, "setup identity"):
        verify_loaded_setup(tmp_path, "prog", "a" * 64, "c" * 64, 123)
    with self.assertRaisesRegex(RuntimeError, "another switch"):
        verify_loaded_setup(tmp_path, "prog", "d" * 64, "b" * 64, 123)


def test_switch_identity_is_stable_and_device_specific():
    first = compute_switch_id("machine-1\n", "tofino-a", 0)
    assert first == compute_switch_id("machine-1", "tofino-a\n", 0)
    assert first != compute_switch_id("machine-1", "tofino-a", 1)


def test_sealed_identity_requires_setup_hash_before_mutation(self):
    reply = "SEALED_IDENTITY mcp_fabric_clf_eg %s %s %s %s 123\n" % (
        GOOD_SWITCH_ID, GOOD_BUILD_ID, GOOD_SETUP_ID, GOOD_RUNTIME_ID)
    gate = FakeGate([reply])
    config = self.config(expected_setup_id="d" * 64)
    with self.assertRaisesRegex(sequential_trials.HarnessError, "setup_id"):
        sequential_trials.run_trial(gate, FakeProbe(sent=40), None, config)
    self.assertEqual(gate.commands, ["V2"])


def test_sealed_identity_requires_switch_hash_before_mutation(self):
    reply = "SEALED_IDENTITY mcp_fabric_clf_eg %s %s %s %s 123\n" % (
        GOOD_SWITCH_ID, GOOD_BUILD_ID, GOOD_SETUP_ID, GOOD_RUNTIME_ID)
    gate = FakeGate([reply])
    config = self.config(expected_switch_id="e" * 64)
    with self.assertRaisesRegex(sequential_trials.HarnessError, "switch_id"):
        sequential_trials.run_trial(gate, FakeProbe(sent=40), None, config)
    self.assertEqual(gate.commands, ["V2"])
```

Add a dry-run test that asserts `loaded-setup.sha256` is written only after both setup commands and the exact `tbl_eg_vlink verified: 16 exact rows` check.

- [ ] **Step 2: Run focused tests and observe failure**

Run: `python3 -m pytest p4/hw/loop/test_gate_agent_core.py p4/hw/loop/test_sequential_trials.py p4/hw/test_setup_manifest_contract.py -q`

Expected: FAIL because the receipt helper, switch/setup IDs, and V2 protocol are absent.

- [ ] **Step 3: Implement the applied-setup receipt check**

```python
def compute_switch_id(machine_id, hostname, device_id):
    normalized = "%s\n%s\n%d\n" % (machine_id.strip(), hostname.strip(), device_id)
    if not machine_id.strip() or not hostname.strip() or device_id < 0:
        raise RuntimeError("stable switch identity inputs are unavailable")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_loaded_setup(root, program, switch_identity, setup_identity, switchd_pid):
    receipt = pathlib.Path(root).resolve() / (program + ".loaded-setup.sha256")
    try:
        fields = receipt.read_text().split()
    except OSError as error:
        raise RuntimeError("missing loaded-setup receipt") from error
    if len(fields) != 3 or not fields[0].isdigit():
        raise RuntimeError("malformed loaded-setup receipt")
    receipt_pid, receipt_switch, receipt_identity = int(fields[0]), fields[1], fields[2]
    if receipt_pid != switchd_pid:
        raise RuntimeError("loaded setup does not name the live build owner")
    if receipt_switch != switch_identity:
        raise RuntimeError("loaded setup names another switch")
    if receipt_identity != setup_identity:
        raise RuntimeError("loaded setup identity does not match sealed setup")
```

In `bringup.sh`, read the nonempty switch-side `/etc/machine-id`, hostname, and BFRT device ID 0, derive `switch_id` with the same canonical helper, compute the setup-manifest SHA-256 already verified by the script, and atomically write `<pid> <switch_id> <setup_id>` only after setup skeleton, setup attention, and exact table readback succeed. Raw machine identity never enters repository artifacts.

- [ ] **Step 4: Implement the V2 protocol and campaign-side enforcement**

```python
SETUP_ID = verify_sha256_manifest(RUNTIME_ROOT, PROG + ".setup-manifest.sha256")
SWITCHD_PID = verify_loaded_build(RUNTIME_ROOT, PROG, BUILD_ID)
SWITCH_ID = compute_switch_id(
    pathlib.Path("/etc/machine-id").read_text(), socket.gethostname(), 0,
)
verify_loaded_setup(RUNTIME_ROOT, PROG, SWITCH_ID, SETUP_ID, SWITCHD_PID)

# request branch
elif f[0] == "V2":
    conn.sendall(("SEALED_IDENTITY %s %s %s %s %s %d\n" %
                  (PROG, SWITCH_ID, BUILD_ID, SETUP_ID,
                   RUNTIME_ID, SWITCHD_PID)).encode())
    continue
```

Make `sequential_trials.require_identity` request `V2`, parse exactly seven fields, validate switch plus all three artifact IDs as 64-hex values, and compare switch/setup identity before the first mutating command. Add required CLI arguments `--expected-switch-id` and `--expected-setup-id`.

- [ ] **Step 5: Run protocol and deployment tests**

Run: `python3 -m pytest p4/hw/loop/test_gate_agent_core.py p4/hw/loop/test_sequential_trials.py p4/hw/test_setup_manifest_contract.py -q`

Expected: all tests PASS, including the legacy V contract.

- [ ] **Step 6: Run deploy and bring-up dry runs**

Run: `p4/hw/deploy.sh mcp_fabric_clf_eg --dry-run`

Run: `p4/hw/bringup.sh mcp_fabric_clf_eg --dry-run --port-timeout 17`

Expected: runtime/setup manifests are verified; the applied-setup receipt is ordered after exact setup readback; no SSH/SCP or switch mutation occurs.

- [ ] **Step 7: Commit the identity seal**

```bash
git add p4/hw/loop/gate_agent_core.py p4/hw/loop/gate_agent.py p4/hw/loop/sequential_trials.py p4/hw/loop/test_gate_agent_core.py p4/hw/loop/test_sequential_trials.py p4/hw/bringup.sh p4/hw/test_setup_manifest_contract.py
git commit -m "feat: seal applied setup identity"
```

---

### Task 4: Matched decision arms on one sealed observation stream

**Files:**
- Create: `experiments/nsdi27/baselines.py`
- Create: `experiments/nsdi27/tests/test_baselines.py`
- Create: `controller/tests/test_seal_invariants.py`
- Modify only on exposed defect: `controller/evidence_ledger.py`

**Interfaces:**
- Consumes: `EpochRecord`, `SequentialEvidenceLedger`, `verdict_counts`, frozen detector constants.
- Produces: `MatchedDecisionSet.ingest(record: EpochRecord, observation_id: str) -> Tuple[ArmDecision, ...]`.
- Produces: `binomial_lower_tail(delivered: int, sent: int, p0: float) -> float` for the fixed-horizon Alternate Marking arm.
- Invariant: every arm receives the identical sealed record; a censored record returns `CENSORED` for every arm.

- [ ] **Step 1: Write failing matched-arm tests**

```python
def test_all_arms_propagate_censor_without_scoring():
    detectors = MatchedDecisionSet(alpha=0.05, healthy_delivery=0.99,
                                   alternatives=DEFAULT_ALTERNATIVES,
                                   saturation=255, horizon=4)
    record = EpochRecord(sublink=2, epoch=0, tx=40, rx=38,
                         censor_reason=CensorReason.INCOMPLETE)
    decisions = detectors.ingest(record, observation_id="obs-censored")
    assert {decision.detector for decision in decisions} == set(PRIMARY_DETECTORS)
    assert all(decision.verdict == "CENSORED" for decision in decisions)
    assert {decision.observation_id for decision in decisions} == {"obs-censored"}


def test_presence_and_fixed_threshold_keep_their_declared_boundaries():
    decisions = decide_once(tx=40, rx=5)
    assert by_name(decisions, "monitor-no-action").verdict == "MONITOR"
    assert by_name(decisions, "presence").verdict == "MONITOR"
    assert by_name(decisions, "fixed-1-in-8").verdict == "STARVED"


def test_alternate_marking_uses_bonferroni_fixed_epoch_alpha():
    arm = AlternateMarkingExact(alpha=0.05, healthy_delivery=0.99, horizon=4)
    result = arm.ingest(EpochRecord(sublink=2, epoch=0, tx=200, rx=198))
    assert result.p_value == pytest.approx(binomial_lower_tail(198, 200, 0.99))
    assert result.statistical_alarm is (result.p_value <= 0.05 / 4)
```

- [ ] **Step 2: Write exhaustive seal-invariant tests**

```python
@pytest.mark.parametrize("reason", list(CensorReason))
def test_every_censor_reason_is_inconclusive_and_restarts(reason):
    ledger = make_ledger()
    ledger.ingest(record(epoch=0, tx=20, rx=19))
    result = ledger.ingest(record(epoch=1, tx=20, rx=19, censor_reason=reason))
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.sequence_index == 1


def test_no_impossible_count_can_produce_a_health_or_fault_verdict():
    for tx in range(0, 20):
        for rx in range(tx + 1, 21):
            result = make_ledger().ingest(record(epoch=0, tx=tx, rx=rx))
            assert result.verdict is Verdict.INCONCLUSIVE
```

- [ ] **Step 3: Run tests and confirm missing implementation**

Run: `python3 -m pytest experiments/nsdi27/tests/test_baselines.py controller/tests/test_seal_invariants.py -q`

Expected: FAIL because the matched detector module is absent.

- [ ] **Step 4: Implement fixed baselines and delegate sequential inference**

```python
def binomial_lower_tail(delivered, sent, p0):
    if not 0 <= delivered <= sent:
        raise ValueError("delivered must lie in 0..sent")
    return sum(math.comb(sent, value) * p0 ** value * (1.0 - p0) ** (sent - value)
               for value in range(delivered + 1))


class MatchedDecisionSet:
    def __init__(self, alpha, healthy_delivery, alternatives, saturation, horizon):
        self.alpha = alpha
        self.healthy_delivery = healthy_delivery
        self.horizon = horizon
        self.ledger = SequentialEvidenceLedger(
            alpha=alpha, healthy_delivery=healthy_delivery,
            alternatives=alternatives, saturation=saturation)

    def ingest(self, record, observation_id):
        if record.censor_reason is not None:
            ledger = self.ledger.ingest(record)
            return tuple(censored_decision(name, ledger.censor_reason.value,
                                            observation_id)
                         for name in PRIMARY_DETECTORS)
        fixed = verdict_counts(record.tx, record.rx, evidence_complete=True)
        p_value = binomial_lower_tail(record.rx, record.tx, self.healthy_delivery)
        sequential = self.ledger.ingest(record)
        return (
            monitor_decision(record, observation_id),
            presence_decision(record, observation_id),
            fixed_decision(fixed, observation_id),
            alternate_marking_decision(record, p_value, self.alpha / self.horizon,
                                       observation_id),
            sequential_decision(sequential, observation_id),
        )
```

`monitor_decision` always returns `MONITOR`, never raises a statistical alarm, and still carries the identical observation ID so its zero-action/zero-false-action tradeoff remains visible instead of being omitted. Every helper constructs an `ArmDecision` with the supplied `observation_id` and explicit `ComparisonProvenance.MATCHED_REIMPLEMENTATION`. Handle idle records without evaluating the binomial tail and keep immediate blackhole operational verdicts separate from statistical alarms.

- [ ] **Step 5: Run focused and existing ledger tests**

Run: `python3 -m pytest experiments/nsdi27/tests/test_baselines.py controller/tests/test_seal_invariants.py controller/tests/test_evidence_ledger.py sim/tests/test_clf_verdict.py -q`

Expected: all tests PASS.

- [ ] **Step 6: Commit matched decisions**

```bash
git add experiments/nsdi27/baselines.py experiments/nsdi27/tests/test_baselines.py controller/tests/test_seal_invariants.py controller/evidence_ledger.py
git commit -m "feat: add matched sealed-evidence baselines"
```

Omit `controller/evidence_ledger.py` from `git add` when the new invariants pass without a production change.

---

### Task 5: Paired randomized simulation campaign

**Files:**
- Create: `experiments/nsdi27/simulate.py`
- Create: `experiments/nsdi27/tests/test_simulate.py`
- Modify: `sim/clf/sequential_eval.py`
- Modify: `sim/tests/test_sequential_eval.py`
- Create from runner: `docs/review/artifacts/nsdi27/simulation/manifest.json`
- Create append-only from runner: `docs/review/artifacts/nsdi27/simulation/trials.jsonl`
- Create from validator: `docs/review/artifacts/nsdi27/simulation/validation.json`

**Interfaces:**
- Consumes: frozen simulation scenarios and `MatchedDecisionSet`.
- Produces: `simulate_attempt(manifest, campaign_hash, block_index, attempt=0) -> Tuple[TrialRecord, ...]`, `balanced_simulation_schedule(campaign) -> Tuple[ScheduledAttempt, ...]`, `run_simulation(campaign, output) -> None`, and CLI subcommands `freeze`, `run`, `validate`.
- Produces realized counts once per epoch, then feeds the same `EpochRecord` to all matched arms.
- Preserves: `sim.clf.sequential_eval.run_campaign` public behavior for historical callers.

- [ ] **Step 1: Write failing paired-stream tests**

```python
def test_every_arm_uses_the_same_realized_counts():
    manifest = simulation_manifest(seed=9, survival=0.95)
    records = simulate_attempt(manifest, CAMPAIGN_HASH, block_index=0)
    for record in records:
        assert {decision.observation_id for decision in record.decisions} == {record.trial_id}


def test_fixed_seed_and_cell_order_are_reproducible():
    manifest = simulation_manifest(seed=11, survival=0.75)
    assert (simulate_attempt(manifest, CAMPAIGN_HASH, block_index=3)
            == simulate_attempt(manifest, CAMPAIGN_HASH, block_index=3))


def test_shared_fate_uses_one_loss_draw_for_declared_siblings():
    manifests = shared_fate_manifests(seed=13, sublinks=(2, 6))
    left, right = [simulate_attempt(manifest, CAMPAIGN_HASH, block_index=2)
                   for manifest in manifests]
    assert [(r.tx, r.rx) for r in left] == [(r.tx, r.rx) for r in right]


def test_simulation_append_is_byte_reproducible(tmp_path):
    first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    campaign = primary_smoke_campaign(identity())
    run_simulation(campaign, output=first)
    run_simulation(campaign, output=second)
    assert first.read_bytes() == second.read_bytes()


def test_one_valid_attempt_is_exactly_one_horizon_not_four_samples():
    manifest = simulation_manifest(seed=17, survival=0.95, horizon=4)
    records = simulate_attempt(manifest, CAMPAIGN_HASH, block_index=0)
    assert len(records) == 4
    assert {(record.block_index, record.attempt) for record in records} == {(0, 0)}
    assert [record.epoch_offset for record in records] == [0, 1, 2, 3]


def test_full_schedule_has_2000_paired_campaigns_per_survival_and_all_dimensions():
    campaign = full_simulation_campaign(identity())
    schedule = balanced_simulation_schedule(campaign)
    primary = [item for item in schedule if item.stage_id == "primary-clean"]
    counts = collections.Counter(item.manifest.survival for item in primary)
    assert counts == {survival: 2000 for survival in SIMULATION_SURVIVAL}
    assert {item.manifest.packets_per_epoch for item in primary} == {40, 100, 200}
    assert {item.manifest.fault_model for item in primary} == {
        "single", "concurrent-independent", "shared-fate",
    }
    assert {item.manifest.loss_pattern for item in primary} >= {
        LossPattern.IID, LossPattern.BURST, LossPattern.SHARED_FATE,
    }
    assert {item.manifest.epoch_condition for item in schedule} == {
        "clean", "delayed", "duplicate", "stale", "repair-change",
    }
    assert {item.manifest.evidence_condition for item in schedule} == {
        "valid", "saturation", "overflow", "count-mismatch", "missing-side",
    }
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest experiments/nsdi27/tests/test_simulate.py sim/tests/test_sequential_eval.py -q`

Expected: FAIL because `simulate.py` is absent.

- [ ] **Step 3: Implement deterministic realized-loss generators**

```python
def iid_arrivals(rng, packets, survival):
    return sum(rng.random() < survival for _ in range(packets))


def exact_arrivals(packets, survival):
    return packets - int(round(packets * (1.0 - survival)))


def arrivals_for_epoch(rng, manifest, epoch_offset, shared_draw=None):
    if manifest.loss_pattern is LossPattern.IID:
        return iid_arrivals(rng, manifest.packets_per_epoch, manifest.survival)
    if manifest.loss_pattern in (LossPattern.BURST, LossPattern.DISPERSED):
        return exact_arrivals(manifest.packets_per_epoch, manifest.survival)
    if manifest.loss_pattern is LossPattern.SHARED_FATE:
        if shared_draw is None:
            raise ValueError("shared-fate simulation requires a shared draw")
        return shared_draw
    raise ValueError("unknown loss pattern %r" % manifest.loss_pattern)
```

Burst/dispersed have identical counts in the pure count model; preserve the labels so silicon may reveal timing-dependent differences without fabricating a simulation distinction.

- [ ] **Step 4: Implement one observation stream and append-only output**

For each `(scenario_id, block_index, attempt)`, construct one `MatchedDecisionSet`, seed one RNG with `stable_seed(manifest.seed, block_index, attempt)`, and emit exactly `horizon` `EpochRecord` values unless the frozen synthetic condition deliberately censors the attempt. Create each trial ID with `trial_identity(campaign_hash, scenario, block_index, attempt, epoch_offset)` before inference and store all five decisions inside that epoch-granular raw trial record. All four records form one statistical attempt; summaries must never count them as four independent samples. Each attempt gets a fresh decision set so evidence state never leaks across blocks or replacements.

`full_simulation_campaign` freezes two non-Cartesian but complete stages:

1. `primary-clean`: 2,000 block indexes. Every block contains one condition for each of the 11 frozen survival points. A deterministic balanced cycle assigns each block one of 12 `(packets, loss/fault)` profiles: packets `40/100/200` crossed with IID-single, burst-single, IID-concurrent-independent, and correlated shared-fate multi-sublink loss. Therefore every survival has exactly 2,000 paired campaigns and every primary dimension is represented 166 or 167 times.
2. `adversarial-validity`: 2,000 disjoint block indexes balanced across packet counts and the eight non-clean transition/evidence conditions (`delayed`, `duplicate`, `stale`, `repair-change`, `saturation`, `overflow`, `count-mismatch`, `missing-side`) at frozen survival 0.95. These attempts exercise typed censor/restart paths and never enter detector miss/false-alarm denominators.

The stage records freeze the exact schedule algorithm, profile list, block-index ranges, seed derivation, valid target, and attempt cap. `validate` requires 2,000 primary blocks per survival, exact balanced counts (difference at most one), all dimensions above, identical observation IDs across arms, full-horizon clean attempts, typed adversarial censors, and the raw JSONL hash.

The simulation campaign uses an explicitly synthetic `DeploymentIdentity` with PID zero and a deterministic `switch_id` labelled as simulation in the report. Its source closure hashes `simulate.py`, schema/codec/frozen/baselines, `controller/evidence_ledger.py`, and `sim/clf/verdict.py`; any change requires a new simulation manifest rather than silently regenerating old raw results.

- [ ] **Step 5: Preserve historical sequential evaluation**

Refactor `sim/clf/sequential_eval.py` to call the shared IID count helper without changing `CampaignSummary`, CLI columns, defaults, or current tests. Add an assertion that its default alternatives equal `experiments.nsdi27.frozen.DEFAULT_ALTERNATIVES`.

- [ ] **Step 6: Run focused and regression tests**

Run: `python3 -m pytest experiments/nsdi27/tests/test_simulate.py sim/tests/test_sequential_eval.py controller/tests/test_evidence_ledger.py -q`

Expected: all tests PASS.

- [ ] **Step 7: Run the small deterministic simulation smoke twice**

Run: `python3 -m experiments.nsdi27.simulate freeze --quick --manifest /tmp/nsdi27-sim-manifest.json`

Run: `python3 -m experiments.nsdi27.simulate run --manifest /tmp/nsdi27-sim-manifest.json --output /tmp/nsdi27-sim-a.jsonl`

Run: `python3 -m experiments.nsdi27.simulate run --manifest /tmp/nsdi27-sim-manifest.json --output /tmp/nsdi27-sim-b.jsonl`

Run: `sha256sum /tmp/nsdi27-sim-a.jsonl /tmp/nsdi27-sim-b.jsonl`

Expected: both SHA-256 values are identical.

- [ ] **Step 8: Freeze and run the broad paired simulation campaign**

Run:

```bash
python3 -m experiments.nsdi27.simulate freeze --full --manifest docs/review/artifacts/nsdi27/simulation/manifest.json
```

Run:

```bash
python3 -m experiments.nsdi27.simulate run --manifest docs/review/artifacts/nsdi27/simulation/manifest.json --output docs/review/artifacts/nsdi27/simulation/trials.jsonl
```

Run:

```bash
python3 -m experiments.nsdi27.simulate validate --manifest docs/review/artifacts/nsdi27/simulation/manifest.json --trials docs/review/artifacts/nsdi27/simulation/trials.jsonl --receipt docs/review/artifacts/nsdi27/simulation/validation.json
```

Expected: every primary survival has exactly 2,000 paired attempts; all balanced-dimension and typed-censor checks pass; the receipt seals manifest/raw hashes; rerunning to a separate output is byte-identical.

- [ ] **Step 9: Commit paired simulation code and raw evidence**

```bash
git add experiments/nsdi27/simulate.py experiments/nsdi27/tests/test_simulate.py sim/clf/sequential_eval.py sim/tests/test_sequential_eval.py docs/review/artifacts/nsdi27/simulation/manifest.json docs/review/artifacts/nsdi27/simulation/trials.jsonl docs/review/artifacts/nsdi27/simulation/validation.json
git commit -m "feat: run paired sealed-evidence simulations"
```

---

### Task 6: Statistical summaries, provenance enforcement, and acceptance gates

**Files:**
- Create: `experiments/nsdi27/analysis.py`
- Create: `experiments/nsdi27/tests/test_analysis.py`
- Create from analysis: `docs/review/artifacts/nsdi27/simulation/summary.json`
- Create from analysis: `docs/review/artifacts/nsdi27/simulation/TABLE.md`
- Create: `docs/review/artifacts/nsdi27/simulation/REPORT.md`

**Interfaces:**
- Consumes: canonical manifests/trials and frozen confirmatory comparisons.
- Reuses: `sim.dynamic.metrics.wilson`, `bootstrap_median_ci`, and `cluster_bootstrap_rate_ci`.
- Produces: `paired_rate_difference`, `exact_mcnemar_p`, `holm_adjust`, `summarize_trials`, `evaluate_gates`.
- CLI: `python3 -m experiments.nsdi27.analysis --manifest <json> --trials <jsonl> [--validation <json>] --summary <json> --table <md>`. `--validation` is mandatory for calibration/result partitions and optional-but-verified when supplied for simulation.

- [ ] **Step 1: Write failing statistical tests**

```python
def test_censors_are_not_false_alarms_or_misses():
    records = (sealed_attempt(alarm_epoch=1) + sealed_attempt(alarm_epoch=None)
               + censored_attempt(censor_epoch=2))
    summary = summarize_trials(records)
    assert summary.valid_trials == 2
    assert summary.censored_trials == 1
    assert summary.alarm_rate == 0.5
    assert summary.censor_rate == 1 / 3


def test_exact_paired_test_uses_discordant_pairs_only():
    assert exact_mcnemar_p(a_only=8, b_only=0) == pytest.approx(2 / 256)
    assert exact_mcnemar_p(a_only=0, b_only=0) == 1.0


def test_holm_is_monotone_in_original_comparison_order():
    adjusted = holm_adjust((0.01, 0.04, 0.03))
    assert adjusted == pytest.approx((0.03, 0.06, 0.06))


def test_time_to_alarm_reports_median_sealed_epochs_and_packets():
    records = (sealed_attempt(alarm_epoch=1, packets_per_epoch=200)
               + sealed_attempt(alarm_epoch=3, packets_per_epoch=200)
               + sealed_attempt(alarm_epoch=None, packets_per_epoch=200))
    summary = summarize_trials(records)
    assert summary.kaplan_meier_median_epochs_to_alarm == 3.0
    assert summary.kaplan_meier_median_packets_to_alarm == 600.0
    assert summary.valid_trials == 3


def test_one_censored_epoch_invalidates_its_whole_attempt():
    records = sealed_prefix(epochs=2) + (censored_epoch(epoch_offset=2),)
    summary = summarize_trials(records)
    assert summary.valid_trials == 0
    assert summary.censored_trials == 1


def test_truncated_attempt_is_invalid_not_a_short_healthy_run():
    with pytest.raises(ValueError, match="truncated attempt"):
        summarize_trials(sealed_prefix(epochs=3), expected_horizon=4)


def test_gate_thresholds_are_frozen_constants_not_cli_overrides():
    gates = evaluate_gates(passing_summary())
    assert gates.thresholds["healthy_false_alarm_ucl"] == 0.05
    assert gates.thresholds["gray_095_rate"] == 0.80
    assert gates.thresholds["blackhole_first_epoch_rate"] == 0.99


def test_result_analysis_requires_a_matching_validation_receipt(tmp_path):
    with pytest.raises(ValueError, match="validation receipt"):
        analyze(result_manifest_path, result_trials_path, validation_path=None)
    with pytest.raises(ValueError, match="raw trial hash"):
        analyze(result_manifest_path, tampered_trials_path, validation_path=receipt_path)


def test_simulation_analysis_validates_embedded_hashes_without_a_receipt(tmp_path):
    with pytest.raises(ValueError, match="scenario manifest"):
        analyze(sim_manifest_path, trial_with_wrong_scenario_hash,
                validation_path=None)
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest experiments/nsdi27/tests/test_analysis.py sim/tests/test_dynamic_metrics.py -q`

Expected: FAIL because `analysis.py` is absent.

- [ ] **Step 3: Implement exact paired p-values and Holm correction**

```python
def exact_mcnemar_p(a_only, b_only):
    discordant = a_only + b_only
    if discordant == 0:
        return 1.0
    tail = sum(math.comb(discordant, k) for k in range(min(a_only, b_only) + 1))
    return min(1.0, 2.0 * tail / (2.0 ** discordant))


def holm_adjust(p_values):
    indexed = sorted(enumerate(p_values), key=lambda item: item[1])
    adjusted = [0.0] * len(indexed)
    running = 0.0
    for rank, (index, value) in enumerate(indexed):
        running = max(running, min(1.0, (len(indexed) - rank) * value))
        adjusted[index] = running
    return tuple(adjusted)
```

Collapse epoch records into attempts keyed by `(campaign_hash, scenario_id, block_index, attempt)` before computing any rate. A valid attempt has exactly offsets `0..horizon-1`, all sealed; if any epoch is censored, exclude the entire attempt from detector denominators and count one censor under the terminal reason. Reject duplicate offsets and crash-truncated attempts unless the runner has appended their recovery-censor record. For each arm, define an attempt-level hit as its first alarm within the horizon and a miss as no alarm after all sealed epochs. Compute time-to-alarm with a Kaplan-Meier estimator that treats horizon-complete misses as right-censored; report `not reached` rather than taking the median only over detected runs.

Implement paired bootstrap by resampling whole `(campaign_hash, block_index)` clusters, never packets, epoch rows, detector rows, or condition cells independently. Exact paired detector tests join arms from the same valid attempt. This preserves the randomized-block pairing across every frozen condition.

- [ ] **Step 4: Implement artifact validation before aggregation**

Require:

```python
if campaign.partition is Partition.RESULT:
    campaign.require_result()
if campaign.partition in (Partition.CALIBRATION, Partition.RESULT):
    if receipt is None:
        raise ValueError("hardware analysis requires a validation receipt")
if receipt is not None and sha256_file(trials_path) != receipt.raw_trials_sha256:
    raise ValueError("raw trial hash does not match validation receipt")
raw_trials_sha256 = sha256_file(trials_path)
campaign_hash = sha256_identity(campaign)
scenario_hashes = {
    scenario.scenario_id: sha256_identity(scenario)
    for scenario in campaign.scenarios
}
if any(trial.campaign_hash != campaign_hash for trial in trials):
    raise ValueError("trial references another campaign manifest")
if any(trial.scenario_hash != scenario_hashes.get(trial.scenario_id)
       for trial in trials):
    raise ValueError("trial references another scenario manifest")
```

For simulation, the analysis computes `raw_trials_sha256` directly and validates every embedded campaign/scenario hash; it does not pretend that this self-computed hash is an independently frozen receipt. For calibration/result data, the separately generated campaign-validation receipt is mandatory and its raw JSONL hash must match. Summaries print valid-attempt count, invalid-attempt count, censor reasons, alarm/miss rates, Kaplan-Meier median sealed epochs/packets to alarm, exact/Wilson intervals, paired difference intervals, raw hash, manifest hash, validation-receipt hash when present, and analysis revision. `evaluate_gates` imports the frozen bounds from Task 2; the CLI exposes no threshold override.

- [ ] **Step 5: Run tests and analyze the smoke simulation**

Run: `python3 -m pytest experiments/nsdi27/tests/test_analysis.py sim/tests/test_dynamic_metrics.py -q`

Expected: all tests PASS.

Run: `python3 -m experiments.nsdi27.analysis --manifest /tmp/nsdi27-sim-manifest.json --trials /tmp/nsdi27-sim-a.jsonl --summary /tmp/nsdi27-sim-summary.json --table /tmp/nsdi27-sim-table.md`

Expected: summary and table name all five arms, separate censors, and carry raw/manifest hashes.

Run:

```bash
python3 -m experiments.nsdi27.analysis --manifest docs/review/artifacts/nsdi27/simulation/manifest.json --trials docs/review/artifacts/nsdi27/simulation/trials.jsonl --validation docs/review/artifacts/nsdi27/simulation/validation.json --summary docs/review/artifacts/nsdi27/simulation/summary.json --table docs/review/artifacts/nsdi27/simulation/TABLE.md
```

Expected: all 11 primary survival points have 2,000 paired attempts; packet/loss/fault profiles remain balanced; transition/censor cases are reported separately; all five arms have clustered intervals and Holm-adjusted paired comparisons; and every number carries manifest/raw/validation/analysis hashes.

Write `docs/review/artifacts/nsdi27/simulation/REPORT.md` with the schedule proof, all primary/adversarial cells, paired detector results, adverse outcomes, and the explicit boundary that simulation is not silicon evidence.

- [ ] **Step 6: Commit analysis**

```bash
git add experiments/nsdi27/analysis.py experiments/nsdi27/tests/test_analysis.py docs/review/artifacts/nsdi27/simulation/summary.json docs/review/artifacts/nsdi27/simulation/TABLE.md docs/review/artifacts/nsdi27/simulation/REPORT.md
git commit -m "feat: add paired campaign statistics"
```

---

### Task 7: Frozen ablation matrix and non-deployable negative controls

**Files:**
- Create: `experiments/nsdi27/ablations.py`
- Create: `experiments/nsdi27/tests/test_ablations.py`
- Modify: `experiments/nsdi27/frozen.py`
- Create from runner: `docs/review/artifacts/nsdi27/ablation/manifest.json`
- Create from runner: `docs/review/artifacts/nsdi27/ablation/trials.jsonl`
- Create incrementally from validated hardware: `docs/review/artifacts/nsdi27/ablation/completion.json`
- Create from analysis: `docs/review/artifacts/nsdi27/ablation/summary.json`
- Create: `docs/review/artifacts/nsdi27/ablation/REPORT.md`

**Interfaces:**
- Consumes: frozen simulation campaigns, `simulate_attempt`, `MatchedDecisionSet`, and `summarize_trials`.
- Produces: `AblationKind`, `AblationSpec`, `AblationHardwareReference`, `AblationManifest`, `AblationCompletionManifest`, `REQUIRED_ABLATIONS`, `ablation_specs(identity) -> Tuple[AblationSpec, ...]`, `negative_control_decision(record, manifest, policy) -> ArmDecision`, and `pool_epoch_records(records) -> EpochRecord`.
- CLI: `python3 -m experiments.nsdi27.ablations --manifest <json> --trials <jsonl> [--calibration-manifest <json> --calibration-trials <jsonl> --calibration-validation <json>] [--result-manifest <json> --action-trials <jsonl> --action-validation <json>] --completion <json> --summary <json> --report <md>`; `--verify-complete` performs read-only hash/status validation.
- Boundary: negative controls accept only `Partition.SIMULATION`; no hardware or result runner imports them.

- [ ] **Step 1: Write failing ablation-contract tests**

```python
def test_required_ablation_families_are_complete_and_exact():
    assert REQUIRED_ABLATIONS == (
        AblationKind.SEAL,
        AblationKind.DECISION,
        AblationKind.MIXTURE,
        AblationKind.PACKET_HORIZON,
        AblationKind.CLOSURE,
        AblationKind.CENSOR_POLICY,
        AblationKind.RESOLUTION,
        AblationKind.LOCALIZER,
        AblationKind.CONTEXT_COUNT,
        AblationKind.ACTION,
    )


def test_mixture_ablation_has_full_model_and_each_leave_one_out_model():
    specs = [spec for spec in ablation_specs(identity())
             if spec.kind is AblationKind.MIXTURE]
    alternatives = {spec.alternatives for spec in specs}
    assert DEFAULT_ALTERNATIVES in alternatives
    assert len(alternatives) == len(DEFAULT_ALTERNATIVES) + 1
    for removed in DEFAULT_ALTERNATIVES:
        assert tuple(value for value in DEFAULT_ALTERNATIVES if value != removed) in alternatives


def test_negative_control_is_simulation_only():
    with pytest.raises(ValueError, match="simulation-only"):
        negative_control_decision(
            result_record(), result_manifest(), policy="censor-as-healthy",
        )


def test_pooling_can_mask_one_failed_element_and_keeps_provenance():
    pooled = pool_epoch_records((epoch(sublink=2, tx=40, rx=0),
                                 epoch(sublink=6, tx=40, rx=40),
                                 epoch(sublink=10, tx=40, rx=40),
                                 epoch(sublink=14, tx=40, rx=40)))
    assert (pooled.tx, pooled.rx) == (160, 120)
    assert pooled.sublink == POOLED_SUBLINK


def test_complete_hardware_reference_requires_every_evidence_hash():
    reference = pending_hardware_reference("calibration-closure", "fixed-guard")
    with pytest.raises(ValueError, match="complete hardware reference"):
        replace(reference, status="COMPLETE").validate()
```

- [ ] **Step 2: Run the focused tests and confirm the module is absent**

Run: `python3 -m pytest experiments/nsdi27/tests/test_ablations.py -q`

Expected: FAIL because `experiments.nsdi27.ablations` does not exist.

- [ ] **Step 3: Implement the exact frozen families and levels**

```python
class AblationKind(str, Enum):
    SEAL = "sealed-vs-unsealed"
    DECISION = "matched-decision"
    MIXTURE = "mixture-leave-one-out"
    PACKET_HORIZON = "packet-count-and-horizon"
    CLOSURE = "fixed-vs-receipt-closure"
    CENSOR_POLICY = "censor-policy-negative-control"
    RESOLUTION = "saturation-and-count-resolution"
    LOCALIZER = "per-element-vs-pooled"
    CONTEXT_COUNT = "one-vs-multiple-contexts"
    ACTION = "selective-vs-whole-link"


REQUIRED_ABLATIONS = tuple(AblationKind)
PACKET_HORIZON_LEVELS = tuple(
    (packets, horizon) for packets in (40, 200) for horizon in (1, 2, 4, 8)
)
RESOLUTION_LEVELS = (
    (40, 64), (40, 128), (40, 255),
    (200, 255),
)
CONTEXT_LEVELS = ((2,), (2, 6, 10, 14))
CLOSURE_LEVELS = ("fixed-guard", "injected-receipt")
POOLED_SUBLINK = 1023


@dataclass(frozen=True)
class AblationHardwareReference:
    reference_id: str
    kind: str
    level: str
    manifest_path: str
    trials_path: str
    validation_receipt_path: str
    report_path: str
    status: str
    manifest_sha256: Optional[str]
    trials_sha256: Optional[str]
    validation_receipt_sha256: Optional[str]
    report_sha256: Optional[str]

    def validate(self):
        if self.kind not in ("calibration-closure", "result-action"):
            raise ValueError("unknown hardware-reference kind")
        if (not self.reference_id or not self.level or not self.manifest_path
                or not self.trials_path or not self.validation_receipt_path
                or not self.report_path):
            raise ValueError("hardware reference paths are incomplete")
        hashes = (self.manifest_sha256, self.trials_sha256,
                  self.validation_receipt_sha256, self.report_sha256)
        if self.status == "PENDING-HARDWARE":
            if any(value is not None for value in hashes):
                raise ValueError("pending hardware reference cannot carry partial hashes")
        elif self.status == "COMPLETE":
            if any(value is None or len(value) != 64
                   or any(char not in "0123456789abcdef" for char in value)
                   for value in hashes):
                raise ValueError("complete hardware reference requires every SHA-256")
        else:
            raise ValueError("unknown hardware-reference status")


@dataclass(frozen=True)
class AblationSpec:
    ablation_id: str
    kind: AblationKind
    level: str
    alternatives: Tuple[float, ...]
    packets_per_epoch: int
    horizon: int
    saturation: int
    contexts: Tuple[int, ...]
    manifest: Optional[ScenarioManifest]
    hardware_reference: Optional[AblationHardwareReference]


@dataclass(frozen=True)
class AblationManifest:
    campaign_version: str
    simulation_campaign: CampaignManifest
    specs: Tuple[AblationSpec, ...]

    def validate(self):
        self.simulation_campaign.validate()
        if self.simulation_campaign.partition is not Partition.SIMULATION:
            raise ValueError("ablation simulation subcampaign must be simulation-only")
        if {spec.kind for spec in self.specs} != set(REQUIRED_ABLATIONS):
            raise ValueError("ablation families differ from the frozen set")
        simulated = {scenario.scenario_id
                     for scenario in self.simulation_campaign.scenarios}
        if simulated != {spec.manifest.scenario_id for spec in self.specs
                         if spec.manifest is not None}:
            raise ValueError("ablation simulation scenarios differ from specs")
        for spec in self.specs:
            if (spec.manifest is None) == (spec.hardware_reference is None):
                raise ValueError("each ablation row must be simulated or a hardware reference")
            if spec.hardware_reference is not None:
                spec.hardware_reference.validate()


@dataclass(frozen=True)
class AblationCompletionManifest:
    ablation_manifest_sha256: str
    references: Tuple[AblationHardwareReference, ...]

    def require_complete(self):
        for reference in self.references:
            reference.validate()
            if reference.status != "COMPLETE":
                raise ValueError("ablation hardware reference remains pending")
```

Build the matrix with one helper so IDs and manifests cannot diverge:

```python
def ablation_specs(identity):
    base = simulation_scenarios(identity)[0]
    specs = []

    def add(kind, level, alternatives=DEFAULT_ALTERNATIVES,
            packets=200, horizon=4, saturation=255,
            contexts=(2,), manifest_changes=None, hardware_reference=None):
        ablation_id = "ablation/%s/%s" % (kind.value, level)
        if hardware_reference is not None:
            specs.append(AblationSpec(
                ablation_id=ablation_id, kind=kind, level=level,
                alternatives=tuple(alternatives), packets_per_epoch=packets,
                horizon=horizon, saturation=saturation, contexts=tuple(contexts),
                manifest=None, hardware_reference=hardware_reference,
            ))
            return
        changes = dict(manifest_changes or {})
        changes.update(
            scenario_id=ablation_id,
            alternatives=tuple(alternatives), packets_per_epoch=packets,
            horizon=horizon, contexts=",".join(str(value) for value in contexts),
        )
        manifest = dataclasses.replace(base, **changes)
        specs.append(AblationSpec(
            ablation_id=manifest.scenario_id, kind=kind, level=level,
            alternatives=tuple(alternatives), packets_per_epoch=packets,
            horizon=horizon, saturation=saturation,
            contexts=tuple(contexts), manifest=manifest, hardware_reference=None,
        ))

    for level in ("sealed", "unsealed-analysis-only"):
        add(AblationKind.SEAL, level)
    for level in PRIMARY_DETECTORS:
        add(AblationKind.DECISION, level)
    add(AblationKind.MIXTURE, "complete")
    for removed in DEFAULT_ALTERNATIVES:
        remaining = tuple(value for value in DEFAULT_ALTERNATIVES if value != removed)
        add(AblationKind.MIXTURE, "without-%g" % removed, alternatives=remaining)
    for packets, horizon in PACKET_HORIZON_LEVELS:
        add(AblationKind.PACKET_HORIZON, "%d-packets-%d-epochs" % (packets, horizon),
            packets=packets, horizon=horizon)
    for level in CLOSURE_LEVELS:
        add(AblationKind.CLOSURE, level,
            hardware_reference=pending_hardware_reference(
                "calibration-closure", level,
            ))
    for level in ("censor", "censor-as-healthy", "censor-as-zero"):
        add(AblationKind.CENSOR_POLICY, level)
    for packets, saturation in RESOLUTION_LEVELS:
        add(AblationKind.RESOLUTION, "%d-packets-sat-%d" % (packets, saturation),
            packets=packets, saturation=saturation)
    for level in ("per-element", "pooled"):
        add(AblationKind.LOCALIZER, level, packets=40,
            contexts=(2, 6, 10, 14))
    for contexts in CONTEXT_LEVELS:
        patterns = ((LossPattern.IID, LossPattern.SHARED_FATE)
                    if len(contexts) > 1 else (LossPattern.IID,))
        for pattern in patterns:
            fault_model = ("shared-fate" if pattern is LossPattern.SHARED_FATE
                           else ("single" if len(contexts) == 1
                                 else "concurrent-independent"))
            add(AblationKind.CONTEXT_COUNT,
                "%d-contexts-%s" % (len(contexts), pattern.value),
                packets=40, contexts=contexts,
                manifest_changes={"loss_pattern": pattern,
                                  "fault_model": fault_model})
    for level in PRIMARY_ACTION_MODES:
        add(AblationKind.ACTION, level,
            hardware_reference=pending_hardware_reference("result-action", level))
    return tuple(specs)
```

`pending_hardware_reference` freezes the exact repository-relative manifest, trials, validation-receipt, and report paths for each reference kind, with status `PENDING-HARDWARE` and no hashes. `--freeze` wraps all non-reference scenario manifests in one valid `Partition.SIMULATION` `CampaignManifest`, then embeds that subcampaign and every spec in `AblationManifest`; it never places calibration/action rows inside that subcampaign. Tasks 10 and 12 never rewrite this frozen manifest. Instead, after independent validation, they create/update the derived `AblationCompletionManifest` with the frozen ablation-manifest hash and `COMPLETE` typed references carrying all four artifact hashes. The simulation runner executes only rows with a non-`None` scenario manifest. `REPORT.md` fails closed if any family has no row, a simulated row is absent from the subcampaign, or a reference row lacks a matching receipt and artifact hashes.

- [ ] **Step 4: Implement analysis-only negative controls and pooled counts**

```python
def negative_control_decision(record, manifest, policy):
    if manifest.partition is not Partition.SIMULATION:
        raise ValueError("negative controls are simulation-only")
    if record.scenario_hash != sha256_identity(manifest):
        raise ValueError("negative control record references another manifest")
    if record.seal_status is not SealStatus.CENSORED:
        raise ValueError("negative control requires a censored record")
    if policy == "censor-as-healthy":
        verdict = "HEALTHY"
    elif policy == "censor-as-zero":
        verdict = "BLACKHOLE"
    else:
        raise ValueError("unknown negative-control policy: %s" % policy)
    return ArmDecision(
        observation_id=record.trial_id,
        detector="negative-control-" + policy,
        verdict=verdict, e_value=None, p_value=None,
        statistical_alarm=False, reason="deliberately-invalid-analysis",
        provenance=ComparisonProvenance.SEMANTIC_REIMPLEMENTATION,
    )


def pool_epoch_records(records):
    records = tuple(records)
    if not records:
        raise ValueError("cannot pool an empty record set")
    epochs = {(record.epoch, record.repair_generation) for record in records}
    if len(epochs) != 1 or any(record.censor_reason is not None for record in records):
        raise ValueError("pooled records must be complete and contemporaneous")
    return EpochRecord(
        sublink=POOLED_SUBLINK, epoch=records[0].epoch,
        tx=sum(record.tx for record in records),
        rx=sum(record.rx for record in records),
        repair_generation=records[0].repair_generation,
    )
```

The negative-control module must not be imported by `controller/`, `p4/hw/`, or the result campaign. Add a repository-boundary test that searches those paths and fails if `negative_control_decision` or `experiments.nsdi27.ablations` appears.

- [ ] **Step 5: Run the frozen paired simulation ablations**

Run:

```bash
python3 -m experiments.nsdi27.ablations --freeze --output-manifest docs/review/artifacts/nsdi27/ablation/manifest.json
```

Run:

```bash
python3 -m experiments.nsdi27.ablations --manifest docs/review/artifacts/nsdi27/ablation/manifest.json --trials docs/review/artifacts/nsdi27/ablation/trials.jsonl --completion docs/review/artifacts/nsdi27/ablation/completion.json --summary docs/review/artifacts/nsdi27/ablation/summary.json --report docs/review/artifacts/nsdi27/ablation/REPORT.md
```

Expected: paired seeds for every level; 95% clustered intervals; every required family present; negative controls visually marked invalid; no confirmatory threshold changed; closure/action rows marked `PENDING-HARDWARE` rather than silently omitted.

- [ ] **Step 6: Run tests and commit the simulation ablations**

Run: `python3 -m pytest experiments/nsdi27/tests/test_ablations.py experiments/nsdi27/tests/test_simulate.py experiments/nsdi27/tests/test_analysis.py -q`

Expected: all tests PASS.

```bash
git add experiments/nsdi27/ablations.py experiments/nsdi27/frozen.py experiments/nsdi27/tests/test_ablations.py docs/review/artifacts/nsdi27/ablation/manifest.json docs/review/artifacts/nsdi27/ablation/trials.jsonl docs/review/artifacts/nsdi27/ablation/completion.json docs/review/artifacts/nsdi27/ablation/summary.json docs/review/artifacts/nsdi27/ablation/REPORT.md
git commit -m "exp: run sealed-evidence ablations"
```

---

### Task 8: Exact burst and dispersed hardware injection

**Files:**
- Modify: `p4/hw/loop/injector_ranges.py`
- Modify: `p4/hw/loop/test_injector_ranges.py`
- Modify: `p4/hw/loop/gate_agent_core.py`
- Modify: `p4/hw/loop/test_gate_agent_core.py`
- Modify: `p4/hw/loop/gate_agent.py`
- Modify: `p4/hw/loop/sequential_trials.py`
- Modify: `p4/hw/loop/test_sequential_trials.py`

**Interfaces:**
- Preserves: `A <sublink> <ndrop>` as contiguous burst injection.
- Produces: `S <sublink> <packet_count> <drop_count> <phase>` as evenly dispersed exact injection.
- Produces: `modular_spread_drop_ranges(current_sequence, packet_count, drop_count, phase) -> Tuple[Tuple[int, int], ...]`.
- Produces: `ClosureReceipt` and `wait_for_injected_receipt(read_receipt, sent, intended_drops, timeout, poll_interval, monotonic, sleeper) -> ClosureReceipt` for calibration-only closure timing.
- Extends: `TrialConfig.loss_pattern`, `TrialConfig.pattern_phase`, `TrialConfig.closure_mode`, `TrialConfig.closure_timeout`, and `TrialConfig.closure_poll_interval`.

- [ ] **Step 1: Write failing pure range tests**

```python
def test_spread_ranges_drop_exactly_the_requested_offsets():
    ranges = modular_spread_drop_ranges(100, packet_count=20, drop_count=5, phase=0)
    assert expand(ranges) == {103, 107, 111, 115, 119}


def test_spread_ranges_wrap_without_duplicate_sequences():
    ranges = modular_spread_drop_ranges(65530, packet_count=20, drop_count=5, phase=1)
    values = expand(ranges)
    assert len(values) == 5
    assert all(0 <= value <= 0xffff for value in values)


def test_spread_range_count_is_bounded_by_drop_count():
    ranges = modular_spread_drop_ranges(0, packet_count=200, drop_count=100, phase=17)
    assert 1 <= len(ranges) <= 100
```

- [ ] **Step 2: Write failing protocol/trial tests**

```python
def test_dispersed_trial_uses_exact_spread_command_and_receipt():
    config = self.config(loss_pattern="dispersed", pattern_phase=17)
    outcome, gate, _ = self.run_once(self.happy_spread_replies(), config=config)
    assert "S 2 40 2 17" in gate.commands
    assert outcome.measured_drops == 2


def test_burst_trial_keeps_existing_arm_command():
    config = self.config(loss_pattern="burst")
    _, gate, _ = self.run_once(self.happy_replies(), config=config)
    assert "A 2 2" in gate.commands


def test_injected_receipt_closure_waits_for_exact_terminal_counts():
    replies = iter(((39, 37, 1), (40, 38, 2)))
    clock = FakeClock()
    receipt = wait_for_injected_receipt(
        lambda: next(replies), sent=40, intended_drops=2,
        timeout=1.0, poll_interval=0.01,
        monotonic=clock.monotonic, sleeper=clock.sleep,
    )
    assert (receipt.tx, receipt.rx, receipt.measured_drops) == (40, 38, 2)
    assert receipt.polls == 2


def test_injected_receipt_closure_rejects_impossible_progress():
    with pytest.raises(HarnessError, match="impossible closure receipt"):
        wait_for_injected_receipt(
            lambda: (41, 38, 2), sent=40, intended_drops=2,
            timeout=1.0, poll_interval=0.01,
        )
```

- [ ] **Step 3: Run tests and confirm failure**

Run: `python3 -m pytest p4/hw/loop/test_injector_ranges.py p4/hw/loop/test_gate_agent_core.py p4/hw/loop/test_sequential_trials.py -q`

Expected: FAIL because dispersed ranges and the S protocol are absent.

- [ ] **Step 4: Implement exact evenly spaced offsets and range compression**

```python
def modular_spread_drop_ranges(current_sequence, packet_count, drop_count, phase=0):
    if not 1 <= drop_count <= packet_count <= 254:
        raise ValueError("require 1 <= drop_count <= packet_count <= 254")
    if not 0 <= current_sequence <= 0xffff:
        raise ValueError("current sequence must fit 16 bits")
    phase %= packet_count
    offsets = sorted({(phase + (i * packet_count) // drop_count) % packet_count
                      for i in range(drop_count)})
    if len(offsets) != drop_count:
        raise RuntimeError("spread schedule did not produce exact unique drops")
    values = sorted(((current_sequence + 3 + offset) & 0xffff) for offset in offsets)
    return compress_inclusive_ranges(values)
```

`compress_inclusive_ranges` merges adjacent non-wrapping 16-bit values; it never emits a wrapped Tofino range key.

- [ ] **Step 5: Implement S in the agent and choose A/S from TrialConfig**

Parse exactly five fields, validate sublink/packet/drop/phase bounds in an SDK-independent helper, install all returned range entries in one BFRT call, and return `SPREAD <sublink> <packet_count> <drop_count> <phase>\nOK <range_count>\n`. Reuse the existing injector `I` counters as exact ground truth.

- [ ] **Step 6: Implement the calibration-only receipt closure**

```python
@dataclass(frozen=True)
class ClosureReceipt:
    tx: int
    rx: int
    measured_drops: int
    elapsed_seconds: float
    polls: int


def wait_for_injected_receipt(read_receipt, sent, intended_drops,
                              timeout, poll_interval,
                              monotonic=time.monotonic, sleeper=time.sleep):
    if timeout <= 0.0 or poll_interval <= 0.0:
        raise ValueError("closure timeout and poll interval must be positive")
    started = monotonic()
    polls = 0
    while True:
        tx, rx, measured_drops = read_receipt()
        polls += 1
        if tx > sent or rx > tx or measured_drops > intended_drops:
            raise HarnessError("impossible closure receipt")
        if tx == sent and measured_drops == intended_drops and tx - rx == intended_drops:
            return ClosureReceipt(tx, rx, measured_drops,
                                  monotonic() - started, polls)
        if monotonic() - started >= timeout:
            raise HarnessError("timed out waiting for injected closure receipt")
        sleeper(poll_interval)
```

For `closure_mode="fixed-guard"`, retain the current post-flip sleep. For `closure_mode="injected-receipt"`, poll the frozen bank plus injector counters through the helper and record elapsed time/poll count in `TrialOutcome`. This mode is valid only for controlled calibration because it uses the preregistered injected-drop receipt; Task 9 rejects it for result manifests, and no paper text may present it as a deployable unknown-fault closure mechanism.

- [ ] **Step 7: Run focused tests and deploy dry run**

Run: `python3 -m pytest p4/hw/loop/test_injector_ranges.py p4/hw/loop/test_gate_agent_core.py p4/hw/loop/test_sequential_trials.py -q`

Expected: all tests PASS.

Run: `p4/hw/deploy.sh mcp_fabric_clf_eg --runtime-only --dry-run`

Expected: all three runtime files are sealed; no compiler or switch mutation runs.

- [ ] **Step 8: Commit exact patterns and closure calibration support**

```bash
git add p4/hw/loop/injector_ranges.py p4/hw/loop/test_injector_ranges.py p4/hw/loop/gate_agent_core.py p4/hw/loop/test_gate_agent_core.py p4/hw/loop/gate_agent.py p4/hw/loop/sequential_trials.py p4/hw/loop/test_sequential_trials.py
git commit -m "feat: add exact injection and closure calibration"
```

---

### Task 9: Resumable, append-only silicon campaign runner

**Files:**
- Create: `p4/hw/loop/nsdi_campaign.py`
- Create: `p4/hw/loop/test_nsdi_campaign.py`
- Modify: `p4/hw/loop/sequential_trials.py`
- Modify: `p4/hw/loop/test_sequential_trials.py`

**Interfaces:**
- Consumes: frozen scenarios, canonical codec, `sequential_trials.run_trial`.
- Produces: `freeze_manifest(...) -> CampaignManifest`, `run_manifest(campaign, output, gate, probe) -> None`, `resume_state(output, campaign_hash) -> ResumeState`, `validate_campaign(campaign, trials) -> ValidationReceipt`, and CLI subcommands `freeze`, `run`, `validate`, `select-calibration`.
- Records every attempted trial, including identity/preflight failures and cleanup failures.
- Runs stage-specific randomized blocks (30 result blocks; five per calibration candidate). Within each block and cell, retries censored attempts until one complete sealed horizon exists. It permits at most 60 total attempted sequences per result cell before failing the campaign as censor-dominated.

- [ ] **Step 1: Write failing resume and partition tests**

```python
def test_result_runner_rejects_calibration_manifest(tmp_path):
    manifest = campaign_manifest(partition=Partition.CALIBRATION)
    with pytest.raises(ValueError, match="result manifest"):
        run_manifest(manifest, tmp_path / "result.jsonl", fake_gate, fake_probe)


def test_result_runner_rejects_injected_receipt_closure(tmp_path):
    manifest = campaign_manifest(
        partition=Partition.RESULT, closure_mode="injected-receipt",
    )
    with pytest.raises(ValueError, match="fixed-guard closure"):
        run_manifest(manifest, tmp_path / "result.jsonl", fake_gate, fake_probe)


def test_resume_counts_only_sealed_trials_and_retains_censors(tmp_path):
    output = tmp_path / "trials.jsonl"
    for record in censored_attempt(block_index=0, attempt=0, censor_epoch=1):
        append_trial(output, record)
    for record in sealed_attempt(block_index=0, attempt=1, horizon=4):
        append_trial(output, record)
    state = resume_state(output, campaign_hash=CAMPAIGN_HASH)
    assert state.attempts == 2
    assert state.valid_by_cell[CELL] == 1
    assert state.completed_blocks_by_cell[CELL] == {0}


def test_resume_closes_a_crash_truncated_attempt_as_censored(tmp_path):
    output = tmp_path / "trials.jsonl"
    for record in sealed_attempt(block_index=0, attempt=0, horizon=2):
        append_trial(output, record)
    state = resume_state(output, campaign_hash=CAMPAIGN_HASH, expected_horizon=4)
    assert state.incomplete_attempts == ((CELL, 0, 0, 2),)
    recover_incomplete_attempts(state, output, clean_gate())
    records = read_trials(output)
    assert records[-1].seal_status is SealStatus.CENSORED
    assert records[-1].censor_reason == "interrupted-attempt"
    assert records[-1].epoch_offset == 2


def test_identity_failure_is_recorded_before_mutation(tmp_path):
    gate = FakeGate([BAD_SEALED_IDENTITY])
    run_manifest(one_cell_manifest(), tmp_path / "trials.jsonl", gate, FakeProbe(200))
    trial = read_trials(tmp_path / "trials.jsonl")[0]
    assert trial.seal_status is SealStatus.CENSORED
    assert trial.censor_reason == "identity-mismatch"
    assert gate.commands == ["V2"]


def test_cleanup_failure_overrides_sealed_status(tmp_path):
    records = run_one_attempt(clean_measurement_replies(cleanup="ERR busy\n"))
    assert records[-1].seal_status is SealStatus.CENSORED
    assert records[-1].censor_reason == "cleanup-failure"
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest p4/hw/loop/test_nsdi_campaign.py p4/hw/loop/test_sequential_trials.py -q`

Expected: FAIL because the runner is absent and cleanup is not part of `TrialOutcome`.

- [ ] **Step 3: Make cleanup status observable without weakening finally cleanup**

Refactor `run_trial` to call a small `cleanup_injector(gate) -> str` helper in `finally`. If cleanup fails, raise a `CleanupError` carrying any completed raw observation; the campaign wrapper records the entire attempt as censored. Direct historical callers still receive an exception and never a sealed decision.

- [ ] **Step 4: Implement manifest freeze and source/runtime identities**

`freeze` builds a `CampaignManifest`, validates it, and writes it through `write_new` so an existing result manifest is never overwritten. It must derive identity and the committed source closure as follows:

```python
identity = require_identity(
    gate, expected_program, expected_switch, expected_build,
    expected_setup, expected_runtime,
)
source_paths = (
    Path("p4/witness/mcp_fabric_clf_eg.p4"),
    Path("p4/hw/loop/gate_agent.py"),
    Path("p4/hw/loop/gate_agent_core.py"),
    Path("p4/hw/loop/injector_ranges.py"),
    Path("p4/hw/loop/multicontext_probe.py"),
    Path("p4/hw/loop/sequential_trials.py"),
    Path("p4/hw/loop/nsdi_campaign.py"),
    Path("controller/evidence_ledger.py"),
    Path("sim/clf/verdict.py"),
    Path("experiments/nsdi27/schema.py"),
    Path("experiments/nsdi27/codec.py"),
    Path("experiments/nsdi27/frozen.py"),
    Path("experiments/nsdi27/baselines.py"),
)
source_closure = tuple(sorted(
    (path.as_posix(), sha256_file(path)) for path in source_paths
))
git_revision = subprocess.run(
    ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
).stdout.strip()
source_revision = sha256_identity({
    "git_revision": git_revision,
    "source_closure": source_closure,
})
runner_id = sha256_files((Path(__file__), Path("p4/hw/loop/multicontext_probe.py"),
                          Path("p4/hw/loop/sequential_trials.py"),
                          Path("controller/evidence_ledger.py"),
                          Path("sim/clf/verdict.py"),
                          Path("experiments/nsdi27/schema.py"),
                          Path("experiments/nsdi27/codec.py"),
                          Path("experiments/nsdi27/frozen.py"),
                          Path("experiments/nsdi27/baselines.py")))
```

Store `source_closure` in the campaign itself and store its Git-plus-file-map digest as `DeploymentIdentity.source_revision`. Do not require the entire worktree to be clean; require every file in the declared closure to match the recorded content hash. Freeze all candidate scenarios before execution and construct ordered `CampaignStage` records whose dependencies, scenario membership, valid targets, and deterministic selection rules encode the complete calibration DAG; the result campaign has one dependency-free stage. The campaign validator requires every frozen scenario to belong to exactly one stage.

- [ ] **Step 5: Implement randomized/resumable execution**

For each stage, use `scenario_blocks` so every `block_index` contains every eligible condition cell once in frozen randomized order. An attempt is one call to the four-epoch `sequential_trials.run_campaign`; every emitted epoch record shares `(scenario_id, block_index, attempt)` and has offset `0..3`. Always run the full horizon so later-alarming baselines receive the same budget even if another arm alarms early. Before every epoch mutation, re-read V2 identity and require the same `switch_id`, all artifact hashes, and `switchd_pid`. On any exception, retain already appended sealed prefix records and append one terminal censored record at the next offset with the precise reason and cleanup state; analysis excludes that whole attempt. On resume, detect any sealed prefix shorter than the frozen horizon, perform verified injector cleanup, and append an `interrupted-attempt` censor before scheduling a replacement. Never rewrite the output file.

- [ ] **Step 6: Implement validation CLI**

`validate` checks canonical decoding, one campaign hash, the exact per-scenario hash, one unchanged `switch_id`, every current source-closure hash (including codec, frozen matrix, runner, agent, and detector code), no duplicate `(scenario_id, block_index, attempt, epoch_offset)`, exact decision set, contiguous epoch offsets, full-horizon valid attempts, typed terminal censors for incomplete attempts, valid/invalid attempt counts, censor reasons, and cleanup. Hardware partitions additionally require a positive live `switchd_pid`; simulation alone may use PID zero and a declared synthetic deployment identity. For `Partition.RESULT` it additionally requires `require_result()`, exactly one complete sealed attempt for every `(scenario_id, block_index)` across 30 blocks, and no reused block. For `Partition.CALIBRATION` it verifies the frozen stage DAG, deterministic skipped branches, stage-specific valid-attempt totals, and disjoint confirmation block seeds. It writes a receipt containing raw JSONL SHA-256 and exits nonzero on any failed invariant.

- [ ] **Step 7: Run campaign contract tests**

Run: `python3 -m pytest p4/hw/loop/test_nsdi_campaign.py p4/hw/loop/test_sequential_trials.py experiments/nsdi27/tests -q`

Expected: all tests PASS.

- [ ] **Step 8: Commit the runner**

```bash
git add p4/hw/loop/nsdi_campaign.py p4/hw/loop/test_nsdi_campaign.py p4/hw/loop/sequential_trials.py p4/hw/loop/test_sequential_trials.py
git commit -m "feat: add resumable silicon campaign"
```

---

### Task 10: Fresh offline gate, model/PTF verification, and silicon calibration

**Files:**
- Modify: `p4/ptf/model/run_context_regressions.sh`
- Modify: `p4/ptf/model/test_runner_contract.py`
- Create from runner output: `docs/review/artifacts/nsdi27/calibration/manifest.json`
- Create from runner output: `docs/review/artifacts/nsdi27/calibration/trials.jsonl`
- Create from validator: `docs/review/artifacts/nsdi27/calibration/validation.json`
- Create from runner output: `docs/review/artifacts/nsdi27/calibration/context-regressions.txt`
- Create from runner output: `docs/review/artifacts/nsdi27/calibration/gap-event.txt`
- Create from analysis: `docs/review/artifacts/nsdi27/calibration/selection.json`
- Create: `docs/review/artifacts/nsdi27/calibration/REPORT.md`
- Create: `docs/review/artifacts/nsdi27/DEFECT-REGRESSION-MATRIX.md`
- Modify from analysis: `docs/review/artifacts/nsdi27/ablation/summary.json`
- Modify: `docs/review/artifacts/nsdi27/ablation/REPORT.md`

**Interfaces:**
- Consumes: Tasks 1--9 and current Tofino runbooks.
- Produces: one frozen deployable calibration selection—exact-count packet rate, fixed guard, packet count, supported injector range count, and censor ceiling—plus a separately labelled injected-receipt closure lower bound.
- Hardware mutation starts only after all offline/model gates pass.

- [ ] **Step 1: Run the focused offline suite**

Run:

```bash
python3 -m pytest controller/tests/test_evidence_ledger.py controller/tests/test_seal_invariants.py sim/tests/test_clf_verdict.py sim/tests/test_sequential_eval.py experiments/nsdi27/tests p4/hw/loop/test_clf_trials.py p4/hw/loop/test_sequential_trials.py p4/hw/loop/test_nsdi_campaign.py p4/hw/loop/test_gate_agent_core.py p4/hw/loop/test_injector_ranges.py p4/control/tests/test_setup_attention.py p4/hw/test_setup_manifest_contract.py -q
```

Expected: all tests PASS.

- [ ] **Step 2: Run the full offline regression suite**

Run: `python3 -m pytest -q`

Expected: all tests PASS. If an unrelated dirty-tree test fails, record its exact path and prove the campaign subset remains green before deciding whether the failure blocks hardware.

- [ ] **Step 3: Write a failing contract test for current-source W4 coverage**

```python
def test_runner_includes_current_w4_source_and_ptf_suite(self):
    text = RUNNER.read_text()
    self.assertIn(
        'run_one mcp_fabric_w4_arm "$REPO_DIR/p4/ptf/test_w4_witness.py"',
        text,
    )
    self.assertIn(
        'run_one mcp_fabric_cw4 "$REPO_DIR/p4/ptf/test_cw4_sublinks.py"',
        text,
    )
    self.assertNotIn("run_ptf.sh", text)
    self.assertNotIn("pkill", text)
```

- [ ] **Step 4: Run the runner contract and confirm W4 is absent**

Run: `python3 -m pytest p4/ptf/model/test_runner_contract.py -q`

Expected: FAIL only at `test_runner_includes_current_w4_source_and_ptf_suite`.

- [ ] **Step 5: Add W4 and C-W4 to the PID-owned current-source runner**

Append exactly these invocations after the existing capsule and gate invocations:

```bash
run_one mcp_fabric_w4_arm "$REPO_DIR/p4/ptf/test_w4_witness.py"
run_one mcp_fabric_cw4 "$REPO_DIR/p4/ptf/test_cw4_sublinks.py"
```

Do not invoke the legacy `run_ptf.sh`/`run_stack_host.sh` path: it assumes external stack state and globally kills named model processes. The context runner must remain the single safe owner of every PID/config it creates.

Run: `python3 -m pytest p4/ptf/model/test_runner_contract.py -q`

Expected: all tests PASS.

- [ ] **Step 6: Run fresh model/PTF regressions and capture full logs**

Run: `mkdir -p docs/review/artifacts/nsdi27/calibration`

Run: `bash p4/ptf/model/run_context_regressions.sh > docs/review/artifacts/nsdi27/calibration/context-regressions.txt 2>&1`

Run: `bash p4/ptf/model/run_gap_event.sh > docs/review/artifacts/nsdi27/calibration/gap-event.txt 2>&1`

Run: `tail -n 80 docs/review/artifacts/nsdi27/calibration/context-regressions.txt docs/review/artifacts/nsdi27/calibration/gap-event.txt`

Expected: context, gap-event, W4/CLF, and health-gate semantics PASS from current sources. Archive the unabridged outputs under the calibration directory.

- [ ] **Step 7: Deploy and bring up the exact campaign program**

Run: `p4/hw/deploy.sh mcp_fabric_clf_eg`

Run: `p4/hw/bringup.sh mcp_fabric_clf_eg --port-timeout 120`

Expected: compile exit 0; build/setup/runtime manifests verify; exact `tbl_eg_vlink` has 16 rows; all required ports train; V2 reports the expected switch/build/setup/runtime identity and one live `bf_switchd` PID.

- [ ] **Step 8: Freeze and execute calibration**

Run:

```bash
python3 p4/hw/loop/nsdi_campaign.py freeze --partition calibration --program mcp_fabric_clf_eg --output docs/review/artifacts/nsdi27/calibration/manifest.json
```

Run:

```bash
python3 p4/hw/loop/nsdi_campaign.py run --manifest docs/review/artifacts/nsdi27/calibration/manifest.json --output docs/review/artifacts/nsdi27/calibration/trials.jsonl
```

The frozen calibration manifest is a deterministic four-stage DAG, not the full Cartesian product:

1. Timing screen: 200 packets, sublink 2, survival `(1.0, 0.95)`, dispersed loss, rates `(200, 1000, 5000)` pps, guards `(2.0, 1.0, 0.5, 0.25, 0.1)`, five sealed repetitions per cell: 150 valid attempts.
2. Coverage screen: the winning rate/guard, packets `(40, 200)`, sublinks `(2, 6, 10, 14)`, survival `(1.0, 0.95)`, both burst/dispersed patterns, five repetitions: 160 valid attempts.
3. Closure ablation: the provisionally selected packet/rate/guard across the same four sublinks, two survival points, and two patterns, paired between `fixed-guard` and `injected-receipt`, five repetitions: 160 valid attempts. Receipt mode uses a 2-second timeout and 10-millisecond poll interval.
4. Independent confirmation: the selected fixed-guard point across four sublinks, two survival points, and two patterns, five new repetitions with disjoint seeds: 80 valid attempts.

The immutable manifest contains every candidate, tie-break, stage dependency, and seed before stage 1 begins. The runner records skipped branches with their deterministic selection reason but creates trial records only for attempted cells. Invalid attempts are retained and replacements do not count toward the stated valid totals. Receipt closure remains a controlled-injection calibration lower bound and is never eligible for the result partition.

- [ ] **Step 9: Validate calibration identities, stage totals, hashes, and cleanup**

Run:

```bash
python3 p4/hw/loop/nsdi_campaign.py validate --manifest docs/review/artifacts/nsdi27/calibration/manifest.json --trials docs/review/artifacts/nsdi27/calibration/trials.jsonl --receipt docs/review/artifacts/nsdi27/calibration/validation.json
```

Expected: append-only/hash validation passes; all stage/block/attempt invariants hold; the raw JSONL SHA-256 is sealed in the receipt; and final gate-agent injector readback is `OK 0` for the targeted table. Selection and ablation code refuse calibration inputs without this receipt.

- [ ] **Step 10: Select the efficient safe operating point mechanically**

Run:

```bash
python3 p4/hw/loop/nsdi_campaign.py select-calibration --manifest docs/review/artifacts/nsdi27/calibration/manifest.json --trials docs/review/artifacts/nsdi27/calibration/trials.jsonl --validation docs/review/artifacts/nsdi27/calibration/validation.json --output docs/review/artifacts/nsdi27/calibration/selection.json
```

Selection rule: screening stages require zero identity/setup/cleanup failures, zero count mismatches, and exact programmed/measured drops; ties choose highest pps, then shortest guard, then 200 packets. The independent 80-attempt fixed-guard confirmation must again have zero identity/setup/cleanup/count failures and an exact one-sided 95% censor upper bound below 0.05 (with zero censors, `1 - 0.05 ** (1 / 80) < 0.05`). If confirmation fails, calibration fails and the result partition is not frozen. Report receipt-conditioned latency/polls as an exploratory lower bound without using it to select or justify the result closure.

- [ ] **Step 11: Document calibration and defect closure**

Write `REPORT.md` with exact identities, selected values, every rejected candidate and reason, raw hashes, test/model commands, and the single-switch boundary.

Write `DEFECT-REGRESSION-MATRIX.md` from `DEFECT_REGRESSION_TESTS`: one row per D1--D7, the exact test/model case, current source hash, fresh output artifact/hash, and PASS/FAIL. A missing row, stale hash, or non-passing case blocks the result freeze.

- [ ] **Step 12: Complete the closure ablation without changing result selection**

Run:

```bash
python3 -m experiments.nsdi27.ablations --manifest docs/review/artifacts/nsdi27/ablation/manifest.json --trials docs/review/artifacts/nsdi27/ablation/trials.jsonl --calibration-manifest docs/review/artifacts/nsdi27/calibration/manifest.json --calibration-trials docs/review/artifacts/nsdi27/calibration/trials.jsonl --calibration-validation docs/review/artifacts/nsdi27/calibration/validation.json --completion docs/review/artifacts/nsdi27/ablation/completion.json --summary docs/review/artifacts/nsdi27/ablation/summary.json --report docs/review/artifacts/nsdi27/ablation/REPORT.md
```

Expected: only the closure references change from `PENDING-HARDWARE` to `COMPLETE`, each carrying manifest/trials/validation/report hashes; action references remain pending. Fixed-guard and injected-receipt elapsed-time/censor intervals are paired; the report states that injected-receipt closure depends on known fault injection and is not deployable evidence.

- [ ] **Step 13: Commit safe-runner changes and calibration evidence**

```bash
git add p4/ptf/model/run_context_regressions.sh p4/ptf/model/test_runner_contract.py docs/review/artifacts/nsdi27/calibration/manifest.json docs/review/artifacts/nsdi27/calibration/trials.jsonl docs/review/artifacts/nsdi27/calibration/validation.json docs/review/artifacts/nsdi27/calibration/selection.json docs/review/artifacts/nsdi27/calibration/context-regressions.txt docs/review/artifacts/nsdi27/calibration/gap-event.txt docs/review/artifacts/nsdi27/calibration/REPORT.md docs/review/artifacts/nsdi27/DEFECT-REGRESSION-MATRIX.md docs/review/artifacts/nsdi27/ablation/completion.json docs/review/artifacts/nsdi27/ablation/summary.json docs/review/artifacts/nsdi27/ablation/REPORT.md
git commit -m "exp: calibrate sealed silicon trials"
```

---

### Task 11: Frozen randomized silicon result campaign

**Files:**
- Create from runner output: `docs/review/artifacts/nsdi27/result/manifest.json`
- Create append-only: `docs/review/artifacts/nsdi27/result/trials.jsonl`
- Create from validator: `docs/review/artifacts/nsdi27/result/validation.json`
- Create from analysis: `docs/review/artifacts/nsdi27/result/summary.json`
- Create from analysis: `docs/review/artifacts/nsdi27/result/TABLE.md`
- Create: `docs/review/artifacts/nsdi27/result/REPORT.md`

**Interfaces:**
- Consumes: committed calibration selection and exact deployment identity.
- Produces: 30 sealed repetitions per primary cell, all invalid attempts, matched-arm results, confidence intervals, and gate verdicts.
- The manifest is committed before the result runner starts; the runner refuses a changed manifest or source closure.

- [ ] **Step 1: Freeze the result manifest from the committed calibration selection**

Run:

```bash
python3 p4/hw/loop/nsdi_campaign.py freeze --partition result --program mcp_fabric_clf_eg --calibration docs/review/artifacts/nsdi27/calibration/selection.json --calibration-validation docs/review/artifacts/nsdi27/calibration/validation.json --output docs/review/artifacts/nsdi27/result/manifest.json
```

Run: `git add docs/review/artifacts/nsdi27/result/manifest.json`

Run: `git commit -m "exp: freeze silicon result matrix"`

Expected: matrix contains sublinks 2/6/10/14, survival 1/.99/.95/.75/.50/.10/0, burst/dispersed, the selected rate/guard/packet count, 30 repetitions, four-epoch horizon, randomized block order, and interleaved healthy controls.

- [ ] **Step 2: Execute or resume the result campaign**

Run:

```bash
python3 p4/hw/loop/nsdi_campaign.py run --manifest docs/review/artifacts/nsdi27/result/manifest.json --output docs/review/artifacts/nsdi27/result/trials.jsonl
```

The same command resumes after interruption by reading the append-only file. It must not truncate, reorder, or replace earlier attempts.

- [ ] **Step 3: Validate identities, sample counts, hashes, and cleanup**

Run:

```bash
python3 p4/hw/loop/nsdi_campaign.py validate --manifest docs/review/artifacts/nsdi27/result/manifest.json --trials docs/review/artifacts/nsdi27/result/trials.jsonl --receipt docs/review/artifacts/nsdi27/result/validation.json
```

Expected: one complete four-epoch sealed attempt for every cell in each of 30 randomized blocks, every valid and censored attempt retained, no truncated sequence, all exact identities unchanged, no result/calibration mixing, raw SHA-256 emitted, final injector cleanup verified.

- [ ] **Step 4: Produce the locked statistical result**

Run:

```bash
python3 -m experiments.nsdi27.analysis --manifest docs/review/artifacts/nsdi27/result/manifest.json --trials docs/review/artifacts/nsdi27/result/trials.jsonl --validation docs/review/artifacts/nsdi27/result/validation.json --summary docs/review/artifacts/nsdi27/result/summary.json --table docs/review/artifacts/nsdi27/result/TABLE.md
```

Expected: every frozen cell appears; censors are separate; confirmatory paired comparisons carry Holm-adjusted p-values; healthy, gray, and blackhole gates are explicit PASS/FAIL.

- [ ] **Step 5: Write the result report without changing thresholds**

`REPORT.md` maps each claim to manifest/raw/validation/analysis hashes, reports all cells and adverse results, states that burst/dispersed have equal programmed counts, and repeats the one-switch limitation.

- [ ] **Step 6: Commit immutable result artifacts**

```bash
git add docs/review/artifacts/nsdi27/result/trials.jsonl docs/review/artifacts/nsdi27/result/validation.json docs/review/artifacts/nsdi27/result/summary.json docs/review/artifacts/nsdi27/result/TABLE.md docs/review/artifacts/nsdi27/result/REPORT.md
git commit -m "exp: record randomized silicon results"
```

---

### Task 12: Selective-action versus whole-link action microbenchmark

**Files:**
- Create: `p4/hw/loop/nsdi_action_trials.py`
- Create: `p4/hw/loop/test_nsdi_action_trials.py`
- Create from runner: `docs/review/artifacts/nsdi27/result/action-trials.jsonl`
- Create from validator: `docs/review/artifacts/nsdi27/result/action-validation.json`
- Create: `docs/review/artifacts/nsdi27/result/ACTION.md`
- Modify from analysis: `docs/review/artifacts/nsdi27/ablation/summary.json`
- Modify: `docs/review/artifacts/nsdi27/ablation/REPORT.md`

**Interfaces:**
- Consumes: sealed detector decision, V2 identity, `gate_keys_for_sublink`, and gate-agent batch operations.
- Produces: `action_rows(sublink, mode)`, `run_action_trial`, and action modes `none`, `selective`, `whole-link`.
- Selective installs only the failed context's path keys. Whole-link installs the configured active contexts `(2, 6, 10, 14)` for the same physical vlink.

- [ ] **Step 1: Write failing action-row and safety tests**

```python
def test_selective_rows_touch_only_the_failed_context():
    rows = action_rows(sublink=2, mode="selective")
    assert {row[3] for row in rows} == {2}
    assert len(rows) == 4


def test_whole_link_rows_cover_all_active_contexts():
    rows = action_rows(sublink=2, mode="whole-link")
    assert {row[3] for row in rows} == {2, 6, 10, 14}
    assert len(rows) == 16


def test_monitor_no_action_installs_no_rows():
    assert action_rows(sublink=2, mode="none") == ()


def test_censored_decision_cannot_install_any_gate_row():
    gate = FakeGate()
    with pytest.raises(ValueError, match="sealed fault decision"):
        run_action_trial(censored_decision(), "selective", gate, probe)
    assert gate.commands == []
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest p4/hw/loop/test_nsdi_action_trials.py controller/tests/test_sublink_feedback.py -q`

Expected: FAIL because the action runner is absent.

- [ ] **Step 3: Implement exact action expansion and reversible cleanup**

```python
ACTIVE_CONTEXTS = (2, 6, 10, 14)


def action_rows(sublink, mode):
    vlink, failed_context = sublink >> 4, sublink & 0xf
    if mode == "none":
        return ()
    if mode == "selective":
        contexts = (failed_context,)
    elif mode == "whole-link":
        contexts = ACTIVE_CONTEXTS
    else:
        raise ValueError("unknown action mode: %s" % mode)
    rows = []
    for context in contexts:
        for src, dst, spray, ctx in gate_keys_for_sublink(vlink, context):
            rows.append((src, dst, spray, ctx, 1 - spray))
    return tuple(rows)
```

Require one successful batch reply and exact rerouted-probe evidence before marking an action effective. Always remove every installed key in `finally`; cleanup failure censors the action trial.

- [ ] **Step 4: Run offline action tests**

Run: `python3 -m pytest p4/hw/loop/test_nsdi_action_trials.py controller/tests/test_sublink_feedback.py p4/hw/loop/test_controller_loop.py -q`

Expected: all tests PASS.

- [ ] **Step 5: Run paired silicon action trials**

Run:

```bash
python3 p4/hw/loop/nsdi_action_trials.py run --manifest docs/review/artifacts/nsdi27/result/manifest.json --detector-trials docs/review/artifacts/nsdi27/result/trials.jsonl --detector-validation docs/review/artifacts/nsdi27/result/validation.json --output docs/review/artifacts/nsdi27/result/action-trials.jsonl --modes none,selective,whole-link --repetitions 30
```

Expected: paired scenario IDs; exact V2 identity; action latency, bad packets, residual loss, removed contexts/capacity, false actions, reroute proof, and cleanup status for every attempt.

- [ ] **Step 6: Validate action identities, pairing, hashes, and cleanup**

Run:

```bash
python3 p4/hw/loop/nsdi_action_trials.py validate --manifest docs/review/artifacts/nsdi27/result/manifest.json --detector-trials docs/review/artifacts/nsdi27/result/trials.jsonl --detector-validation docs/review/artifacts/nsdi27/result/validation.json --trials docs/review/artifacts/nsdi27/result/action-trials.jsonl --receipt docs/review/artifacts/nsdi27/result/action-validation.json
```

Expected: the receipt seals result-manifest, detector-trial, detector-validation, and action-trial hashes; every eligible detector attempt has exactly the three paired action modes; no censored detector decision caused an action; every installed row was removed; identities/PID stayed fixed; and final gate readback is empty.

- [ ] **Step 7: Analyze and document action results**

Use `experiments.nsdi27.analysis` to report paired selective-vs-no-action and selective-vs-whole-link differences with confidence intervals and Holm adjustment within the two-action comparison family. `ACTION.md` states whether selective action reduces bad packets relative to no action while preserving unaffected contexts at no worse false-action rate than whole-link quarantine; no restoration result appears.

- [ ] **Step 8: Complete the action ablation row**

Run:

```bash
python3 -m experiments.nsdi27.ablations --manifest docs/review/artifacts/nsdi27/ablation/manifest.json --trials docs/review/artifacts/nsdi27/ablation/trials.jsonl --calibration-manifest docs/review/artifacts/nsdi27/calibration/manifest.json --calibration-trials docs/review/artifacts/nsdi27/calibration/trials.jsonl --calibration-validation docs/review/artifacts/nsdi27/calibration/validation.json --result-manifest docs/review/artifacts/nsdi27/result/manifest.json --action-trials docs/review/artifacts/nsdi27/result/action-trials.jsonl --action-validation docs/review/artifacts/nsdi27/result/action-validation.json --completion docs/review/artifacts/nsdi27/ablation/completion.json --summary docs/review/artifacts/nsdi27/ablation/summary.json --report docs/review/artifacts/nsdi27/ablation/REPORT.md
```

Expected: every family in `REQUIRED_ABLATIONS` is `COMPLETE`, none is `PENDING-HARDWARE`, and confirmatory result thresholds remain unchanged.

- [ ] **Step 9: Commit action implementation and evidence**

```bash
git add p4/hw/loop/nsdi_action_trials.py p4/hw/loop/test_nsdi_action_trials.py docs/review/artifacts/nsdi27/result/action-trials.jsonl docs/review/artifacts/nsdi27/result/action-validation.json docs/review/artifacts/nsdi27/result/ACTION.md docs/review/artifacts/nsdi27/ablation/completion.json docs/review/artifacts/nsdi27/ablation/summary.json docs/review/artifacts/nsdi27/ablation/REPORT.md
git commit -m "exp: compare selective failure actions"
```

---

### Task 13: Reproducible resource, bandwidth, and control-cost accounting

**Files:**
- Create: `experiments/nsdi27/overhead.py`
- Create: `experiments/nsdi27/tests/test_overhead.py`
- Create: `p4/hw/capture_build.sh`
- Create: `p4/hw/test_capture_build_contract.py`
- Create from exact builds: `docs/review/artifacts/nsdi27/overhead/baseline/`
- Create from exact builds: `docs/review/artifacts/nsdi27/overhead/sealed/`
- Create from parser: `docs/review/artifacts/nsdi27/overhead/summary.json`
- Create: `docs/review/artifacts/nsdi27/overhead/REPORT.md`

**Interfaces:**
- Produces: `CompileCost`, `RuntimeCost`, `parse_table_summary`, `diff_cost`, `measured_bytes`, and CLI.
- Raw compiler logs and runner JSONL remain authoritative. Derived extrapolations carry `provenance="derived"`.

- [ ] **Step 1: Write failing parser and provenance tests**

```python
def test_compile_delta_uses_raw_stage_and_sram_counts():
    base = parse_table_summary(BASE_FIXTURE)
    sealed = parse_table_summary(SEALED_FIXTURE)
    delta = diff_cost(base, sealed)
    assert delta.egress_stages == 1
    assert delta.sram_blocks == 12


def test_measured_and_derived_costs_cannot_be_merged():
    with pytest.raises(ValueError, match="provenance"):
        combine_costs(measured_cost(), derived_cost())


def test_evidence_bytes_are_counted_from_raw_payload():
    payload = (b"SEALED_IDENTITY p " + b"a" * 64 + b" " + b"b" * 64
               + b" " + b"c" * 64 + b" " + b"d" * 64 + b" 123\n")
    assert measured_bytes((payload,)) == len(payload)


def test_capture_script_names_every_authoritative_compiler_artifact():
    text = Path("p4/hw/capture_build.sh").read_text()
    for name in ("build.log", "table_summary.log", "mau.resources.log",
                 "context.json", "bfrt.json", "build-manifest.sha256"):
        assert name in text
    assert "hw_scp_down" in text
    assert "rm -rf" not in text
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest experiments/nsdi27/tests/test_overhead.py p4/hw/test_capture_build_contract.py -q`

Expected: FAIL because `overhead.py` and `capture_build.sh` are absent.

- [ ] **Step 3: Implement strict raw parsers**

Use anchored regular expressions for the exact `table_summary.log` and build-log lines already archived by `deploy.sh`. Missing categories are errors, not zeros. Parse stages, SRAM, map RAM, TCAM, stateful ALUs, PHV, and table count into immutable dataclasses.

- [ ] **Step 4: Implement bounded verified build-artifact capture**

`p4/hw/capture_build.sh <program> <output-dir>` sources `common.sh`, accepts only a bare `[a-zA-Z0-9_]+` program, refuses a nonempty output directory, and asks the switch to archive exactly:

```text
<program>.p4
<program>.build.log
<program>.bfrt.json
<program>.build-manifest.sha256
<program>.tofino/pipe/context.json
<program>.tofino/pipe/logs/table_summary.log
<program>.tofino/pipe/logs/mau.resources.log
```

The remote archive name comes from `mktemp` under `/tmp/nsdi27-build-capture.XXXXXX.tar.gz`; return its SHA-256, copy it with `hw_scp_down`, require the local SHA-256 to match, extract only the listed members into the explicit output directory, and remove only that exact temporary archive locally/remotely in `trap`. Never use a wildcard or recursive remote deletion.

Run: `python3 -m pytest p4/hw/test_capture_build_contract.py -q`

Expected: all tests PASS.

- [ ] **Step 5: Capture fresh `mcp_fabric_noclf` and sealed builds**

Run: `p4/hw/deploy.sh mcp_fabric_noclf`

Run: `p4/hw/capture_build.sh mcp_fabric_noclf docs/review/artifacts/nsdi27/overhead/baseline`

Run: `p4/hw/deploy.sh mcp_fabric_clf_eg`

Run: `p4/hw/capture_build.sh mcp_fabric_clf_eg docs/review/artifacts/nsdi27/overhead/sealed`

`mcp_fabric_noclf.p4` is the checked-in source-matched removal baseline generated from `mcp_fabric_clf_eg.p4`; no other program may substitute. Do not copy only selected lines.

- [ ] **Step 6: Parse compile and runtime evidence**

Run:

```bash
python3 -m experiments.nsdi27.overhead --baseline docs/review/artifacts/nsdi27/overhead/baseline --sealed docs/review/artifacts/nsdi27/overhead/sealed --trials docs/review/artifacts/nsdi27/result/trials.jsonl --actions docs/review/artifacts/nsdi27/result/action-trials.jsonl --output docs/review/artifacts/nsdi27/overhead/summary.json
```

Expected: incremental resources, evidence bytes/epoch, controller operations and timing, selected guard/throughput, and gate latency are present with raw hashes and measured/derived labels.

- [ ] **Step 7: Run tests and write overhead report**

Run: `python3 -m pytest experiments/nsdi27/tests/test_overhead.py p4/hw/test_capture_build_contract.py -q`

Expected: all tests PASS.

Write `REPORT.md` with the exact closest baseline, raw sources, deltas, scaling equations, and the distinction between measured data and arithmetic extrapolation.

- [ ] **Step 8: Commit overhead implementation and evidence**

```bash
git add experiments/nsdi27/overhead.py experiments/nsdi27/tests/test_overhead.py p4/hw/capture_build.sh p4/hw/test_capture_build_contract.py docs/review/artifacts/nsdi27/overhead
git commit -m "exp: price sealed failure evidence"
```

---

### Task 14: Best-effort external compatibility, final comparison, and adversarial audit

**Files:**
- Create: `experiments/nsdi27/external.py`
- Create: `experiments/nsdi27/tests/test_external.py`
- Create: `docs/review/artifacts/nsdi27/external/manifest.json`
- Create: `docs/review/artifacts/nsdi27/external/REPORT.md`
- Create/update: `docs/review/artifacts/nsdi27/IMPROVEMENT-LEDGER.md`
- Create: `docs/review/NSDI-FINAL-COMPARISON.md`

**Interfaces:**
- Produces: pinned artifact inventory and `validate_comparison_row(row) -> None`.
- Pinned upstream revisions at planning time:
  - FANcY `24e9a44e164b89313063540b91ef987fa0b22560`
  - dDrops `76cf5aba442af613f58775fd517599d0f7aaf53a`
  - altmark `25d577f51f4602acdde8b2e2171892c31639c5a9`
  - LinkGuardian `bd46f4bb1371e25d6d40e011766a1e07b35ea898` only for mitigation context
- External repositories live under `/home/philip/Projects/nsdi27-baselines/`; none is copied into this repository.

- [ ] **Step 1: Write failing comparison-provenance tests**

```python
def test_upstream_artifact_requires_revision_command_and_compatible_metric():
    row = comparison_row(provenance="upstream-artifact", revision="", command_sha256="")
    with pytest.raises(ValueError, match="revision"):
        validate_comparison_row(row)


def test_published_point_cannot_support_superiority():
    row = comparison_row(provenance="published-point", supports_superiority=True)
    with pytest.raises(ValueError, match="published point"):
        validate_comparison_row(row)


def test_detector_and_recovery_metrics_cannot_share_one_rank():
    row = comparison_row(metric_family="mixed")
    with pytest.raises(ValueError, match="metric family"):
        validate_comparison_row(row)
```

- [ ] **Step 2: Run tests and confirm failure**

Run: `python3 -m pytest experiments/nsdi27/tests/test_external.py -q`

Expected: FAIL because `external.py` is absent.

- [ ] **Step 3: Implement strict artifact and comparison records**

Every system record includes name, URL, revision, license, artifact status, execution environment, build command hash, run command hash, raw-output hash, metric family, compatibility verdict, provenance label, and whether it may support a direct comparison. `published-point`, `replay-only`, and incompatible rows force `supports_superiority = false`.

- [ ] **Step 4: Pin external repositories without installing dependencies**

Run:

```bash
mkdir -p /home/philip/Projects/nsdi27-baselines
git clone https://github.com/nsg-ethz/FANcY.git /home/philip/Projects/nsdi27-baselines/FANcY
git -C /home/philip/Projects/nsdi27-baselines/FANcY checkout --detach 24e9a44e164b89313063540b91ef987fa0b22560
git clone https://github.com/AntLab-Repo/dDrops.git /home/philip/Projects/nsdi27-baselines/dDrops
git -C /home/philip/Projects/nsdi27-baselines/dDrops checkout --detach 76cf5aba442af613f58775fd517599d0f7aaf53a
git clone https://github.com/ozaki-r/altmark.git /home/philip/Projects/nsdi27-baselines/altmark
git -C /home/philip/Projects/nsdi27-baselines/altmark checkout --detach 25d577f51f4602acdde8b2e2171892c31639c5a9
git clone https://github.com/NUS-SNL/linkguardian.git /home/philip/Projects/nsdi27-baselines/linkguardian
git -C /home/philip/Projects/nsdi27-baselines/linkguardian checkout --detach bd46f4bb1371e25d6d40e011766a1e07b35ea898
```

If a target directory already exists, verify its remote and revision; do not overwrite or reset unknown work. Use only already-installed toolchains. A missing ns-3/SDE/kernel environment becomes an exact blocker receipt rather than an unapproved dependency installation.

- [ ] **Step 5: Run compatibility preflights and compatible metrics**

For each artifact, archive license, README build/run commands, tool versions, command text and SHA-256, exit status, unabridged output, and compatibility verdict. Run comparable detector metrics only when fault definition, observation budget, and output semantics can be matched. Keep LinkGuardian in mitigation/recovery context and Alternate Marking in measurement/fixed-horizon context.

- [ ] **Step 6: Validate the external manifest**

Run:

```bash
python3 -m experiments.nsdi27.external --manifest docs/review/artifacts/nsdi27/external/manifest.json --report docs/review/artifacts/nsdi27/external/REPORT.md
```

Expected: every row has one provenance label; incompatible or blocked artifacts cannot support superiority; detection, overhead, and mitigation metrics remain separate.

- [ ] **Step 7: Write the final comparison from measured artifacts**

`docs/review/NSDI-FINAL-COMPARISON.md` must contain:

1. claim-to-artifact table;
2. broad paired simulation results (2,000 campaigns per survival) with confidence intervals, coverage proof, and Holm-adjusted comparisons;
3. matched silicon detector results plus reproducibility/censor table;
4. selective versus whole-link action table;
5. incremental resource/bandwidth/control costs;
6. external artifact compatibility/results table;
7. complete ten-family ablation table, with non-deployable negative controls marked visually;
8. related-work scope table for FANcY, dDrops, Alternate Marking, NetBouncer, LinkGuardian, LossRadar, SprayCheck, dShark, NetSeer, and other directly adjacent work;
9. explicit one-switch, no-root-cause, no-restoration, and no-workload-benefit limits; and
10. an evidence-based `READY`, `BORDERLINE`, or `NOT READY` NSDI verdict.

Every numeric claim links to a raw/manifest/analysis hash. Every prior-work claim cites a primary source. Published points are visually separated from matched implementations. The comparison links `IMPROVEMENT-LEDGER.md`, names every campaign version, distinguishes invalidated defective runs from valid adverse runs, and proves that no tuned version reused an earlier result seed or merged result partitions.

- [ ] **Step 8: Run fresh complete verification**

Run: `python3 -m pytest -q`

Run: `bash p4/ptf/model/run_context_regressions.sh`

Run: `bash p4/ptf/model/run_gap_event.sh`

Run:

```bash
python3 -m experiments.nsdi27.ablations --verify-complete --manifest docs/review/artifacts/nsdi27/ablation/manifest.json --trials docs/review/artifacts/nsdi27/ablation/trials.jsonl --calibration-manifest docs/review/artifacts/nsdi27/calibration/manifest.json --calibration-trials docs/review/artifacts/nsdi27/calibration/trials.jsonl --calibration-validation docs/review/artifacts/nsdi27/calibration/validation.json --result-manifest docs/review/artifacts/nsdi27/result/manifest.json --action-trials docs/review/artifacts/nsdi27/result/action-trials.jsonl --action-validation docs/review/artifacts/nsdi27/result/action-validation.json --completion docs/review/artifacts/nsdi27/ablation/completion.json --summary docs/review/artifacts/nsdi27/ablation/summary.json --report docs/review/artifacts/nsdi27/ablation/REPORT.md
```

Run:

```bash
python3 p4/hw/loop/nsdi_campaign.py validate --manifest docs/review/artifacts/nsdi27/result/manifest.json --trials docs/review/artifacts/nsdi27/result/trials.jsonl --receipt docs/review/artifacts/nsdi27/result/validation.json
```

Run:

```bash
python3 p4/hw/loop/nsdi_action_trials.py validate --manifest docs/review/artifacts/nsdi27/result/manifest.json --detector-trials docs/review/artifacts/nsdi27/result/trials.jsonl --detector-validation docs/review/artifacts/nsdi27/result/validation.json --trials docs/review/artifacts/nsdi27/result/action-trials.jsonl --receipt docs/review/artifacts/nsdi27/result/action-validation.json
```

Expected: all code/model tests pass, hardware artifacts validate, and no injector/gate entry remains armed after campaign cleanup.

- [ ] **Step 9: Request independent adversarial review and fix every blocker**

The reviewer checks code/config/artifact/statistic/comparison consistency, attempts to reproduce primary tables from raw JSONL, verifies all provenance labels/citations, and returns either `APPROVE` or blocking corrections. Repeat verification after every correction.

If a quantitative gate or review fails, invoke the failure-driven improvement protocol. Proven defects invalidate and version the affected partition before a fresh disjoint-seed rerun; valid underperformance remains reported and may only motivate a separately preregistered development/calibration redesign. The reviewer must approve the classification and `IMPROVEMENT-LEDGER.md` entry before any new result freeze.

- [ ] **Step 10: Commit final comparison**

```bash
git add experiments/nsdi27/external.py experiments/nsdi27/tests/test_external.py docs/review/artifacts/nsdi27/external docs/review/artifacts/nsdi27/IMPROVEMENT-LEDGER.md docs/review/NSDI-FINAL-COMPARISON.md
git commit -m "docs: compare sealed evidence for NSDI"
```

---

## Spec coverage check

- Outcome/thesis/non-claims: Tasks 2, 11, and 14.
- Seal before inference and exact identities: Tasks 1, 3, 4, and 9.
- Closure/observation/decision/action separation: Tasks 1, 4, 9, and 12.
- Condition/guard efficiency: Tasks 8 and 10 compare a deployable fixed guard with a controlled-injection receipt lower bound; only the independently confirmed fixed guard may enter result manifests.
- Correctness/model/PTF: Tasks 3, 4, 8, 9, 10, and 14.
- Statistical simulation and paired seeds: Tasks 2, 5, 6, and 7.
- Randomized silicon and benign controls: Tasks 9--11.
- Matched and external baselines: Tasks 4, 12, and 14.
- Ablations: Tasks 7, 8, 10, and 12 implement and complete every frozen family; analysis marks confirmatory, exploratory, and deliberately invalid controls separately.
- Statistical contract: Tasks 2 and 6.
- Overhead: Task 13.
- Result schema and append-only evidence: Tasks 1 and 9.
- Single-switch reproducibility boundary: Global Constraints, Tasks 10, 11, and 14.
- Selective action: Task 12.
- Deliverables, acceptance, and narrowing verdict: Tasks 11 and 14.
- Workload extension: deliberately excluded from this core plan; create a separate reviewed plan only after Task 14 reports that the core gate passed and the extension can materially strengthen the submission.

## Plan self-review

- All approved core-spec requirements map to a task above.
- The primary and secondary claim axes are separated.
- The same field names and signatures are used across schema, runner, analysis, and reports.
- Every production-code step begins with a failing focused test and ends with fresh passing evidence.
- Hardware mutation occurs only after offline, model, manifest, ownership, and identity gates.
- The plan contains no dependency installation, silent result replacement, post-hoc threshold change, or multi-switch claim.
