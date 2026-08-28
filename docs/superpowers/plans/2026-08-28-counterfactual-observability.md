# Counterfactual Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a tested detect–quarantine–audit–probation–restore lifecycle that safely creates bounded evidence on avoided links in a packet-sprayed AI fabric.

**Architecture:** Keep the compiled W4 post-TM witness as a borrowed active-link detector. Add a pure Python lifecycle policy, a small event simulator, a Tofino audit gate that enforces a per-link packet cap, and a thin BFRT adapter. Prove the research question and safety/capacity result in simulation before completing silicon integration.

**Tech Stack:** Python 3, pytest, htsim C++, P4_16/TNA on Intel Tofino 1, BFRT Python, PTF, Markdown preregistration and artifact reports.

**Spec:** `docs/superpowers/specs/2026-08-28-counterfactual-observability-design.md`

## Global Constraints

- W4, NetSeer-style sequencing, LinkGuardian-style dummy traffic, alternate marking, active probing, and sequential tests are prior art or baselines, not inventions.
- The first audit source is host/controller injected; the switch must enforce the maximum packet count even if the controller continues sending.
- Use W4 on the current virtual fabric because one physical loop port carries two directed vlinks; W2 remains a cost floor only.
- Do not claim arbitrary directed-link auditing until the upstream endpoint demonstrably forces the selected `link_id`.
- Do not claim an all-data-plane timeout unless a tested packet-generator/tick path enforces it.
- No new dependency may be added for the policy, simulator, or analysis.
- All stochastic scenarios use explicit stable seeds and print the realized fault/recovery schedule.
- Primary results use matched audit bytes and a preregistered unsafe-restoration bound; no post-hoc composite score.
- Functional hardware claims come from the virtual Tofino fabric; scale and quantitative topology claims come from simulation cross-validated at the hardware topology.

---

### Task 1: Close the counterfactual-observability prior-art gate

**Files:**
- Modify: `docs/NOVELTY-MATRIX.md`
- Modify: `docs/review/LITERATURE.md`
- Modify: `docs/review/NOVELTY-GATE.md`
- Modify: `docs/superpowers/specs/2026-08-28-counterfactual-observability-design.md`

**Interfaces:**
- Consumes: the contribution boundary in the spec.
- Produces: a dated `PASS`, `NARROW`, or `FAIL` verdict for the evidence-lease and bounded-audit lifecycle.

- [ ] **Step 1: Search primary literature by capability, not project vocabulary**

Search ACM, USENIX, IEEE, arXiv, standards, and vendor primary sources for all of:

```text
failed-link rehabilitation OR link revalidation
quarantine probation network link recovery
safe exploration adaptive routing failure
active probing after reroute OR after mitigation
gray failure recovery certification
failure detector feedback observability routing
```

Record mechanism, trigger, link targeting, safety cap, restoration rule, topology, hardware, and evaluation for every close work.

- [ ] **Step 2: Test the four-part novelty conjunction**

For each close work, answer yes/no with a primary-source section or page:

```text
1. Does mitigation remove the work's passive evidence?
2. Does it explicitly target an avoided directed link?
3. Does hardware enforce an exposure/probe cap?
4. Does restoration require confidence-qualified evidence?
```

- [ ] **Step 3: Write the verdict**

Append one of these exact outcomes to `docs/review/NOVELTY-GATE.md`:

```text
PASS: no retrieved work provides all four capabilities; proceed with the scoped contract.
NARROW: prior work occupies part of the contract; remove those parts from the claim and proceed.
FAIL: a retrieved system provides the same contract and lifecycle; stop lifecycle Tasks 2-5 and 7-10, complete only Task 6 as existing W4 infrastructure, and retain the replay/W4 artifact.
```

- [ ] **Step 4: Verify every new literature claim has primary-source provenance**

Run:

```bash
rg -n "counterfactual|rehabil|revalid|quarant|probation|safe exploration|evidence lease" \
  docs/NOVELTY-MATRIX.md docs/review/LITERATURE.md docs/review/NOVELTY-GATE.md
```

Expected: each mechanism claim is adjacent to a paper/standard/vendor source and a page or section where available.

- [ ] **Step 5: Commit the gate**

```bash
git add docs/NOVELTY-MATRIX.md docs/review/LITERATURE.md docs/review/NOVELTY-GATE.md \
  docs/superpowers/specs/2026-08-28-counterfactual-observability-design.md
git commit -m "research: close counterfactual observability novelty gate"
```

---

### Task 2: Define the lifecycle types and evidence contract

**Files:**
- Create: `controller/audit_types.py`
- Create: `controller/tests/test_audit_types.py`

**Interfaces:**
- Produces: `LinkPhase`, `AuditContract`, `AuditObservation`, `LinkAuditState`, `AuditEvent`, and `AuditCommand` used by policy, simulator, and BFRT adapter.

- [ ] **Step 1: Write the failing contract tests**

```python
from controller.audit_types import AuditContract, LinkPhase


def test_contract_derives_hard_byte_cap():
    c = AuditContract(
        link_id=7, audit_id=11, max_packets=128,
        packet_size=256, traffic_class=7, deadline_us=50_000,
    )
    assert c.max_bytes == 32_768


def test_contract_rejects_zero_exposure():
    try:
        AuditContract(7, 11, 0, 256, 7, 50_000)
    except ValueError as exc:
        assert "max_packets" in str(exc)
    else:
        raise AssertionError("zero-packet audit accepted")


def test_phase_names_are_stable_for_logs():
    assert [p.value for p in LinkPhase] == [
        "healthy", "suspect", "quarantined", "audit", "probation"
    ]
```

- [ ] **Step 2: Run the tests and confirm the module is absent**

Run: `pytest -q controller/tests/test_audit_types.py`

Expected: FAIL with `ModuleNotFoundError: No module named 'controller.audit_types'`.

- [ ] **Step 3: Implement immutable public records**

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Tuple


class LinkPhase(str, Enum):
    HEALTHY = "healthy"
    SUSPECT = "suspect"
    QUARANTINED = "quarantined"
    AUDIT = "audit"
    PROBATION = "probation"


@dataclass(frozen=True)
class AuditContract:
    link_id: int
    audit_id: int
    max_packets: int
    packet_size: int
    traffic_class: int
    deadline_us: int

    def __post_init__(self):
        for name in ("max_packets", "packet_size", "deadline_us"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")

    @property
    def max_bytes(self) -> int:
        return self.max_packets * self.packet_size


@dataclass(frozen=True)
class AuditObservation:
    link_id: int
    audit_id: int
    sent: int
    received: int
    first_seq: Optional[int]
    last_seq: Optional[int]
    timed_out: bool = False

    @property
    def losses(self) -> int:
        return max(self.sent - self.received, 0)


@dataclass
class LinkAuditState:
    link_id: int
    phase: LinkPhase = LinkPhase.HEALTHY
    lease_expires_us: int = 0
    next_audit_us: int = 0
    active_audit_id: Optional[int] = None
    relapse_count: int = 0


@dataclass(frozen=True)
class AuditEvent:
    kind: str
    link_id: int
    now_us: int
    observation: Optional[AuditObservation] = None


@dataclass(frozen=True)
class AuditCommand:
    kind: str
    link_id: int
    contract: Optional[AuditContract] = None
    route_fraction_ppm: Optional[int] = None
```

- [ ] **Step 4: Run the type tests**

Run: `pytest -q controller/tests/test_audit_types.py`

Expected: PASS.

- [ ] **Step 5: Commit the contract**

```bash
git add controller/audit_types.py controller/tests/test_audit_types.py
git commit -m "feat: define counterfactual audit contract"
```

---

### Task 3: Implement the deterministic lifecycle policy

**Files:**
- Create: `controller/audit_policy.py`
- Create: `controller/tests/test_audit_policy.py`

**Interfaces:**
- Consumes: Task 2 records.
- Produces: `AuditConfig`, `transition(state, event, config)`, and
  `choose_link(states, now_us, capacity_weight)`.

- [ ] **Step 1: Write transition tests before policy code**

```python
from controller.audit_policy import AuditConfig, choose_link, transition
from controller.audit_types import AuditEvent, LinkAuditState, LinkPhase


CFG = AuditConfig(
    recheck_delay_us=10_000,
    lease_us=100_000,
    probation_us=50_000,
    probation_fraction_ppm=10_000,
    max_packets=512,
    packet_size=256,
    traffic_class=7,
)


def test_suspect_is_quarantined_before_audit():
    st = LinkAuditState(link_id=3, phase=LinkPhase.SUSPECT)
    commands = transition(st, AuditEvent("confirm_fault", 3, 1_000), CFG)
    assert st.phase is LinkPhase.QUARANTINED
    assert st.next_audit_us == 11_000
    assert [c.kind for c in commands] == ["remove_from_routing"]


def test_expired_quarantine_issues_one_bounded_audit():
    st = LinkAuditState(link_id=3, phase=LinkPhase.QUARANTINED, next_audit_us=5)
    commands = transition(st, AuditEvent("timer", 3, 5), CFG)
    assert st.phase is LinkPhase.AUDIT
    assert commands[0].contract.max_packets == 512


def test_scheduler_prefers_earliest_deadline_then_capacity_then_id():
    states = [
        LinkAuditState(8, LinkPhase.QUARANTINED, next_audit_us=10),
        LinkAuditState(4, LinkPhase.QUARANTINED, next_audit_us=5),
    ]
    assert choose_link(states, now_us=20, capacity_weight={4: 1, 8: 2}).link_id == 4
```

- [ ] **Step 2: Confirm failure**

Run: `pytest -q controller/tests/test_audit_policy.py`

Expected: FAIL because `controller.audit_policy` does not exist.

- [ ] **Step 3: Implement only the five-state transition table**

The implementation must:

```text
healthy + suspect           -> suspect
suspect + confirm_fault     -> quarantined + remove_from_routing
quarantined + due timer     -> audit + start_audit(contract)
audit + healthy evidence    -> probation + add_probation_route
audit + faulty/timeout      -> quarantined
probation + lease complete  -> healthy + add_full_route
probation + relapse         -> quarantined + remove_from_routing
```

Generate `audit_id` monotonically from policy state; never reuse an active id. Ignore stale observations whose `audit_id` does not match `state.active_audit_id`.
`add_probation_route` must carry `config.probation_fraction_ppm`; validate it in `[1, 1_000_000]`
and charge every production packet admitted during probation to the exposed-packet metric.

- [ ] **Step 4: Run policy and existing controller tests**

Run: `pytest -q controller/tests/test_audit_policy.py controller/tests`

Expected: all tests PASS.

- [ ] **Step 5: Commit the lifecycle policy**

```bash
git add controller/audit_policy.py controller/tests/test_audit_policy.py
git commit -m "feat: add quarantine audit lifecycle policy"
```

---

### Task 4: Build the event-level audit simulator

**Files:**
- Create: `sim/audit/__init__.py`
- Create: `sim/audit/model.py`
- Create: `sim/audit/run.py`
- Create: `sim/audit/tests/test_model.py`

**Interfaces:**
- Consumes: `controller.audit_policy` and Task 2 records.
- Produces: `FaultInterval`, `Scenario`, `RunMetrics`, `run_scenario(scenario, policy, seed)` and one JSON record per run.

- [ ] **Step 1: Write deterministic scenario tests**

```python
from sim.audit.model import FaultInterval, Scenario, run_scenario


def test_quarantine_removes_passive_evidence_until_audit():
    scenario = Scenario(
        duration_us=1_000_000,
        production_pps=100_000,
        fault=[FaultInterval(100_000, 600_000, 0.01)],
        recovery_us=600_000,
    )
    result = run_scenario(scenario, policy_name="earliest_deadline", seed=9)
    assert result.passive_packets_while_quarantined == 0
    assert result.audit_packets > 0
    assert result.certified_restore_us >= 600_000


def test_same_seed_replays_byte_identical_record():
    scenario = Scenario.blackhole_then_recover(recovery_us=300_000)
    assert run_scenario(scenario, "earliest_deadline", 17).to_json() == \
           run_scenario(scenario, "earliest_deadline", 17).to_json()
```

- [ ] **Step 2: Confirm failure**

Run: `pytest -q sim/audit/tests/test_model.py`

Expected: FAIL because `sim.audit.model` does not exist.

- [ ] **Step 3: Implement an explicit discrete-event loop**

The simulator clock advances to the next production packet, fault transition, policy timer, audit packet, or audit deadline. Use `random.Random(seed)` only; serialize the realized fault intervals and every policy command. Production traffic becomes zero on a quarantined link. Audit traffic is the only observation source until probation.

- [ ] **Step 4: Add CLI output with stable provenance**

Run:

```bash
python3 -m sim.audit.run --policy earliest_deadline --seed 17 \
  --fault-p 0.001 --fault-start-us 100000 --recovery-us 600000
```

Expected JSON keys:

```text
seed, policy, realized_faults, quarantine_us, certified_restore_us,
unsafe_restores, false_quarantines, audit_packets, audit_bytes,
bad_production_packets, inconclusive_audits, stranded_capacity_gbps_s
```

- [ ] **Step 5: Run simulator and controller tests**

Run: `pytest -q sim/audit/tests controller/tests`

Expected: PASS.

- [ ] **Step 6: Commit the simulator**

```bash
git add sim/audit controller
git commit -m "sim: model self-hiding gray-failure lifecycle"
```

---

### Task 5: Add matched baselines, metrics, and preregistration amendment

**Files:**
- Create: `sim/audit/baselines.py`
- Create: `sim/audit/analyze.py`
- Create: `sim/audit/tests/test_baselines.py`
- Modify: `paper/PREREG.md`
- Modify: `docs/review/PLAN.md`

**Interfaces:**
- Consumes: Task 4 scenario and metrics API.
- Produces: policies `permanent_quarantine`, `fixed_timer`, `continuous_probe`, `round_robin`, `earliest_deadline`, and `oracle`; paired CSV/JSON summaries; preregistered lifecycle hypotheses.

- [ ] **Step 1: Write cost-matching regression tests**

```python
from sim.audit.baselines import make_policy
from sim.audit.model import Scenario, run_scenario


def test_equal_budget_policies_never_exceed_declared_packets():
    scenario = Scenario.blackhole_then_recover(recovery_us=300_000)
    for name in ("fixed_timer", "round_robin", "earliest_deadline"):
        result = run_scenario(
            scenario, make_policy(name, audit_packet_budget=4096), seed=1
        )
        assert result.audit_packets <= 4096


def test_oracle_never_restores_before_recovery():
    scenario = Scenario.blackhole_then_recover(recovery_us=300_000)
    result = run_scenario(scenario, make_policy("oracle", 4096), seed=1)
    assert result.certified_restore_us == 300_000
```

- [ ] **Step 2: Implement the six policies without sharing hidden state**

Each policy receives only the same public events except `oracle`, which receives the realized recovery time and is always labelled as an unattainable bound.

- [ ] **Step 3: Add paired analysis**

`sim/audit/analyze.py` must report medians and bootstrap intervals for:

```text
time_to_certified_restore_us
stranded_capacity_gbps_s
unsafe_restores
bad_production_packets
audit_bytes
inconclusive_audits
```

It must print the count and identities of seeds where an arm violates the unsafe-restoration bound.

- [ ] **Step 4: Amend PREREG with non-overlapping hypothesis ids**

Open a visibly separate `CF-H*` family so these confirmatory hypotheses cannot be confused with
the retired paper H1–H9 or with `HURDLES` ids:

```text
CF-H1: passive post-quarantine evidence is zero by construction and audit restores identifiability.
CF-H2: at equal audit bytes and the fixed unsafe-restoration bound, evidence leases reduce median healthy-capacity-time stranded by the preregistered material margin versus fixed timer and round robin under concurrent recoveries.
CF-H3: the switch-enforced audit cap is never exceeded under controller over-send, timeout, stale id, or concurrent audit attempts.
```

- [ ] **Step 5: Compute the evidence floor, then run tests and a 30-seed pilot**

Before any pilot-derived threshold, tabulate the zero-background-loss sanity floor
`ceil(log(alpha_restore) / log(1 - p_faulty))`. For every general
`p_healthy > 0, p_faulty > p_healthy` pair, tabulate the exact binomial or published sequential-test
boundary instead of reusing the zero-loss formula. Include the
`p_healthy=0, p_faulty=1e-4, alpha_restore=0.05` case (approximately 30,000 zero-loss packets). A
contract below the required evidence returns `INCONCLUSIVE`; tests must reject any policy that
converts it to `HEALTHY`.

Derive only the material margin and seed count from a labelled pilot; freeze them in the amendment
before running the confirmatory block.

Run:

```bash
pytest -q sim/audit/tests controller/tests
python3 -m sim.audit.run --matrix pilot --seeds 30 --out sim/audit/pilot.jsonl
python3 -m sim.audit.analyze sim/audit/pilot.jsonl
```

Expected: all tests PASS; every non-oracle arm reports exact audit bytes, unsafe-restoration count,
and `INCONCLUSIVE` count. The pilot includes single-link cases and concurrent recovery bursts over
2, 8, and 25% of links.

- [ ] **Step 6: Commit baselines and frozen amendment**

```bash
git add sim/audit paper/PREREG.md docs/review/PLAN.md
git commit -m "eval: preregister counterfactual audit lifecycle"
```

---

### Task 6: Complete W4 semantic validation before extending the data plane

**Files:**
- Modify: `p4/ptf/test_fabric.py`
- Create: `p4/ptf/test_witness.py`
- Create: `p4/ptf/run_model_test.sh`
- Modify: `p4/witness/COMPILE-GATE.md`

**Interfaces:**
- Consumes: `p4/witness/mcp_fabric_w4_egdrop.p4` and its BFRT tables.
- Produces: verified W4 initialization, resynchronization, wrap, duplicate, reorder, consecutive-loss, multi-queue, stale-header, and explicit-link-id behavior.

- [ ] **Step 1: Add PTF cases with exact expected gap counts**

Required cases:

```text
contiguous 0,1,2,3              -> 0 gap events
0,1,3,4                         -> 1 gap event, gap magnitude 1
65534,65535,0,1                 -> 0 gap events
0,1,1,2                         -> duplicate classified separately, not link loss
0,2,1,3                         -> reorder result matches the declared ordering contract
0,4                             -> 1 event representing three consecutive losses
same ingress port, link ids 0/1 -> independent expected-sequence state
two traffic classes on link 0   -> behavior matches declared per-link ordering scope
```

- [ ] **Step 2: Run PTF against the software/model target**

Create one checked-in runner so model validation is repeatable and does not depend on copying
artifacts into `$SDE_INSTALL`. Its public invocation is:

```bash
./p4/ptf/run_model_test.sh \
  --source p4/witness/mcp_fabric_w4_egdrop.p4 \
  --test p4/ptf/test_witness.py
```

The runner must:

1. use `/home/philip/bf-sde-9.13.1` unless `SDE` is already set;
2. compile to a temporary directory and rewrite the generated `.conf` paths to absolute paths;
3. preflight the four veth ports and fail with the exact one-time setup command below if absent;
4. launch `run_tofino_model.sh`, launch `bf_switchd` with that absolute config, wait for BFRT,
   invoke `run_p4_tests.sh` with only the named test, and preserve all three logs;
5. install a trap that stops only the processes it started and returns the PTF exit code.

One-time workstation setup:

```bash
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL="$SDE/install"
sudo "$SDE_INSTALL/bin/veth_setup.sh"
```

If this SDE revision cannot select one file directly, the runner must copy only the named test into
its temporary test directory and pass that directory with `-t`; do not silently run the whole stale
skeleton.
Expected: the new duplicate/reorder cases initially FAIL until the contract is implemented or
explicitly narrowed. A model pass is necessary but not sufficient for the ASIC.

- [ ] **Step 3: Make the smallest W4 correction needed for the declared contract**

Regenerate variants through `p4/witness/gen_variants.py`; never patch only the generated W4 file. If multi-queue ordering cannot be guaranteed, key sequence state by `(link_id, traffic_class)` and price the state increase; otherwise exclude unsupported reordering from the loss claim and record the false-gap behavior.

- [ ] **Step 4: Recompile W4 and rerun PTF**

Expected: bf-p4c returns 0 with no new warnings; all declared W4 cases PASS; `COMPILE-GATE.md` records any resource delta.

- [ ] **Step 5: Commit semantic closure**

```bash
git add p4/witness p4/ptf
git commit -m "test: close W4 witness semantics"
```

---

### Task 7: Implement the switch-enforced audit cap

**Files:**
- Create: `p4/audit/gen_variant.py`
- Create: `p4/audit/build.sh`
- Create: `p4/audit/extract.py`
- Create: `p4/audit/mcp_fabric_w4_audit.p4`
- Create: `p4/ptf/test_audit.py`
- Create: `p4/audit/COMPILE-GATE.md`

**Interfaces:**
- Consumes: the semantically closed W4 source.
- Produces BFRT objects `reg_audit_id`, `reg_audit_tokens`, `audit_accept_ctr`, `audit_reject_ctr`, and `tbl_audit_target`.

- [ ] **Step 1: Write PTF behavior before P4 implementation**

```text
install audit_id=9, link_id=4, tokens=3
send ids [9,9,9,9] targeted to link 4
expect exactly 3 forwarded, 1 rejected, tokens=0
send stale id 8
expect rejected and tokens remain 0
install audit_id=10, tokens=2 while id 9 packets are in flight
expect only id 10 may consume the new tokens
attempt target link 5
expect rejection before forwarding
```

- [ ] **Step 2: Confirm PTF failure against W4 without audit tables**

Expected: BFRT lookup for `reg_audit_tokens` fails.

- [ ] **Step 3: Generate one auditable variant without duplicating W4**

W4 already supplies the explicit 16-bit `link_id` and 16-bit sequence. Reuse them. First compile
the zero-new-byte encoding:

```text
fabric.flags bit 3 = audit marker
csig.epoch         = audit_id, only when the audit marker is set
witness.link_id    = directed target and token-register index
witness.seq        = delivery/loss evidence
```

For non-audit traffic, `csig.epoch` retains its existing meaning. If a compiler constraint or a
semantic collision prevents safe reuse, add only this 2-byte fallback:

```p4
header audit_id_h {
    bit<16> audit_id;
}
```

Do not add another `link_id` or sequence. Store the cap in `reg_audit_tokens[link_id]`, not in the
packet. The stateful action accepts only the active `audit_id` and decrements exactly once for each
accepted packet. Use fixed packet size per contract so the byte cap is
`tokens * packet_size`.

- [ ] **Step 4: Compile and record the full resource delta**

Use the same bf-p4c 9.13.2 evidence path as `p4/witness/COMPILE-GATE.md`. Compile both the preferred
reuse encoding and the 2-byte fallback if the preferred form fails. Record placed/source stages,
SRAM, TCAM, SALUs, PHV, parser states, header bytes, and BFRT object names; select the least-overhead
form that passes semantics.

- [ ] **Step 5: Run hostile PTF cases**

Run normal cap, controller over-send, stale id, wrong link, reset, wrap, and two concurrent link audits.

Expected: accepted packets never exceed installed tokens; no stale or wrong-link packet consumes a token.

- [ ] **Step 6: Commit the audit primitive**

```bash
git add p4/audit p4/ptf/test_audit.py
git commit -m "feat: enforce bounded directed-link audits in Tofino"
```

---

### Task 8: Add the thin BFRT audit adapter and controller loop

**Files:**
- Create: `p4/control/setup_audit.py`
- Create: `controller/audit_loop.py`
- Create: `controller/tests/test_audit_loop.py`
- Modify: `controller/hw_adapter.py`

**Interfaces:**
- Consumes: Task 3 `AuditCommand` and Task 7 BFRT objects.
- Produces: `AuditHardware.install(contract)`, `AuditHardware.read(contract)`, `AuditHardware.clear(link_id)`, and `AuditLoop.step(now_us)`.

- [ ] **Step 1: Write adapter tests with a fake BFRT table map**

```python
def test_install_writes_id_before_tokens(fake_hw, contract):
    fake_hw.install(contract)
    assert fake_hw.calls == [
        ("reg_audit_tokens", contract.link_id, 0),
        ("reg_audit_id", contract.link_id, contract.audit_id),
        ("tbl_audit_target", contract.link_id, contract.link_id),
        ("reg_audit_tokens", contract.link_id, contract.max_packets),
    ]


def test_timeout_never_becomes_healthy(fake_loop):
    fake_loop.start_audit(link_id=4, now_us=0)
    fake_loop.step(now_us=100_000)
    assert fake_loop.state[4].phase.value == "quarantined"
```

- [ ] **Step 2: Confirm failure**

Run: `pytest -q controller/tests/test_audit_loop.py`

Expected: FAIL because `controller.audit_loop` does not exist.

- [ ] **Step 3: Implement safe write ordering and idempotent reads**

Token installation must follow the order in the test so packets from a prior audit cannot consume a new budget. `read()` returns sent, accepted, rejected, gap count, and timeout status; it never mutates policy state.

- [ ] **Step 4: Run all controller tests**

Run: `pytest -q controller/tests`

Expected: PASS.

- [ ] **Step 5: Commit the adapter**

```bash
git add controller p4/control/setup_audit.py
git commit -m "feat: orchestrate bounded link audits"
```

---

### Task 9: Add recovery and audit traffic to htsim

**Files:**
- Modify: the fault-schedule implementation under `sim/htsim`
- Create: `sim/audit/run_htsim.sh`
- Create: `sim/audit/tests/test_htsim_schedule.py`
- Create: `sim/audit/HTSIM-VALIDATION.md`

**Interfaces:**
- Consumes: a CSV fault schedule `time_us,link_id,drop_probability` and audit commands `time_us,link_id,audit_id,packets,size,traffic_class`.
- Produces: per-link production/audit tx/rx/drop counters and lifecycle events in CSV.

- [ ] **Step 1: Write a three-transition fixture**

```text
time_us,link_id,drop_probability
100000,4,0.01
300000,4,0.0
700000,4,1.0
```

The test must assert that production and audit packets observe the scheduled probability in the corresponding intervals and that the realized schedule is printed in the run manifest.

- [ ] **Step 2: Add time-varying Bernoulli loss without adding new fault classes**

Reuse the existing F1 drop path. At each scheduled timestamp update only the selected link's probability. Tag audit traffic separately in counters; do not give the detector simulator ground truth.

- [ ] **Step 3: Add explicit bounded audit trains**

An audit command injects exactly `packets` packets at the upstream endpoint and routes them through `link_id`; the simulator rejects a command if exact link steering is impossible in the selected topology.

- [ ] **Step 4: Cross-validate at the hardware topology**

Run identical W4/audit scenarios in the event simulator and htsim on the 4-leaf x 2-spine topology. Record packet counts, decisions, and any timing-model differences in `HTSIM-VALIDATION.md`.

- [ ] **Step 5: Run targeted htsim tests**

Run one healthy, partial-loss, recovery, blackhole, and relapse scenario.

Expected: exact commanded audit counts; no passive production packets during quarantine; stable realized schedules across repeated seeds.

- [ ] **Step 6: Commit htsim lifecycle support**

```bash
git add sim/htsim sim/audit
git commit -m "sim: add link recovery and bounded audit traffic"
```

---

### Task 10: Run silicon lifecycle tests and the confirmatory evaluation

**Files:**
- Create: `p4/reports/counterfactual-audit-silicon.md`
- Create: `sim/audit/run_confirmatory.sh`
- Create: `sim/audit/RESULTS.md`
- Modify: `docs/review/PLAN.md`
- Modify: `.omx/plans/high-novelty-telemetry-plan.md`
- Modify: `paper/PREREG.md`

**Interfaces:**
- Consumes: Tasks 1-9.
- Produces: hardware functional evidence, a paired confirmatory dataset, a Pareto figure input table, and a pass/fail publication verdict.

- [ ] **Step 1: Run silicon safety cases before performance cases**

Verify on the virtual fabric:

```text
exact directed-link steering
token cap under 2x controller over-send
stale audit id rejection
partial loss, tail loss, and blackhole timeout
quarantine -> audit -> probation -> healthy
probation relapse -> quarantine
two simultaneous audits on distinct links
```

Record raw BFRT reads, packet captures, compiler hashes, topology limits, and switch configuration in `counterfactual-audit-silicon.md`.

- [ ] **Step 2: Freeze the confirmatory matrix before execution**

Use the seed count from Task 5 power analysis and the spec's fault/workload matrix. Hash the configuration, policy code, simulator binary, and input traces into the run manifest.

- [ ] **Step 3: Execute matched baselines**

Run permanent quarantine, fixed timer, continuous probing, round robin, earliest deadline, SprayCheck/W4 plus timer, and oracle. Charge all audit duplicates and liveness packets to `beta_probe`; report W4/audit headers in `beta_tag`.

- [ ] **Step 4: Analyze without changing thresholds**

Produce paired estimates and confidence intervals for restoration delay, stranded capacity-time,
unsafe restorations, bad packets exposed, audit bytes, `INCONCLUSIVE` audit count/duration, and
collective completion time. A result that violates the unsafe-restoration or probe cap cannot win
on restoration time.

- [ ] **Step 5: Apply the publication gate verbatim**

```text
INTEGRATED SYSTEMS PAPER: prior-art, feasibility, safety, and frontier gates all pass.
NEGATIVE-RESULT ARTIFACT: integrated gate fails, but the replay/decomposition artifact remains independently complete.
STOP: neither contribution is independently defensible.
```

- [ ] **Step 6: Run full verification**

```bash
pytest -q controller/tests sim/audit/tests
python3 -m compileall -q controller sim/audit
git diff --check
```

Run the PTF and bf-p4c commands recorded in the two compile-gate reports. Expected: all tests pass, compiler exits 0, and `git diff --check` emits no output.

- [ ] **Step 7: Commit results and gate outcome**

```bash
git add p4/reports sim/audit docs/review/PLAN.md \
  .omx/plans/high-novelty-telemetry-plan.md paper/PREREG.md
git commit -m "eval: close counterfactual observability publication gate"
```

---

## Execution order and review gates

- Task 1 blocks lifecycle Tasks 2-5 and 7-10. A `FAIL` verdict stops that branch; Task 6 may still
  close the already-started W4 infrastructure attempt.
- Tasks 2-5 form the simulation/research gate and must finish before Task 7.
- Task 6 closes the already-open W4 prerequisite and may run in parallel with Task 1.
- Task 7 is the hardware feasibility gate; Task 8 follows only after its resource and PTF results pass.
- Task 9 begins after the event simulator freezes the scenario semantics.
- Task 10 is confirmatory; no threshold, seed, baseline, or metric changes are permitted after it starts without a dated preregistration amendment and a complete rerun.
