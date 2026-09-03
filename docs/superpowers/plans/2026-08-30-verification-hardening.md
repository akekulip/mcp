# 2026-08-30 Verification Hardening Plan

## Goal and evidence boundary

Verify and harden the implementation described by `WORKING_NOTES.md` without changing the
approved architecture in
`docs/superpowers/specs/2026-08-28-counterfactual-observability-design.md`. The deliverable is a
reproducible, fail-closed local implementation whose claims are supported by fresh tests, Tofino
compiles, and software-model PTF results. Physical-switch experiments and selection of a new
STARVED policy threshold remain outside this local pass.

The starting tree is intentionally dirty. Existing user changes are inputs, not disposable
scratch work. Edits stay limited to the files named below and must not reset or overwrite
unrelated modifications.

## Task 1 — Make gate control schema-aware and fail closed

Files:

- `p4/hw/loop/gate_agent_core.py`
- `p4/hw/loop/gate_agent.py`
- `p4/hw/loop/test_gate_agent_core.py`
- `p4/hw/loop/injector_ranges.py`
- `p4/hw/loop/test_injector_ranges.py`

Tests first:

1. Fake BFRT rows prove an `act_enter` rewrite preserves every existing action argument, changes
   only requested fields, and returns the exact modified-row count.
2. Missing `bank`/`epoch`, zero matching rows, malformed action data, and any `entry_mod` failure
   raise an error; no exception is swallowed.
3. Protocol-level helpers reject malformed arity/ranges before any BFRT mutation.
4. A clean-checkout-style import smoke proves all modules imported by `gate_agent.py` are tracked.

Implementation:

- Move the SDK-independent row-rewrite and validation contract into `gate_agent_core.py`.
- Keep the live socket/BFRT owner in `gate_agent.py`, but route `N <bank>` and new `E <epoch>`
  commands through the tested helper.
- Require all expected source `act_enter` rows to update. Return `ERR`, never `OK 0`, on a
  schema mismatch or partial write.
- Retain and verify the existing strict injector-range helpers; include both imported helper
  modules and their tests in the reproducible change set.

## Task 2 — Preserve hardware epochs and use real arrival evidence

Files:

- `p4/hw/loop/controller_loop.py`
- `p4/hw/loop/test_controller_loop.py`
- `controller/hw_adapter.py` and `controller/tests/test_epoch_loop.py` only if an adapter contract
  assertion is required

Tests first:

1. `GateClient.set_epoch()` requires the expected modified-row count.
2. Startup stamps epoch zero; every epoch transition stamps and reads back the new 16-bit hardware
   epoch before `SublinkFeedback.begin_epoch()` accepts it.
3. Parsed `GapEvent.epoch` reaches the decision core unchanged; a prior hardware epoch is dropped
   as stale.
4. Census parsing retains both transmit sequence and ingress clean-run values.
5. Arrival deltas use only `reg_wit_observed`: monotone growth yields its delta, a decrease is a
   witnessed reset and yields the new run length, saturation never invents evidence, and transmit
   growth alone yields no arrivals.
6. Truncation, missing requested rows, duplicate rows, or malformed terminal counts fail closed.
7. A census result captured under an older epoch is discarded without updating the decision core;
   a current result is applied exactly once. A discarded result may reduce evidence but can never
   be re-labeled as current evidence.

Implementation:

- Synchronize `act_enter.epoch` through `E <epoch>`; never reconstruct a hardware event's epoch
  from local wall clock. The agent must read back every source row and acknowledge only after the
  exact requested epoch is visible on all rows.
- Keep the update synchronous at the epoch boundary so the controller cannot accept a new epoch
  before the data plane stamps it. Account for its RPC latency with existing write metrics. Bound
  one controller session to the 16-bit epoch space and fail before wrap rather than silently
  changing the ordering contract.
- Drop queued census results whose capture epoch is older than the decision core's current epoch.
  The counter delta worker may advance its private snapshot on a discarded read, making the
  evidence conservative; it must never relabel old observations with a newer epoch.
- Treat `reg_wit_observed` as a conservative arrival lower bound. It is a saturating ingress
  clean-run counter that resets on a discontinuity; its reset/saturation semantics are explicit
  and do not permit modular-wrap arithmetic.
- Keep `reg_wit_seq` only as diagnostic source-side state, never as delivered traffic.

## Task 3 — Seal and verify control-plane setup provenance

Files:

- `p4/hw/deploy.sh`
- `p4/hw/bringup.sh`
- `p4/control/setup_attention.py`
- `p4/control/tests/test_setup_attention.py`
- a focused local script-contract test if needed

Tests first:

1. Exact `tbl_eg_vlink` verification accepts the complete planned key/action/data set.
2. It rejects a missing row, stale row, wrong action, wrong `vlink`, or wrong `vlink_base`.
3. Dry-run/script assertions prove both setup scripts are shipped, hashed, and checked before
   execution without forcing an unnecessary binary reload when only a setup script changes.

Implementation:

- Ship `setup_skeleton.py` and `setup_attention.py` with the program/build inputs.
- Seal them in a separate setup manifest, leaving the compiled-build identity/load receipt scoped
  to the binary artifacts.
- Add an exact readback verifier in `setup_attention.py`; bring-up must run it after installation
  and abort on any mismatch instead of trusting a printed nonzero count.

Live shared-chip sequence, after local verification:

1. Resolve `bf_switchd` ownership and exact active config without writing anything.
2. Run deploy/bring-up dry-runs and compare the planned schema/program with the active owner.
3. Remote-compile and seal before considering a load; compile-only work must leave the active PID
   and BFRT listener unchanged.
4. Before a table/port write, re-check ownership. Reuse the existing matching owner or abort; never
   take over a foreign config implicitly.
5. After setup, verify the exact BFRT key/action/data set from hardware and record build/setup
   manifest identities beside the run.
6. After every campaign, clear only the injector/gate rows owned by that campaign, read back the
   cleanup, and leave `bf_switchd` running unless a validated build replacement is required.

## Task 4 — Make CLF controls and verdict evidence reproducible

Files:

- `p4/witness/gen_variants.py`
- a focused no-CLF generation/reproduction test under `p4/witness/`
- `p4/hw/loop/clf_trials.py`
- a new `p4/hw/loop/test_clf_trials.py`
- `sim/clf/verdict.py`
- `sim/tests/test_clf_verdict.py`
- `p4/witness/mcp_fabric_clf_eg.p4` only through its canonical generator/source path

Tests first:

1. Regeneration derives `mcp_fabric_noclf.p4` deterministically from the CLF source and asserts
   byte identity with the checked-in control.
2. A fake agent proves every trial requires a positive exact bank rewrite, verified zero, probe
   success, injector ground truth, freeze, and complete read.
3. Count rows from `X` feed `verdict_counts()` and expose STARVED separately from BLACKHOLE;
   presence-mask mode remains available only as the historical blackhole comparison.
4. Boundary tests and prose agree that the current implementation is inclusive: RX at or below
   one eighth of TX is STARVED while unsaturated.

Implementation:

- Add the smallest auditable CLF-to-no-CLF transformation/check; do not maintain another manual
  1,500-line source fork without a proof.
- Parse and classify the count frontier in the campaign driver by default.
- Validate the numeric response for every mutating agent command.
- Correct comments/docs to the implemented inclusive boundary. Do not change `STARVED_RATIO=8`
  or add unmeasured hysteresis in this pass; retain the explicit open research caveat.
- Remove the obsolete egress-receiver placement comment from the generated CLF source path.

## Task 5 — Close record and clean-checkout gaps

Files:

- `WORKING_NOTES.md`
- only directly affected review artifacts/comments

Actions:

- Remove the trailing whitespace and correct statements made false by Tasks 1–4.
- Add a clean temporary-checkout smoke that imports the agent/controller modules and runs their
  focused unit tests without relying on untracked files.
- Do not rewrite the earlier history or recast the unmeasured STARVED threshold as preregistered.

## Verification matrix

Run, read, and record all of the following after implementation:

1. Focused red/green tests for every task.
2. `python3.12 -m unittest discover` for `controller/tests`, `sim/tests`, `p4/control/tests`,
   `p4/witness`, and `p4/hw/loop`.
3. `python3.12 -m compileall -q controller sim/clf sim/sublink p4/control p4/hw/loop p4/witness`.
4. Shellcheck for all touched hardware/model scripts and `git diff --check`.
5. JSON/schema parse plus `setup_audit.py --dry-run`.
6. Fresh local Tofino 9.13.1 builds of CLF, no-CLF, and gate-event; compare the CLF/no-CLF
   resource delta with the recorded table.
7. `run_gap_event.sh` and `run_context_regressions.sh`; confirm model/switchd processes are gone.
8. Quick dynamic sweep and CLF feedback smoke.
9. Clean temporary-checkout import, regeneration, and focused-test smoke.
10. Independent comprehensive code review followed by architect review; repair every actionable
    correctness, safety, or reproducibility finding.
11. Hostile QA scenarios: malformed commands, partial BFRT updates, missing schema fields, stale
    epochs, counter reset/saturation, truncated census, stale setup scripts, wrong table rows,
    failed probes, and incomplete frontier reads.

Completion requires every local check above to pass. Hardware-only guard-interval measurement,
silicon validation of the new controller commands, and policy selection for STARVED are reported
as explicit remaining validation, not silently inferred from model results.

## Separate Phase B gate — stronger gray/blackhole contribution

Phase B is not an implicit extension of this implementation plan. It receives its own design and
novelty review after Phase A establishes a trustworthy evidence contract.

The first design lane stays controller-side and reuses the existing paired CLF count frontier,
C-W4 gap events, and declared audit receipts. It may replace the provisional fixed STARVED ratio
with calibrated sequential evidence and use that evidence to schedule bounded audits, but it adds
no header byte, P4 witness, or wire semantic until a controller-only prototype proves a missing
capability. Stop or label the idea baseline-only if it collapses into a fixed retry timer, generic
sequence numbering, a presence-bit blackhole detector, or an existing telemetry-zoom mechanism.

Required comparisons and ablations are fixed before Phase B implementation:

- count frontier vs historical presence frontier;
- paired frontier alone vs frontier plus C-W4 gaps vs frontier plus gaps and declared receipts;
- with and without stale-epoch rejection;
- calibrated sequential policy vs quarantine-only, fixed retry, and deterministic
  earliest-deadline audit scheduling;
- selective blackhole, all-context blackhole, near-total and low-rate gray loss, congestion without
  link loss, idle demand, reordering, epoch races, flapping, repair, and controller restart.

Report detection delay with censoring, false actions/restorations, INCONCLUSIVE rate, audit packets
and bytes, controller events, BFRT writes, and switch resources. Novelty claims are limited to the
systems composition and its measured evidence/action cost unless primary prior-art review supports
something narrower and stronger.
