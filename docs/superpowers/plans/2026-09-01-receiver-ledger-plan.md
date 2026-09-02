# Receiver-ledger P4 redesign — implementation plan

**Status:** approved by Philip 2026-09-01. Design source: `docs/review/BRAINSTORM-2026-09-01.md`
§2 (C1), §5 (build order steps 1-3), §9 (red team, esp. finding 4 on the reorder-credit window).
Compile feasibility already validated locally by the p4-dataplane-engineer agent in scratchpad
compiles `s1.p4` (32-bit widening, free) and `s7.p4` (ledger + Bernoulli injector, 11 ingress /
5 egress, fewer resources than the current program). This plan formalizes that work as a real
repo artifact, adds tests, and does not touch the switch.

## Goal

Replace the CLF epoch/bank/guard scheme in the current witness program with a receiver-side
ledger: an advance-only highest-sequence register (`hi`) and a widened arrivals register (`lo`)
per sublink, so loss over any interval is exactly `Δhi − Δlo`, readable with no wall-clock guard —
only a measured reorder-credit window (red team finding 4: the loopback fabric can reorder within
a nominal sublink per HURDLES H33, so "exact at any instant" must be qualified). Add a
per-sublink Bernoulli fault injector so silicon gray loss can be stochastic, matching the
simulator. Widen the TX frontier to 32 bits (free per the RAM-quantization finding — do this
first, it de-risks everything else).

## Non-goals for this pass

Controller/ledger statistics changes from the brainstorm (data-driven floor, e-BH, continuous
mitigation weight) are NOT in scope here — this pass is the data-plane mechanism only. Deploying
to the switch is NOT in scope — the chip's current owner is unknown until checked, and no port or
table write on shared hardware happens without that check (CLAUDE.md). Deleting the ingress
attention/gate control loop (brainstorm §5 step 3) is a separate, smaller follow-up.

## Tasks

1. **Widen the TX frontier to 32 bits.** Copy `p4/witness/mcp_fabric_clf_eg.p4` to
   `p4/witness/mcp_fabric_ledger.p4`. Change `reg_tx_frontier` and its RegisterAction to
   `bit<32>`, widen the associated metadata field. Compile locally (bf-p4c 9.13.1, laptop SDE).
   Acceptance: exit 0, stage/table/SRAM counts match `base` (per the `s1` finding — this should be
   a no-op on cost).
2. **Build the receiver ledger.** Make `reg_wit_expect` advance-only (the
   `mcp_fabric_gate_event_advonly.p4` SALU pattern: `rv = v - hdr.witness.seq; if
   ((int<16>)(v - hdr.witness.seq) <= 0) { v = hdr.witness.seq + 1; }`) and widen
   `reg_wit_observed` to `bit<32>` with its reset removed. Delete `reg_rx_frontier` and the bank-OR
   logic entirely (no bank dimension is needed once there is no epoch). Acceptance: compiles at
   11 ingress / 5 egress or better (the `s7` scratchpad result was 11/5, 40 tables, 89 SRAM,
   27 mapRAM, 15 TCAM, 7 SALU — cheaper than `base` on every axis; match or beat it).
3. **Add the Bernoulli injector.** New table `tbl_eg_bern` alongside the existing `tbl_eg_fail`:
   `Random<bit<16>>` compared against a per-sublink programmable range, DirectCounter on both
   drop/no-drop actions so offered/dropped counts are ground truth. Keep `tbl_eg_fail` for the
   deterministic one-shot latency trials. Acceptance: compiles, DirectCounter readback matches
   the configured probability within Monte Carlo tolerance in a model/PTF test.
3a. **State the reorder-credit window.** Do not claim "exact at any instant" anywhere in code
    comments or docs for this file. The controller-side reorder-credit accounting (per the
    networks-expert report: a gap opens a debt, each later out-of-order arrival retires one unit,
    only debt outstanding after one BDP is scored as loss) is a follow-up to controller code, not
    this pass — note it explicitly as an open item in the compile-gate report so it is not
    silently implied to be solved.
4. **Compile-gate report.** Write `docs/review/artifacts/LEDGER-COMPILE-GATE.md` in the style of
   `p4/witness/COMPILE-GATE.md`: exact `base` vs `mcp_fabric_ledger.p4` stage/table/SRAM/mapRAM/
   TCAM/SALU counts, both source SHA-256 hashes, bf-p4c version and exit code. This is the
   acceptance evidence for tasks 1-3, not a separate task.
5. **Tests.** Add/update a model or unit test (wherever `p4/witness/test_gap_event_variant.py` or
   `p4/witness/test_noclf_generation.py` pattern lives) proving: (a) `Δhi − Δlo` equals injected
   loss count exactly under a controlled deterministic drop, in a software model or PTF run if the
   local tofino-model is available, otherwise a table/register logic unit test; (b) the Bernoulli
   injector's realized drop rate matches its configured probability within tolerance over N
   trials; (c) a regression test pinning that `reg_rx_frontier` and the bank fields no longer
   exist in the generated schema, so nothing silently keeps reading them.
6. **Full local suite.** Run `python3 -m pytest controller/tests p4/control/tests p4/hw p4/witness
   p4/ptf -q` (or the equivalent per-directory commands used elsewhere in the repo) and report
   exact pass/fail counts. Do not claim done without this.
7. **Code review.** `code-reviewer` agent (or `/code-review`) on the diff before reporting
   complete. Check especially: no out-of-scope files touched, no silently dropped requirement
   (the reorder-credit caveat from 3a must appear in the written report), P4 constraint classes
   from the tofino-p4 skill respected.
8. **Report, no commit.** Summarize with real evidence (compile-gate table, test counts). Do not
   commit — the user has not asked for a commit in this pass. Update `WORKING_NOTES.md` with the
   verified status.

## Verification

Every task above states its own acceptance evidence. Task 6's full suite run is the final gate
before declaring the pass complete, per the repo's delivery-gate rule (no "done" without a fresh
verification run visible in this conversation).
