# Wire-overhead reduction — dropping `wit_h.link_id`

**Date** 2026-09-02. Written in two passes on the same day: §1–4 are the local compile-gate and
model-verification pass (laptop SDE 9.13.1, `decps@10.10.54.81` not contacted at all); §5–6 are
the follow-on pass that took the same change through the real 9.13.2 compile gate on the switch
itself and then onto real silicon — see each section's own scope statement for exactly what did
and did not touch the shared chip at that point in the day.

**Motivation.** The head-to-head comparison against SprayCheck-Z and FlowPulse-theta
(`docs/review/artifacts/BASELINE-COMPARISON-2026-09-02.md`) found MCP pays a real, non-zero wire
cost the two fully-passive baselines do not: 4 bytes/packet (`wit_h { link_id, seq }`). Philip
asked whether that overhead could be cut while keeping detection performance, and specifically
whether the `link_id` field was load-bearing. It is not: the receiving hop already knows its own
ingress port, and `hdr.fabric.spray` (already on the wire for an unrelated reason) is enough to
name the same directed link `link_id` was carrying.

**Result in one line.** `wit_h` shrinks from 4 bytes to 2 (**50% less wire overhead**,
~0.28% -> ~0.14% of a 1400 B payload), the local compile is clean (0 errors, no new warnings),
and all 9 of the ledger's own PTF/model correctness tests still pass with identical values to the
pre-change run — but this is not a free change: it costs **+1 ingress MAU stage** (11 -> 12,
Tofino 1's hard ceiling — ingress now has zero stage headroom left) and a small SRAM/TCAM
increase (+2 SRAM blocks, +1 TCAM block). Egress, table-allocation warnings, and every other
resource axis are unchanged.

---

## 1. What changed

| file | SHA-256 | role |
|---|---|---|
| `p4/witness/mcp_fabric_ledger.p4` (pre-change) | `4e889bfd…2ac136f3` | **before** — byte-identical to the version `LEDGER-COMPILE-GATE.md` measured |
| `p4/witness/mcp_fabric_ledger.p4` (this pass) | `00aa7d54…19ae689b` | **after** — the only file touched |

Three changes to `mcp_fabric_ledger.p4`, nothing else in that file:

1. **`wit_h` shrinks to `{ bit<16> seq; }`.** `link_id` is dropped from the wire, the egress
   `wit_link()` action and its `tbl_wit_link` table (which stamped `hdr.witness.link_id =
   md.sublink` right after `tbl_wit_stamp`) are deleted, and the ingress parser no longer reads
   `hdr.witness.link_id` into `md.wit_link`.
2. **`md.wit_link` is reconstructed at ingress in two steps**, mirroring the *existing* two-table
   pattern the egress side already uses for the same field (`tbl_eg_vlink` + `tbl_ctx_index`
   composing `md.sublink`), because it turns out to need the same split for the same reason:
   - `tbl_wit_link_recon` (new, applied right after `tbl_port_role`): keyed on
     `(ig_intr_md.ingress_port : exact, hdr.fabric.spray : ternary)`, supplies the vlink's upper
     bits (`wit_vlink_base = vlink << 4`, low nibble 0) as action data. The sending hop picked
     `link_id`'s vlink component from its OWN `(egress_port, egress_qid)` via `tbl_eg_vlink`; the
     receiving hop's ingress port is that egress port's loopback peer, so
     `(ingress_port, spray)` names exactly the same directed vlink. Loop ports match spray
     EXACTLY; host/NIC ports fall through to the default (`0`, never read, since `md.wit_link` is
     only consumed under `hdr.witness.isValid()`).
   - `tbl_wit_ctx_index` (new, applied right after `tbl_context`): `md.wit_link[3:0] =
     md.ctx[3:0]`, composing the ctx/stratum low nibble.
   - **Why two steps and not one:** the first draft of this change folded a *constant* ctx nibble
     into `tbl_wit_link_recon`'s per-entry action data, on the assumption that ctx is fixed per
     link. It is not — `tbl_context` classifies ctx fresh, per packet, from that packet's own
     `hdr.ipv4.total_len`/`diffserv` (size bin x DSCP class), and a single link can carry many
     contexts. A constant-per-entry ctx would have silently mislabeled every packet whose real
     class differed from whatever was baked into the entry — caught before any compile or test
     run by re-reading how `tbl_context`/`tbl_health_gate` actually use `md.ctx` elsewhere in
     this same file, not by observation. The fix composes ctx as a *second*, independent step
     once `md.ctx` is live, exactly mirroring the sending side's own `set_eg_vlink` +
     `ctx_index()` split — which exists for the identical reason (two independent sources for
     one field cannot be one action).
3. **The now-dead `hdr.witness.link_id = 0` zeroing** in `act_enter` (ingress) is removed along
   with it.

### What deliberately did not change

Option 2 from the original brainstorm — moving `seq` into the confirmed-dead `hdr.fabric.vsw_id`
field to eliminate `wit_h` entirely (0 added bytes) — is **not** implemented in this pass. It
touches the fault injector's TCAM range-match key (`hdr.witness.seq : range` in `tbl_eg_fail`/
`tbl_eg_bern`) and other consuming sites, a larger and more invasive change with a different risk
profile; it is documented here as a precisely-specified, deferred follow-up, not attempted.
`controller/hw_adapter.py`'s existing `witness.link_id == mirror.vlink` cross-check has not yet
been replaced — it references a field that no longer exists on the wire and needs a bring-up-time
validation test in its place before this program goes anywhere near hardware.

---

## 2. The cost table

Source for stages/tables: `<prog>.tofino/pipe/logs/table_summary.log`, "Table allocation done"
block. Source for SRAM/TCAM: `<prog>.tofino/pipe/logs/resources.json`, summing
`mau_stages[*].rams.srams[]` / `.tcams.tcams[]` / `.map_rams.maprams[]` / `.meter_alus.meters[]`
/ `.statistic_alus.stats[]` across all 12 physical stages. `before`/`after` here compile the
identical file pair the SHA table above lists.

| | before (pristine) | after (this pass) | delta |
|---|---|---|---|
| **bf-p4c exit code** | **0** | **0** | — |
| errors / warnings | 0 / 5 | 0 / 5 | **no new warning** |
| **ingress stages placed** | **11** | **12** | **+1 (now at the 12-stage hardware ceiling)** |
| **egress stages placed** | **5** | **5** | **+0** |
| tables allocated | 40 | 41 | +1 (−1 `tbl_wit_link`, +2 `tbl_wit_link_recon`/`tbl_wit_ctx_index`) |
| SRAM blocks | 89 | 91 | +2 |
| TCAM blocks | 15 | 16 | +1 |
| map RAM blocks | 27 | 27 | +0 |
| meter ALUs | 7 | 7 | +0 |
| stat ALUs | 5 | 5 | +0 |
| wire bytes (`wit_h`) | 4 | **2** | **−2 (−50%)** |
| added load at 1400 B payload | ~0.28% | **~0.14%** | **−0.14 pts** |

The stage cost is a direct, disclosed consequence of a design choice made before compiling: rather
than widen the key of the existing multi-purpose `tbl_port_role` table (which also carries
unrelated role/audit-provenance logic consumed elsewhere), this pass adds two new, narrowly-scoped
tables. That traded a small risk of destabilizing `tbl_port_role`'s existing behavior for a
disclosed stage cost — which turned out to be real (+1), not merely possible, and it now consumes
the one ingress stage of headroom the receiver ledger previously had (`LEDGER-COMPILE-GATE.md`:
11 of 12 ingress stages used). **Any future ingress-side addition to this program will not fit
without either removing a stage elsewhere or revisiting this trade** — e.g. merging
`tbl_wit_link_recon`'s key into `tbl_port_role` directly, which was avoided here for risk reasons
but remains available if the stage is needed back.

---

## 3. Correctness: PTF model run against the compiled program

`p4/ptf/model/run_ledger.sh` recompiles `mcp_fabric_ledger.p4` from the current source and runs
`p4/ptf/test_ledger.py` against the laptop's local `tofino-model` (SDE 9.13.1) — the same suite and
harness `PTF-MODEL.md` used to validate the pre-change program. **All 9 asserted tests still
pass, exit code 0**, with values identical to the pre-change run recorded in `PTF-MODEL.md`:

| # | Semantics | Before → After |
|---|---|---|
| 60 | core estimator: `Δhi−Δlo` recovers 5 injected losses of 40 exactly | PASS → **PASS** (hi=40, lo=35, est=5) |
| 61 | trailing loss invisible until the next survivor | PASS → **PASS** (est=2 after the survivor) |
| 62 | 32-bit TX frontier exact past 255/256 | PASS → **PASS** (tx=300, seq=300) |
| 63 | reorder manufactures no phantom loss (H33) | PASS → **PASS** (frontier=[1,2,4,4,5], gaps match) |
| 64 | duplicate drives the estimate to −1 | PASS → **PASS** (hi=3, lo=4, est=−1) |
| 65 | Bernoulli realised rate within 4σ of configured p | PASS → **PASS** (p_hat=0.266 vs p=0.25, band 0.061) |
| 66 | Bernoulli full-range endpoints are all-or-nothing | PASS → **PASS** |
| 67 | one-shot injector still drops exactly one packet beside the stochastic arm | PASS → **PASS** (hi=6, lo=5, est=1) |
| 68 | model's own `Random<bit<16>>` is uniform, ranges tile fully | PASS → **PASS** (χ²=3.47 on 7 df) |

This is not a re-run of the old test file: the test fixture itself needed updating, because the
wire-format change removes a test-only affordance the old suite depended on (see §4). The
important claim is that **the underlying ledger arithmetic — `Δhi−Δlo`, the reorder/duplicate
edge cases, the injector rates — is byte-for-byte unchanged**, verified against the actual
compiled program, not just argued from the diff.

## 4. Why the test fixture needed a real update, not a find-and-replace

`p4/ptf/test_ledger.py` used to hand-craft `Wit(link_id=<arbitrary value>, seq=...)` and inject
every packet — both the "sender" and "receiver" halves of its two-pass model — through the same
physical test port (`LOOP_IN`), relying entirely on the wire's `link_id` byte to tell the two
passes' ledger accounting apart. That affordance is gone by design: `md.wit_link` is no longer a
free-form wire value, it is derived from the packet's real ingress port and spray/ctx. The test's
minimal 5-port topology collapses two hops (a real sender-side link and a real receiver-side link)
onto one physical port purely for convenience — something a real deployment never does, since a
real sender-hop and receiver-hop ingress always land on genuinely different front-panel ports.

The fix mirrors the real topology instead of fighting it: the receiver pass (`deliver()`/
`arrive()`) now injects on the model's second loop port (`LOOP_B`) rather than `LOOP_IN`, and each
test selects its target ledger sublink via `hdr.fabric.spray` (which `tbl_wit_link_recon`'s
control-plane entries map to a vlink, per port) and `hdr.ipv4.diffserv`/tos (which `tbl_context`
maps to a ctx nibble) instead of a hand-picked wire value. `LedgerBase._path()` gained the three
`tbl_wit_link_recon` entries and two `tbl_context` entries this requires. No test's *assertions*
changed — only how each test steers a packet onto the sublink it means to exercise, and the one
assertion (`Ether(f)[Wit].link_id`) that checked a field which no longer exists on the wire, which
is deleted rather than weakened.

## 5. Closed since first written

- **`controller/hw_adapter.py`'s stale `witness.link_id == mirror.vlink` cross-check is removed**,
  not silently deleted: `_WITNESS` shrank to `struct.Struct("!H")` (seq only), `parse_copy`/
  `build_copy` updated to match, and the removed check is replaced by an explanatory comment
  recording why no per-packet cross-check is possible any more (mirror_h.vlink is now the only
  surviving source of sublink identity in an event copy) and where the equivalent validation now
  lives (bring-up, against the installed `tbl_wit_link_recon` entries, not per-packet). Two latent
  test gaps this surfaced, both fixed rather than papered over: `test_bench_feedback_path.py`
  pinned the old 106-byte mirror-copy size (now 104, matching the 2-byte wire saving exactly), and
  `test_epoch_loop.py`'s "missing witness" test was actually passing via the now-removed mismatch
  check firing on unrelated zeroed filler bytes, not via real truncation detection — fixed by
  making the test build a genuinely truncated copy (`payload_len=0`) instead.
- **`p4/control/setup_attention.py` gained a real, topology-driven `plan_wit_link_recon()` /
  `install_wit_link_recon()`**, mirroring `plan_eg_vlink()`'s exact 16-row structure with the
  ingress port swapped to the sending egress port's loopback peer (`LOOP_DN_DP[leaf]` for what
  `plan_eg_vlink()` sends from `LOOP_UP_DP[leaf]`, and vice versa) — verified programmatically
  against `plan_eg_vlink()`'s own output, not just argued by hand, and pinned by
  `p4/control/tests/test_setup_attention.py::WitLinkReconControlPlaneTest`. Gated by
  `has_wit_link_recon(program)` so `setup_attention.py --program <other>` cannot try to write a
  table that program's schema does not have. Full regression after both fixes: 295/295
  (controller + control-plane + P4-source-pinning tests).
- **9.13.2 compile gate, run on the switch itself** (`decps@10.10.54.81`, compile-only — no port
  or table write, no `bf_switchd` restart for this step): both the pristine baseline and the
  wire-reduction source were copied to `/home/decps/mcp_m2_gate/` and compiled with the switch's
  own `build.sh`. Numbers are **byte-for-byte identical to the 9.13.1 laptop gate above** — 0
  errors, the same 5 warnings on both sides, 11→12 ingress stages, 5→5 egress stages, 89→91 SRAM
  blocks, 15→16 TCAM blocks. No SDE-version drift for this change.

## 6. Loaded and validated on real hardware

The program was deployed, taken live, and validated against real silicon via `deploy.sh` /
`takeover.sh` / `bringup.sh`, replicating `HW-LEDGER-SMOKE-TEST.md`'s exact methodology. Zero loss
across 80 packets in 4 real DSCP-driven contexts on two independent hop directions, and exact
recovery of a known 5-packet injected loss, with no discrepancy anywhere. Full transcript, numbers,
and the one real infrastructure gap found and fixed along the way (a missing `bringup.sh` receipt
step, now closed for every future bring-up):
`docs/review/artifacts/HW-LEDGER-WIRE-REDUCTION-SMOKE-TEST.md`.

## 7. Extended soak: primary claim held, a secondary anomaly is open (PI decision recorded)

A 57-cycle soak (`p4/hw/loop/overnight_ledger_soak.py`, fixed to request explicit sublinks rather
than a bare `R` that a stray bring-up sublink can make fail outright — a real, general fix, not a
one-off) found: **the injected-loss recovery mechanism itself passed 57/57 with zero exceptions**,
but two *unmeasured, unarmed* sublinks each showed an unexplained one-packet "stamp with no
matching arrival" during clean traffic — a signature never seen once across the pre-change binary's
~3,200 historical soak cycles. MAC-level port counters ruled out a physical-layer drop; a 30-second
fully-idle window ruled out spontaneous/ambient noise. No confirmed root cause. Full finding and the
PI decision to not revert, not declare it resolved, and stop further live-hardware cycling pending
a properly-instrumented follow-up:
`docs/review/artifacts/HW-LEDGER-WIRE-REDUCTION-SOAK-ANOMALY-2026-09-02.md`.

## What is still open

- Option 2 (§1) — eliminating `wit_h` entirely by moving `seq` into `hdr.fabric.vsw_id` — remains
  a separately-specified, unimplemented follow-up; out of scope for this pass.
- The §7 soak anomaly: no root cause yet. A matched-conditions short soak against the
  **pre-wire-reduction** binary (same script, same timing) would give a fresh comparison baseline
  rather than relying on older historical logs from a possibly-different testbed background state.
