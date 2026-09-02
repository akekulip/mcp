# Receiver-ledger compile gate — `mcp_fabric_ledger.p4`

**Date** 2026-09-01 · **Compiler** `bf-p4c` p4c **9.13.1** (SHA `e558d01`), the LAPTOP SDE at
`/home/philip/bf-sde-9.13.1/install`. **Every number in this file is a 9.13.1 number.** The
switch's 9.13.2 was not used and was not contacted.

**Scope.** Local compile only. `decps@10.10.54.81` was not reached in any way this session: no
`ssh`, no `scp`, no port write, no table write, no `bf_switchd` restart, no chip-ownership check
(none was needed, because nothing went near the chip). The 9.13.2 numbers that belong in the
switch's own gate are therefore **not** in this file, and the counts below must be re-measured on
9.13.2 before anything is loaded.

**Result in one line.** The receiver ledger replaces the CLF epoch/bank/guard scheme at **no MAU
stage cost in either gress** — 11 ingress / 5 egress, the same as the program it replaces, even with
a Bernoulli fault injector added on top — and is cheaper on tables (−2), SRAM (−3 blocks), stateful
ALUs (−1) and PHV containers (−2).

---

## 1. What was built

| file | SHA-256 | role |
|---|---|---|
| `p4/witness/mcp_fabric_clf_eg.p4` | `9010a44d1935853db133e3af21cc0fa0e810b25e52d57d1c257ef9cddcba77c0` | **base** — unchanged by this pass, the reference point |
| `p4/witness/mcp_fabric_ledger.p4` | `4e889bfdb9630aeb339e05ce5f97b344d35744b073dbfc847513462e2ac136f3` | **new** — the receiver ledger |

`mcp_fabric_ledger.p4` is a copy of the base with three changes and nothing else. Each was compiled
on its own so the cost of each is attributable, which is the whole reason the intermediate steps are
reported below rather than only the endpoint.

1. **TX frontier widened.** `reg_tx_frontier` 512 × `bit<8>` → 2048 × `bit<32>`, with its
   `RegisterAction` and `eg_md_t.clf_tx_prev` widened to match.
2. **The receiver ledger.** `reg_wit_expect` becomes an **advance-only** highest-sequence frontier
   (`hi`); `reg_wit_observed` becomes a never-reset 32-bit arrivals counter (`lo`); the CLF receiver
   half (`reg_rx_frontier`, `rx_seen`, `rx_frontier_mark`, `tbl_rx_frontier`, `ig_md_t.clf_idx`,
   `ig_md_t.clf_rx_prev`) is deleted, and so is the bank-parity index arithmetic on **both** sides
   (`md.clf_idx |= 0x100` in ingress, `md.clf_tx_idx |= 0x100` in egress).
3. **`tbl_eg_bern`**, a per-sublink Bernoulli fault injector with its own `Random<bit<16>>` and a
   `DirectCounter` on both the drop and the no-drop action, alongside the existing deterministic
   one-shot `tbl_eg_fail`.

### What deliberately did NOT change

`hdr.fabric.clf_bank` is still on the wire and `act_enter` still takes its `bank` action-data
parameter. Nothing in the program reads either any more. They stay because removing them changes
the 12-byte shim layout **and** an action signature the control plane writes against:
`p4/control/setup_skeleton.py:1041` proposes `Ingress.act_enter{epoch, bank}` as optional action
args, and `p4/hw/loop/clf_trials.py:126` `set_bank()` actively flips the parity across
`act_enter` rows. Changing the signature is a control-plane change and out of this pass's scope, so
the wire format and every existing control-plane entry for this program are unchanged. A follow-up
that retires `set_bank()` can reclaim the byte; the bank flip is now a no-op for measurement, which
is worth knowing before someone debugs why flipping it changes nothing.

The CSIG egress telemetry (`worst_qdepth` carriage, `tbl_csig_diff` / `tbl_csig_replace_a/b`) and
the ingress attention/gate loop (`tbl_exceed_*`, `tbl_attn`, `tbl_gate`) are both untouched. Per
red-team finding 8 (`docs/review/BRAINSTORM-2026-09-01.md` §9), CSIG telemetry must be kept, and
deleting the attention loop is a separate, smaller follow-up — not this pass.

---

## 2. The cost table

Source for stages/tables: `<prog>.tofino/pipe/logs/table_summary.log`, last "Table allocation done"
block. Source for memory/ALUs: `<prog>.tofino/pipe/logs/resources.json` → `resources.mau.mau_stages[*]`,
summing `rams.srams[]`, `map_rams.maprams[]`, `tcams.tcams[]`, `meter_alus.meters[]`,
`statistic_alus.stats[]`, each attributed to a gress via `pipe/context.json`. Archived as
`p4/witness/artifacts/mcp_fabric_{clf_eg,ledger}.{metrics.json,resources.json,table_summary.txt,build.txt}`.
The two raw compiler outputs carry a `.txt` extension rather than their native `.log`, because the
repo's root `.gitignore:8` is `*.log` and would have kept the stated source of the headline stage
and table counts out of the commit. Renaming was preferred over editing `.gitignore`, which is
outside this pass's file scope.

### 2.1 Base vs. the shipped ledger

| | base (`clf_eg`) | ledger | delta |
|---|---|---|---|
| **bf-p4c exit code** | **0** | **0** | — |
| errors / warnings | 0 / 5 | 0 / 5 | no new warning |
| **ingress stages placed** | **11** | **11** | **+0** |
| **egress stages placed** | **5** | **5** | **+0** |
| critical path length | 11 | 11 | +0 |
| **tables allocated** | **42** | **40** | **−2** |
| **SRAM blocks, total** | **92** | **89** | **−3** |
| SRAM blocks, ingress | 78 | 72 | −6 |
| SRAM blocks, egress | 14 | 17 | +3 |
| **map RAMs, total** | **27** | **27** | **+0** |
| map RAMs, ingress | 21 | 19 | −2 |
| map RAMs, egress | 6 | 8 | +2 |
| **TCAM blocks, total** | **13** | **15** | **+2** |
| TCAM blocks, ingress | 11 | 11 | +0 |
| TCAM blocks, egress | 2 | 4 | +2 |
| **stateful ALUs (meter ALUs), total** | **8** | **7** | **−1** |
| stateful ALUs, ingress | 6 | 5 | −1 |
| stateful ALUs, egress | 2 | 2 | +0 |
| statistics ALUs, total | 4 | 5 | +1 |
| logical table IDs, ingress | 31 | 28 | −3 |
| logical table IDs, egress | 11 | 12 | +1 |

Tofino 1 has 12 MAU stages per gress (`resources.json` → `resources.mau.nStages` = 12), so the
ledger leaves 1 ingress stage and 7 egress stages free — the same headroom the base had.

The 5 warnings are byte-identical in kind to the base's: two `uninitialized_out_param` on the two
parsers, two `max_loop_depth` unroll notices, and the long-standing
`Ingress.tbl_gate: Table key name not supported. Replacing "md.attn[15:8]" with "md.attn"`.

### 2.2 Per-step attribution

Each row is its own bf-p4c run. "step 2" is the program after change 2 but before the injector.

| | ingress stages | egress stages | tables | SRAM | mapRAM | TCAM | SALU | statALU |
|---|---|---|---|---|---|---|---|---|
| base | 11 | 5 | 42 | 92 | 27 | 13 | 8 | 4 |
| step 1 — 32-bit TX frontier | **11** | **5** | **42** | **92** | **27** | **13** | **8** | **4** |
| step 2 — + receiver ledger | 11 | **4** | 38 | 86 | 25 | 13 | 7 | 4 |
| step 3 — + Bernoulli injector (**shipped**) | 11 | 5 | 40 | 89 | 27 | 15 | 7 | 5 |

Steps 1 and 2 are archived as `p4/witness/artifacts/mcp_fabric_ledger.step1-txwiden.metrics.json`
and `…step2-ledger.metrics.json`. Two further measurements quoted in this report are **not**
archived and cannot be reproduced from the repo, because the sources were intermediate scratch
files that were not kept: the two rejected `md.eg_rnd` placements below, and the 12-vs-11 ingress
stage measurement in §4. They are reported as assertions, and a reader who needs them should
re-derive them by making the one-line edit each describes.

Three things to read off that table.

**Step 1 is exactly free**, on every axis, to the block. The measurement, stated as a measurement
rather than as a rule: `resources.json` shows `Egress.reg_tx_frontier` occupying **2 `stateful_ram`
blocks in both builds**, at 512 × 8 b and at 2048 × 32 b alike. Two blocks is evidently a floor for a
stateful register here, and 2048 × 32 b = 65536 bits still fits inside a single Tofino 1 unit SRAM
(1024 × 128 b = 131072 bits), so nothing had to grow. **Counter width and depth were not the cost at
these sizes.** Do not generalise that to "register size is always free": once the stored bits
approach a unit RAM the allocation must grow, so re-measure before going much past 4096 × `bit<32>`.
The corollary matters more than the measurement: the old `bit<8>` saturating TX counter pinned at
255, so a healthy sublink became indistinguishable from any other busy sublink after 255 packets,
and 512 slots under-covered an index space (`md.sublink = (vlink << 4) | ctx`, 64 × 16) that needs
1024. Both were latent defects bought for nothing.

**The ledger is where the savings are.** Step 2 alone removes 4 tables, 6 SRAM blocks, 2 map RAMs,
one stateful ALU and one **egress** stage relative to the base. Two mechanisms:
- deleting `reg_rx_frontier` + `tbl_rx_frontier` removes an ingress SALU and its table outright;
- deleting the egress bank-OR (`if (hdr.fabric.clf_bank != 0) md.clf_tx_idx |= ...`) removes a
  gateway that was serialising `tbl_tx_frontier` behind its own conditional, which is what
  recovers the egress stage.

There is also a **dependency** improvement that does not show as a count. In the base, the arrivals
SALU read `md.wit_result.gap`, so it had to be placed after the frontier SALU: `reg_wit_expect` at
stage 3, `reg_wit_observed` at stage 4. The ledger's `lo` reads nothing but memory, so the two
co-place at stage 3 (`resources.json` → `meter_alu_detail`). The two halves of the ledger are read
in the same stage.

**The injector costs the egress stage back** (4 → 5) and +2 TCAM, **+3 SRAM** (2 `statistics_ram`
for `eg_bern_ctr` plus 1 `ternary_indirection_ram` for `tbl_eg_bern`), +2 map RAM, +1 statistics
ALU. That is the price of a second range-matched table with its own direct counter in egress, and it
is exactly the target the plan set (11 ingress / 5 egress). Two placements were tried and rejected:
drawing `md.eg_rnd` at the top of the egress `apply` changed nothing (still 5), and drawing it
inside `set_eg_vlink` **fails to compile** — see §4.

### 2.3 PHV

Source: `<prog>.tofino/pipe/logs/phv_allocation_summary_0.log`, "Overall PHV Usage" and the
per-width rows. Columns are *Containers Used* / *Bits Used* out of 224 containers / 4096 bits.

| | base | ledger |
|---|---|---|
| containers used, overall | 83 (37.1 %) | **81 (36.2 %)** |
| bits used, overall | 1383 (33.8 %) | 1375 (33.6 %) |
| bits used, ingress | 1041 (25.4 %) | 1025 (25.0 %) |
| bits used, egress | 342 (8.35 %) | 350 (8.54 %) |
| 8 b containers | 21 (32.8 %) | 20 (31.2 %) |
| 16 b containers | 41 (42.7 %) | 40 (41.7 %) |
| 32 b containers | 21 (32.8 %) | 21 (32.8 %) |

PHV pressure goes **down**, despite two fields widening to 32 bits, because deleting
`ig_md_t.clf_idx` (16 b) and `ig_md_t.clf_rx_prev` (8 b) more than pays for
`eg_md_t.eg_rnd` (16 b) and the `clf_tx_prev` widening.

### 2.4 Wire format

**Unchanged.** No header was added, removed, widened or narrowed. `hdr.fabric.clf_bank` is still
stamped (see §1). The witness stays the 4-byte W4 header. Nothing in this pass changes bytes on the
wire, which is the reason existing captures and the existing collector parser stay valid.

### 2.5 Generated bfrt schema

From `p4/witness/artifacts/mcp_fabric_ledger.bfrt.json`:

- `pipe.Ingress.reg_rx_frontier` and `pipe.Ingress.tbl_rx_frontier`: **absent**. Nothing can keep
  reading them by accident.
- `pipe.Ingress.reg_wit_expect.f1`: width **16** (the modular frontier `hi`).
- `pipe.Ingress.reg_wit_observed.f1`: width **32** (the arrivals ledger `lo`).
- `pipe.Egress.reg_tx_frontier.f1`: width **32**.
- `pipe.Egress.tbl_eg_bern`: present, alongside `pipe.Egress.tbl_eg_fail`.

`p4/witness/test_ledger_program.py` pins all six of those facts so a later edit cannot silently
reintroduce the RX frontier or narrow a ledger register.

---

## 3. The reorder-credit window — an OPEN ITEM, not a solved one

This is stated here at length because the plan (task 3a) requires it to be impossible to miss, and
because the mechanism is easy to over-claim.

**The claim this program supports.** For a directed sublink, the controller reads the pair
(`hi`, `lo`) at two instants and scores

    lost[t0, t1]  =  (hi(t1) − hi(t0)) mod 2^16  −  (lo(t1) − lo(t0))

Both terms are differences of monotone counters, so the read needs no double buffering, no bank
parity and no wall-clock guard interval. That is what retires the epoch/bank/guard scheme.

**The claim this program does NOT support.** It is **not** exact at an arbitrary instant. `HURDLES`
H33 records that the deployed witness inferred loss from a single adjacent reorder, i.e. packets on
one nominal sublink are **not** guaranteed FIFO on this loopback fabric — multi-queue TM scheduling
across a shared lane can reorder one directed link's own traffic. So at the instant of a read,
`Δhi − Δlo` counts genuinely lost packets **plus** packets that are still in flight or that will yet
arrive out of order.

**What would make it exact, and where it is not implemented.** Per the networks-expert report: a
hole opens a *debt*; each later out-of-order arrival on that sublink retires one unit of that debt;
only debt still outstanding after one bandwidth-delay product is scored as loss. That accounting is
**controller-side**, and it exists **nowhere yet** — not in `controller/infer.py`, not in
`controller/sublink_feedback.py`, not in this P4 file. It is a follow-up to controller code and is
explicitly out of scope for this data-plane pass.

**Consequence for how the mechanism is described.** The honest framing is *"the read-order argument
replaces an untested, arbitrary 2 s sleep (`p4/hw/loop/sequential_trials.py:62`) with a guard derived
from the fabric's own measured worst-case latency plus a reorder-credit window — smaller and
justified, not eliminated"* (red-team finding 4). Everywhere the design says "kill the epoch" it
should read "shrink and measure the guard". The phrase **"exact at any instant" must not appear** in
this program's comments, in the design doc, or in the paper. The advance-only SALU is what makes the
window *safe* to have (a late packet can no longer rewind the frontier and manufacture a phantom
hole, which is the H33 failure); it is not what makes the window unnecessary.

**Also still open** — recorded here so the same gap is not rediscovered:

- **`controller/hw_adapter.py:218`** parses the mirror's `attn` slot as
  `observed_packets=int(copy["attn"]) + 1`, and `controller/sublink_feedback.py:429` feeds the
  resulting `GapEvent.observed_packets` to `observe_clean(...)`, which at
  `sublink_feedback.py:555` does `st.clean_packets += observed_packets` — an **accumulating
  increment**. That slot now carries the low 16 bits of the ledger's `lo`, a *lifetime* count,
  where it used to carry *arrivals since the previous gap*. The `+ 1` is also meaningless under
  lifetime semantics. The fix is to difference successive values per sublink, at
  `hw_adapter.py:218`. No controller file was touched in this pass, so **the controller is
  currently mis-reading that field for this program.**
- **`p4/hw/loop/gate_agent.py` breaks against this program, in three distinct ways.** It binds to
  whatever `MCP_PROG` names (`gate_agent.py:44`), so it is exactly the harness that would drive a
  ledger build. (i) **Hard failure:** `gate_agent.py:311`, `:346` and `:357` call
  `table_get("pipe.Ingress.reg_rx_frontier")`, and that table does not exist in this program's
  schema — §2.5 proves its absence — so the `F`, `X` and `Z` commands will raise. (ii) **Silent
  mis-attribution, which is worse:** `:315-317` and `:349-350` decode the register index as
  `bank = idx >> 8`, `sublink = idx & 0xFF`. This pass deleted the bank bit and made the index the
  raw `md.sublink` (0..1023) into a 2048-deep register, so `idx >> 8` now reads vlink bits 4-5 and
  `idx & 0xFF` truncates the sublink. No exception, wrong answer. (iii) **Stale comment:**
  `:333-336` says "Both registers now hold a saturating count (255 = saturated)", false for the
  32-bit TX frontier. `gate_agent.py:377` also reads `reg_wit_observed` for the `R` census, whose
  semantics changed from since-last-gap to lifetime. None of this was touched in this pass.
- `p4/ptf/gap_event/test.py:106,262` also writes `reg_wit_observed`, but that file pins
  `PROG = "mcp_fabric_gate_event"`, so it is **not** affected. Recorded so the next reader does not
  have to re-derive it.
- **A duplicate arrival makes the estimate go NEGATIVE.** A duplicate increments `lo` without
  advancing `hi`, so `Δhi − Δlo` drops below zero — confirmed against the committed model, the
  stream `[0,1,2,2]` scores −1. §3 above describes only the over-count direction. The controller
  must clamp at zero, and must not mistake a negative for an underflow of the modular subtraction.
  Pinned by `test_a_duplicate_arrival_drives_the_estimate_NEGATIVE`.
- None of the above is a regression for `mcp_fabric_clf_eg.p4`, which is unchanged and still ships
  the old semantics.
- `hi` is 16-bit modular. The controller must take `Δhi` modulo 2^16, and the read cadence must be
  fast enough that a sublink cannot advance by ≥ 2^16 between reads. `lo` is 32-bit and does not
  wrap at any rate this fabric can produce.
- Both registers must be seeded by the controller, not left to an in-SALU sentinel (constraint
  Class 8). Seeding `reg_wit_expect[l] = 0` and `Egress.reg_wit_seq[l] = 0` together is consistent;
  seeding only one produces exactly one spurious gap on the first packet.

---

## 4. Constraint classes encountered

| class | where | what happened |
|---|---|---|
| **new, worth recording** — a table's default action may not require a random number | tried `md.eg_rnd = rng_eg_bern.get()` inside `set_eg_vlink`, which is `tbl_eg_vlink`'s `const default_action` | hard error: `error: Cannot specify set_eg_vlink as the default action, as it requires a random number.` Same family as Class 11 (a computed-index stateful action cannot be a default action). Fix: draw in the `apply` block, as `rng_fail` / `rng_attn` already do in ingress |
| **new, worth recording** — a wide register may return a narrow value, and sometimes must | `reg_wit_observed` is 32 bits; its only per-packet consumer is a 16-bit mirror slot | `RegisterAction<bit<32>, bit<16>, bit<16>>` with `rv = (bit<16>)v` compiles and is **one ingress stage cheaper** than returning `bit<32>` and slicing in the consuming action. Measured: `bit<32>` return + `md.attn = ...arrivals[15:0]` places at **12** ingress stages (the last one on the chip); `bit<16>` return + a plain 16→16 move places at **11**. Nothing else differed between the two builds. `md.attn` is also a `tbl_gate` key, so filling it from a 32-bit container's low half late in ingress pulls the whole attention chain apart |
| **2** — a range key is at most 20 bits over 5 nibble pairs | `tbl_eg_bern`'s `md.eg_rnd : range` (16 b = 4 nibbles) | one range field only; documented in the source that a second may not be added. This is why the Bernoulli arm needs its own table and cannot be folded into `tbl_eg_fail`, which already spends its range budget on `hdr.witness.seq` |
| **3 / N12** — sub-byte fields next to register outputs | `eg_md_t.eg_rnd`, `wit_result_t.arrivals` | both `bit<16>`, like everything else in this program |
| **11** — a stateful action with a computed index cannot be a default action | `tbl_wit_check`, `tbl_wit_count`, `tbl_tx_frontier` | inherited unchanged from the base: real keys with `const entries` |
| **advance-only SALU** | `wit_check` | the two-operation form `rv = v - seq; if ((int<16>)(v - seq) <= 0) v = seq + 1;` compiles and places at stage 3. One PHV input plus memory, driving both ALU outputs — inside Tofino 1's two-PHV-input-per-register limit. The signed test on the difference the SALU already computes is modular, hence wrap-correct across the 16-bit sequence space |

---

## 5. Control-plane state the change adds or removes

Not compiled evidence; the other half of the cost.

| object | size | change | who writes it |
|---|---|---|---|
| `Ingress.reg_rx_frontier` | was 512 × 8 b | **removed** | — |
| `Ingress.tbl_rx_frontier` | was 2 const entries | **removed** | — |
| `Ingress.reg_wit_expect` (`hi`) | 1024 × 16 b | semantics change: advance-only | controller seeds to 0, then reads |
| `Ingress.reg_wit_observed` (`lo`) | 1024 × **32** b (was 16 b) | semantics change: never reset | controller seeds to 0, then reads |
| `Egress.reg_tx_frontier` | **2048 × 32** b (was 512 × 8 b) | widened and deepened | controller seeds to 0, then reads |
| `Egress.tbl_eg_bern` | ≤ 64 entries | **new** — 2 per armed sublink | controller, per experiment |
| `Egress.eg_bern_ctr` | direct, 1 per entry | **new** | controller reads |
| bank-parity flip + guard-interval wait | — | **no longer needed** | the reader protocol this retires |

`tbl_eg_bern` entries, for a sublink to drop with probability `p`, with `W = round(p * 65536)`:

```
(sublink, eg_rnd in [0,   W-1  ])  ->  eg_bern_drop
(sublink, eg_rnd in [W,   65535])  ->  eg_bern_none
offered = drop_ctr + none_ctr ;  realised p_hat = drop_ctr / offered
```

Both entries are required. Do not lean on the default action for the survivor count: a direct
counter on a default action is one shared slot, not one per sublink, so per-sublink *offered* counts
would be lost. The default is `eg_bern_none()` only so an unarmed sublink forwards.

---

## 6. Reproducing this

Local, laptop SDE 9.13.1, no switch:

```bash
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
mkdir -p /tmp/ledger-build && cd /tmp/ledger-build
cp ~/Projects/mcp/p4/witness/mcp_fabric_clf_eg.p4 base.p4
cp ~/Projects/mcp/p4/witness/mcp_fabric_ledger.p4 .
for p in base mcp_fabric_ledger; do
  $SDE_INSTALL/bin/bf-p4c --target tofino --arch tna --verbose 2 \
      -o "$p.tofino" --bf-rt-schema "$p.bfrt.json" "$p.p4" > "$p.build.log" 2>&1
  echo "$p exit=$?"
  python3 ~/Projects/mcp/p4/witness/extract.py "$p" /tmp/ledger-build > "$p.metrics.json"
done
```

`--verbose 2` is required or `pipe/logs/` is created but left empty. `extract.py` takes an optional
second argument naming the build directory; with no second argument it keeps its original default of
the switch's `/home/decps/mcp_m2_gate`, so the 9.13.2 recipe in `p4/witness/COMPILE-GATE.md` is
unchanged.

Two caveats. The recipe above builds the base under the local name `base`, so it writes
`base.metrics.json` (whose `"program"` field reads `"base"`); the archived copy of the same run is
`p4/witness/artifacts/mcp_fabric_clf_eg.metrics.json`. Nothing is missing — it is a rename.

And when diffing builds: bf-p4c names anonymous gateway tables after the **source line number**, so
any inserted line renames them all. Compare on the named tables, never the anonymous ones.

---

## 7. Gate decision

- **Compiles:** yes, exit 0, 0 errors, 5 warnings, none of them new.
- **Fits:** yes. 11 ingress / 5 egress out of 12 per gress, unchanged from the program it replaces,
  with 2 fewer tables, 3 fewer SRAM blocks, one fewer stateful ALU and 2 fewer PHV containers.
- **Resource delta acceptable:** yes. The mechanism that replaces epoch/bank/guard is net *cheaper*
  than what it replaces; the only growth is the Bernoulli injector's egress TCAM and statistics ALU,
  which is a test fixture and can be omitted from a production build.
- **9.13.2:** **not measured.** Nothing in this file was compiled on the switch's SDE, and the chip's
  current owner was not checked because nothing went near it. Re-measure on 9.13.2 before load.
- **Local test suite:** `python3 -m pytest controller/tests p4/control/tests p4/hw p4/witness
  p4/ptf/model -q` → **315 passed, 0 failed** (280 before this change, +35 from
  `p4/witness/test_ledger_program.py`). The five modules `p4/ptf/test_{capsule,cw4_sublinks,fabric,
  health_gate,w4_witness}.py` are excluded because they cannot be *collected* under the system
  python3 — `ModuleNotFoundError: No module named 'ptf'`, since `ptf` ships only in the SDE's
  site-packages and those tests run via `p4/ptf/model/run_ptf.sh`. That is pre-existing and
  unrelated to this change (`p4/ptf/` was not touched), but it means the headline count does not
  cover them.
- **Model / PTF semantics:** not run here. `p4/witness/test_ledger_program.py` covers the ledger
  arithmetic in software and pins the generated schema. Its Bernoulli rate test exercises the
  two-entry range arithmetic and the counter identity against CPython's RNG — it does **not**
  verify Tofino's `Random<bit<16>>` uniformity or the inclusivity of hardware range bounds, which
  remain assumptions. The plan's task-3 acceptance ("DirectCounter readback matches the configured
  probability in a model/PTF test") is therefore **deferred, not met**. Running it needs a
  per-program conf and a case under `p4/ptf/`, outside this pass's file scope.
- **Reorder-credit accounting:** **NOT IMPLEMENTED.** See §3. Do not describe the ledger as exact at
  any instant.
- **Downstream consumers: TWO are known broken, not one.** `controller/hw_adapter.py:218` (the
  mirror `attn` slot, now a lifetime count) and `p4/hw/loop/gate_agent.py` (reads the deleted
  `reg_rx_frontier` at `:311/:346/:357`, and silently mis-decodes the register index at
  `:315-317`/`:349-350` now that the bank bit is gone). See §3 for the full list, including the
  negative-loss case on duplicates. No controller or harness file was touched in this pass, so
  **this program cannot be driven by the existing gate agent as-is.** That is the first thing to
  fix before any bring-up attempt.
