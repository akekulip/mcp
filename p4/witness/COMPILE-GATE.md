# M2 compile gate — post-TM link-local order witness

**Date** 2026-08-28 · **Compiler** `bf-p4c` p4c 9.13.2 (SHA `1baf055`), the switch's SDE at
`/home/decps/Downloads/bf-sde-9.13.2/install` on `decps@10.10.54.81`. The laptop's 9.13.1 was
not used for any number in this file.

**Scope.** Compile only. Nothing was loaded, no port or table was written, `bf_switchd` was not
restarted. The sibling program `defense4_rrc_bor_unified12` (pid 36630) was running before and
after and was not disturbed — verified by `pgrep -x bf_switchd` plus `/proc/36630/cmdline` at the
end of the session. All files created live under `p4/witness/`.

**Result in one line.** Both variants compile clean and both fit. The witness itself — stamp,
check, and on-chip gap counter — costs **zero extra MAU stages in either gress**. Only wiring the
gap verdict into the existing attention path costs a stage, and only because of a
write-after-write on `md.exceed`.

---

## 1. What was built

Five programs, all generated from one frozen baseline copy by `gen_variants.py` so that every
resource delta is attributable to exactly the listed edits.

| file | SHA-256 (first 16) | what it is |
|---|---|---|
| `mcp_fabric_base.p4` | `5d16721b227baaf9` | byte-identical copy of `p4/mcp_fabric.p4` (same SHA), the reference point |
| `mcp_fabric_w2.p4` | `baf01704b5948b92` | **W2** — 2 B witness, sequence only; detect + count |
| `mcp_fabric_w4.p4` | `c478a440bdaee7aa` | **W4** — 4 B witness, explicit 16 b link id + 16 b sequence; detect + count |
| `mcp_fabric_w2_arm.p4` | `94d3a868d91ec103` | W2 plus: a gap sets `md.exceed`, arming the existing `tbl_attn`/`tbl_gate` path |
| `mcp_fabric_w4_arm.p4` | `1dda00263ef5ab33` | W4 plus the same arming |
| `mcp_fabric_w4_egdrop.p4` | `106acf6214b4ca73` | W4_arm plus egress fault injection (see §6) |

The mechanism, in both variants:

- **Upstream egress**, immediately after `tbl_eg_vlink` resolves `(egress_port, egress_qid)` to a
  directed vlink: `Register<bit<16>, bit<16>>(64) reg_wit_seq`, read-then-increment, indexed by
  `md.vlink`. The returned value goes into the witness header. Modular 16-bit, so wrap is free.
- **Downstream ingress**: `Register<bit<16>, bit<16>>(64) reg_wit_expect` holds the next expected
  sequence per directed link. One SALU both tests and re-synchronises:
  `gap = expected − observed`, then `expected = observed + 1`. Unconditional re-sync is what makes
  the check raise exactly one gap event per discontinuity instead of one per packet forever, and
  it is what makes reset, re-seed and burst loss self-healing.
- A `DirectCounter` on the verdict table is the on-chip ground truth for the F0 false-gap floor
  and the F1 gap-to-reaction split. Per PREREG it is not read by the detector.

The witness is a **standalone byte-aligned header**, placed after `csig_h` in both the ingress and
the egress header stacks. It is never packed into `csig_h.epoch`, per the hard constraint in
`docs/review/PLAN.md` M2 and the "Tag insertion" row of `docs/DESIGN-ALTERNATIVES.md`. It is
inserted and zeroed in ingress `act_enter` (ingress action data is unconstrained; egress packed-
container writes are not) and stripped in `act_deliver` with the rest of the shim stack, so it
never leaves the fabric.

---

## 2. The cost table

Every number below was read from a file generated in this session. Provenance is given per row;
the local copies are in `p4/witness/artifacts/<prog>.<file>`.

### 2.1 Stages and tables

Source: `<prog>.tofino/pipe/logs/table_summary.log`, last "Table allocation done" block, fields
`Number of stages for ingress table allocation`, `… for egress table allocation`,
`Critical path length through the table dependency graph`, `Number of tables allocated`.
Cross-checked against `pipe/logs/resources.json` → `resources.mau.mau_stages[*].stage_number`,
attributing each `logical_tables.ids[*].table_name` to a gress via `pipe/context.json`
`tables[*].direction` (the two agree exactly for every build).

| | baseline | W2 | W4 | W2_arm | W4_arm | W4_egdrop |
|---|---|---|---|---|---|---|
| ingress stages **placed** | 8 | **8** (+0) | **8** (+0) | 9 (+1) | 9 (+1) | 9 (+1) |
| egress stages **placed** | 3 | **3** (+0) | **3** (+0) | 3 (+0) | 3 (+0) | 3 (+0) |
| critical path length (source-implied depth) | 8 | 8 (+0) | 8 (+0) | 8 (+0) | 8 (+0) | 8 (+0) |
| tables allocated | 21 | 24 (+3) | 25 (+4) | 24 (+3) | 25 (+4) | 27 (+6) |
| logical table IDs, ingress | 17 | 19 (+2) | 19 (+2) | 19 | 19 | 19 |
| logical table IDs, egress | 4 | 5 (+1) | 6 (+2) | 5 | 6 | 8 (+4) |

Tofino 1 has 12 MAU stages per gress (`resources.json` → `resources.mau.nStages` = 12), so W2 and
W4 leave 4 ingress stages and 9 egress stages free.

"Source stages" as PLAN M2 asks for it is reported here as the **critical path length through the
table dependency graph**, which is the depth the P4 source implies independently of placement. It
is 8 for every build, including the ones that place at 9 — see §4, which is the most useful
finding in this report.

### 2.2 Memory and ALUs

Source: `<prog>.tofino/pipe/logs/resources.json` → `resources.mau.mau_stages[*]`, summing
`rams.srams[]`, `map_rams.maprams[]`, `tcams.tcams[]`, `meter_alus.meters[]`,
`statistic_alus.stats[]`. Each block is attributed to a gress by the `usages[*].used_by` table
name; a block shared by two gresses would be split fractionally (none were).

| | baseline | W2 | W4 | W4_egdrop |
|---|---|---|---|---|
| SRAM blocks, ingress | 47 | 56 (+9) | 55 (+8) | 55 (+8) |
| SRAM blocks, egress | 4 | 6 (+2) | 6 (+2) | 9 (+5) |
| SRAM blocks, total | 51 | 62 (+11) | 61 (+10) | 64 (+13) |
| map RAMs, ingress | 13 | 17 (+4) | 17 (+4) | 17 (+4) |
| map RAMs, egress | 0 | 2 (+2) | 2 (+2) | 4 (+4) |
| TCAM blocks, ingress | 10 | 10 (+0) | 10 (+0) | 10 (+0) |
| TCAM blocks, egress | 0 | 0 (+0) | 0 (+0) | 2 (+2) |
| meter ALUs (= SALU slots), ingress | 3 | 4 (+1) | 4 (+1) | 4 (+1) |
| meter ALUs (= SALU slots), egress | 0 | 1 (+1) | 1 (+1) | 1 (+1) |
| statistics ALUs, ingress | 2 | 3 (+1) | 3 (+1) | 3 (+1) |
| statistics ALUs, egress | 0 | 0 | 0 | 1 (+1) |

Tofino 1 provides 4 meter ALUs and 4 statistics ALUs **per stage**
(`resources.json` → `mau_stages[*].meter_alus.nAlus` = 4, `statistic_alus.nAlus` = 4), so these
totals are nowhere near a per-stage limit; they are listed because each one is a distinct piece of
state the control plane has to seed and read.

Named occupancy, from `mau_stages[*].meter_alus.meters[*].usages[*].used_by` and the same field
under `statistic_alus`:

- baseline ingress: `reg_spray_rr` (st1, stateful), `spray_sel_impl` (st2, selector), `reg_attn`
  (st5, stateful); counters `vlink_ctr` (st4), `fail_ctr` (st5).
- W2/W4 add ingress `reg_wit_expect` (st3, stateful) and counter `wit_ctr` (st4), and egress
  `reg_wit_seq` (st1, stateful). `reg_attn` moves st5 → st7 and the two baseline counters shift
  with it; that is re-placement inside the same 8 stages, not growth.

Note that **W4 uses one fewer ingress SRAM block than W2** (55 vs 56). W2 folds the directed-link
id into `tbl_port_role`'s action data, which widens that table's action RAM; W4 carries the id on
the wire and leaves `tbl_port_role` untouched. So the 2 extra wire bytes W4 spends buy back an
SRAM block and, more importantly, buy correctness (§5).

### 2.3 PHV

Source: `<prog>.tofino/pipe/logs/phv_allocation_summary_0.log`, the "Overall PHV Usage" and MAU-
group rows. Columns are *Containers Used* and *Bits Used* out of 4096 bits / 224 containers.

| | baseline | W2 | W4 |
|---|---|---|---|
| containers used, overall | 69 (30.8 %) | 73 (32.6 %) | 74 (33.0 %) |
| bits used, overall | 1137 (27.8 %) | 1211 (29.6 %) | 1243 (30.3 %) |
| bits used, ingress | 887 (21.7 %) | 936 (22.9 %) | 952 (23.2 %) |
| bits used, egress | 250 (6.1 %) | 275 (6.7 %) | 291 (7.1 %) |
| 16 b containers | 38 (39.6 %) | 40 (41.7 %) | 40 (41.7 %) |
| 32 b containers | 16 (25.0 %) | 17 (26.6 %) | 18 (28.1 %) |
| 8 b containers | 15 (23.4 %) | 16 (25.0 %) | 16 (25.0 %) |
| tagalong containers (8/16/32 b) | 11 / 20 / 13 | 11 / 20 / 13 | 11 / 20 / 13 |

Per-MAU-group container occupancy (the number that actually binds, not the overall percentage):

| group | baseline | W2 | W4 |
|---|---|---|---|
| B0-15 | 12 (75 %) | 12 (75 %) | 12 (75 %) |
| B16-31 | 3 (18.8 %) | 4 (25 %) | 4 (25 %) |
| **H0-15** | **16 (100 %)** | **16 (100 %)** | **16 (100 %)** |
| H16-31 | 10 (62.5 %) | 11 (68.8 %) | 12 (75 %) |
| H32-47 | 12 (75 %) | 13 (81.2 %) | 12 (75 %) |
| W0-15 | 12 (75 %) | 13 (81.2 %) | 14 (87.5 %) |
| W16-31 | 4 (25 %) | 4 (25 %) | 4 (25 %) |

`H0-15` is already at 16/16 in the **baseline** — that group is full before the witness is added,
which is why both variants' new 16-bit metadata landed in `H16-31`/`H32-47` instead. That is the
group to watch for anything added after this; it is not a wall the witness hit.

### 2.4 Header bytes added

Confirmed on the wire, not from the P4 source: `<prog>.tofino/pipe/<prog>.bfa`, ingress
`parse_csig` `shift:` and the egress `parse_csig.$split_0` state.

| | baseline | W2 | W4 |
|---|---|---|---|
| ingress `parse_csig` shift (bytes) | 14 | 16 | 18 |
| egress witness extract (bytes) | — | 2 (`0..1: H26`) | 4 (`0..1: H25`, `2..3: H24`) |
| **witness bytes added per fabric packet** | 0 | **2** | **4** |
| overhead at 1500 B | — | 0.133 % | 0.267 % |
| overhead at 4096 B | — | **0.0488 %** | 0.0977 % |

The 2 B / 4096 B figure of 0.0488 % is the number `docs/review/PLAN.md` line 30 asks to be put on
the record as 0.049 %; it agrees.

Two qualifications on those percentages. First, the witness rides **only inside the fabric**: it is
added at the source leaf and stripped at the destination leaf, so it costs nothing on the host-
facing links and nothing end-to-end. Second, the fabric shim stack already carries 12 B (`fabric_h`)
+ 14 B (`csig_h`) = 26 B on every internal hop; the witness takes that to 28 B (W2) or 30 B (W4),
i.e. a relative increase of 7.7 % or 15.4 % on the existing shim, not on the packet.

### 2.5 Parser

`resources.json` → `resources.parser` is `{"nParsers": 18, "parsers": 2}` for every build:
unchanged. The ingress parser gains **no new state** — bf-p4c merged the witness extract into
`parse_csig`, which simply shifts 16 or 18 bytes instead of 14. The egress parser state list
(from the `.bfa` `parser egress:` section) goes from 11 states to **10**: the larger header stack
reaches the minimum parse depth sooner and one `min_parse_depth_accept_loop` unroll disappears.
The witness is, in parser terms, free.

---

## 3. Verdicts

### W2 — 2 B, sequence only

**Compiles: yes. Fits: yes. Correct on this testbed: no.**

`bf-p4c` exit status 0, 0 errors, 4 warnings — the same 4 warnings the baseline emits, no new
ones (`artifacts/mcp_fabric_w2.build.log`). Placement 8 ingress / 3 egress: identical to the
baseline. Cost: +2 B on the wire, +11 SRAM blocks, +2 SALU slots (one per gress), +1 statistics
ALU, +4 containers, 0 stages, 0 TCAM.

W2 is the cheaper variant and it is the one to use **on a real fabric where one physical port
carries one directed link**. It is not usable on the current one-chip emulation, for the reason in
§5. Recommend: do not take W2 to silicon.

### W4 — 4 B, explicit link id + sequence

**Compiles: yes. Fits: yes. Correct on this testbed: yes.**

`bf-p4c` exit status 0, 0 errors, the same 4 baseline warnings
(`artifacts/mcp_fabric_w4.build.log`). Placement 8 ingress / 3 egress: identical to the baseline.
Cost: +4 B on the wire, +10 SRAM blocks (one *fewer* ingress block than W2), +2 SALU slots, +1
statistics ALU, +5 containers, 0 stages, 0 TCAM, +2 egress logical table IDs.

The Class-13 hazard the design record warned about did not bite. `link_id` and `seq` are adjacent
16-bit fields and in the **ingress** PHV they did land in one 32-bit container
(`.bfa`: `hdr.witness.link_id: W3(16..31)`, `hdr.witness.seq: W3(0..15)`) — but ingress writes
both from one constant source in one action, which is legal. In **egress**, where the two sources
differ, splitting the write into two actions in two tables let the allocator place them in two
separate 16-bit containers (`.bfa`: `hdr.witness.link_id: H25`, `hdr.witness.seq: H24`), so the
one-source-per-container rule was never tested. The `csig_replace_a`/`csig_replace_b` precedent
worked exactly as intended.

**Recommendation: take W4 to model/PTF and then to silicon.** It costs 2 B more than W2 per
internal hop — 0.098 % at 4096 B — and in exchange it removes the identifiability failure that
M3 exists to solve, and it costs one SRAM block *less* in ingress.

---

## 4. The finding that matters: placement, not depth

The critical path length through the table dependency graph is **8 for every build in this
report**, including the ones that place at 9 or 10 ingress stages. The witness adds no depth. What
adds stages is where the verdict table is written in the `apply` block, because
`tbl_wit_verdict` and `tbl_exceed_csig`/`tbl_exceed_evid` all write `md.exceed` and the compiler
must honour program order on that write-after-write.

Measured this session, three placements of the same code:

| witness `apply` block placed … | ingress stages | delta |
|---|---|---|
| **after** the exceedance tables, verdict does **not** write `md.exceed` (shipped W2/W4) | **8** | +0 |
| after the exceedance tables, verdict writes `md.exceed` (W2_arm/W4_arm) | 9 | +1 |
| **before** the exceedance tables, verdict writes `md.exceed` (first attempt, not shipped) | 10 | +2 |

The chain in the 9-stage case, from `mcp_fabric_w2_arm.tofino/pipe/logs/table_summary.log`:
`tbl_exceed_csig` at stage 3 → `tbl_wit_check` at 4 → `tbl_wit_verdict` at 5 → `tbl_vlink` at 5 →
`tbl_fail`/`tbl_attn` at 6 → `tbl_gate` at 7 → `tbl_final` at 8. `tbl_wit_check`'s own minimum
stage is 1; it is held at 4 purely by the ordering against `md.exceed`.

Two consequences.

1. **M2 as specified does not need the arming.** M2's deliverable is that the next surviving packet
   reveals a post-TM sequence discontinuity, with on-chip ground truth in a counter the detector
   does not read. That is `mcp_fabric_w4.p4` and it is free in stages. Arming the fast loop from a
   gap event is M6's job (the `QUIET → SUSPECT → ZOOM → COOLDOWN` FSM), and when M6 wants it the
   price is one ingress stage out of the four still free.
2. If a future edit needs the arming *and* the stage back, the fix is not to restructure the
   pipeline: give the witness verdict its own metadata field and let `tbl_attn`'s key consume both,
   or move `tbl_exceed_csig` after the witness. Do not re-derive this by trial and error — the
   dependency graph will keep saying 8 either way.

---

## 5. Where the mechanism as specified is not achievable on this testbed

### 5.1 W2's premise is false on the one-chip emulation (the blocking one)

W2 is valid "only when ingress-port/topology mapping proves link identity". It does not, here, and
the reason is structural rather than a resource limit.

Tofino 1 exposes no ingress queue identifier: `ingress_intrinsic_metadata_t` carries the ingress
port, but the TM queue the packet occupied at the **upstream** switch is not recoverable at the
**downstream** ingress. The MCP fabric maps virtual links onto real queues precisely to get more
links than ports: from `p4/control/setup_skeleton.py`, uplink `leaf l → spine s` is
`(port = LEAF_A[l], qid = s)`, so one physical loop port carries `N_SPINE = 2` distinct directed
vlinks distinguished only by qid. The downstream ingress port therefore identifies the link up to
a factor of `N_SPINE`; with the 4 × 2 fabric that is a 2-way ambiguity, and it grows with the
spine count.

**Nearest thing that is possible:** W4, which puts the 16-bit directed-link id on the wire where
the downstream can read it. That is the tradeoff — 2 extra bytes per internal hop, 0.098 % at
4096 B, in exchange for unambiguous directed-link identity. W2 remains correct on a real fabric
with one directed link per physical port, and is worth keeping compiled as the cost floor for the
paper's cost table.

### 5.2 A pre-increment drop produces no gap (a correctness bug in the current fault path)

The baseline injects faults in **ingress** (`tbl_fail`, `mcp_fabric.p4:563`), which sets
`ig_dprsr_md.drop_ctl` before the packet ever reaches the upstream egress. Such a packet never
consumes a sequence number, so the downstream sees a perfectly contiguous sequence and the witness
reports nothing. As written, the existing fault injector cannot exercise this mechanism at all.
`docs/review/PLAN.md` M2 anticipates this ("a pre-increment drop cannot validate wire-loss
semantics"); this report confirms it against the source and prices the fix.

**Fix, compiled:** `mcp_fabric_w4_egdrop.p4` adds `tbl_eg_fail` in egress, applied after
`tbl_wit_stamp`, with the same shape as ingress `tbl_fail` — a hardware `Random<bit<16>>` draw as a
TCAM range key, a `DirectCounter` for ground truth, control-plane range bounds so the rate retunes
without a recompile. It compiles clean and costs, relative to `mcp_fabric_w4_arm`:
**0 extra stages in either gress**, +3 egress SRAM blocks, +2 egress map RAMs, +2 egress TCAM
blocks (the first TCAM this program has ever used in egress), +1 egress statistics ALU, +2 egress
logical table IDs. Class 2 applies: the 16-bit range key consumes 4 of the 5 range nibbles, so no
second range field may be added to that table.

### 5.3 What the witness is structurally blind to

These are properties of a post-TM sequence, not compiler limits, and they belong in the honest-
claim paragraph M2 already asks for.

- **TM drops.** The sequence is allocated in the egress MAU, which runs after the traffic manager.
  A packet the TM tail-drops never reaches egress, never consumes a sequence, and produces no gap.
  The witness covers loss from the egress deparser onward — the wire — which is the gray-failure
  target, but it is not a queue-drop detector. The existing `deq_qdepth` CSIG path remains the
  congestion signal.
- **Ingress drops** for the same reason, including the baseline's own `tbl_fail`.
- **Idle-tail loss and a 100 % blackhole.** A discontinuity is only observable to the *next
  survivor*. With no survivor there is no evidence, and no amount of sequencing changes that; it
  needs the separately priced marker plus timeout that PLAN M2 already excludes from the main
  claim.
- **Reordering.** The check treats any `observed ≠ expected` as a gap, including a legitimate
  reorder, and then re-syncs. On a per-packet-sprayed fabric reordering happens *across* links, not
  within one directed link+queue, so a within-link reorder should be rare — but this is exactly
  what the F0 false-gap floor experiment must measure, and the counter is already in place to
  measure it.

---

## 6. Constraint classes encountered, and what was done about them

Applied preemptively per the `tofino-p4` skill; none of these cost a compile iteration.

| class | where it would have bitten | what was done |
|---|---|---|
| 11 — a stateful action with a computed index cannot be a table's default action | both `tbl_wit_check` (ingress, index `md.wit_link`) and `tbl_wit_stamp` (egress, index `md.vlink`) | real keys with `const entries`, the `tbl_attn` precedent. Ingress keys on `md.role` with one entry for `ROLE_LOOP`, which also scopes the check correctly for free; egress keys on `hdr.fabric.nxt`, whose domain is two compile-time constants |
| 13 — one PHV source per packed container in an egress action | W4's adjacent `link_id`/`seq` written from `tbl_eg_vlink` action data and the SALU return | two actions in two tables (`tbl_wit_stamp`, `tbl_wit_link`), the `csig_replace_a`/`_b` precedent. The allocator then split them into `H25`/`H24` and the rule was never tested |
| 13 (again) — `csig_h.epoch` | the packing the design record forbids | not attempted. The witness is a standalone header throughout |
| 3 / N12 — sub-byte fields next to register outputs | new metadata `wit_link`, `wit_gap` | both `bit<16>` like everything else in this program |
| parser byte-aliasing (silicon, `step4-silicon.md`) — an 8→16 cast in the parser does not zero-extend | `md.wit_link = hdr.witness.link_id` | same-width 16→16 copy, which is a clean container move |
| parser write-once per path | `md.wit_link` is written only in `parse_witness` | it is therefore *not* zeroed in the start state, and is read only under `hdr.witness.isValid()` — the same treatment `md.attn_idx` already gets |
| 2 — range key ≤ 20 bits | `tbl_eg_fail`'s 16-bit range key in the egdrop variant | one range field only; documented in the source that a second may not be added |

One pattern worth recording as working: the two-operation ingress SALU

```p4
RegisterAction<bit<16>, bit<16>, bit<16>>(reg_wit_expect) wit_check = {
    void apply(inout bit<16> v, out bit<16> rv) {
        rv = v - hdr.witness.seq;
        v  = hdr.witness.seq + 1;
    }
};
```

compiles and places at stage 3. It takes one PHV input plus memory and drives both ALU outputs
(one to the output bus, one back to memory), which is inside Tofino 1's per-register limit of two
PHV inputs.

---

## 7. Control-plane state the mechanism adds

Not compiled evidence, but it is the other half of the cost and M2's table asks for it.

| object | size | who writes it | when |
|---|---|---|---|
| `Egress.reg_wit_seq` | 64 × 16 b | controller, seed to 0 | at bring-up, and on any deliberate resynchronisation |
| `Ingress.reg_wit_expect` | 64 × 16 b | controller, seed to 0 | same |
| `Ingress.tbl_wit_check` | 1 const entry | — | compiled in |
| `Ingress.tbl_wit_verdict` | 1 const entry | — | compiled in |
| `Egress.tbl_wit_stamp` (+ `tbl_wit_link` in W4) | 1 const entry each | — | compiled in |
| `Ingress.wit_ctr` | direct, 2 entries | controller reads | per epoch, for F0/F1 ground truth |
| `tbl_port_role` action data (**W2 only**) | +16 b per row, 64 rows | controller | the port→directed-link map; this is the piece that is not well defined on this testbed (§5.1) |
| `tbl_eg_fail` (egdrop only) | ≤ 64 rows | controller | per experiment, to set the injected loss rate |

Both registers must be seeded, not left to an in-SALU `v == 0` sentinel (Class 8). Seeding
`reg_wit_expect[l] = 0` and `reg_wit_seq[l] = 0` together is consistent; seeding only one produces
exactly one spurious gap on the first packet, which the F0 run must either avoid or subtract.

---

## 8. Reproducing this

```bash
# 1. regenerate the variants from the frozen baseline copy (local, no switch needed)
cd p4/witness && python3 gen_variants.py

# 2. compile each on the switch's SDE 9.13.2.  Compile only — this does not touch the chip.
scp mcp_fabric_*.p4 build.sh extract.py decps@10.10.54.81:/home/decps/mcp_m2_gate/
ssh decps@10.10.54.81 'cd /home/decps/mcp_m2_gate && \
    for p in mcp_fabric_base mcp_fabric_w2 mcp_fabric_w4 \
             mcp_fabric_w2_arm mcp_fabric_w4_arm mcp_fabric_w4_egdrop; do \
        bash build.sh $p >/dev/null 2>&1; echo "$p exit=$?"; \
        python3 extract.py $p > $p.metrics.json; done'
```

`build.sh` runs `bf-p4c --target tofino --arch tna --verbose 2`; `--verbose 2` is required or
`pipe/logs/` is created but left empty. `extract.py` writes one JSON per build naming the source
file and field for every number; those JSONs are archived in `p4/witness/artifacts/`, together
with the raw `resources.json`, `table_summary.log`, `phv_allocation_summary_0.log` and build log
for each build.

One caveat when diffing builds: bf-p4c names anonymous gateway tables after the **source line
number** (`tbl_mcp_fabric_w2869`), so any inserted line renames them all. Compare on the named
tables, never on the anonymous ones.

---

## 9. Gate decision

`docs/review/PLAN.md` M2 admits silicon only if one primary form compiles, directed-link identity
is proven, and model/PTF semantics pass.

- **One primary form compiles:** yes — both do, cleanly, with no new warnings and no stage cost.
- **Directed-link identity:** proven for **W4** by construction (the id is on the wire).
  **Disproven for W2** on this testbed (§5.1) — the emulation's `N_SPINE` virtual links per
  physical port make ingress port an ambiguous key. This is a real answer to the question M3 was
  going to ask, obtained at compile time.
- **Resource delta acceptable:** yes. 0 stages in either gress, 10 SRAM blocks, 2 SALU slots,
  4 B/packet inside the fabric only.
- **Model/PTF:** not started. That is the next item, and it is the gate that still stands between
  this and the chip: initialisation, reset/resync, modulo wrap, duplicates, allowed reorder,
  consecutive losses, multi-queue traffic.

**Recommendation.** Carry `mcp_fabric_w4.p4` forward as the M2 primary. Keep `mcp_fabric_w2.p4`
compiled as the cost floor for the paper's cost table, labelled as valid only where one port
carries one directed link. Fold `tbl_eg_fail` in before any silicon run, because without it the
existing fault injector cannot produce a single gap event. The fallback in PLAN M2 (RFC 9341
alternate marking) is **not needed** — nothing here failed.
