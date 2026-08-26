# Step 3 — Spray, all modes in one binary

Design reference: `docs/P4-DESIGN-SPACE.md` §9.2 step 3, mechanisms from §4.

## What was built, and one deliberate departure from the design doc

§4's recommendation is **B1 (Random) + B2 (hash of UDP sport entropy) + B4
(control-plane-seeded round-robin SALU)**, with B2 as the default and **B3
(ActionSelector) explicitly ranked last** ("heaviest of the three … the selection is
still hash-driven so it buys no determinism B2 does not already have").

The task for this step asked for Random + hash + **ActionSelector**. Both were built
and measured rather than argued about:

| variant | modes | ingress stages | tables |
|---|---|---|---|
| 3-mode, exactly as §4 recommends | Random, hash, round-robin | **5** | 8 |
| + ActionSelector, selector fed from its own `bit<32>` md field | + B3 | **7** | 10 |
| + ActionSelector, selector fed **directly from `md.spray_hash`** | + B3 | **6** | 9 |

**Shipped: the 6-stage four-mode variant.** The ActionSelector costs **+1 ingress
stage** over the design's three modes, and it is kept because §7.5 wants it for a
fault class nothing else provides — removing a member from the selector group
emulates *link-down plus reroute*, where deleting a `tbl_vlink` row only emulates a
silent sink.

Two things worth knowing about that +1:

- The naive wiring costs **+2**, not +1. Copying the hash into a dedicated selector
  field (`md.sel_hash = (bit<32>)md.spray_hash;`) is a bare statement that becomes its
  own logical table, and that table sits between the hash draw and the selector table,
  serialising three stages. Using `md.spray_hash : selector` as the selector key field
  directly deletes that stage.
- **To drop back to the design's 5-stage three-mode version**: delete `spray_prof`,
  `sel_hash_fn`, `spray_sel_impl`, `spray_member`, `tbl_spray_sel`, `spray_from_sel`,
  the `tbl_spray_sel.apply()` call, and `md.spray_sel`. Nothing else references them.

## Build

**Result: `0 errors, 2 warnings generated.` — bf-p4c exit status 0.** First compile of
each variant; no iteration was needed.

**No Class 7 hash canary.** The warning `Expected single call to get for hash instance`
did **not** appear. `h_spray` has exactly one `.get()` call site, on the 3-tuple
`{ipv4.src_addr, ipv4.dst_addr, udp.src_port}`. The moment a second tuple shape is
hashed anywhere in this program it needs its own `CRCPolynomial` + `Hash` instance.

## Stages — 6 ingress, 0 egress (step 2: 4 / 0)

```
Number of stages for ingress table allocation: 6
Critical path length through the table dependency graph: 6
Number of tables allocated: 9
+-------+-----------------+------------------------+
| Stage | Min / Max Stage |       Table Name       |
+-------+-----------------+------------------------+
|   0   |    [ 0, 6 ]     | Ingress.tbl_port_role  |
|   1   |    [ -, - ]     |  Ingress.tbl_dst_leaf  |
|   1   |    [ -, - ]     |   tbl_mcp_fabric486    |   <- md.spray_rr = rr_next.execute()
|   1   |    [ 1, 8 ]     |   tbl_mcp_fabric490    |   <- md.spray_hash = h_spray.get()
|   1   |   [ 1, 11 ]     |   tbl_mcp_fabric478    |   <- md.spray_rand = rng_spray.get()
|   2   |    [ 2, 8 ]     | Ingress.tbl_spray_sel  |
|   3   |    [ 3, 9 ]     | Ingress.tbl_spray_mode |
|   4   |   [ 4, 10 ]     |   Ingress.tbl_vlink    |
|   5   |   [ 5, 11 ]     |   Ingress.tbl_final    |
+-------+-----------------+------------------------+
```

The three independent draws **co-place in stage 1** with `tbl_dst_leaf`, exactly as
§8.1's S1 predicted. Each is a separate logical table (N10 again — three bare
statements, three tables), but they cost zero extra stages because they are mutually
independent.

## Per-stage resources (non-zero columns)

| stage | Exact xbar | Hash bits | Hash dist | Gateway | SRAM | Map RAM | VLIW | Meter ALU | Stats ALU | LTIDs |
|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 2 | 10 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 1 |
| 1 | 21 | 72 | 2 | 3 | 6 | 2 | 3 | **1** | 0 | **4** |
| 2 | 4 | 54 | 0 | 0 | 7 | 2 | 1 | **1** | 0 | 1 |
| 3 | 4 | 40 | 0 | 0 | 4 | 0 | 4 | 0 | 0 | 1 |
| 4 | 10 | 40 | 0 | 1 | 9 | 5 | 2 | 0 | 1 | 1 |
| 5 | 4 | 40 | 0 | 0 | 4 | 0 | 3 | 0 | 0 | 1 |

- **Meter ALU in stage 1** is the round-robin `RegisterAction` (`reg_spray_rr`);
  **Meter ALU in stage 2** is the `ActionSelector`. On Tofino 1 both stateful ALUs and
  selectors are charged to the Meter ALU column, so the two spray mechanisms consume
  1 of the 4 Meter ALUs in each of two different stages. The attention register in
  step 5 will want its own, which is fine, but they must not all land in one stage.
- **TCAM still 0.** The whole build is exact-match SRAM so far.
- Peak logical table IDs is 4 of 16 (stage 1). No LTID pressure.

## PHV — the H0-15 wall reached, as predicted in step 2

| MAU group | step 1 | step 2 | step 3 |
|---|---|---|---|
| B0-15 (8-bit, ingress) | 2/16 | 2/16 | 3/16 (18.8 %) |
| B16-31 (8-bit, egress) | 2/16 | 2/16 | 2/16 |
| **H0-15 (16-bit, ingress)** | 1/16 | 14/16 | **16/16 (100 %)** — 242 of 256 bits |
| H16-31 (16-bit, egress) | 1/16 | 1/16 | 1/16 |
| **H32-47 (16-bit, free)** | 0/16 | 0/16 | **0/16** |
| W0-15 (32-bit, ingress) | 0/16 | 1/16 | 3/16 |
| Overall PHV | 6 (2.68 %) | 20 (8.93 %) | 25 (11.2 %) |
| Tagalong | 1096 b (53.5 %) | 1000 b (48.8 %) | 952 b (46.5 %) |

**H0-15 is now full at 16/16 containers while overall PHV is 11 %.** This is the same
shape of failure defense4 hit (B0-15 at 16/16 at 16.5 % overall) — the per-MAU-group
container count binds, not the chip.

Two measurements that matter for the remaining steps:

1. **H32-47 is still at 0/16.** The allocator did not spill the ingress 16-bit working
   set into the next free 16-bit group even with H0-15 at 100 %. Whether it *can* is
   the open question that step 4 answers by adding `md.rnd_fail`.
2. **When H0-15 was full, the allocator demoted rather than failed.** In the 7-stage
   variant `md.spray_sel` landed in B0-15 (which went 3/16 → 5/16) instead of H.
   So the practical fallback if H0-15 binds is to declare new small metadata as
   `bit<8>`: B0-15 has 13 free containers, and Class 3 only forbids going *below* 8
   bits next to register outputs.

## Semantics fixed in this step

- **The spray index is drawn once, at the source leaf, and carried on the wire.** The
  parser lifts `hdr.fabric.spray` into `md.spray_idx` on every looped pass, and
  `tbl_spray_mode` is applied only at `md.hop == 0`. A spine cannot change mid-flight,
  and a collector capture reconstructs the path even in the unseeded Random mode —
  which is §4's stated substitute for the seed Tofino 1 does not have.
- **Gating the draws on `hop == 0` also fixes the round-robin counter.** Executed on
  every pass it would advance three times per packet; gated, it advances once per
  packet, which is what "perfectly balanced baseline" requires.
- `k` (spines per leaf) is the action-data `mask` of the mode actions, so 2x4 vs 4x2
  is a control-plane edit.
