# Step 2 — Forwarding + virtual-link resolve

Design reference: `docs/P4-DESIGN-SPACE.md` §9.2 step 2, tables from §8.1 (S0, S1, S3, S8).

Added: `tbl_port_role`, `tbl_dst_leaf`, `tbl_vlink` (+ `DirectCounter`), `tbl_final`,
the `qid` / loop-port writes (§3 mapping option M2), and the host-port spoof guard.

## Build

**Result: `0 errors, 2 warnings generated.` — bf-p4c exit status 0.** First compile,
no iteration. The two warnings are the same compiler-generated
`min_parse_depth_accept_loop` pair as step 1.

## Stages — 4 ingress, 0 egress (step 1: 0 / 0)

`table_summary.log`:

```
Number of stages in table allocation: 4
  Number of stages for ingress table allocation: 4
  Number of stages for egress table allocation: 0
Critical path length through the table dependency graph: 4
Number of tables allocated: 5
+-------+-----------------+-----------------------+
| Stage | Min / Max Stage |      Table Name       |
+-------+-----------------+-----------------------+
|   0   |    [ 0, 8 ]     | Ingress.tbl_port_role |
|   1   |    [ -, - ]     | Ingress.tbl_dst_leaf  |
|   1   |   [ 1, 11 ]     |   tbl_mcp_fabric393   |
|   2   |   [ 2, 10 ]     |   Ingress.tbl_vlink   |
|   3   |   [ 3, 11 ]     |   Ingress.tbl_final   |
+-------+-----------------+-----------------------+
```

**Five tables for four named ones.** `tbl_mcp_fabric393` is the anonymous table
bf-p4c created for the one bare statement in the apply body — the spoof-guard
`ig_dprsr_md.drop_ctl = 1;` at `mcp_fabric.p4:393`. This is constraint N10 observed
directly on this build: *a bare action call becomes its own logical table*. It cost
no extra stage here (it co-placed with `tbl_dst_leaf` in stage 1) but it did consume
a logical table ID, and the naming confirms the forensic rule that bf-p4c names
anonymous tables after the SOURCE LINE NUMBER — so inserting lines above it renames
it and breaks any diff against a previously loaded binary.

## Per-stage resources (non-zero columns only, from `mau.resources.log`)

| stage | table(s) | Exact xbar | Hash bits | Gateway | SRAM | Map RAM | TCAM | VLIW | Stats ALU | Action data bytes | Logical TableIDs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | `tbl_port_role` | 2 | 10 | 0 | 1 | 0 | 0 | 1 | 0 | 4 | 1 |
| 1 | `tbl_dst_leaf`, `tbl_mcp_fabric393` | 7 | 40 | 1 | 4 | 0 | 0 | 2 | 0 | 2 | 2 |
| 2 | `tbl_vlink` | 10 | 40 | 1 | 9 | 5 | 0 | 2 | **1** | 5 | 1 |
| 3 | `tbl_final` | 4 | 40 | 0 | 4 | 0 | 0 | 3 | 0 | 2 | 1 |

- **TCAM: 0.** Everything so far is exact match in SRAM. The TCAM budget is untouched
  and available for `tbl_fail`'s range key in step 4.
- **Stats ALU 1 in stage 2** is `tbl_vlink`'s `DirectCounter`. Confirmed working:
  bf-p4c accepted a direct counter whose `count()` is called from BOTH the hit action
  (`to_loop`) and the default action (`black_hole`), which is what §7.6 requires for
  exact black-hole ground truth.
- Logical table IDs peak at 2 of 16 per stage. Nowhere near the LTID wall.

## PHV — this is the finding of step 2

| MAU group | step 1 | step 2 | note |
|---|---|---|---|
| B0-15 (8-bit, ingress) | 2/16 (12.5 %) | 2/16 (12.5 %) | flat |
| B16-31 (8-bit, egress) | 2/16 | 2/16 | flat |
| **H0-15 (16-bit, ingress)** | **1/16 (6.25 %)** | **14/16 (87.5 %)** | **203 of 256 bits** |
| H16-31 (16-bit, egress) | 1/16 | 1/16 | flat |
| W0-15 (32-bit, ingress) | 0/16 | 1/16 | `hdr.ipv4.dst_addr` |
| Overall PHV | 6 (2.68 %) | 20 (8.93 %) | 261 of 4096 bits |
| Tagalong total | 1096 bits (53.5 %) | 1000 bits (48.8 %) | went DOWN — matched fields left the tagalong |

**The 16-bit ingress MAU group H0-15 is at 14 of 16 containers after step 2.**

§8.3/N12 said "prefer `bit<16>` for new metadata because the 8-bit group B0-15
saturates first". On this program the opposite group is binding: B0-15 is at 2/16
while H0-15 is at 14/16. The reason is visible in `phv_allocation_summary_0.log`:
H0–H13 hold the intrinsic fields (`ucast_egress_port`, `ingress_port`, a compiler
`$tmp`), all six `fabric_h` bytes (they are read and written, so they are "hot", not
tagalong), plus the seven `ig_md_t` fields step 2 actually uses — `role`, `src_leaf`,
`dst_leaf`, `hop`, `next_vsw`, `spray_idx`, `fault`.

Two facts that follow, both measured rather than assumed:

1. **Unused metadata is free.** Ten `ig_md_t` fields are zero-initialized in the
   parser start state and never read; none of them were allocated. So the step-by-step
   PHV numbers in these reports track what each step actually *uses*.
2. **Steps 3–8 need roughly ten more 16-bit metadata fields** (`spray_rand`,
   `spray_hash`, `spray_rr`, `vlink_id`, `rnd_fail`, `path_id`, `attn`, `rnd_attn`,
   `do_measure`, `mirror_sid`) and there are 2 containers left in H0-15. Either the
   allocator spills into the free H32-95 groups, or PHV allocation fails.

**This is now the top resource risk in the build, ahead of stages.** It is the first
thing steps 3 and 4 test, and the mitigations if it binds are, in order:
demote fields that only ever hold small values to `bit<8>` (B0-15 has 14 free
containers), let `md.hop`/`md.vsw_id` be read straight from `hdr.fabric` instead of
being mirrored into metadata, and fold `md.spray_rand`/`spray_hash`/`spray_rr` into
one shared container by making the mode table read a single `md.spray_cand` field.

## Design decisions worth recording

- `to_loop(vlink_id, loop_port, qid, next_vsw)` takes all four as **action data**, so
  the M2 encoding (`vlink_id[3]` = loop port, `vlink_id[2:0]` = qid) lives entirely in
  the control plane. The data plane never computes it.
- `act_enter`/`act_transit` take `next_hop` as action data rather than computing
  `md.hop + 1`. `hop` is already a key of `tbl_final`, so the increment is free in the
  control plane and costs zero data-plane ALU ops.
- `set_dst(dst_leaf, path_base)` ships `path_base = dst_leaf << 2` precomputed —
  the Class 5 (single-stage action arithmetic) mitigation named in §8.4.
- Black hole is implemented exactly as §7.5 asks: delete the `tbl_vlink` row and the
  counted default action drops.
