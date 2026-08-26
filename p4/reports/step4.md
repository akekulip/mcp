# Step 4 — Failure injection (forked from `sdnp_exp.p4`)

Design reference: `docs/P4-DESIGN-SPACE.md` §9.2 step 4, mechanisms §7.1–§7.3, §7.6.
Source forked: `/home/philip/Projects/dnp3-research/research/synthesis/validation/tofino/sdnp_exp.p4`
lines 54–89 (silicon-verified 2026-06-27) and its control plane `sdnp_setup.py:62-89`.

Added: `Random<bit<16>> rng_fail`, `DirectCounter fail_ctr`, `tbl_fail` with an exact
`md.vlink_id` key and a 16-bit `md.rnd_fail` **range** key, and the three actions
`inj_drop` / `inj_corrupt` / `inj_none`.

## Build

**Result: `0 errors, 2 warnings generated.` — bf-p4c exit status 0.** First compile.

## Stages — 7 ingress, 0 egress (step 3: 6 / 0)

```
Number of stages for ingress table allocation: 7
Critical path length through the table dependency graph: 7
Number of tables allocated: 11
+-------+-----------------+------------------------+
| Stage | Min / Max Stage |       Table Name       |
+-------+-----------------+------------------------+
|   0   |    [ 0, 5 ]     | Ingress.tbl_port_role  |
|   1   |    [ -, - ]     |   tbl_mcp_fabric537    |   <- anonymous: the four draws
|   1   |    [ -, - ]     |   tbl_mcp_fabric543    |
|   1   |    [ 1, 7 ]     |   tbl_mcp_fabric547    |
|   1   |   [ 1, 11 ]     |   tbl_mcp_fabric530    |
|   2   |    [ 2, 7 ]     | Ingress.tbl_spray_sel  |
|   3   |    [ 3, 8 ]     | Ingress.tbl_spray_mode |
|   3   |    [ 1, 8 ]     |  Ingress.tbl_dst_leaf  |
|   4   |    [ 4, 9 ]     |   Ingress.tbl_vlink    |
|   5   |   [ 5, 10 ]     |    Ingress.tbl_fail    |
|   6   |   [ 6, 11 ]     |   Ingress.tbl_final    |
+-------+-----------------+------------------------+
```

`tbl_fail` costs exactly **+1 stage**, and it is a genuine dependency, not a placement
accident: its key is `md.vlink_id`, which `tbl_vlink` produces in stage 4.

Note also that **`tbl_dst_leaf` moved from stage 1 to stage 3** between step 3 and
step 4 without being touched. Placement is not monotonic in program size; read the
report, never assume a table stayed where it was.

## Per-stage resources (non-zero columns)

| stage | Exact xbar | Ternary xbar | Hash bits | Gateway | SRAM | Map RAM | **TCAM** | VLIW | Meter ALU | Stats ALU | LTIDs |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 2 | 0 | 10 | 0 | 1 | 0 | 0 | 1 | 0 | 0 | 1 |
| 1 | 17 | 0 | 32 | 3 | 2 | 2 | 0 | 3 | 1 | 0 | 4 |
| 2 | 4 | 0 | 54 | 0 | 7 | 2 | 0 | 1 | 1 | 0 | 1 |
| 3 | 8 | 0 | 80 | 0 | 8 | 0 | 0 | 4 | 0 | 0 | 2 |
| 4 | 10 | 0 | 40 | 1 | 10 | 5 | 0 | 2 | 0 | 1 | 1 |
| **5** | 0 | **6** | 0 | 0 | 3 | 2 | **2** | 2 | 0 | **1** | 1 |
| 6 | 4 | 0 | 40 | 0 | 4 | 0 | 0 | 3 | 0 | 0 | 1 |

**Stage 5 is the first TCAM in the entire program: 2 TCAM blocks, 6 ternary crossbar
bytes, 1 Stats ALU** (the `DirectCounter`). The 16-bit range key behaves exactly as
Class 2 predicts — 4 of the 5 range nibbles. There is now no room for a second range
field in this table; a second range condition needs its own table.

Peak logical table IDs is still 4 of 16 (stage 1). LTIDs are not the binding resource
in this program, which is the opposite of what prior defense4/GridCloak work found —
worth stating, because it means the "use textual macros instead of named actions"
mitigation (N10) is not needed here yet.

## PHV — H0-15 stayed full and the allocator spilled DOWN, not sideways

| MAU group | step 2 | step 3 | step 4 |
|---|---|---|---|
| **B0-15 (8-bit, ingress)** | 2/16 | 3/16 | **5/16 (31.2 %)**, 35 bits |
| B16-31 (8-bit, egress) | 2/16 | 2/16 | 2/16 |
| **H0-15 (16-bit, ingress)** | 14/16 | **16/16** | **16/16 (100 %)**, 242 bits |
| H16-31 (16-bit, egress) | 1/16 | 1/16 | 1/16 |
| H32-47 (16-bit, free) | 0/16 | 0/16 | **0/16** |
| W0-15 (32-bit, ingress) | 1/16 | 3/16 | 4/16 |
| Overall PHV | 20 (8.93 %) | 25 (11.2 %) | 28 (12.5 %) |
| Tagalong | 1000 b (48.8 %) | 952 b (46.5 %) | 936 b (45.7 %) |

The one new metadata field, `md.rnd_fail` (`bit<16>`), could not fit in H0-15 — so
bf-p4c **split it across two 8-bit containers in B0-15** (B went 3 -> 5 containers,
19 -> 35 bits) rather than using the completely empty H32-47 group.

That answers the question step 2 raised, and it is the single most useful placement
fact this compile sequence has produced so far:

- **The ingress 16-bit MAU group does not spill into the next 16-bit group.** H32-47
  stayed at 0/16 through three steps of growth.
- **It spills into the 8-bit group instead**, at two containers per `bit<16>` field.
- Therefore the real remaining metadata headroom is **B0-15's 11 free containers ≈ 5
  more `bit<16>` fields**, not "the chip is only 12 % full".

Steps 5–8 want roughly five more metadata fields (`attn`, `rnd_attn`, `do_measure`,
`mirror_sid`, `path_id`), which is exactly at that limit. Mitigations, cheapest first:

1. Declare the remaining new metadata `bit<8>` where the value provably fits (`attn`
   and `rnd_attn` are 8-bit by design in §5.3; `do_measure` is one bit). That halves
   the container cost and stays legal — Class 3 forbids going *below* 8 bits, not
   using 8.
2. Stop mirroring `hdr.fabric.hop` / `vsw_id` into metadata and match on the header
   fields directly; that returns containers to H0-15.
3. Reuse `md.spray_rand` as the attention draw. Both are `Random` outputs consumed in
   different stages, and §5.3 needs 8 bits of it.

## Semantics fixed in this step

- **`md.rnd_fail` is drawn on every fabric pass**, not once per packet, because each
  pass crosses a different virtual link and each link has its own failure profile. It
  is drawn next to the other independent draws so it co-places in stage 1 rather than
  serialising behind `tbl_vlink`.
- **`tbl_fail` is applied only when `md.hop != LAST_HOP`.** The destination-leaf pass
  is not on a virtual link, so no virtual link can fail it. Without this guard the
  delivery pass would be exposed to a `vlink_id` left over from the previous pass.
- **`md.fault` is carried into `fabric_h.flags`** by `tbl_final`, so a fault-injected
  packet is marked on the wire and a collector capture can tell an injected loss from
  a real one. This is what makes §7.6's ground-truth claim checkable end to end.
- **Ground truth is per row.** `fail_ctr.count()` is called from all three actions
  including the default `inj_none`, so forwarded, dropped and corrupted are all
  counted per virtual link. Read with `t.operations_execute(tgt, "SyncCounters")`
  first — mandatory, per `sdnp_setup.py:107-115`.

## Still to wire, and where

- `inj_drop` must also arm mirror session 3 before dropping, so the collector gets a
  trimmed header for every injected drop (§5.6). That is step 6: add
  `md.mirror_sid = 3; ig_dprsr_md.mirror_type = 3w1;` to `inj_drop` and emit in the
  ingress deparser. `simple_l3_mirror.p4:456` shows the composition, and confirms the
  mirror still fires on a dropped packet because the mirror is taken in the deparser.
- Latency inflation L1 (§7.4) needs `tbl_delay` writing `fabric_h.loops`; L2 (the
  recommended primary mechanism) is a TM queue shaper and needs no P4 at all.
