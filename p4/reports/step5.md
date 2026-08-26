# Step 5 — In-switch attention register, §7.4 update rule, measurement gate

Design reference: `docs/P4-DESIGN-SPACE.md` §5.3, §5.7, §6 D1; PREREG §7.4 (frozen as amendment
v1.3, 2026-08-26). Source hash after this step: `sha256(mcp_fabric.p4) = 584599f469250760…`.

## What was added

- `struct attn_pair_t { bit<16> attn; bit<16> clean; }` — one 32-bit SALU word per path,
  `Register<attn_pair_t, bit<16>>(256) reg_attn`, indexed by `md.attn_idx` (= path id, from
  `tbl_vlink` action data at hops 0/1, from `hdr.csig.path_id` at hop 2, from
  `hdr.evid.path_id` for NIC evidence packets).
- Two RegisterActions, exactly one executes per packet, selected by `tbl_attn` on `md.exceed`
  (const entries 0→`attn_on_clean`, 1→`attn_on_exceed`):
  - exceedance: `if (attn < bump_cap) attn += k_up; clean = 0` → a_max = bump_cap + k_up − 1
  - clean: `if (clean >= n_clean−1 && attn > a_min) {clean=0; attn−=1} else if (clean >= n_clean−1) {clean=0} else {clean+=1}`
  - constants are `RegisterParam`s the controller sets: `p_k_up` (1024), `p_bump_cap` (64512),
    `p_a_min` (256), `p_n_clean_m1` (4095). Defaults are placeholders until tuning (PREREG §3.2).
- Exceedance sources (ingress-visible on Tofino 1): `tbl_exceed_evid` (range on
  `evid.loss_q`, `evid.rtt_q`; both actions also set the index) and `tbl_exceed_csig` (range on
  `csig.worst_qdepth` written by the previous hop's egress — step 7 supplies it).
- Gate: `tbl_gate` — key `md.attn[15:8]` exact + `md.rnd_attn` range; row L matches
  `rnd_attn ∈ [0, L<<8)`; hit sets `md.do_measure=1` and `flags_out |= 1`. Resolution 1/256.
- `fabric_h.flags` is now `fault | measured`: bit0 measured, bit1 dropped (2), bit2 corrupted (4).
- Evidence packets update attention and are dropped; they never enter the fabric.

## Build

Local 9.13.1 and switch 9.13.2: **0 errors, 4 warnings** (2 parser-unroll, 1 cosmetic
key-name substitution for the slice key, 1 benign). `tofino.bin` 1 457 311 bytes on both.

## Stages — 8 ingress (step 4: 7), 0 egress

| Stage | Tables |
|---|---|
| 0 | tbl_port_role |
| 1 | tbl_dst_leaf + the three Random/hash draws + rr SALU |
| 2 | tbl_spray_sel |
| 3 | tbl_spray_mode, tbl_exceed_evid, tbl_exceed_csig |
| 4 | tbl_vlink |
| 5 | tbl_fail, **tbl_attn** (SALU; co-placed as predicted — both depend only on tbl_vlink) |
| 6 | **tbl_gate** (TCAM, 4 blocks) |
| 7 | tbl_final |

Resource use stays low: max per stage 16.4 % exact xbar (1), 33 % hash-dist (1), 25 % meter
ALU (1, 2, 5), 25 % stats ALU (4, 5), 16.7 % TCAM (6). Nothing above 35 %.

## bf-p4c constraints hit (added to the tofino-p4 skill as Classes 9–11)

1. `rnd_attn < attn` in a gateway: **one operand must be a constant** — the design doc's §5.3
   compare cannot exist; replaced by the TCAM gate.
2. 5 RegisterParams + a 65535 constant → **4 parameter slots** per register; dropped `a_max`.
3. `act_attn_clean` as default action → **needs hash-distribution**; const entries instead.
4. Parser: one assignment per field per path — the evidence index moved into MAU actions.

## Control-plane contract (to add to setup_skeleton.py)

- Seed `reg_attn[0..63]` (attn = A0, clean = 0) at startup (Class 8).
- Write the four RegisterParams; `tbl_gate` rows L = 1..255: key attn[15:8]=L, rnd range
  [0, (L<<8)−1], priority any; `tbl_exceed_evid`/`_csig` threshold rows.
- `to_loop` gained a `path_id` action-data field.
