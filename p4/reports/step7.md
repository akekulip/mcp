# Step 7 — CSIG-style "worst hop so far" tag (egress compare-and-replace)

Design reference: `docs/P4-DESIGN-SPACE.md` §5.5. Source hash after this step:
`sha256(mcp_fabric.p4) = 232b7355fe58c67c…`. Wire format inside the fabric is now
`eth | fabric_h 8B | csig_h 14B | ipv4 …`.

## What was added / changed

- `fabric_h` grew a 16-bit `path_id` (6 → 8 B): written by `act_enter`, it lets every pass
  index `reg_attn` from the shim (`parse_fabric` sets `md.attn_idx`) and lets egress stamp the tag.
- `csig_h` is 14 B, all fields ≥ 16 bit: `worst_hop`, `worst_vlink`, `worst_qdepth` (16),
  `worst_tdelta` (32), `path_id`, `epoch`.
- **Insertion happens in INGRESS** (`act_enter`, source leaf): tag set valid and zeroed,
  `path_id` = `md.attn_idx`, `epoch` = `tbl_final` action data, `fabric.nxt = NXT_CSIG`.
- **Egress** (`if (hdr.csig.isValid())`): `tbl_eg_vlink` maps (egress_port, egress_qid) →
  `vlink` (control-plane data, same encoding as ingress) and stages `this_q`, `hop`, `tdelta`;
  `tbl_csig_diff`: `diff = worst_qdepth |-| this_q`; `if (diff == 0)` → `tbl_csig_replace_a`
  (hop, qdepth) then `tbl_csig_replace_b` (vlink, tdelta). Because the tag starts zeroed, hop 0's
  own queue depth is recorded on the first pass. Stripping stays in ingress `act_deliver`.
- No bridged metadata: hop and path_id come from the shim, the virtual link from (port, qid).

## Build

Local 9.13.1 and switch 9.13.2: 0 errors. **Ingress is now 9 stages** (0–8: `tbl_final` moved
from 7 to 8 once `act_enter` also initializes the tag) — exactly the §8.1 target of ≤ 9, so the
next ingress feature must reuse a stage or spend one of the README levers. Egress uses 3 stages
(tbl_eg_vlink → tbl_csig_diff → replace_a + replace_b). `tofino.bin` 1 461 583 bytes (both SDEs).

## bf-p4c constraints hit on the way (Classes 12–13 in the tofino-p4 skill)

1. §5.5's `if (this_q > worst_qdepth)` is Class 9 (two runtime operands): replaced by a
   saturating subtract and an equality-with-zero gateway.
2. `deq_timedelta` is **18 bits** on Tofino 1, not 32: explicit widening cast.
3. **A mid-word slice of intrinsic metadata (`deq_qdepth[18:3]`) breaks egress PHV allocation**
   ("Unable to slice the following group of fields … eg_intr_md.*"); the low slice `[15:0]` is fine.
4. **Egress header-write packing**: adjacent 16-bit tag fields share a container and an action may
   fill it from one source (two only if the sources are already co-packed); zero-extending casts
   count as constants. Fix used: write each packed pair from two actions in two tables, stage
   widened sources in metadata, and insert/initialize the tag in ingress (whose action data is
   unconstrained) so egress never writes `path_id|epoch`.

## Control-plane contract

- `tbl_final.act_enter` gained an `epoch` action-data field (controller epoch parity).
- `Egress.tbl_eg_vlink`: rows for all 8 loop ports × 2 qids → vlink id.
- `tbl_exceed_csig`: threshold row in cells (not 8-cell units) after this change.
