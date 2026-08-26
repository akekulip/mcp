# Step 8 — Evidence header: delivered inside step 5

§9.2 step 8 ("parser arm plus the second RegisterAction on `reg_attn`") is already in the
program since step 5: `parse_evid` (UDP dst 0xE5E5 → `evid_h`), `tbl_exceed_evid` (range on
`loss_q`, `rtt_q`; both actions set `md.attn_idx = evid.path_id`), and `attn_on_exceed` —
the second RegisterAction on `reg_attn` — executed for exceedance packets. Evidence packets
update attention and are dropped at the switch; they never enter the fabric. Nothing further to
compile. The NIC-side producer of evidence packets (§6 D1, `nic/`) is host-side work.

All eight §9.2 steps are therefore implemented: `sha256(mcp_fabric.p4) = 1a8fc6104b03bcdf…`,
ingress 9 stages, egress 3, 0 errors on SDE 9.13.1 and 9.13.2.
