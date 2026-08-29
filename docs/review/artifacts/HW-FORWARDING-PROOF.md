# First hardware forwarding proof — 2026-08-29

The emulated 4x2 fabric forwards on silicon. This is the first end-to-end hardware result in the
project; everything before it was compile reports and simulation.

## Setup

Tofino 1, SDE 9.13.2, `mcp_fabric_gate_event` (11 ingress / 4 egress, 36 tables), loaded after
displacing the sibling program. 10 ports created at 25G RS-FEC, all UP. Fabric configured by
`p4/control/setup_skeleton.py --program mcp_fabric_gate_event up`: `tbl_port_role` 10 rows,
`tbl_dst_leaf` 4, **`tbl_context` 16** (the capsule classifier, live on silicon for the first
time), `tbl_vlink` 64, `tbl_final` 12, spray mode = hash.

## Method

Leaves 2 and 3 both deliver to dp9, which is Vision, so one host proves the whole path:

    dp9 (ROLE_HOST, hop 0) -> spray -> loop port (hop 1) -> loop port (hop 2) -> deliver dp9

200 UDP frames to `10.0.1.3` (leaf 2) and 200 to `10.0.1.4` (leaf 3), source ports 40000..40199,
captured inbound on the same NIC with `tcpdump -Q in`.

## Result — two independent witnesses

**Host capture:** leaf2 200/200 returned, leaf3 200/200 returned, 400 frames inbound.

**On-chip `tbl_vlink` counters** (read `from_hw`, after `SyncCounters`):

| role | hop | src | dst | spray | vlink | packets |
|---|---|---|---|---|---|---:|
| HOST | 0 | 0 | 2 | 0 | 0 | 100 |
| HOST | 0 | 0 | 2 | 1 | 1 | 100 |
| HOST | 0 | 0 | 3 | 0 | 0 | 100 |
| HOST | 0 | 0 | 3 | 1 | 1 | 100 |
| LOOP | 1 | 0 | 2 | 0 | 10 | 100 |
| LOOP | 1 | 0 | 2 | 1 | 14 | 100 |
| LOOP | 1 | 0 | 3 | 0 | 11 | 100 |
| LOOP | 1 | 0 | 3 | 1 | 15 | 100 |

Each 200-frame burst split **exactly 100/100** across the two spines, and the hop-1 rows show the
packets on the correct loop vlinks. The two witnesses were measured independently and agree.

## What this establishes

The whole configured path works on real silicon: port roles (including the new `audit_src` action
parameter added for H35), host-IP-to-leaf mapping, the capsule size/class classifier, spray
selection, vlink resolution and three-hop delivery.

## What it does NOT establish

- The witness/gap path. `tbl_wit_verdict` fails to allocate at load (H42) and no mirror sessions
  are configured yet, so no gap event can reach a collector.
- `egress_qid` correctness. Both vlinks of a pair here resolve through different loop PORTS, not
  through two queues on one port. The port-group queue mapping `(dev_port % 4) * 8 + qid` is still
  untested, and the PTF model never exercised it either.
- Any loss, latency or lifecycle claim.

Traffic from `src_leaf 1` (Hulk, 77/76 packets) and to `dst 0` appears in the counters and is not
from this pilot; the fabric carries other traffic and the per-key counters separate it cleanly.
