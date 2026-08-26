# Step 1 — Skeleton compile (headers, parser, deparser, empty controls)

Design reference: `docs/P4-DESIGN-SPACE.md` §9.2 step 1.
Purpose: prove the on-the-wire header layout parses and deparses, and take the
baseline PHV report before any MAU logic exists.

## Build

```
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
$SDE_INSTALL/bin/bf-p4c --target tofino --arch tna --verbose 2 \
    -o mcp_fabric.tofino --bf-rt-schema mcp_fabric.bfrt.json mcp_fabric.p4
```

**Result: `0 errors, 2 warnings generated.` — bf-p4c exit status 0.**

Both warnings are the same one, emitted twice:

```
warning: Parser state min_parse_depth_accept_loop will be unrolled up to 3 times
         due to @pragma max_loop_depth.
```

This is compiler-generated, not ours: the egress parser deliberately stops after the
L2 shims (§5.5 — everything from IPv4 on is unparsed residual), which is shorter than
Tofino's minimum egress parse depth, so bf-p4c inserts a `min_parse_depth_padding_0`
header stack and pads. Cost is tagalong PHV only (see below), zero MAU.

## Stages

| | value |
|---|---|
| Ingress MAU stages used | **0** of 12 |
| Egress MAU stages used | **0** of 12 |
| Tables allocated | 0 |
| Critical path through the table dependency graph | 0 |

`table_summary.log`:

```
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 1
  Number of stages for ingress table allocation: 0
  Number of stages for egress table allocation: 0
Critical path length through the table dependency graph: 0
Number of tables allocated: 0
```

`mau.resources.log` — every column is 0 across all 12 stages (SRAM, TCAM, Map RAM,
gateways, VLIW, Meter ALU, Stats ALU, Logical TableID all `0` / `0.00%`). The only
row in "Allocated Resource Usage" is `IgParser.$PORT_METADATA` at stage -1.

## PHV baseline (the number that matters for later steps)

MAU groups (`phv_allocation_summary_0.log`):

| MAU group | containers used | bits used | ingress | egress |
|---|---|---|---|---|
| B0-15 | 2 / 16 (12.5 %) | 10 | 10 | 0 |
| B16-31 | 2 / 16 (12.5 %) | 6 | 0 | 6 |
| B32-63 | 0 | 0 | 0 | 0 |
| H0-15 | 1 / 16 (6.25 %) | 10 | 10 | 0 |
| H16-31 | 1 / 16 (6.25 %) | 9 | 0 | 9 |
| H32-95 | 0 | 0 | 0 | 0 |
| W0-63 | 0 | 0 | 0 | 0 |
| **Overall PHV** | **6 (2.68 %)** | 35 bits (0.854 %) | 20 | 15 |

Tagalong collections (headers that are never matched on):

| collection | gress | 8b | 16b | 32b | bits used |
|---|---|---|---|---|---|
| 0 | E | 4/4 | 6/6 | 4/4 | 256 (100 %) |
| 1 | I | 4/4 | 6/6 | 4/4 | 256 (100 %) |
| 2 | I | 4/4 | 6/6 | 4/4 | 256 (100 %) |
| 3 | E | 3/4 | 6/6 | 4/4 | 248 (96.9 %) |
| 4 | I | 0 | 4/6 | 0 | 64 (25 %) |
| 5 | E | 0 | 1/6 | 0 | 16 (6.25 %) |
| 6, 7 | — | 0 | 0 | 0 | 0 |
| **Total** | | 15 (46.9 %) | 29 (60.4 %) | 16 (50 %) | **1096 (53.5 %)** |

**6 of 8 tagalong collections are already occupied at step 1.** Prior work on this
chip records the tagalong wall at 7/8, so this is the resource with the least
headroom in the whole build, and it is spent on header bytes, not on logic. Two of
the six (collections 0 and 3, both egress) are the compiler's
`min_parse_depth_padding_0` payload. If tagalong ever binds, the first lever is the
egress parser, not the ingress tables.

The 8-bit MAU group B0-15 — the group that N12 says saturates first — is at 2/16
containers. That is the number to watch as metadata is added in steps 2–8.

## What this step proves

- The L2-shim layout (`eth | fabric 6B | [csig 12B] | ipv4 | udp | [bth 12B | evid 8B]`)
  parses and deparses on Tofino 1 with no parser-TCAM or PHV complaint.
- Using `fabric_h.nxt` as an 8-bit "what follows" selector (a `select` on a whole
  value, per N11) is accepted by the parser.
- Two separate header structs — `headers_t` for ingress, `eg_headers_t` for egress —
  compile fine and keep the egress parse short.

## Deviation from the design document

`fabric_h`'s sixth byte is named `nxt` and carries `NXT_IPV4`/`NXT_CSIG`, where §3
called it `rsvd`. Reason: the CSIG tag is optional on the wire (inserted at the source
leaf, stripped at the destination leaf), so the parser needs one value to select on.
Header size is unchanged at 6 B and the 16-bit-container-friendly layout is unchanged.
