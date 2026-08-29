# P2 placement evidence — bf-p4c 9.13.1

This artifact records the exact local compile evidence used by the P2/P3 audit. It is intentionally
small enough to review in Git while retaining the compiler identity, source identity, output-log
identity, placement totals, and the health-gate table's presence. No pipeline was loaded.

## Compiler

```text
/home/philip/bf-sde-9.13.1/install/bin/bf-p4c --version
p4c 9.13.1 (SHA: e558d01)
```

## Source and output identities

| variant | source SHA-256 | `table_summary.log` SHA-256 | `resources.json` SHA-256 |
|---|---|---|---|
| armed W4 | `208f888f6f83080c5ea380096324c2fc04c91d601c9da275e4e1d5fb01610873` | `91dbf21e373f15af851d7064d0850a46ecddbde0a46c5e40f030e9f334c59f06` | `bfb0000ac09bebca22c58ead3082d456cca19737ec8ea799ddec94f969f6bb1d` |
| C-W4 | `deccd483db14bbe376d5b8f9db905a124ebe2eb876253893532004eec98f970e` | `ccf48e9ce29b8a9e3919565cebc1cd707411bc3ac59f1d571426087419842875` | `cb459b60aeb669883a0454af306a1fe33ebb582f8e88ac83e4fb6b72db1c909b` |
| Context Capsule | `f640a45089c45fde7340b653ca0f845f411d7dd55839614347a1476956cf299a` | `30348ee712dcf97432a653d6756d50b58ce9bce0e2ea78f9af827b43f616486c` | `9b64b0419ec99c8eaea6f94e7ddeacb0f92c95a4b1b3c1cb53438e4b49d85d3e` |
| Capsule + health gate | `d6f7e7c25c2d674206e6170e93da097e804f9cf33b89d1cb2eb41ba842eff3d8` | `65a666ec6a533541144867453f1d4984cc10ed76174e90b16ba3f1dfd2aee23e` | `267d7a1236da6ba22130d3285c33ef809ab7eb0b600ce44a96c7f0de49825449` |

## Verbatim placement totals

```text
# mcp_fabric_w4_arm.tofino/pipe/logs/table_summary.log
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 9
  Number of stages for ingress table allocation: 9
  Number of stages for egress table allocation: 3
Critical path length through the table dependency graph: 8
Number of tables allocated: 26

# mcp_fabric_cw4.tofino/pipe/logs/table_summary.log
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 9
  Number of stages for ingress table allocation: 9
  Number of stages for egress table allocation: 4
Critical path length through the table dependency graph: 8
Number of tables allocated: 27

# mcp_fabric_capsule.tofino/pipe/logs/table_summary.log
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 9
  Number of stages for ingress table allocation: 9
  Number of stages for egress table allocation: 4
Critical path length through the table dependency graph: 8
Number of tables allocated: 28

# mcp_fabric_gate.tofino/pipe/logs/table_summary.log
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 10
  Number of stages for ingress table allocation: 10
  Number of stages for egress table allocation: 4
Critical path length through the table dependency graph: 9
Number of tables allocated: 29
```

The gate build's table allocation includes the following entry, proving that the reported 10/4
program is the health-gate variant rather than the stale baseline artifact under
`p4/mcp_fabric.tofino`:

```text
|   4   |    [ 4, 7 ]     |  Ingress.tbl_health_gate  |
```

The corrected capsule and gate logs remained under disposable compile directories
`/tmp/mcp-capsule-final.tOFJHl` and `/tmp/mcp-gate-final.sjxlgc`. The 2026-08-29 rebuild is
load-bearing: the earlier 9/3 and 10/3 sources widened the packed 8-bit shim pad directly into
16-bit egress metadata, and the model trace showed the adjacent `nxt` byte contaminating the
context (`ctx=0` became `0x0100`). Keeping the parser copy 8-to-8 and writing only the low context
nibble fixes real vlinks 0--15 at the honest cost of one egress stage. The hashes above make copied
raw logs independently checkable; this Markdown artifact is the durable in-repository record.
