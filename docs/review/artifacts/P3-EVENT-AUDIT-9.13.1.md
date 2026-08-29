# P3 event/audit placement and model evidence — bf-p4c 9.13.1

This artifact records the exact local compile and semantic evidence for
`mcp_fabric_gate_event.p4`. No physical pipeline was loaded.

## Identity and placement

```text
/home/philip/bf-sde-9.13.1/install/bin/bf-p4c --version
p4c 9.13.1 (SHA: e558d01)
```

| item | SHA-256 |
|---|---|
| source | `a356102487c1881fbbf0342489d23818cf7c17559f5925260c4a579f46c607d2` |
| `table_summary.log` | `0dec930e963e414e698dbdffbcfa2074e38a860c9e3eee65ff81d4d0dde0cbbe` |
| `resources.json` | `1ec5c422769f9bd91078733cd56aa6691865ad06912e66c15e40ac212c1ce1a7` |

```text
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 11
  Number of stages for ingress table allocation: 11
  Number of stages for egress table allocation: 4
Critical path length through the table dependency graph: 11
Number of tables allocated: 35
```

The allocation contains `Ingress.tbl_audit_steer`, `Ingress.tbl_wit_count`,
`Ingress.tbl_health_gate`, and the final forced-event gateway/action. Tofino 1 has 12 stages per
gress, so the prototype leaves one ingress and eight egress stages. The raw build is under
`/tmp/mcp-p3-capsule-fix.htpOQ9` for this run.

## Model semantics

`bash p4/ptf/model/run_gap_event.sh` passes both tests on the Tofino software model:

1. one session-2 event per nonzero C-W4 discontinuity, exact sublink/epoch/gap/arrival attribution,
   and no repeat on the next contiguous packet;
2. production in a quarantined context takes the backup, a declared audit takes the original
   primary, the source emits no false receipt, downstream arrival emits an exact audit receipt,
   and a declared packet that is not re-injected produces no positive receipt.

The second test uses real fabric vlinks 2 and 3. It exposed two defects before passing: a source
pass initially manufactured a receipt after inserting its own witness, and a packed-width parser
copy changed context zero to `0x0100`. Both are fixed in the generated source and guarded by tests.

## Claim boundary

This proves a local data-plane producer, attributed collector transport, exact audit steering, and
receipt semantics on the software model. It does not measure silicon event-to-gate latency, provide
the production packet-injection/topology adapter, authenticate the reserved UDP audit marker, or
prove workload value. Those remain P3/P4 gates.
