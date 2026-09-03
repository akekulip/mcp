# P3 event/audit placement and model evidence — bf-p4c 9.13.1

This artifact records the fresh 2026-08-29 compile and semantic evidence for
`mcp_fabric_gate_event.p4`. No physical pipeline was loaded during this verification compile.

## Identity and placement

```text
/home/philip/bf-sde-9.13.1/install/bin/bf-p4c --version
p4c 9.13.1 (SHA: e558d01)
```

| item | SHA-256 |
|---|---|
| source | `5f55380eb32d4dbf067c4bba1b21762e6a6ccfa49187ecad740594d85e2850fa` |
| checked-in/generated BFRT schema | `92302aee7d5ce20c59af9e89e49ece96ed0b820269bd5bb5b2b5395cd372b4a3` |
| `table_summary.log` | `42b8e91fc78da3ae57348a9d9344b86692f3f09d2323c67e13374387ca278958` |

```text
Table allocation done 1 time(s), state = INITIAL
Number of stages in table allocation: 11
  Number of stages for ingress table allocation: 11
  Number of stages for egress table allocation: 4
Critical path length through the table dependency graph: 11
Number of tables allocated: 36
```

The previous version of this artifact recorded source
`a356102487c1881fbbf0342489d23818cf7c17559f5925260c4a579f46c607d2` and 35 tables. It is
superseded: that build predated the audit-source provenance key and post-stamp fault injector.
The current 36-table allocation includes `Ingress.tbl_audit_steer`,
`Ingress.tbl_health_gate`, and `Egress.tbl_eg_fail`. Tofino 1 has 12 stages per gress, so the
prototype leaves one ingress and eight egress stages.

## Model semantics

`bash p4/ptf/model/run_gap_event.sh` now compiles the checked-in source into a fresh temporary
directory and reports the source and table-summary hashes before running the suite. It no longer
loads the obsolete 35-table artifact.

The two PTF tests prove:

1. one session-2 event per nonzero C-W4 discontinuity, exact sublink/epoch/gap/arrival attribution,
   and no repeat on the next contiguous packet;
2. production in a quarantined context takes the backup; an audit from an authorized source takes
   the original primary; the source emits no false receipt; downstream arrival emits an exact
   receipt; and audit-shaped traffic from an unauthorized host does not bypass quarantine.

Generator regression tests additionally require the audit provenance key and require the
fault-injection table to execute after witness stamping and before the final evidence comparison.
This prevents regeneration from silently deleting later hand-added mechanisms.

## Claim boundary

This proves a local data-plane producer, attributed collector transport, authorized audit
steering, post-stamp selective fault injection, and receipt semantics on the software model. Newer
`HW-GAP-EVENT.md` and `HW-SELECTIVE-MITIGATION.md` artifacts prove event delivery and manual
selective mitigation separately on silicon. It does not prove an integrated event-driven
controller, end-to-end latency, automatic restoration, or workload value.
