# The restoration lifecycle on silicon — and a bring-up defect that invalidated earlier vlink labels

**Date:** 2026-08-30. Program `mcp_fabric_clf_eg.p4`. `BEHAVIORAL-SUBLINK-PLAN.md` P3 records the
open half of the lifecycle as: *"no running controller has yet injected sufficient probation
traffic, consumed all declared receipts, and removed the gate on silicon."*

## A bring-up defect found first, which changes an earlier conclusion

`tbl_eg_vlink` maps (egress_port, egress_qid) -> virtual link and is what composes `md.vlink`,
hence `md.sublink = (vlink << 4) | ctx`. It carries:

```p4
const default_action = set_eg_vlink(0, 0);
```

so a **miss yields vlink 0**. It is installed by `setup_attention.py`, **not** by
`setup_skeleton.py`. Every bring-up in this session ran only `setup_skeleton.py up`, so the table
was empty and every packet's vlink collapsed to 0.

Proven directly. With a health-gate row installed to reroute spray 0 -> 1, the independent ingress
vlink counter reported the truth while the frontier did not:

```
role=1 hop=0 src=0 dst=2 spray=1 vlink=1 pkts=30     <- ingress counter: traffic really on vlink 1
X 0 0 2 30 0                                          <- frontier claimed vlink 0
```

After running `setup_attention.py up` (`tbl_eg_vlink: 16 rows installed`):

```
no gate  -> X 0 0 2 30 30      (vlink 0)
gate ON  -> X 0 1 2 30 30      (vlink 1)
```

**This corrects an earlier conclusion.** `HW-CLF-FRONTIER-PLACEMENT.md` attributed the
`TX=20 RX=20` double-count to "the second link has no distinct sublink identity", and the frontier
entries were reverted from `{1,2}` to `{1}` on that basis. The observation was real; the
attribution was wrong. The cause was this uninstalled table, and with it populated the two hops
resolve to different vlinks, so the two-link entries may now be correct. **That revert rests on a
falsified premise and must be re-tested.** It has not been, so the shipped build still marks one
link per frontier.

Consequence for every measurement taken earlier in the session: the **ctx** dimension was always
correct and all TX/RX counts stand, but the **vlink** label was uniformly 0 and carried no
information. All of those runs used a single virtual link, so no result changes; only the labels
were meaningless.

## The lifecycle

Sublink (vlink 0, ctx 2), 30 packets per step, health gate rerouting spray 0 -> 1.

| step | frontier | what it shows |
|---|---|---|
| 1. healthy | `vlink0/ctx2 TX=30 RX=30` | baseline |
| 2. fault injected | `vlink0/ctx2 TX=30 RX=0` | BLACKHOLE |
| 3. quarantine installed | `vlink1/ctx2 TX=30 RX=30`, **no vlink0 row** | production moved to the backup and is healthy there; the faulty sublink reads TX=0 RX=0 |
| 4. fault cleared, gate still on | `vlink1/ctx2 TX=30 RX=30`, **no vlink0 row** | the link is repaired and there is still no evidence of it |
| 5. probation | `vlink0/ctx2 TX=30 RX=30` | declared audit flow bypasses the gate and delivers 30/30 |
| 6. gate removed | `vlink0/ctx2 TX=30 RX=30` | production returns, healthy |

Three things are measured here that the project has argued for but not previously shown together
on hardware:

1. **Selective mitigation works.** Production moves to the backup sublink and is healthy there,
   while the physical port and every other context keep running.
2. **Mitigation destroys the passive evidence** — the premise the whole "counterfactual
   observability" direction rests on. Steps 3 and 4 are indistinguishable from the quarantined
   sublink's point of view: it is IDLE in both, whether the link is broken or repaired. The
   frontier returns TX=0 RX=0, which the frozen truth table classifies as **IDLE, never HEALTHY**
   — absence of demand is not evidence of health.
3. **Probation restores the evidence** without returning production to a suspect link.
   `tbl_audit_steer` admits a controller-declared flow to a deliberate `tbl_health_gate` bypass,
   and the frontier then reads 30/30 on a sublink production is still avoiding.

## Scope — what this is NOT

This is a **scripted** lifecycle: the sequencing, the probation round and the restore decision were
driven by a shell script issuing agent commands. It demonstrates that the data-plane path exists
end to end on silicon and that every state transition is observable.

It is **not** the running controller making those decisions. `controller/sublink_feedback.py`
holds the tested decision core — `AuditReceipt`, the bounded probation-round matcher,
`probation_packets_required`, flap damping — and none of it was in the loop here. The plan's
wording, *"no running controller has yet injected sufficient probation traffic, consumed all
declared receipts, and removed the gate"*, is therefore still only half discharged: the mechanism
is proven, the autonomous decision path is not.

Also unmeasured: how much probation traffic is *sufficient*. Step 5 used 30 packets because that
is what the other steps used, not because
`probation_packets_required(p_restore_target, restore_alpha)` said so.
