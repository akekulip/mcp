# P2 — Behavioural health gate: built, compiles at 10/3, hostile suite 5/5

**Independent verification, 2026-08-28:** the four exact source files were compiled on local SDE
9.13.1 and remote SDE 9.13.2 without loading a pipeline. Both compilers placed armed W4 at 9/3,
C-W4 at 9/4, Context Capsule at 9/3, and Capsule + health gate at 10/3. The earlier 8/3 W4 row was
a stale count and is corrected below.

The piece that makes behavioural sublinks *do* something rather than merely observe: when a
(source, destination, spray path, context) sublink is quarantined, the packet's **spray choice** is
rewritten to a prevalidated backup, and `tbl_vlink` then resolves and counts the path actually
taken.

## Design decisions that matter

**It runs before `tbl_vlink`, never after.** `tbl_vlink` is the counted table. Overriding
forwarding downstream of it would leave the ground-truth counter naming a link the packet never
used — corrupting exactly the evidence the witness exists to provide. Test 43 exists to catch that
mistake specifically: it reads the stamped link id off the wire rather than trusting any table.

**Quarantine is the presence of an entry.** The default action is `NoAction`, so a healthy context —
or one with no entry at all — is untouched and keeps using the same physical link. Revocation is an
entry delete, which means there is no timer and no separate un-quarantine path to get wrong
(test 44).

**It rewrites only the spray index.** One action, one field, single stage. The gate does not choose
ports or queues; it changes which path the existing machinery resolves, so every downstream
invariant (vlink resolution, counting, witness stamping) is unchanged by construction.

## Cost

| variant | ingress / egress stages |
|---|---|
| armed W4 witness | 9 / 3 |
| C-W4 (egress-classified sublinks) | 9 / 4 |
| Context Capsule (source-classified) | 9 / **3** |
| **Capsule + health gate** | **10 / 3** |

From the authoritative `pipe/logs/table_summary.log` of `--verbose 2` builds. The gate costs one
ingress stage relative to Context Capsule. Tofino 1 has 12 per gress, so **2 ingress and 9 egress
remain** — ingress is the binding constraint for anything added later.

## Hostile suite — 5/5 (`p4/ptf/test_health_gate.py`)

The spray choice is pinned (round robin, mask 0) so any change of egress port in these tests is the
gate's doing and nothing else.

| # | gate condition from the plan | result |
|---|---|---|
| 40 | no entry → no action: same physical link, counted correctly | PASS |
| 41 | bad context → rerouted to the prevalidated backup | PASS |
| 42 | **healthy context of the same physical link keeps using it** — a different service class and a different size bin both stay on the original link while the quarantined context reroutes | PASS |
| 43 | counters name the path actually taken; the capsule context survives the reroute intact | PASS |
| 44 | deleting the entry restores the sublink, and the counter follows it back | PASS |
| — | no loops or black holes: every test asserts an actual egress | PASS |

Test 42 is the contribution in one assertion: with one context quarantined, the other contexts of
the same physical link are still carrying traffic on it.

**Confirmed independently in the model's own trace**, not just by the assertions: 4
`sublink_reroute` executions against 4 `tbl_health_gate` hits, and the 8 host packets split exactly
4 to port 0x2 and 4 to port 0x3 — rerouted versus retained.

## What is still required

P3 remains partial: a downstream C-W4 event still needs a real source-to-selector transport, and a
quarantined primary needs explicit probation/audit traffic before restoration. The current
controller decision core programs the exact P2 keys and rejects restoration by silence, but this is
not an end-to-end feedback path. P4 (trace-driven Ring-AllReduce and MoE AlltoAll value) remains
blocked on that observability gate, then silicon. The capacity numbers in `CAPSULE-RESULT.md` assume
an instantaneous post-localization decision.
