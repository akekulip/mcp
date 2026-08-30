# CLF frontier hop semantics — a standing IMPOSSIBLE verdict, and what caused it

**Date:** 2026-08-30. **Program:** `p4/witness/mcp_fabric_clf_eg.p4`.
**Build before fix:** `87cc6a5cdf9c6c65…`. **Build after fix:** manifest
`29fed8b6f0317e14607e603923989d58a6264bca6393acf87c3ea1d3e09dcc2b`, 11 ingress / 5 egress
(unchanged — the fix costs nothing).

## Symptom

Every CLF trial, on both the fault and the control arm, reported exactly one IMPOSSIBLE verdict
(TX=0, RX=1) at vlink 0, context 0. PREREG rule 5 requires IMPOSSIBLE to never occur, so the
rule was failing on every single trial.

## Cause

`md.hop` in EGRESS names the hop the packet is being sent **to**, not the one it is at: ingress
has already advanced `hdr.fabric.hop` (`act_enter` writes 1, `act_transit` writes 2). Both
frontier tables were keyed on `md.hop` with entries chosen for *ingress* numbering:

| pass | ingress hop | action | egress `md.hop` | crossed a link? |
|---|---|---|---|---|
| 1 — source leaf | 0 | `act_enter` → hop=1 | **1** | **no** |
| 2 — spine | 1 | `act_transit` → hop=2 | 2 | yes |
| 3 — dest leaf | 2 = `LAST_HOP` | `act_deliver` | 2 | yes |

`tbl_rx_frontier` held `{1, 2}`. Entry 1 can only ever match the source leaf's own egress —
`act_enter` is the sole writer of hop=1 and it is host injection by definition. So every packet
marked an "arrival" before it had crossed any link, at index `hdr.witness.link_id`, which is
still the ingress-zeroed **0** because `tbl_wit_link` stamps later in the same apply block.

Index 0 is a legal sublink (vlink 0, context 0), not a reserved sentinel. The unstamped source
mark was therefore indistinguishable from a genuine arrival on vlink 0 / context 0.

`tbl_tx_frontier` held `{0, 1}` and carried the same off-by-one in the other direction: entry 0
is dead — nothing presents `md.hop == 0` in egress — while entry 1 fires at the source leaf,
which is *accidentally* the correct place to commit the source→spine link. The comment on that
table ("hop 0 leaving the source leaf, hop 1 leaving the spine") documented ingress numbering
and is what misled both tables.

## Proof, from data already collected

The fault arm settles it without a new experiment. With sublink 2 blackholed, the injector
counter read exactly **400** against 400 probes sent: every packet was discarded at
`tbl_eg_fail`, which runs *after* `tbl_rx_frontier` in the same egress apply block. Not one
packet reached a downstream hop. RX nevertheless registered an arrival. The only site that
could have written it is the source leaf's own egress.

## Fix

`tbl_rx_frontier` → `{ 2 }` (the spine's egress, the one genuine arrival over a directed link).
`tbl_tx_frontier` → `{ 1 }` (dead entry 0 removed). Both comments rewritten to state the egress
numbering explicitly, since the wrong mental model is what produced the defect.

## Before and after, same protocol, same probe

| arm | before | after | reading |
|---|---|---|---|
| fault (sublink 2 blackholed) | `TX=0x0004 RX=0x0001` | `TX=0x0004 RX=0x0000` | detected; phantom arrival gone |
| control (no fault) | `TX=0x0004 RX=0x0005` | `TX=0x0004 RX=0x0004` | healthy; zero blackholes |

Across the first 3-trial set on the corrected build: IMPOSSIBLE **0** in every trial, fault
detection 3/3, false blackholes 0.

## Coverage limit this exposed — CLF observes ONE directed link

The spine's egress (`md.hop == 2`) is deliberately **not** a TX site. Its arrival counterpart
would have to be recorded at the destination leaf, and it is not: `csig` is removed at
`LAST_HOP`, so the CLF block never runs there. Committing a link whose arrivals cannot be
observed would report a permanent, unfalsifiable blackhole on that link.

Evidence that the destination leaf records nothing: every reading returns a **single vlink row**
(`F 0 0 …`). Had pass 3 marked RX, a second vlink — the spine→leaf link — would appear.

So a CLF verdict today is a statement about the **first directed link (source leaf → spine)**,
not about the whole path. Extending to the second link is separate work and requires resolving
the `LAST_HOP` header-removal question first. Any paper claim must carry this scope.

## Why this was missed for so long

Two agreeing instruments are not a cross-check when they share an input — the lesson already
recorded in the repository's standing rules. Here the failure was narrower and worth naming:
the *encoding* had no way to say "absent". Because sublink 0 is a valid address, "no upstream
stamp" and "arrived on vlink 0, context 0" are the same 16-bit value. A reserved index, or a
validity bit, would have made the defect a loud error instead of a plausible verdict.
