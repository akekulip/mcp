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

---

# Second defect, same family: the bank parity did not survive transit

Found immediately after the hop fix, by the 10-trial rate run it enabled.

## Symptom

Fault detection was 9/9, but the CONTROL arm reported a blackhole in 5 of 9 trials (56%),
where PREREG rule 1 requires 0%.

## The control failures were not noise — they were perfectly deterministic

`clf_trials.py` alternates the measurement bank per trial (`bank = i % 2`):

| trials | bank | control arm |
|---|---|---|
| 1, 3, 5, 7 | 0 | correct, 0/4 false |
| 2, 4, 6, 8, 10 | 1 | **false blackhole, 5/5** |

Every bank-1 trial failed and no bank-0 trial did. A 56% "false positive rate" was one bug
with a 100% hit rate on half the trials.

## Cause

TX is marked at the SOURCE leaf's egress and RX at the SPINE's egress. `act_transit` runs at
the spine's ingress, between them, and wrote:

```p4
hdr.fabric.flags = (bit<8>)md.flags_out;     // bank bit erased
```

while `act_enter` had stamped the parity into `hdr.fabric.flags` bit 3. So RX was always
recorded in bank 0 while TX went to bank B. With B=0 they agreed and everything looked
correct; with B=1 every sublink showed TX with no RX — a false blackhole on every one.

This is the same shape as the hop defect: the comment above `act_enter` stated the intent
outright — "stamped ... at the SOURCE so every switch the packet traverses agrees which
frontier bank the packet belongs to" — and the implementation did not honour it.

## A second, latent defect found while fixing the first

The bank shared **bit 3 of `flags` with `set_gap_event()`** (`md.flags_out |= 8`). A packet
raising a gap event would be stamped into the wrong bank. It never fired in these trials
because a full blackhole leaves no surviving packet to reveal a gap — the structural limit
C-W4 already has — but it would corrupt every reading the moment the controller loop runs
with real gap events. Found by reading the bit allocation, not by a test.

## Fix — and why it is not in `flags`

The parity now rides `hdr.fabric.clf_bank`, the byte formerly declared as `loops` (§7.4 L1
extra latency loops: written to 0 once, never read, never implemented).

Two compiler constraints ruled out the alternatives, and both are worth recording:

* Preserving the bit across transit needs `flags = md.flags_out | (flags & BANK)`, which
  bf-p4c rejects: *"or: action spanning multiple stages"* (constraint class 5).
* Pre-computing the mask in the parser is also rejected: *"Assignment source cannot be
  evaluated in the parser"*. The parser does plain copies, not arithmetic.

The dead byte solves both by construction: `act_transit` does not write it, so the parity
survives every transit hop with no OR, no extra table, no stage, and no wire bytes. Bits 0-4
of `flags` are taken (1, 2, 4, 8, 16, and 24 = 8|16), so there was no free bit there anyway.

Compiles 11 ingress / 5 egress — unchanged, as with the hop fix.

## Lesson

Both defects were found the same way and neither needed a new experiment: the code was
checked against its own stated intent. A comment that says what a mechanism does is a
testable claim about the implementation, and in both cases the implementation disagreed.

---

# Rates on the corrected build, and a third masking window

## Result after the bank fix (10 trials/arm, guard 2.0 s, one directed link)

| metric | before bank fix | after bank fix | PREREG |
|---|---|---|---|
| control false-blackhole rate | 56% (5/9) | **0% (0/10)** | rule 1 requires 0% — **met** |
| IMPOSSIBLE verdicts | 1 per trial, every trial | **0** | rule 5 requires 0 — **met** |
| fault detection | 9/9 | 8/9 (89%) | rule 1 requires >= 95% — **not yet met** |
| false blackholes (non-target) | 1 | 0 | — |

Rule 5 is satisfied and the control half of rule 1 is satisfied. The fault half is not, and
the single miss has an identified cause rather than being noise.

## The miss: a third way an RX bit can mask a blackhole

Trial 6 reported HEALTHY for the target sublink with **401 packets dropped** by the injector.
A blackholed sublink cannot legitimately show an arrival, so something else set RX.

The driver's own ordering was the cause:

```
N bank -> guard -> Z (zero) -> verify -> K (arm) -> settle -> probe
                               ^^^^^^^^^^^^^^^^^^ ~0.8 s with the target LIVE
```

Between the reset and the arm, the target sublink still forwards. One stray background packet
arriving in that window sets RX=1, and that bit masks the blackhole for the whole trial.

This is the *third* distinct source of the same failure — an RX bit that does not belong to
the measured traffic reads as evidence of health:

1. stale residue from earlier runs (no zero step at all);
2. the source leaf marking its own egress as an arrival (the hop defect);
3. a background packet arriving between the zero and the arm (this one).

The fabric is not silent: `dropped=401` and `402` against `sent=400` show background traffic
on the target sublink, and one trial was excluded outright for `zero did not take,
rows [(1, 0, 2, 2)]` — background traffic marking both TX and RX immediately after the reset.

**Fix:** arm before zeroing. Once the injector is armed, nothing can mark RX for the target,
so the reset is the last thing to touch that sublink before the probe.

## Standing caveat

`TX & ~RX` is only as trustworthy as the claim that RX was set by the traffic under
measurement. Every defect in this document is a different way that claim failed. A blackhole
result should therefore always be reported beside the injector's drop count, which is what
`clf_trials.py` now prints on every line: a detection with `dropped=0`, or a miss with
`dropped>0`, is a harness statement before it is a result.
