# Context Capsule (P1): closes the class-selective gap completely, and reclassifies the other one

Built against `docs/review/BEHAVIORAL-SUBLINK-PLAN.md` P1 and measured against the two negative
controls that `CW4-CAPACITY-GATE.md` left open at 25 oracle-gap points each.

## What it is

C-W4 classified at the **egress**, where the only thing visible is `eg_intr_md.pkt_length`. Service
class is not visible there at all, which is why a class-selective fault cost 25 points. The source
leaf is the one place in the fabric where the IPv4 header is still parsed, so the capsule
classifies once, there, into a 4-bit context = size bin × DSCP class, and carries it in the fabric
shim's **existing pad byte**. Every hop then indexes its witness by `(vlink << 4) | context`, and
transit and downstream agree by construction because they read the carried label instead of
re-deriving it from whatever they happen to see.

**It is also cheaper than C-W4**: 9 ingress / **3** egress against C-W4's 9 / 4, because the egress
no longer needs a range classifier — it reads a label and ORs it. Zero added wire bytes; the packet
size does not vary with the context it carries (asserted in the suite).

## Model tests — 4/4 pass (`p4/ptf/test_capsule.py`)

| # | assertion | result |
|---|---|---|
| 30 | same size, **different service class** → different behavioural sublinks | PASS |
| 31 | a gap in one class leaves the other class of the same link, at the same size, contiguous | PASS |
| 32 | zero wire cost: shim stays 12 B, witness stays 4 B, packet size independent of context | PASS |
| 33 | all 16 contexts (4 sizes × 4 classes) hold independent sequences | PASS |

## Capacity — the two open controls

Safe delivery fraction across the frozen headroom sweep:

**Class-selective negative control — closed, 100 %:**

| alternate headroom | directed W4 | C-W4 | **capsule** | oracle |
|---|---|---|---|---|
| 0.00 | 50.0 % | 50.0 % | **75.0 %** | 75.0 % |
| 0.10 | 55.0 % | 55.0 % | **80.0 %** | 80.0 % |
| 0.25 | 62.5 % | 62.5 % | **87.5 %** | 87.5 % |
| 0.50 | 75.0 % | 75.0 % | **100.0 %** | 100.0 % |

The capsule matches the oracle exactly at every headroom — the full 25 points, recovered because
the class is now carried rather than inferred.

**Misaligned size boundary — not closed by the capsule, and it is not a mechanism limit.** With the
frozen bins the capsule is identical to C-W4 (50 / 55 / 62.5 / 75 against the oracle's
75 / 80 / 87.5 / 100). The fault drops packets above 1500 B, and 1500 falls *inside* the
1024–2047 bin, so no label can separate the demand. Placing a boundary at 1500 closes it outright:

| size boundaries | bins | capsule @ headroom 0 | oracle | gap |
|---|---|---|---|---|
| (256, 1024, 2048) — frozen | 4 | 50.0 % | 75.0 % | **25.0 pts** |
| (256, 1024, **1500**, 2048) | 5 | **75.0 %** | 75.0 % | **0.0 pts** |
| (256, 512, 1024, 1500, 2048, 4096, 9000) | 8 | 75.0 % | 75.0 % | 0.0 pts |

So the second "limitation" is really a **budget allocation**: 4 bits buy 16 contexts, and how they
are spent decides which faults are isolable — 4 sizes × 4 classes, 8 × 2, 16 × 1 and 2 × 8 all fit.
The frozen 4 × 4 mapping closes class-selective faults and misses a boundary at 1500; a mapping
with a 1500 boundary closes that one and costs class resolution unless the budget grows.

## What this makes the next piece of work

The classifier is **control-plane programmable**, which turns the boundary problem into a search
rather than a wall: the system can place bins where it has evidence a boundary lies, and re-cut
them when it learns better. That is exactly the boundary audit P4 anticipates — test *around* a
suspected threshold instead of enumerating sizes — and it is now a concrete, buildable target
rather than a caveat, because the measurement above says precisely what a correct bin edge is
worth (25 points at every headroom).

Unchanged and still required before any publication claim: trace-driven CCT, realistic feedback,
the behavioural health gate (P2), and silicon.
