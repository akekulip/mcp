# Behavioral-sublink value gate (frozen before implementation)

**Frozen:** 2026-08-28, before `sim/sublink_capacity.py` or its result existed.

## Question and scope

After a conditional link fault has been localized, does quarantining only the affected C-W4
behavioral sublink retain useful traffic at the same safety bound as quarantining the whole
physical link or directed link?

This first gate isolates the value of the controlled resource. It is deliberately **post-
localization**: detection delay, feedback latency, false positives, and application CCT are not
modeled and no claim about them may be made from this result. Every conservative policy must admit
zero demand known to exercise the fault. A later packet-level/htsim experiment must add those
dynamic effects before a paper can claim application benefit.

## Frozen resource and policies

The implemented C-W4 schema is exactly the P4 schema, not the broader proposal:

- direction is part of the directed vlink;
- size strata are `[0,256)`, `[256,1024)`, `[1024,2048)`, and `[2048,65536)` bytes;
- traffic class is **not** in the current data-plane classifier.

Policies:

1. `physical`: if any demanded context is faulty, quarantine both directions (CorrOpt-shaped).
2. `directed_w4`: quarantine every demanded context in the affected direction.
3. `witness_stop`: identical post-localization forwarding to `directed_w4`; it differs only in
   detection/exposure, which this gate intentionally excludes.
4. `cw4_size`: quarantine each affected `(direction, size_stratum)`.
5. `oracle`: quarantine only the exact faulty demand records.

All quarantined demand may use a healthy alternate path up to the same per-direction spare-capacity
budget. Excess demand is blocked. Offered byte-demand, not packet count, is the primary unit.

## Frozen scenarios and sweep

Each run offers equal total demand in the forward and reverse directions.

- **Aligned direction x size:** only the forward `>=2048 B` stratum is faulty. Its share of forward
  byte-demand is swept over `{0.10, 0.25, 0.50, 0.75, 0.90}`.
- **Whole forward direction:** every forward context is faulty (no conditionality benefit).
- **No fault:** no context is faulty (no-regression control).
- **Misaligned size boundary:** in forward stratum 2, `1400 B` is healthy and `1800 B` is faulty.
  C-W4 must conservatively quarantine both; the oracle need not.
- **Class-selective negative control:** both traffic classes occupy the same small and large size
  strata, and only class 1 is faulty. Because class is not implemented, size-only C-W4 must not be
  credited with isolating it.

Alternate-path spare capacity per direction is swept over `{0, 0.10, 0.25, 0.50}` of that
direction's offered demand.

## Metrics

- safe delivered fraction = healthy primary bytes + alternate-path bytes, divided by offered;
- unsafe primary bytes admitted (must be zero for every conservative policy);
- healthy primary bytes unnecessarily quarantined;
- alternate bytes consumed and blocked bytes;
- oracle-gap closure of C-W4 relative to directed W4.

## Decision rules

The mechanism-value gate passes only if all of the following hold:

1. every conservative policy admits zero known-unsafe primary bytes;
2. on the aligned conditional fault with zero alternate headroom, C-W4's median safe-delivery gain
   over directed W4 across the frozen affected-share sweep is at least 10 percentage points;
3. C-W4 closes 100% of the directed-W4-to-oracle gap on aligned strata;
4. C-W4 ties directed W4 on a whole-direction fault and every policy ties on no fault;
5. misaligned-size and class-selective results are reported even when unfavorable.

Failure of rules 1--4 stops the behavioral-sublink capacity claim. A gap larger than 10 percentage
points to the oracle in either negative control makes a finer context classifier a required design
decision before the paper may claim general conditional-fault isolation. Passing this analytical
gate authorizes a trace-driven htsim/ATLAHS implementation; it does not replace it.
