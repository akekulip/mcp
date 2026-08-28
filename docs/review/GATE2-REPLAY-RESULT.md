# Gate 1 (replay): a competent synthetic prober matches live cloning — on every dimension tested

`sim/audit/replay_audit.py`, 24 trials per cell, **equal 120 MB measurement budget** per arm, loss
modelled as a function of packet features rather than of the link alone. Metric is a pair, because
reporting only the first hides an arm that never acts:

* **FR** = P(certify HEALTHY | the link is really faulty) — unsafe restoration, lower better
* **OK** = P(certify HEALTHY | the link is really healthy) — usefulness, higher better

Every arm reaches OK = 100 % at this budget, so FR is comparable across the table. (At 80 MB the
size-mixed arms sent 25,829 packets against the 29,956 needed and could never certify, scoring
FR = 0 by construction — checked and excluded before reading anything into it.)

| fault the link really has | 64 B idle | 1500 B idle | 1500 B @line | mixed @line | **mixed @line, random 5-tuple** | twins r=0.02 | twins r=0.2 | twins r=1 |
|---|---|---|---|---|---|---|---|---|
| IID 1e-4 | 0 | 0 | 0 | 0 | **0** | 0 | 0 | 0 |
| size > 1 KB (the Aegis fault) | **100** | 0 | 0 | 0 | **0** | 0 | 0 | 0 |
| class = bulk | **100** | 0 | 0 | 0 | **0** | 0 | 0 | 0 |
| load > 0.5 | **100** | **100** | 0 | 0 | **0** | **100** | **100** | 0 |
| bursty (Gilbert–Elliott) | 0 | 0 | 0 | 0 | **0** | 0 | 0 | 0 |
| entropy, 64 bad buckets of 4096 | 88 | 83 | 83 | 88 | **0** | 0 | 0 | 0 |

## The finding

**Production-conditioning did not beat a competent synthetic prober on any dimension modelled
here.** Each conditional fault defeats *naive* probing and is then fixed synthetically:

* **size and class** — defeated by a 64 B probe, fixed by varying the probe's size and class.
  Aegis already shipped this fix ("we enhance RDMA Pingmesh to cover varied lengths of probes"),
  so it cannot carry a novelty argument.
* **load** — defeated by any probe sent to an idle link, fixed by blasting at line rate. Note that
  it also defeats **twins at r = 0.02 and r = 0.2**: a dark link carries only the load its twins
  induce, so covering the high-load stratum needs a clone ratio near 1. Cloning is the *expensive*
  way to buy load coverage, not the cheap one.
* **entropy / 5-tuple** — the dimension I expected to be decisive, since a prober fixing 8 tuples
  touches 8 of 4096 buckets while cloned production spans all 4096. It defeats every fixed-tuple
  prober (83–88 % unsafe restorations) — **and is completely fixed by a prober that randomises its
  5-tuple** (FR 0 %). Verified directly: the randomising arm touches all 4096 buckets.

Marginal coverage is synthesisable. That is the result.

## What it does and does not rule out

It does **not** show that synthetic probing is always sufficient. It shows that *marginal*
conditioning — one feature at a time — is reproducible without cloning. The remaining case for
live traffic is **correlation structure**: a fault conditioned on a combination of features that
co-occur in production but that a prober randomising each feature independently would rarely
produce, or on values it cannot know to generate. That is a narrower claim than the direction
started with, and it needs a fault model that exhibits genuine correlation to be worth anything.

Two limits of this gate, stated rather than buried:

1. **The burst model is not a discriminator as configured** — every arm passes it. Either the
   Gilbert–Elliott parameters are too generous or sampling structure does not matter at this
   budget; it should not be cited either way until re-tuned.
2. **The model prices bytes, not disruption.** A synthetic prober that blasts a quarantined link at
   line rate to buy load coverage is free here. On a real fabric that train shares buffers, and the
   twins' control arm rides a *healthy in-production* link — which is where a bounded budget
   genuinely earns its place, as noted in `GATE2-AUDIT-BUDGET.md`.

## Consequence for the direction

The pre-registered expectation for this gate was "IID ties; ShadowTwin wins on conditional faults
without extra bytes". **IID tied and ShadowTwin did not win.** By the plan's own rule that gates
the expensive work, this is a stop-and-rethink, not a proceed: the P4 for cloning should not be
written on the strength of size, class, load or entropy conditioning, because a prober with a
randomised 5-tuple, a mixed size profile and a line-rate sender covers all four at equal cost.
