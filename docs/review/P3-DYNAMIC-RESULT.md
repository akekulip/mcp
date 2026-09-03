# P3 dynamic operating point — measured, 2026-08-29

> Historical simulation record. The statement below that end-to-end feedback was unmeasured was
> closed for partial loss on 2026-08-30; see `artifacts/HW-CLOSED-LOOP.md`. Restoration and
> total-blackhole limitations remain current.

Closes audit gap #6 of `docs/review/P2-P3-INDEPENDENT-AUDIT.md`. Pre-registered before any code or
number existed in `sim/dynamic/PREREG.md`; the emission-rule cross-check was pinned to exact PTF
values in the same commit. **Three of the six frozen decision rules fail.** They are reported here
as results, not edited away.

## What now exists

`sim/dynamic/` drives the REAL `controller.sublink_feedback.SublinkFeedback` and the REAL frozen
`controller/infer.py` over simulated time. Nothing in the decision path is re-implemented or
monkeypatched: `fabric.py` generates evidence and honours installed gate keys, `transport.py` delays
events and writes, `runner.py` runs one configuration, `sweep.py` runs the grid.

Verified independently by the PI, not taken from the builders' reports: `sim/tests` 83 passed,
`controller/tests` 84 passed, `python3 -m sim.dynamic.sweep --quick` = 96 runs / 32 cells / 11.0 s,
frozen localizer byte-unchanged at `sha256=1cc6349a7f239f462fd13be5b10af8d3ab402625bd8a18e22f6496665a34f18e`.

## The evidence model is validated against silicon, not asserted

PREREG tripwire 4. Forcing the PTF's exact loss pattern, the generator emits one event with
`gap == 0xFFFE` and `observed_packets == 3`, then falls silent — reproducing
`p4/ptf/gap_event/test.py::Test50OneForcedEventPerDiscontinuity` exactly.

## Rule-by-rule

| rule | verdict | evidence |
|---|---|---|
| 1. specificity vs usefulness at each `h` | **not yet decided** | needs the full grid; the quick grid shows `no_fault` INERT at every tau and `persistent_partial` quarantined 1.0 at tau <= 2.2 ms |
| 2. `reorder_only` and `wrap` produce zero quarantines | **FAIL on the unfixed mechanism; PASSES with the fix** | see the swept table below. `wrap` half HOLDS throughout |
| 3. `all_context_blackhole` reported UNDETECTED | **PASS, and it extends further than written** | `md.sublink = (vlink << 4) \| ctx`, so the witness register is per behavioural sublink and a 100 %-lost *context* also emits no survivor. `selective_blackhole` is equally invisible: cw4_feedback 0.0 quarantine rate against oracle 1.0 |
| 4. zero unsafe restorations at k=3 | **FAIL** | 10 unsafe restorations per 5 runs where the fault persists. Root cause below |
| 5. cw4 collateral below directed_w4 at equal exposure | **PASS on `persistent_partial`** | 1,250,016 vs 8,750,040 collateral packets (7x) at identical unsafe exposure (172) and identical detection (9,374 us). On `selective_blackhole` it is 0 vs 0 because neither arm detects |
| 6. report every tau including the useless ones | **PASS** | the tau cliff below is published rather than trimmed |

## The feedback-latency cliff — the mechanism does not degrade, it stops

`persistent_partial`, cw4_feedback, p=1e-3, h=6.5, 30 epochs, 5 seeds:

| tau | quarantined | restored | unsafe restorations | audit C/L/I/S | stale events |
|---|---|---|---|---|---|
| 0 | 5/5 | 5/5 | 25 (k=1) / 10 (k=3) | 75/0/0/0 | 0 |
| 100 us | 5/5 | 5/5 | 25 / 10 | 75/0/0/0 | 1 |
| 2.20 ms | 5/5 | 5/5 | 25 / 10 | 75/0/0/0 | 53 |
| 60 ms | 5/5 | **0/5** | 0 | **0/0/0/45** | 578 |
| 106.6 ms | **0/5** | 0/5 | 0 | 0/0/0/0 | 5369 |

Two distinct failures, and the four audit counters exist to tell them apart. At 60 ms the probation
round trip (2 x tau) outlives the 100 ms epoch, so every round closes STALE and the sublink is held
forever — safe, useless, and *held*. At 106.6 ms every gap event is dropped as stale by `on_gap`, so
nothing is ever quarantined and no round is ever opened. A rule that never fires is not a safe rule.

## Root cause of rule 4: probation counts rounds, not evidence

`SublinkFeedback.on_clean_epoch` requires `observed_packets > 0` and then increments a counter;
restoration needs `clean_epochs_to_restore x quarantines` clean *rounds*. The magnitude of the
evidence is discarded. `tbl_audit_steer` holds 16 entries and `AuditRound` refuses more, so one
round is at most 16 packets.

| clean rounds at k | probation packets | P(certifying a STILL-FAULTY 1e-3 sublink) |
|---:|---:|---:|
| 1 | 16 | 0.984 |
| 3 | 48 | **0.953** |
| 10 | 160 | 0.852 |

The frozen k=3 rule certifies a still-faulty link 95.3 % of the time. **This is the H28 defect class
again** — counting calls instead of counting evidence — reappearing in the restoration path after
being fixed in the warm-up path. Restoration is not merely mistuned; the criterion is dimensionless.

### Proposed fix: evidence-sized probation, and it gives a publishable cost

Gate restoration on accumulated observed probation packets, `N >= ln(alpha)/ln(1-p_target)`:

| fault rate excluded | packets @95% | rounds @16 | wall clock | packets @99% | wall clock |
|---|---:|---:|---:|---:|---:|
| 1e-2 | 299 | 19 | 1.9 s | 459 | 2.9 s |
| 1e-3 | 2,995 | 188 | 18.8 s | 4,603 | 28.8 s |
| 1e-4 | 29,956 | 1,873 | 187.3 s | 46,050 | 287.9 s |

This converts a failing rule into a priced mechanism: certifying a quarantined behavioural sublink
to 1e-3 at 95 % confidence costs 2,995 declared audit packets and 18.8 s. That is a result about
what safe restoration COSTS, which is what the lifecycle claim needed all along.

## Proposed fix for rule 2: a reorder-exact witness

`reg_wit_expect` resyncs unconditionally, so a late packet moves `expected` backwards and the next
in-order arrival reports loss that never happened. Two halves, both required — measured over 4,000
randomized loss+swap patterns, the current semantics report the wrong loss count in **3,041**;
advance-only resync plus a controller-side credit for any small positive gap is exact in **4,000/4,000**:

| arrivals | real loss | current | advance-only | advance-only + credit |
|---|---:|---:|---:|---:|
| one adjacent swap | 0 | 2 | 1 | **0** |
| two adjacent swaps | 0 | 4 | 2 | **0** |
| swap beside a real loss | 1 | 3 | 2 | **1** |
| PTF Test50 | 2 | 2 | 2 | **2** |

The credit is principled, not a fudge: after a resync a small positive gap can only mean a packet
previously counted missing has arrived; real loss never produces one.

**The data-plane half is free on Tofino 1.** `p4/witness/mcp_fabric_gate_event_advonly.p4` compiles
on bf-p4c 9.13.1 at **11 ingress / 4 egress — identical to the baseline compiled in the same
session**, with byte-identical PHV allocation, table placement, and dependency graphs. The single
stage of headroom is untouched. The normalized `.bfa` delta is two instructions:

    - add lo, phv_lo, 1                    baseline: unconditional resync
    + leq.uus lo, lo, -phv_lo              advance-only: comparator
    + add cmplo, lo, phv_lo, 1             predicated resync

The correct form is also the cheap one: the TF1 SALU comparator only ever computes a two-operand
difference and tests its sign, with a signedness selector, so `(int<16>)(v - seq) <= 0` is one
comparator and one predicated write. Wrap-correctness therefore comes from the same modular
arithmetic the baseline already relies on. Verified exhaustively against the modular spec over
4 seq anchors x 65536 register values = **262,144 cases**, independently by the PI: 4 disagreements,
all at the 2^15 antipode, which is ambiguous by construction in any 2^16 ring and which the baseline
resolves the same way.

Class 8 (SALU sentinel flattening) does not apply and was ruled out positively rather than by
absence: five differential compiles show the relop and polarity tracking the source (`leq`/`lss`/
`grt`), `cmplo` as write-on-true, and an explicit `else` arm emitting a second predicated line that
our no-else form correctly lacks.

**A correction to the premise, worth keeping.** The naive `if (v <= seq)` form is NOT broken by wrap
alone — contiguous arrivals across 65535 -> 0 work, and all three formulations emit zero events, so
rule 2's wrap half would never have caught it. It breaks on wrap COINCIDING WITH LOSS, where it
wedges permanently at `expected = 65535` and bleeds one false event per packet with a growing gap.
Any wrap regression test must therefore be wrap-WITH-loss.

The two halves compose exactly, confirmed across two independently written implementations: the
event tuples emulated from the compiled assembly, `[(3, 0xFFFF), (2, 0x0002)]` for arrivals
0,1,3,2,4,5, run through the controller credit rule give net loss **0**.

### Swept result: the fix holds at every rate, and the earlier single-rate number was the outlier

**Read the `witness` column before quoting any row.** `baseline` is the semantics compiled on
silicon today (`mcp_fabric_gate_event.p4`) and is the harness default; `advance_only` models the
PROPOSED variant, compiled locally at the same 11/4 cost but **not recompiled on the switch and not
adopted**. The zeros in the advance_only rows are what the fix would buy, not what the system does.

`reorder_only`, 5 seeds x 12 epochs, zero packets lost in every cell (asserted), quarantines driven
through the real `SublinkFeedback` carrying the reorder credit. RESIDUAL is phantom loss surviving
the credit.

| reorder rate | witness | h=5.0 | h=6.5 | h=8.0 | h=10.0 | phantom offered | credited | RESIDUAL |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 1e-6 | baseline | 7 | 2 | 0 | 0 | 424 | 212 | 212 |
| 1e-6 | advance_only | 0 | 0 | 0 | 0 | 212 | 212 | **0** |
| 3e-6 | baseline | 18 | 4 | 0 | 0 | 1234 | 617 | 617 |
| 3e-6 | advance_only | 0 | 0 | 0 | 0 | 617 | 617 | **0** |
| 1e-5 | baseline | 9 | 3 | 0 | 0 | 4004 | 2002 | 2002 |
| 1e-5 | advance_only | 0 | 0 | 0 | 0 | 2002 | 2002 | **0** |
| 3e-5 | baseline | 4 | 1 | 1 | 0 | 11788 | 5894 | 5894 |
| 3e-5 | advance_only | 0 | 0 | 0 | 0 | 5894 | 5894 | **0** |
| 1e-4 | baseline | 0 | 0 | 0 | 0 | 39820 | 19910 | 19910 |
| 1e-4 | advance_only | 0 | 0 | 0 | 0 | 19910 | 19910 | **0** |

The arithmetic is exact and rate-independent: baseline offers two phantom losses per swap, the credit
cancels one, so **baseline+credit leaves exactly one phantom loss per swap at every rate**;
advance-only offers one and the credit cancels it, leaving zero everywhere. Baseline+credit
false-quarantines at h=5.0 and h=6.5 for every rate from 1e-6 to 3e-5, and at h=8.0 for 3e-5.

**The earlier 32 / 10 / 3 / 0 figures at 1e-4 are superseded and are no longer reproducible** against
the current controller, which now carries the credit. Worse, 1e-4 — the single rate that first
measurement used — is the one rate where baseline+credit happens to pass, because uniform reordering
lifts the shared pooled baseline until no sublink stands out. Had the fix been evaluated only at the
rate the original failure was found at, it would have looked unnecessary.

**NEITHER HALF IS SUFFICIENT ALONE, and one measurement appeared to say otherwise.** Over 3,000
randomized reorder-only traces carrying zero real loss, the controller credit alone still reports
phantom loss in 2,822 of them (10,489 phantom packets); advance-only plus the credit reports none in
any. An end-to-end run at one reorder rate and one `h` showed the credit alone removing every false
quarantine, which invited the conclusion that the two halves fix the problem independently. They do
not: the credit roughly halves the phantom loss, and at that particular rate the residue fell below
the CUSUM threshold. The result is rate-dependent, so the free data-plane change is still required.
The credit alone is a threshold accident; the pair is an identity.

**Confirmed on the switch's own SDE, 2026-08-29.** Both programs were shipped to
`decps@10.10.54.81` (sha256 verified identical on both sides) and compiled with bf-p4c **9.13.2**,
the version that actually runs the chip, using the compile-only `build.sh` which never touches the
pipeline. Both returned exit 0 with 4 warnings, and `pipe/logs/table_summary.log` — the
authoritative source, not `context.json` — reports **11 ingress / 4 egress for both**. The
advance-only fix therefore costs zero stages on the deployed toolchain, not merely on the laptop's
9.13.1. The sibling program running on the chip was undisturbed (pid unchanged).

Remaining before adoption: a PREREG amendment.

### Why the exposure is bounded

`reg_wit_seq` stamps the sequence in EGRESS indexed by `md.sublink`, *after* `tbl_eg_vlink`. Packets
are numbered as they leave on an already-chosen sublink, in TM release order, so per-packet spraying
cannot reorder a sublink's own sequence: the detector is immune to spray-induced reordering **by
construction**. The residual is reordering within one physical link. The PREREG names no reorder
rate, so rule 2 currently has no operating point attached — that requires a dated amendment.

## Other measured findings

- **Write latency feeds the flap damper.** `on_gap` coalesces per (sublink, epoch), so at
  `tau_write` = 0 / 100 ms / 300 ms one fault produced 3 / 4 / 6 installs and `st.quarantines` of
  3 / 4 / 6. Restoration needs `k x quarantines` clean rounds, so a slower write path makes a sublink
  harder to give back. Emergent, not designed.
- **The arrival register saturates.** `reg_wit_observed` uses `v |+| 1`. On a clean link at 1e-6
  background, gaps are ~19 epochs apart, so it pins at 65535 and silicon under-reports arrivals on
  exactly the healthy links that feed the pooled baseline.
- **Reorder false quarantine is non-monotone in the reorder rate** (1e-4 quarantines less than 1e-5
  at h >= 6.5), consistent with uniform reordering lifting the shared pooled baseline until no single
  sublink stands out.
- **A harness bug, caught by an impossible result.** k=1 restored 0/5 while k=3 restored 5/5. Probation
  was opening before the install write landed, so a CLEAN round enqueued its `remove` ahead of the
  in-flight `install` and the key stayed installed while the controller believed it had restored.
  Fixed by requiring the gate to be effective before probation starts, which is also the physically
  correct model.

## Controller-host latency (audit gap #4, partial)

`controller/bench_feedback_path.py` measures the segment that needs no switch: parse -> GapEvent ->
decision -> BFRT marshalling. Median 47.0 us total, of which **28.2 us is the frozen localizer and
7.7 us is the P3 logic** — 78.6 % of the controller's cost is inference, not the new mechanism. A
coalesced event costs 5.0 us. This is a LOWER BOUND on the controller's contribution; the mirror
transport and the BFRT gRPC round trip are excluded and the end-to-end figure remains unmeasured.

## What remains

1. Decide the two proposed mechanism fixes; both need a PREREG amendment naming an operating point.
2. Run the full frozen grid. It is 92,160 runs and ~200 h single-threaded, dominated by
   `reorder_only` at p=1e-2 (~450 s/run, because the witness emits three events per swap and the
   frozen layer scores every one). Shard by seed.
3. Measure the on-switch segment of gap #4 when the chip is free.
