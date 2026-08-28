# M1 — exact replay: the decomposition and the scoped negative result (2026-08-27)

Harness: `sim/gate/replay.py`. Inputs: the per-link counter logs recorded by htsim for the 30
pre-registered gate seeds (`results_real_v12/`). Detector: the frozen localizer
(`controller/infer.py`, hash **`0a989aaf`**, h = 6.5 nats, δ = 1e-4, pooled) — the detector PREREG
§3.3 names, not the simulator's ratio rule (PREREG v1.5 §1).

**Re-issued 2026-08-28 (PREREG v1.6/v1.7), after an adversarial review of this file, the harness and
the detector.** Every number below was recomputed. Ten defects were fixed; the ones that changed
what a number *means* are: the localizer's warm-up counted update calls rather than evidence, which
blinded low-cadence collection; semi-synthetic faults were drawn inside each schedule's read loop,
so every arm faced a different fabric and the paired tests compared different worlds; the "moving"
fault relabelled the success criterion without moving any drops, so the vacated link kept dropping
and its *correct* detections were counted as false alarms; the oracle was handed only the recorded
fault, so under `all` it was not an upper bound; both gated schedules advanced their cursor 4096
times = 0 mod 1024 and so made no round-robin progress on partially idle epochs; coverage medians
were complete-case, silently dropping the censored runs that carry the largest coverage times; and
the H9 gate's `min` over KM medians picked NaN, so a budget where the gate was *undefined* printed
"not tripped". Scenario randomness is now materialised once per seed before any schedule runs, so
multi-fault replays are as exact and as paired as the single-fault ones.

## Why replay is exact

The counter logs are **byte-identical across all five measured arms for every seed (120/120
arm-seed pairs)**: the measurement policy never perturbs the simulated fabric. Replaying a
different read schedule over the recorded counters therefore reproduces exactly what that schedule
would have observed — it is not a model.

**Validation.** Replaying `uniform` reproduces the recorded arm per seed: of 10 seeds checked,
every uncensored seed matches to the epoch (31, 27, 18, 14, 19, 17, 26) and all three censored
seeds are censored in both. The candidate order matters and was the earlier discrepancy: the
simulator enumerates uplinks agg-major, core-minor (`main_uec.cpp:816-819`), not lexicographically.

Cost: **3 minutes** for 6 schedules × 5 budgets × 30 seeds, against 64 minutes *per run* in htsim.

## C1 — detection delay decomposes into evidence time + coverage time

Evidence time (first observable drop − onset) is computed from the log and the injected fault's
identity. It is **ground truth, identical for every arm by construction** — 8.0 epochs on these 30
seeds — so it is a definition, not a measurement, and is reported once. Coverage time
(localization − first observable drop) is the compressible term and the whole subject of this file.

## C2 — the coverage lemma, checked across five budgets

The classical search lemma (`paper/THEORY.md` §3 — Bellman/Blackwell, **not ours**, see
`docs/review/NOVELTY-GATE.md`) bounds the *mean* coverage time of any counter-computable policy by
(n−B)/2B. A KM median is not that quantity, so the comparison is against a mean, and censored runs
are counted at the value they were censored at — which understates the true mean, making this a
conservative check:

| budget B | lemma (n−B)/2B | uniform mean coverage (≥) | censored | verdict |
|---|---|---|---|---|
| 10 | 50.7 | ≥ 20.4 | 27/30 | uncheckable — the 36-epoch horizon truncates far below the bound |
| 20 | 25.1 | ≥ 15.9 | 15/30 | uncheckable — same reason |
| 41 (frozen point) | 12.0 | ≥ 11.1 | 4/30 | consistent; the four censored runs carry the deficit |
| 82 | 5.7 | **≥ 6.4** | 0/30 | **confirmed, no censoring** |
| 200 | 2.1 | **≥ 3.3** | 0/30 | **confirmed, no censoring** |

At both budgets where nothing is censored the measured mean sits above the bound. The earlier
"predicted 12, measured 10" claim was an artifact of a complete-case median and has been withdrawn.

## C3 — no counter-computable schedule closes the coverage gap (H9)

KM median TTL from onset, 30 seeds, censored in parentheses. `reads/epoch` is the actual mean cost
of the arm, not its nominal budget — the in-band arms are **unbudgeted (B = n)** and the column says
so rather than leaving it to the reader.

| budget | uniform | random | load-gated | threshold-gated | greedy | **confirm** | **thompson** | oracle | in-band (B=n) | in-band sync/4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 10 | >32 (27) | >32 (28) | >32 (27) | >32 (27) | >32 (23) | >32 (27) | >32 (26) | 9.0 (0) | 9.0 (0) | 10.0 (0) |
| 20 | >31 (15) | >32 (20) | 27.0 (12) | 27.0 (12) | >32 (18) | >31 (15) | >32 (19) | 9.0 (0) | 9.0 (0) | 10.0 (0) |
| **41** | **18.0 (4)** | 22.0 (13) | 24.0 (3) | 20.0 (1) | 22.0 (7) | **18.0 (3)** | 19.0 (5) | **9.0 (0)** | 9.0 (0) | 10.0 (0) |
| 82 | 15.0 (0) | 20.0 (6) | 14.0 (0) | 14.0 (0) | 14.0 (0) | 15.0 (0) | 15.0 (0) | 9.0 (0) | 9.0 (0) | 10.0 (0) |
| 200 | 11.0 (0) | 12.0 (0) | 11.0 (0) | 11.0 (0) | 12.0 (0) | 11.0 (0) | 11.0 (0) | 9.0 (0) | 9.0 (0) | 10.0 (0) |

**H9 not tripped at any budget.** The review's central objection to the earlier version was that the
tested class was round-robin and random wearing different hats — greedy-information ties across
links because a sprayed fabric's loads are equal to 0.4 %, so it degenerates to round-robin. Two
posterior-driven arms were added to answer it: **confirm** (round-robin until the localizer's CUSUM
is non-zero, then pin the suspect — the arm that would win if localization ever needed more than one
read) and **thompson** (sampling the per-link Beta posteriors the localizer already keeps). Confirm
is *exactly* uniform on 29 of 30 seeds at the frozen budget, and that is the interesting result: one
read of the faulty link is always enough, so there is nothing for a confirmation policy to buy. The
reason is `paper/THEORY.md` §3 — cumulative counters make a read's LLR increment scale with the
interval since the last read (≈ 72 nats against a 6.5-nat threshold for a typical post-burst read),
so the first-read bound *is* the delay bound.

**Wrong-link alarms are 0 in 0/30 seeds for every arm at every budget** — and that number is
vacuous, for the reason in the next section.

## C4 — what these runs cannot tell us

**Background loss is exactly zero in every recorded run.** Verified directly: across 2048 links ×
36 epochs, the only link that ever drops a packet is the injected fault (seed1000: 20 drop-bearing
rows, all on US55→CS15; seed1007 the same; seed1019: 27). With the pooled baseline pinned at the
`p_floor` of 1e-6, the frozen localizer therefore fires on ≈ 2 accumulated drops and degenerates to
"is this link's drop counter non-zero". These runs measure a **search** problem, not a detection
problem: the Beta posterior, the forgetting factor, the latency channel and the ranking tie-breaks
do no work. Nothing here may be claimed about the localizer, and the zero false-alarm rate is
guaranteed rather than earned. The F0 block (BG_LOSS = 1e-4, no fault) now running is not an "ROC
nice-to-have" — it is the load-bearing experiment, and every number in this file needs re-issuing
against it.

## C5 — multiple and moving faults

Semi-synthetic faults are materialised once per seed *before* any schedule runs, so every arm
replays the same fabric. Success semantics are explicit (`--objective`): *any* = the top-ranked
element is any injected fault; *all* = suspect-set containment of every injected fault; *original* =
the recorded fault only, the synthetic ones are distractors.

| regime | objective | uniform | threshold-gated | confirm | oracle | in-band (B=n) |
|---|---|---|---|---|---|---|
| single fault | — | 18.0 (4) | 20.0 (1) | 18.0 (3) | 9.0 (0) | 9.0 (0) |
| two faults | any | 13.0 (0) | 12.0 (1) | 13.0 (0) | 4.0 (0) | 4.0 (0) |

**The moving fault now measures re-localization**: the clock starts at the move, only the link the
fault moved *to* counts, and credit for having found it at its old address is not given. The
earlier "in-band closes 100 % under a moving fault" claim has been withdrawn — it was recording
detection of the original fault before the move.

| move epoch | evidence time after the move | uniform | threshold-gated | confirm | oracle | in-band | in-band sync/4 |
|---|---|---|---|---|---|---|---|
| 12 | 9.0 | 15.0 (3) | 16.0 (6) | 16.0 (3) | **4.0 (0)** | **4.0 (0)** | **4.0 (0)** |
| 20 | 17.0 | >15 (25) | >15 (25) | >15 (23) | 15.0 (15) | 14.0 (10) | >15 (27) |

At epoch 20 the scenario is **horizon-bound and reports nothing about the arms**: the new link's own
evidence time (17.0 epochs) exceeds the ~15 epochs of trace left, so even the oracle censors 15/30.
Moved at epoch 12 it is measurable, and the ordering is the same as everywhere else — 4.0 epochs for
unbudgeted per-link evidence against 15.0 for the best schedule.

What the moving fault exposes is a **detector** limitation, not a schedule one: after the fault
leaves, every arm keeps flagging the vacated, now-healthy link — at the epoch-12 move, 4.8 wrong-link
alarm epochs per 100 for uniform, 2.1 for threshold-gating, and 4.7 and 4.0 for the oracle and the
in-band arm, which read the vacated link most often and therefore suffer most. The frozen
localizer's CUSUM has no reset after an alarm and no decay for an element that stops misbehaving,
so stale suspicion is permanent and the arms that win everywhere else are the worst affected. This
is the first genuine false-alarm signal in the whole M1 block (everything else is zero because the
fabric has no background loss), it is a property of the detector every arm shares, and it is the
first question to put to the F0 logs.

## What the oracle proves

The oracle localizes in 9 epochs — 8 of them evidence time, 1 coverage — against uniform's 18. So
schedule matters at this operating point, and nothing computable from counters takes it. Reading
every link every epoch (the `inband` arm) ties the oracle exactly; that is arithmetic, not a
result, since both read the faulty link every epoch. What the arm shows is the *upper bound of the
observation class*: if per-link evidence arrives without being scheduled, the coverage term is 0.

Whether that can be had at O(1) controller cost is **not** established here — it is a property of
the per-directed-link order witness, which is prior art (NetSeer SIGCOMM'20 §3.3, LinkGuardian
SIGCOMM'23, UEC 1.0.2 §5.1) and whose cost on this chip is M2's question. Under PREREG §2.3 the
in-band arm is not free: it is 1024 reads/epoch here against 41, and the honest comparison is in the
byte currency — per-link data-plane state and one exception report per loss event — which is what
the M2 cost table must produce.

## C6 — the false-alarm axis: an OBSERVATION-CLASS PILOT, not an equal-cost H8' result

The F0 control block finished. Background loss is genuinely distributed (`-mcp_bg_loss 1e-4`,
`.fault` = NONE): **1024 of 2048 links carry drops**, up to 47 cumulative each. This is the
regime C4 says the rest of M1 never had, and every alarm on these logs is by construction false.

**False alarms, 20 seeds** — seeds raising ≥ 1 alarm, and alarm epochs per 100 epochs at risk:

| h | uniform | threshold-gated | confirm | thompson | in-band (B=n) | in-band sync/4 |
|---|---|---|---|---|---|---|
| 5.0 | 16/20 (50.5) | 0/20 (0) | 5/20 (0.71) | 3/20 (0.57) | 20/20 (57.8) | 20/20 (40.8) |
| **6.5 (frozen)** | **0/20 (0)** | **0/20 (0)** | **0/20 (0)** | **0/20 (0)** | 20/20 (6.69) | 4/20 (1.00) |
| 8.0 | 0/20 | 0/20 | 0/20 | 0/20 | 4/20 (0.57) | **0/20 (0)** |
| 10.0 | 0/20 | 0/20 | 0/20 | 0/20 | **0/20 (0)** | 0/20 |
| 13.0 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 | 0/20 |

Two things follow. First, **the frozen threshold sits close to a cliff**: one step down to h = 5.0
and uniform false-alarms in 16 of 20 seeds at 50 alarm-epochs per 100. Second, **the in-band arm
is not false-alarm non-inferior at a shared threshold** — it reads 1024 link-epochs per epoch
against uniform's 41, so under fabric-wide background loss it gets ~25× more chances to push a
healthy link past h, and at 6.5 it alarms in every seed. Comparing arms at one threshold flatters
the budgeted arms for the wrong reason: they are protected by their own blindness.

**The clean control isolates the cause.** Hulk's 10 `-mcp_bg_loss 0` seeds (verified: no row
anywhere in the fabric has `drop > 0`) raise **0 alarms for every arm at h = 4.0 and h = 6.5**,
in-band included. The alarms are background loss observed more often, not detector noise.

**Read at each arm's own false-alarm-free operating point, the result stands and strengthens:**

| arm | lowest h with 0/20 false alarms | KM median TTL there | censored | oracle gap closed |
|---|---|---|---|---|
| uniform | 6.5 | 18.0 | 4/30 | 0 % |
| confirm | 6.5 | 18.0 | 3/30 | 0 % |
| thompson | 6.5 | 19.0 | 5/30 | −11 % |
| threshold-gated | 6.5 | 20.0 | 1/30 | −22 % |
| oracle (reference) | 6.5 | 9.0 | 0/30 | — |
| in-band, sync/4 | 8.0 | 10.0 | 0/30 | 89 % |
| **in-band (B = n)** | **10.0** | **9.0** | **0/30** | **100 %** |

At matched zero false-alarm rate on real background loss, unbudgeted per-link evidence **halves
detection delay — 9.0 epochs against 18.0 — and ties the oracle**, and buying that false-alarm
freedom costs it nothing (9.0 epochs at h = 6.5, 8.0 and 10.0 alike, because its evidence per read
clears any of those thresholds on the same epoch).

### What this is NOT

**It is not H8′.** H8′ (PREREG v1.7) asks whether the *post-TM order witness* moves the frontier
against the strongest scheduled-counter baseline **at matched cost in the §2.3 byte currency**.
The arm measured here is not the witness: it is counter reading at B = n, 1024 link-reads per
epoch against uniform's 41, and it is charged nothing on any of the five §2.3 units. What it
establishes is an **upper bound on the observation class** — if per-link evidence arrives without
being scheduled, the coverage term goes to zero. Nothing here prices the witness's own cost: 4
header bytes on every production packet, per-link state, exception reports, controller
operations, and the counter collection it would replace. Until those are on one axis, this is a
pilot, not a frontier result.

**The false-alarm exposure is far short of the pre-registered bound.** PREREG §5 sets a limit of
six false alarms per hour. These are 36-epoch, 100 ms traces, so 20 seeds is **72 seconds of
aggregate no-fault exposure**. Zero observed events over 72 s gives a one-sided 95 % upper bound
of 3/72 s ≈ **150 alarms per hour** — twenty-five times the pre-registered limit. The per-seed
figure (0/20 → 13.9 % upper bound) is arithmetically fine and answers a different question than
the one pre-registered. Reaching < 6/hour with zero events needs **1800 s ≈ 0.5 h aggregate**,
i.e. about 500 seeds of this trace or a proportionally longer horizon.

**The thresholds were selected on the same data they are evaluated on.** Each arm's operating
point is the lowest h giving 0/20 here, which is calibration, not evaluation. They must be frozen
on a calibration split and re-measured on held-out controls.

**The two cohorts do not share a background regime.** The controls run at b = 1e-4 while the
fault traces have b = 0, so this pairs specificity-under-background with
sensitivity-under-fault-only and never measures the pre-registered hard case where both are
present. A fault-plus-background cohort (`FAULT=1 BG_LOSS=1e-4`, seeds 3000+) is running now;
these numbers must be re-issued against it.

**Reproduce** (the F0 counter logs are ~2 MB/seed and live on the hosts, not in the repo):

```
rsync -a --include="*.counters.csv" --include="*.onset" --include="*.fault" --exclude="*" \
      decps@10.10.54.166:mcp/sim/gate/results_f0_bg/moe8x8b_n16/uniform/ <dir>
./replay.py --results <dir> --budgets 41 --schedules uniform,confirm,inband --no-fault --h 6.5
```

## C7 — the forgetting confound: real in principle, inert in fact

The localizer's forgetting factor is applied per *observation*, not per epoch, so at rho = 0.9 an
arm reading a link every epoch remembers ~10 epochs while a B = 41 arm reading it every ~25 epochs
remembers ~250. "One frozen localizer for every arm" is therefore true of the source and false of
the dynamics, and the asymmetry runs the wrong way: it favours long-memory budgeted arms on a
persistent fault and penalises them on a moving one — the two regimes M1 reports.

It was worth measuring rather than arguing about, so `infer.py` gained a `forget_mode` knob
(`per_observation`, the frozen rule, and `per_epoch`, which discounts by `rho ** elapsed_epochs`
so every arm has the same wall-clock memory) and `replay.py` a `--forget-mode` flag. **Every
published number is byte-identical under both modes**, across all three regimes:

| regime | uniform | confirm | oracle | in-band | in-band sync/4 |
|---|---|---|---|---|---|
| single fault, h = 6.5 | 18.0 / 18.0 | 18.0 / 18.0 | 9.0 / 9.0 | 9.0 / 9.0 | 10.0 / 10.0 |
| moving fault (move at 12) | 15.0 / 15.0 | 16.0 / 16.0 | 4.0 / 4.0 | 4.0 / 4.0 | 4.0 / 4.0 |
| F0 background loss, alarms | 0/20 / 0/20 | 0/20 / 0/20 | — | 20/20 / 20/20 | 4/20 / 4/20 |

(`per_observation / per_epoch`; the moving-fault stale-suspicion alarm counts are identical too —
38, 25, 22, 19, 20.)

The reason is structural, and it is the more useful finding: **forgetting never touches the
decision variable.** `rho` discounts the Beta and Normal-Gamma pseudo-counts only; the CUSUM that
`localize` ranks and thresholds accumulates with no decay at all, and in these regimes the pooled
baseline it is compared against is pinned at `p_floor`. So the cadence-dependent memory cannot
reach any reported result, and the frozen default stays `per_observation` — changing it would
alter nothing while invalidating every number.

**Where the concern actually lives is the CUSUM's lack of decay**, not the forgetting factor. That
is the mechanism behind the stale-suspicion alarms in the moving-fault regime: once a link has
been flagged, nothing brings its statistic back down when it stops misbehaving, so the arms that
read it most often suffer most. A standard quickest-change design resets after an alarm; this one
does not, and that is the change to make when re-localization becomes a measured objective.

## C8 — the two mechanisms do not spend the same currency (`sim/gate/cost_model.py`)

C6 stops short of H8′ because it compares delay at matched false alarms without pricing anything.
A single "equal cost" number was never going to work, and putting both mechanisms on the PREREG
§2.3 units shows why. Traffic is measured from the recorded logs (2048 links, 176.7 M pkt/s
aggregate, 2.12 Tb/s carried at 1500 B against 409.6 Tb/s of capacity — this trace runs the fabric
at **0.52 % utilisation**); the per-mechanism costs are our compiled design for the witness and
published figures for the rest.

| mechanism | β_tag (% capacity) | tag as % of carried bytes | control reads/s | coverage delay | provenance |
|---|---|---|---|---|---|
| scheduled counters, B = 41 (uniform) | 0 | 0 | 410 | 11.0 | measured (replay) |
| scheduled counters, B = n (the C6 "in-band" arm) | 0 | 0 | **20,480** | 1.0 | measured (replay) |
| W4 order witness (ours, 4 B) | 0.0014 % | 0.267 % | **0** | 1.0 by construction | bytes measured; delay not yet on silicon |
| NetSeer inter-switch detection (4 B) | 0.0014 % | 0.267 % | 0 | 1.0 by construction | SIGCOMM'20 §3.3, published |
| RFC 9341 alternate marking, 100 ms colour | 0 | 0 | 40,960 | ≥ colour period | RFC 9341, published |

At 4096 B the witness's share of carried bytes falls to 0.098 %; its share of *capacity* stays
0.0014 % either way on this trace.

**The frontier is a plane, not a line.** Scheduled counter reading spends control-plane reads and
buys coverage delay; the witness spends wire bytes on every production packet and buys coverage
delay of zero with no scheduled reads at all. The C6 arm that ties the oracle does it at 20,480
reads/s — fifty times the B = 41 arm — which is precisely why C6 is an observation-class bound and
not a frontier result. What the witness proposes is to buy that same delay for **0.0014 % of
fabric capacity and no scheduled reads**; that is the claim H8′ has to test.

**Not priced here**, and each is required before the frontier is publishable: per-link witness
state and MAU stages (`p4/witness/COMPILE-GATE.md` carries the compiled delta), exception-report
bytes at one per loss event, collector CPU, and — for the NetSeer row — its ring buffer and three
redundant notification packets per loss event. Nor does this trace stress the byte axis: at 0.52 %
utilisation a per-packet tag is nearly free, and the regime that matters is a loaded fabric where
0.267 % of carried bytes is real capacity.

## Still open in M1
