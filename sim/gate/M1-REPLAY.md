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

## C6 — the false-alarm axis, first real data (F0, background loss 1e-4)

The F0 control block is landing. On the first **10 completed Vision seeds** (`-mcp_bg_loss 1e-4`,
no fault injected, `.fault` = NONE), background loss is genuinely distributed: **1024 of 2048 links
carry drops**, up to 47 cumulative each. This is the regime C4 says M1 never had, and the localizer
finally does work: every alarm on these logs is by construction a false alarm.

| h | uniform | threshold-gated | confirm | in-band (B = n) |
|---|---|---|---|---|
| 4.0 | 10/10 seeds, 64.5 alarm-epochs/100 | 10/10, 48.9 | 10/10, 4.3 | 10/10, **83.0** |
| **6.5 (frozen)** | **0/10, 0.00** | **0/10, 0.00** | **0/10, 0.00** | **10/10, 7.39** |
| 10.0 | 0/10, 0.00 | 0/10, 0.00 | 0/10, 0.00 | **0/10, 0.00** |
| 20.0 | 0/10, 0.00 | 0/10, 0.00 | 0/10, 0.00 | 0/10, 0.00 |

**The in-band arm is not false-alarm non-inferior at the frozen threshold.** It reads 1024 link-epochs
per epoch against uniform's 41, so under a fabric-wide background loss it gets ~25× more chances to
push a healthy link's CUSUM past h — and at h = 6.5 it does so in every seed. Comparing arms at one
shared threshold therefore flatters the budgeted arms for the wrong reason: they are protected by
their own blindness. Any equal-cost claim has to fix the false-alarm rate first and read the delay
off at each arm's own operating point.

**Doing that costs the in-band arm nothing:**

| arm | threshold at which it is false-alarm-free on F0 | KM median TTL there | oracle gap closed |
|---|---|---|---|
| uniform | 6.5 | 18.0 (4/30 censored) | 0 % |
| confirm | 6.5 | 18.0 (3) | 0 % |
| in-band (B = n) | 10.0 | **9.0 (0)** | **100 %** |
| in-band, collected every 4th epoch | 10.0 | 10.0 (0) | 89 % |

At matched (zero) false-alarm rate on real background loss, unbudgeted per-link evidence halves
detection delay — 9.0 epochs against 18.0 — and ties the oracle. Raising its threshold from 6.5 to
10.0 to buy that false-alarm freedom costs it nothing, because its evidence per read is large enough
that the LLR clears either threshold on the same epoch.

**The honest limits of this table.** Ten seeds, so "0/10 seeds" is a one-sided 95 % upper bound of
26 % per seed — the remaining 10 Vision seeds and Hulk's 10 clean controls will tighten it, and the
whole table is provisional until they land. The in-band arm here is still B = n counter reading, not
the order witness; what it bounds is the observation class, and the witness's own false-gap floor on
silicon is M2's question, not this one. Reproduce with:

```
rsync -a --include="*.counters.csv" --include="*.onset" --include="*.fault" --exclude="*" \
      decps@10.10.54.166:mcp/sim/gate/results_f0_bg/moe8x8b_n16/uniform/ <dir>
./replay.py --results <dir> --budgets 41 --schedules uniform,confirm,inband --no-fault --h 6.5
```

## Still open in M1

The h-sweep (ADD vs false-alarm rate) needs the F0 logs, running now on Vision (seeds 2000–2019,
BG_LOSS = 1e-4) and Hulk (2020–2029, clean); ~62 min and ~21.5 GB per run, so the fleet is
memory-bound and watched. Once they land the ROC axis is a replay sweep over h, not new simulation
— and per C4 it is also the re-issue of everything above.

Not addressed, and known: the localizer's forgetting factor is applied per *observation*, not per
epoch, so a B=41 arm has a ~250-epoch memory while the in-band arm has ~10 — "one frozen localizer
for every arm" is true of the source and false of the dynamics. Deciding it needs a re-freeze and a
re-issue, so it is queued behind the F0 block rather than done twice.
