# Campaign plan to submission — 2026-08-29

Synthesised from four independent expert reviews (project lead, silicon engineer, evaluation
scientist, networks specialist), each of which found something the others did not. Every blocker
below was found by planning against the SOURCE, not against intent. Nothing here is executed until
its stated gate passes.

## 0. The claim, corrected — this is the biggest change

Our third and strongest surviving claim was: *"a host cannot choose which link its packet crosses,
so probe placement must happen inside the fabric."* **As written it is FALSE, and a reviewer kills it
in one sentence.**

The Ultra Ethernet Specification v1.0 §3.5.10.1 gives the SENDER a 16-bit entropy field, and
§1.5.3.4 requires that *"any two packets with the same entropy values take the same path through the
UE fabric."* Spraying in UEC is a **sender** behaviour (§3.6.16.1), and §3.6.16.5 already
standardises host-driven per-path failure avoidance. On UEC, a host can pin a path.

The correct claim is about **rank and labelling, not steering**:

> Under per-packet spraying a host's end-to-end measurement of a leaf pair is a spray-weighted
> average over that pair's parallel paths. In a 4x2 fabric every host probe traverses a leaf's two
> uplinks in FIXED proportion, so `y_id = A_i + B_d`: 12 ordered pairs give a measurement matrix of
> rank 7 against 16 unknowns. Host observation is therefore **identifiability-limited to bundle
> granularity** — no number of probes separates a leaf's two uplinks. Where the spray is
> switch-local and load-driven (NVIDIA Spectrum-X selects the minimum-egress-queue port per packet
> "regardless of the entropy size"), headers do not influence it at all. Where the spray IS
> sender-driven (UEC), the host recovers path *classes* but never path *labels*: the only REQUIRED
> UEC in-network telemetry is ECN marking (§3.6.4), and the entropy-to-path mapping is explicitly
> not required to be stable (§3.6.16.5). Stamping a per-directed-link sequence number in egress,
> after the spray decision, supplies the link label neither regime gives the host.

Two standing rules for the whole paper: **never write "cannot place a probe", and never argue probe
volume.** Probe volume is not prohibitive (~10^4 probes at p=1e-3) and SprayCheck needs no probes at
all, observing production traffic. We would lose that argument. The scarce resource is
**attribution**, not samples.

**A better contribution surfaced by the same review:** SprayCheck demonstrates down to 0.5-1.5 %
single-link loss. Our target is 1e-3 to 1e-5 — two to four orders of magnitude lower. That gap is
more defensible than probe placement and should be foregrounded.

**Our own repo currently contradicts the claim.** `p4/witness/mcp_fabric_base.p4:407` marks spray
mode **B2 — hash of the NIC's per-packet UDP source-port entropy — as the default**, and
`setup_skeleton.py:236` installs `DEFAULT_SPRAY = "hash"`. That is exactly the UEC regime where a
host CAN pin a path. Run the headline under **B1 (Random) or B4 (control-plane round-robin)**, and
keep **B2 as the adversarial configuration**, showing the mechanism still wins there because the
labelling gap survives even where the steering gap does not. This converts an inconsistency into an
evaluation strength.

## 1. Blockers that must clear before any hardware measurement

| # | blocker | gate |
|---|---|---|
| B1 | **No post-stamp fault injector** (H39a). The sequence is stamped in egress; the only injector `tbl_fail` runs in ingress AFTER `tbl_wit_check`, so a packet is counted and only then discarded and NO GAP IS EVER PRODUCED. C1 and C3 cannot run. | an egress injector after `tbl_wit_stamp`, keyed `md.sublink : exact` + `hdr.witness.seq : range`, with a DirectCounter. Compile locally on 9.13.1 first — free. Class 2 caps it at ONE range field. |
| B2 | **Control plane binds the wrong program** (H39b). `hw_adapter.py:39` hardcodes `PROG = "mcp_fabric"`; against `mcp_fabric_gate_event` this fails as wrong action arity or a silently empty table, not cleanly. Neither the BFRT adapter nor `epoch_loop`'s BFRT path has ever run against the switch. | parameterise the program name; `controller/tests` green |
| B3 | **No deploy automation.** Zero scripts in the repo SSH to the switch. A hand-typed campaign violates the monitor-long-runs rule by construction. | `p4/hw/{deploy,takeover,bringup,canary}.sh`, each with a `--dry-run` proving zero real ssh calls |
| B4 | **Setup covers 6 of 14 runtime tables.** | a script printing planned vs installed rows for all 14 |
| B5 | **H35 audit-path authorization.** `tbl_audit_steer` admits a health-gate bypass on a guessable 16-bit token with no provenance check. | add `md.role` (or the controller's ingress dev_port) to the key — stays one entry — then recompile and re-verify placement |

## 2. Campaign order — revised

C4 (compile) -> bring-up -> **C2 (steering)** -> **C1 (latency)** -> C3 (lifecycle). C2 precedes C1
because a latency number is meaningless if directed-vlink identity is wrong, and C2 is what tests it.

**C1's headline number can be switch-clock exact and costs nothing extra.** `mirror_h.tstamp` is 48
bits of `ig_intr_md.ingress_mac_tstamp`, already emitted on every mirror copy. t0 = the tstamp on the
sid-2 gap-event copy; t1 = the tstamp on the first copy whose `mirror_h.vlink` equals the BACKUP
vlink (set by `tbl_vlink`, which runs after `tbl_health_gate`, so it names the path actually taken).
One free-running counter, no host clock, no PTP, no calibration. Report `R = E2E - S_sw` as one
lumped term; splitting it needs a cross-clock calibration not worth doing for v1.

**Liveness is proven at three levels and all three are reported:** the BFRT write returns OK (weak);
`entry_get(from_hw=True)` reads it back (correctness only, run AFTER t1 — a from-hw read costs tens
of ms and would inflate the number it validates); and a data packet demonstrably takes the new path
(this IS t1, and it is the definition of live).

**The `egress_qid` sentinel sweep is the crux and the PTF model cannot test it.** `eg_intr_md.egress_qid`
is the port-group queue `(dev_port % 4) * 8 + qid`, not the qid ingress wrote. Install sentinels over
qid 0..31, send one packet per (port, qid), read which value returns. The model gave 16 of 17 passes
on queue 0, so it has never exercised this.

**C2's proof is a four-instrument ledger with a negative control.** Wire (`wit_h.link_id` off the
mirror), `tbl_vlink` DirectCounter, TM queue counter, MAC port counter — all four must agree on
10,000/10,000. Then DELETE the steering entry and require a ~50/50 split. Without that control, a
100 % landing proves the spray was stuck, not that steering worked.

## 3. Evaluation — what makes it survive review

**The arm that decides everything is missing.** A7 = congruent probe shape, host-injected, WITHOUT
link steering. Comparing only against 64 B probing beats a strawman Aegis already fixed. **A8 - A7
is the contribution, isolated.** Build both.

**An application-level metric is mandatory.** One htsim block: one ATLAHS MoE trace (the 500 MB one,
not the 9.4 GB), one ring-allreduce, one Aegis-shaped >1 KB conditional fault, arms {none, whole-link,
directed, sublink, oracle}, 15 seeds — ~150 runs, ~10 h wall clock at 15-way concurrency against the
H26 memory ceiling. Report per-collective CCT as PAIRED per-seed ratios against the same seed's
no-fault control. Three traps: H27 recurs (a fault on a link carrying no traffic in the window shows
zero impact — constrain and report the denominator); CCT under loss is dominated by the RTO, not by
us (H25 — report the RTO config as a first-class parameter); and report unsafe exposure in
application terms, since a retransmitted packet is latency, not loss.

**Overheads currently unreported, in order of importance:** register-memory scaling — the witness
registers are **1024 entries indexed by `md.sublink`**, so the abstraction tops out at 1024
(link x context) pairs and `tbl_health_gate` at `size=256` caps simultaneous quarantines; SALU/SRAM/
TCAM/PHV per stage; **mirror bandwidth**, which is rate-dependent and currently unbounded (H38);
control-plane write rate; and the wire-byte claim, which is **zero only against a baseline that
already carries the W4 header** — both numbers must appear.

**Statistics:** Wilson intervals over pooled sublink-epochs are **too narrow** — quarantine state is
autocorrelated within a run by construction. Use a cluster bootstrap over runs for every rate. Pair
seeds across arms and report paired differences. Declare one primary hypothesis per surviving claim,
Holm across those four; everything else descriptive.

**Grid cut, 92,160 -> ~8,600 runs.** `h` is a tuning knob, not a factor — select it on a separate
tuning split and freeze it, or every headline number is a maximum over four thresholds, which is
grid-shaped p-hacking. `k` is dead once evidence-sized probation lands. `tau` gains depth where the
cliff is (add 10/20/40/60/80 ms — there is currently nothing between 2.2 and 106.6 ms) and loses
breadth elsewhere. Reorder becomes its own factor. And per H38 the p=1e-2 reorder cell is 47x beyond
controller capacity — it is past the cliff, not on it, so cutting it is honest.

## 4. Threats, and the one experiment that converts the weakest

The premise — that conditional faults are common enough to warrant a new resource — rests on Aegis's
single anecdote. **Convert it with physics and then with a measurement.** At raw BER e, frame loss is
`1 - (1-e)^(8L)`, so loss is inherently size-dependent; RS-FEC sharpens it, because correctability
depends on burst length relative to codeword, so marginal optics fail longer frames first. That is
WHY Aegis saw ">1KB only", and the curve is unpublished. Measure `p(loss | frame size)` on a
physically degraded 25G link with the SDE's pre/post-FEC counters as covariate. Roughly a day, and it
converts our weakest premise into a contribution nobody can take away.

**Model-vs-silicon agreement table**, N scenarios x {silicon, sim/dynamic, htsim} x {events, losses,
decision, timing}, with every divergence explained rather than averaged. That single table is what
buys credibility for the simulated results.

## 5. Risk register

1. Measured end-to-end latency lands past the 60 ms cliff (p~0.5). Pre-committed response: the paper
   narrows to detection plus selective mitigation and the data-plane fast path becomes the
   contribution — a stronger paper, but only if discovered at week 6, not week 20.
2. A reviewer reduces the 7x to arithmetic (p~0.6). It IS 4.00x arithmetic plus 1.75x definitional
   (H37). Response: report collateral against measured context share as a curve with the arithmetic
   baseline on the same axes, plus an adversarially chosen share vector.
3. The bench shows weak size selectivity and no class selectivity (p~0.35). The paper narrows to
   direction x size; the measurement still publishes.
4. Hardware contradicts simulation (p~0.4). Standing rule: hardware wins, the simulation table is
   retained with a dated superseded label and its hash, never edited away.
5. An unassessed system occupies the sublink (p~0.2, fatal). Y.1731 per-CoS OAM is the closest
   unchecked threat. Close it this week.

## 6. Order of execution

1. Clear B1-B5 off-chip (one day). No hardware measurement before B1 and B2.
2. C4 compile on 9.13.2 — **DONE 2026-08-29**, both programs 11/4, exit 0.
3. Take the chip, bring up, run the `egress_qid` sentinel sweep and the hairpin proof.
4. C2 with its four-instrument ledger and negative control.
5. C1, 30 reps, switch-clock exact, with the disarmed negative control.
6. C3, the seven-step lifecycle figure.
7. In parallel off-chip: build arms A7/A8, the miss-rate-vs-conditionality and alignment curves, and
   the cut confirmatory grid.
8. The physical-impairment size-selectivity bench.
9. The htsim application-level block.
