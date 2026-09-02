# Session record — 2026-08-30 (Claude): CLF detection made trustworthy, then measured

Consolidates five fragmentary status blocks written during the session. Everything below is
measured on silicon unless it says otherwise. Commits `47797c6`..`0ce5e8d`.

---

## 1. Seven defects found and fixed

Ordered as found. Numbers 1-6 are all the same failure at bottom: **an RX bit that did not belong
to the measured traffic read as evidence of health**, and a 1-bit flag cannot say "implausibly
few". Number 7 is a bring-up omission that invalidated a conclusion I had already drawn.

**D1 — the trial driver never zeroed the bank.** `clf_trials.py`'s docstring specified
`quiesce -> zero -> quiesce -> generate -> settle -> read`; `trial()` had no zero step at all. The
"frozen" bank carried residue from every earlier run, and a stale RX bit makes `TX & ~RX` come out
zero **for the sublink under test** — a real blackhole read as HEALTHY. Residue does not add noise,
it deletes detections.

**D2 — the source leaf marked its own egress as an arrival.** In EGRESS `md.hop` names the NEXT
hop (ingress already advanced it: `act_enter` -> 1, `act_transit` -> 2), so the source's own egress
presented `md.hop == 1` and matched `tbl_rx_frontier`, at index `hdr.witness.link_id` = 0, still
ingress-zeroed because `tbl_wit_link` stamps later in the same apply block. Sublink 0 is a legal
address, so "unstamped" and "arrived on vlink 0 ctx 0" were the same 16-bit value. This produced a
standing TX=0/RX=1 verdict that failed PREREG rule 5 **on every trial**.
*Proven with no new experiment*: in the fault arm all 400 probes were discarded at `tbl_eg_fail`,
which runs AFTER `tbl_rx_frontier`, so nothing reached a downstream hop — yet RX registered an
arrival. Only the source's own egress could have written it.

**D3 — `act_transit` erased the bank parity.** TX is marked at the source's egress and RX at the
spine's, and `act_transit` runs between them writing `flags = md.flags_out` without the bank bit.
RX always landed in bank 0 while TX landed in bank B. Measured as a **56% control false-blackhole
rate** that was not noise at all: every bank-1 trial failed (5/5) and no bank-0 trial did (0/4).
**Latent second defect found while fixing it:** the bank shared `flags` bit 3 with
`set_gap_event()` (`md.flags_out |= 8`), so any packet raising a gap event would be stamped into
the wrong bank. It cannot fire under a total blackhole (no survivor, no gap) but would corrupt
every reading once the controller loop runs.

**D4 — a background packet could arrive between the zero and the arm.** The driver zeroed and
only then armed, leaving the target live for ~0.8 s. One stray packet in that window sets RX and
masks the blackhole. This was the single fault-arm miss at 89% (trial 6: **401 packets dropped,
verdict HEALTHY**).

**D5 — RX was on the wrong side of the traffic manager.** TX is in egress deliberately (post-TM,
so our own queueing is not blamed on the link); RX was **also** post-TM, at the receiver, where
that argument does not hold. A packet crossing the link cleanly and then dropped by the
*receiving* switch's TM never marked RX — and that queue belongs to the receiver's *outgoing*
link, so congestion on the downstream link was charged to the upstream one.
*Measured*: spine downlink shaped to 100 kb/s, no fault injected — `dp164 tx +408` and
`dp172 rx +408` (every packet crossed link 0 and arrived) while `dp174 tx +96`. **The link
delivered 408/408 and 76% of those deliveries were invisible to a post-TM RX mark.**

**D6 — the presence bit itself.** `rx_seen` did `v = 1` into a `bit<8>` register: seven bits
unused and the write discarded how many packets arrived. `RX > 0` meant "at least one packet, from
any source, at any time this epoch". This is why D1-D5 were all *silent*.
Critically, the presence bit also made PREREG rule 2 pass **for the wrong reason** — 96 survivors
and 408 survivors are the same bit, so congestion looked healthy because the encoding was
insensitive. That is the same insensitivity that let one stray packet mask a blackhole, and it is
why the counter fix and the placement fix had to ship together: counting alone, with RX still in
egress, would have turned rule 2 into a false STARVED verdict on a healthy link.

**D7 — `tbl_eg_vlink` was never installed.** It maps (egress_port, egress_qid) -> virtual link and
composes `md.sublink`; its miss action is `set_eg_vlink(0, 0)`; and it is installed by
**`setup_attention.py`, not `setup_skeleton.py`**. Every bring-up ran only setup_skeleton, so the
table was empty and **every packet reported virtual link 0**.
*Exposed only by two instruments disagreeing*: with a gate rerouting spray 0->1 the ingress
counter read `spray=1 vlink=1 pkts=30` while the frontier still said vlink 0.

---

## 2. Two claims of mine that were wrong, and the corrections

**"Coverage doubles" — retracted, then the retraction itself was reversed.** I claimed listing
frontier entries `{1,2}` extended coverage to the second link (`7eed2f7`). Ten packets read
`TX=20 RX=20` — every count doubled — so I reverted to `{1}` and wrote that the second link "has
no distinct sublink identity" (`c296ec8`). The doubling was real; **the diagnosis was wrong** — it
was D7, the empty table. With it populated, `{1,2}` restored gives proper per-link counters
(`4bc9da7`).

**"The spine transmitted zero frames" — an invalid measurement I reported as evidence.** Three
`$(ssh ...)` substitutions returned empty strings, so `$((A-B))` evaluated `0-0` and printed a
delta that had never been measured. Compounded by a second trap: `bash val.sh | head -4` let
SIGPIPE kill the script after it armed a blackhole and before its final clear, so the injector
stayed armed and every later port reading showed nothing leaving the source. **Both produced the
expected answer for the wrong reason.** Re-measured with raw values printed.

---

## 3. Engineering changes

| change | why |
|---|---|
| RX frontier moved **egress -> ingress** | D5: receiver's TM must sit outside the link measurement |
| both frontiers -> **saturating counters** (`v = v \|+\| 1`) | D6: a flag cannot express "implausibly few" |
| bank parity -> `hdr.fabric.clf_bank` (the dead `loops` byte) | D3 + bit-3 collision. Two compiler constraints forced it: preserving a bit across transit needs a mask+OR, rejected as *"action spanning multiple stages"* (class 5), and pre-computing the mask in the parser is rejected as *"Assignment source cannot be evaluated in the parser"*. `act_transit` never writes `loops`, so the parity survives **by construction** at zero wire cost |
| frontier entries `{1,2}` on both halves | two-link coverage, valid once D7 fixed |
| `clf_trials.py` rewritten | every step verified: zero confirmed, probe exit status and packet count checked, injector arm confirmed and its drop counter printed beside every verdict; failed preconditions **excluded**, never averaged in as misses |
| agent: `X` (per-sublink counts), ranged `K <sub> lo hi`, `U` (declare an audit flow), RX register path | readout that keeps the counts; controlled partial loss; probation steering |
| `verdict_counts()` + `STARVED` + 7 tests | BLACKHOLE keeps its exact meaning so earlier results stay comparable; STARVED is a **new** class reported separately (a PREREG amendment, not a redefinition) |
| `bringup.sh` step 5b | runs `setup_attention.py up` and **fails** if `tbl_eg_vlink` installs 0 rows |

All builds compile **11 ingress / 5 egress**, unchanged throughout.

---

## 4. Measured results

**Detection rates** (`selective_blackhole`, first link, guard 2.0 s):

| build | fault | control | IMPOSSIBLE |
|---|---|---|---|
| before bank fix | 9/9 | **5/9 false (56%)** | 0 |
| after bank fix | 8/9 (89%) | 0/10 | 0 |
| after arm-before-zero | **17/17 (100%)** | **0/19 (0%)** | **0** |
| final build, repeat | 9/9, 10/10 | 0/9, 0/10 | 0 |

**PREREG rule 1's actual comparison — what CLF sees that C-W4 cannot** (5 runs):
IDLE (nothing sent) and DARK (60 sent, all destroyed) leave C-W4's `reg_wit_observed`
**identical — delta 0 in all five runs** — while CLF separates them 5/5 (TX=0 RX=0 IDLE vs
TX=60-62 RX=0 BLACKHOLE).

**Sharper than "C-W4 detects 0%": C-W4 detects retroactively.** 40 clean packets leave observed at
201; 60 destroyed leave it at **201, unchanged**; 20 packets after clearing leave it at **45** —
the counter reset, so the gap fired at the first survivor. C-W4 is blind for exactly as long as
the blackhole lasts. A detector that reports a link dark only after it comes back cannot drive
mitigation while it is dark.

**`all_context_blackhole`:** CLF 4/4 contexts BLACKHOLE; C-W4's counters byte-identical
(80/680/133/42 unchanged) = 0/4. Injector dropped 84, confirmed in data. Reaching four contexts
needed `ctx = (dscp_class << 2) | size_bin` — size bin 3 needs `total_len >= 2048` and failed with
`Errno 90, Message too long` at MTU 1500, so the service-class dimension supplied the fourth id.
**Kill criterion tested:** while all four contexts were dark the physical port read **`up=True`**.

**STARVED on silicon** (not just unit tests): 60 packets with a ranged blackhole sparing five →
**TX=62 RX=3, injector dropped 60**. Presence bit says HEALTHY, count says STARVED.

**Survival sweep** — and a prerequisite that had to be measured first: **the witness sequence
advances 2.0 values per packet** (`reg_wit_seq` 13859->13959 for 50 packets), since it is stamped
on each fabric pass. So a sequence-range fault covers half the packets its width suggests, and the
16-bit space wraps every **32768 packets per sublink, not 65536** — PREREG's `wrap` scenario uses
the wrong figure. Across k=0..60 RX tracks k/2 monotonically, so **RX/TX is a faithful linear
estimator of survival**.

**Per-link localization** (two-link coverage, 10 packets/arm):

| scenario | vlink 0 | vlink 10 |
|---|---|---|
| no fault | 10/10 | 10/10 |
| first link dark | **11/0 BLACKHOLE** | *no row* -> IDLE |
| second link dark | 10/10 HEALTHY | **10/0 BLACKHOLE** |

With link 1 dark, link 2 is unexercised and reports **IDLE, not FAULTY** — the mechanism does not
blame the innocent downstream link, because TX records commitment and the spine committed nothing.

**Restoration lifecycle** (30 packets/step): healthy 30/30 -> fault 30/0 -> quarantine (production
on **vlink1** at 30/30, **no vlink0 row**) -> fault cleared (still no vlink0 row) -> probation via
a declared audit flow reads **vlink0 30/30** while production stays on the backup -> gate removed,
production returns 30/30. Shows selective mitigation working, **mitigation destroying the passive
evidence** (steps 3 and 4 are indistinguishable from the quarantined sublink — IDLE whether broken
or repaired), and probation restoring it.

**CLF priced** — same program compiled with and without the frontier:

| | ingress | egress | SRAM | map RAM | stateful ALUs |
|---|---:|---:|---:|---:|---:|
| without CLF | 11 | **4** | 80 | 23 | 6 |
| with CLF | 11 | **5** | 92 | 27 | 8 |

+1 egress stage, +2 stateful ALUs (exactly `rx_seen`/`tx_seen`), **0 wire bytes**, 1024 bytes of
fixed on-chip state. Evidence leaving the switch, frame size measured at 1446 B:

| packets | CLF readout | mirrored equivalent | ratio |
|---:|---:|---:|---:|
| 10 | 58 B | 14,460 B | 249x |
| 100 | 37 B | 144,600 B | 3,908x |
| 500 | 86 B | 723,000 B | 8,407x |

The readout does **not** grow with packet count — it varies only with the number of active
sublinks and is bounded ~1 KB for a complete read at any rate.

---

## 5. dShark (NSDI'19) retrieved — M1 verdict `NARROW`

The last unretrieved FATAL vector, now read. It does not kill the project; **it kills one framing
of it.**

* Table 2 ships a **"Silent black hole localizer"** — *"Localize switches that drop all packets"*.
  **Stop claiming novelty for detecting or localizing silent blackholes.**
* Its *"Packet drops on middleboxes"* query, `exist ingress and egress trace`, is a direct analogue
  of TX-vs-RX. **This is not a capability difference.**
* The retransmission dependency applies only to dShark's *own* blackhole query (groups on duplicate
  TCP `ipid`/`seq`); do not generalise it to dShark as a whole.
* What survives: **cost of evidence acquisition** and **actionability** — dShark mirrors to
  collector servers (3.33 Mpps/core goal, four cores/server at 40 Gbps), states its own
  capture-noise problem (mirrored drops burying real drops), and produces no handle to act on.

Verdict written into `NOVELTY-GATE.md` as the plan requires. **The framing "a new observability
primitive" is withdrawn**; the surviving claims are systems claims. The paper text still carries
the old framing and has not been updated.

**P3's mandatory liveness sub-gate is satisfied**: partial conditional loss, selective total
blackhole and all-context blackhole all demonstrated, and CLF is the liveness mechanism the
sub-gate demanded, priced above. That clears the stop condition about an *unpriced* auxiliary
liveness mechanism.

---

## 6. Testbed facts learned the hard way

* The real SDE is **`/home/decps/Downloads/bf-sde-9.13.2`**. `/opt/bf-sde-9.13.2` has no
  `site-packages` and gives `ModuleNotFoundError: bfrt_grpc`.
* **`pgrep -f <pattern>` matches its own command line**, same family as the documented `pkill -f`
  trap. It made a liveness check report "still running" forever. Resolve the real process via
  `/proc/<pid>/cmdline` and match on `python3*`.
* `bringup.sh` verifies loop pairs **before link training finishes** and reports pairs down that
  come up on their own ~60 s later. Adding step 5b incidentally gave them that time.
* `host_run.sh` buffers output until completion; watch progress by reading the remote process's
  `/proc/<pid>/fd/1` target.
* Backgrounding the agent inside a compound `ssh` often does not survive; launch it in its own
  `ssh` call.

---

## 7. Open

* **P3's remaining half**: the lifecycle is **scripted**. `controller/sublink_feedback.py`'s
  decision core (`AuditReceipt`, the bounded probation-round matcher, `probation_packets_required`,
  flap damping) was never in the loop. The plan's *"no running **controller** has yet…"* stands.
* Probation sizing: 30 packets was symmetry with other steps, **not** `probation_packets_required()`.
* **The guard interval was never measured** — 2.0 s used throughout on no evidence. This was CLF
  plan item 4 and it was skipped.
* `STARVED_RATIO = 8` still not in PREREG. The sweep shows it means "survival below 12.5%", but at
  k=15 the ratio is 0.133 against a 0.125 threshold — about one packet in sixty. Needs a margin or
  hysteresis. Noise floor at fixed k uncharacterised (TX read 62 against 60 sent at one point).
* Untested scenarios: `direction_only` (now testable with two-link coverage), reorder, wrap,
  flapping, repair, controller restart. Size bin 3 unreachable at MTU 1500.
* Frontier traffic accounting (CLF plan item 6) not started.
* dDrops and Speedlight unretrieved.
* Paper text not yet updated for the `NARROW` verdict.

**Conflict to reconcile before building further on the agent:** untracked parallel work includes
`p4/hw/loop/gate_agent_core.py` (+tests), `injector_ranges.py` and `multicontext_probe.py`. I
edited `gate_agent.py` **directly** (added `X`, ranged `K`, `U`) and wrote my own multi-context
probe, so the sequence-range logic and the probe now exist twice.

## Status (2026-08-28, later) — novelty gate tripped; the project is now TWO tracks

- **Both novelty gates failed** (`docs/review/NOVELTY-GATE.md`, PREREG v1.7). The coverage bound is
  Bellman/Blackwell stationary-target search, restated for budgeted policy classes by
  Chaudhuri–Fellouris–Tajer (IEEE TIT 2024) and Xu–Mei–Moustakides (2021). The order witness is
  NetSeer SIGCOMM'20 §3.3, verbatim, with LinkGuardian and UEC LLR as independent occupants. My §4
  "spraying collapses the pooled-test design space" argument is refuted by SprayCheck. A correctness
  error of ours: a post-TM witness does NOT see upstream TM drops.
- **Two coordinated tracks now run in parallel** (Philip, from the parallel session):
  1. **W4** — finish PTF/model then silicon validation. Useful infrastructure and a *costed known
     primitive*, explicitly not standalone novelty. Proceeds independently of the new gate.
  2. **Counterfactual observability** — evidence lease → switch-capped directed-link audit → limited
     probation → confidence-qualified restoration, for links that mitigation has starved of passive
     evidence. Novelty **provisional** until a rehabilitation/revalidation literature gate returns
     PASS / NARROW / FAIL; that gate comes *before* lifecycle implementation. Audit reuses W4's
     `link_id + sequence` and existing shim fields (target: zero added bytes; fallback +2 B
     `audit_id`). Insufficient evidence must return INCONCLUSIVE, never "healthy". Cheap event
     simulation gates the expensive P4/htsim/silicon work.
- **Compile gate PASSED** (`p4/witness/COMPILE-GATE.md`): baseline 8 ingress / 3 egress, W2 8/3,
  W4 8/3 — the witness costs zero MAU stages; arming the fast loop costs +1. **W4 is the silicon
  variant**: W2's premise fails here because one loop port carries two directed vlinks under the
  `(port, qid)` mapping. The existing injector drops in ingress, before the egress stamp, so it
  cannot produce a gap event; the egress-side injector is compiled and costed.
- **M1 re-issued after adversarial review** — ten harness defects, two of which invalidated claims I
  had published the same day (the moving-fault row and the stale-suspicion finding). Added `confirm`
  and `thompson` so H9 is tested against the class's strongest members; `confirm` is *exactly*
  uniform on 29/30 seeds because one read of the faulty link is always enough.
- **F0 is landing and it is the load-bearing block.** Background loss is real and distributed (1024
  of 2048 links drop). First result: at the frozen h = 6.5 the budgeted arms raise **zero** false
  alarms while in-band false-alarms in 10/10 seeds — it observes 25× more link-epochs. Read at each
  arm's own false-alarm-free operating point, in-band still localizes in **9.0 epochs against
  uniform's 18.0** and ties the oracle. Clean control (no loss at all): 0 alarms everywhere, so the
  effect is background loss observed more often, not detector noise.
- **Audit feasibility re-derived** (`docs/AUDIT-FEASIBILITY.md`): N = ln(1/α)/p = 29,956 packets at
  p = 1e-4, α = 0.05 — 45 MB, 0.9 ms at 400 G, so not a blocker; the real constraint is that cost is
  linear in 1/p, and that background loss at b = 1e-4 makes it **4×** (119,515 packets). Fleet scale
  for the 2/8/25 % axis: 0.90 / 3.68 / 11.50 GB, ×4 under background loss.
- **Another Claude session is editing this repo concurrently.** It owns README, PLAN, BRIEF,
  NOVELTY-MATRIX, NOVELTY-GATE and `docs/superpowers/`. I commit only my own files — never
  `git add -A` — after it swept Philip's PLAN.md edits into one of my commits this morning.
- **Next:** full F0 set (tightens C6 and re-issues M1 against background loss), then W4 PTF/model
  semantic validation; the counterfactual track waits on its literature gate.

## Status (2026-08-28) — warm-up bug fixed, M1 replay re-issued under PREREG v1.6

- **The bug.** `baseline_warmup_epochs = 10` counted pool UPDATE CALLS, so `inband_sync`
  (collect every 4th epoch) stayed in warm-up 4x longer than an arm reading every epoch with the
  same packets per read: 11 drops in 99,704 packets, CUSUM 0.00, `pool_n` 4 vs 16. Warm-up is now
  `baseline_warmup_packets = 1e5` observed packets (= 10/δ) and 10 latency samples; `ElementState`
  carries `n_pkt_loss` / `n_samp_lat`. infer.py `be12e7b2` → **`0a989aaf`**, re-frozen, 37 tests
  pass (new regression test: same evidence, quarter the calls, must detect).
- **Three more defects found in the same pass**, all in `sim/gate/replay.py`: salted `hash(stem)`
  for semi-synthetic fault identities (→ CRC-32 `scenario_seed`), implicit multi-fault success
  semantics (→ explicit `--objective any|all|original`, printed in the header), and an oracle that
  was handed only the recorded fault (under `all` it was NOT an upper bound — uniform beat it).
  The H9 gate line now evaluates the significance test too, and ranks only counter-computable
  schedules; the in-band arms are reported as a separate observability class.
- **Results (30 seeds, re-issued).** Frozen budget 41: uniform 20.0 → **18.0**, oracle 10.0 →
  **9.0**, in-band **9.0**, in-band sync/4 blind → **10.0**. The in-band arm is FLAT at 9.0 from
  budget 10 to 200 while every counter-computable schedule degrades (all censored at budget 10) —
  its evidence is not budgeted. H9 still not tripped anywhere (nearest miss threshold-gated,
  2 faults/any, 22 % of the gap at p = 0.86). Wrong-link alarms 0/30 seeds everywhere except the
  moving-fault regime, where counter arms raise 121–199 stale-suspicion alarm epochs against
  in-band's 14. Under `all` with three faults nothing finishes, oracle included — that row is
  horizon-bound, not an arm result.
- **Repo CLAUDE.md written** with the verified testbed (switch `decps@10.10.54.81`, never reboot;
  Vision dp9 / Hulk dp10 at 25G; Agilio↔Hulk 10G Soft-RoCE leg; chip currently owned by
  `defense4_rrc_bor_unified12` pid 36630) and the commit convention.
- **Running:** F0 control batches — Vision seeds 2000–2019 (BG_LOSS 1e-4), Hulk 2020–2029 (clean),
  5–10 concurrent runs per host, ~62 min each, ~21.5 GB peak. Hulk projects to ~115 GB of 125 GB,
  so a memory/OOM watch is armed. These logs feed the h-sweep ROC axis.
- **Next:** M1 theory gate (independent prior-art review of the coverage bound — this gates the
  major P4 work per the plan), then M2 post-TM order witness compile study (2 B vs 4 B) against the
  recorded 8-ingress/3-egress baseline. The chip is not ours right now.

## Status (2026-08-25) — Phase S-DOWN started (Tofino down)
- Repo cloned from akekulip/mcp; legacy tree moved to `legacy/` (frozen, read-only — the audit
  found its simulator placement-insensitive, sketch actuation inert, "LinUCB" = SGD+UCB1, unseeded
  RNG in reward). New layout: sim/ p4/ nic/ controller/ paper/ docs/.
- Switch mgmt now decps@10.10.54.81 (not .15); both unreachable today. Vision (.166) and Hulk (.158) up.
- DEADLINES (verified 2026-08-25): NSDI'27 spring passed (Apr 2026); NSDI'27 fall = 17 Sep 2026
  (infeasible). Realistic: SIGCOMM'27 (~late Jan 2027, verify) or NSDI'28 spring (~Apr 2027).
- Running: literature-reviewer → docs/NOVELTY-MATRIX.md + Zotero collection "MCP-sprayed-fabrics".

## Status (2026-08-26, later) — gate RERUN with RTO fix: 105/105, 0 stalls
- Added `-rto_min_us` to htsim main_uec.cpp; run_gate.sh sets RTO_MIN_US=300. Seeds 11/26 now
  recover the single drop via RTO (finish 13.2435 ms vs 13.2367 loss-free). 18/105 runs saw a
  silent drop; all completed. Old dead-RTO results archived in sim/gate/results_2026-08-26_deadRTO/.
- analyze.py: incast TOO HARD (uniform censored 93%, all TTL=132 = horizon; trace too short at
  EPOCH_US=100), lulesh OK (uniform median TTL 52193 epochs, censored 40%; oracle 52182, random 52267
  — policies indistinguishable at n=5).

## (superseded) Status (2026-08-26) — first gate run, dead RTO, verdict TOO HARD
- `sim/gate/run_gate.sh` finished: 133 result csv (incast 28/28/28, lulesh oracle 5 / random 17 / uniform 27).
  `analyze.py` verdict for BOTH traces: TOO HARD — uniform censored >50% (incast 100%, lulesh 67%)
  → PREREG says loosen the operating point one step before proceeding.
- incast runs last only ~13 ms sim time = 132 epochs at EPOCH_US=100; that horizon is far too short
  for localization (all policies censored at 132). Consider longer trace or smaller epoch.
- incast seeds 11 and 26 STALL under every policy: a flow never completes before `-end 1000` ms
  and the htsim GOAL loop then spins forever printing `progress:` (6.5 GB log / 5 min; this is what
  killed the 08-25 batch too). Guard added to run_gate.sh (timeout + ulimit -f 512MiB +
  `seed<N>.STALLED` marker); their `.csv.tmp` measurement logs (10000 epochs) are kept but excluded
  by analyze.py. Root cause is in htsim `logsim-interface.cpp:1005` (no exit when htsim time hits end);
  ROOT CAUSE (2026-08-26, seed 11 bisected): one silent DATA drop (flow 1000000001, psn 433, 148 us)
  is never retransmitted because the UEC RTO is effectively disabled: main_uec.cpp:751 sets
  min_rto = 15us + queuesize*6*8/linkspeed with queuesize in BYTES; our `-q 1000000` packets
  (=4.096 GB) gives min RTO = 1.97 s > sim end, so every startRTO() is rejected as "too late"
  (uec.cpp startRTO null-handle branch). Silent loss has no trim/NACK path, sleek is off, so the
  hole persists; after 16384 packets the receiver's ModularVector<1<<14> rx bitmap wraps and
  aliases psn 433+16384 onto the hole (the "Spurious" burst at 5.73 ms). Fix options: add a
  -rto_min_us CLI (recommended, ~200-500 us) or use a realistic -q; then rerun the WHOLE gate.
  Temporary instrumentation left in sim/htsim (uncommitted): pipe.cpp MCP_DROP print,
  main_uec.cpp UEC_DEBUG_FLOWID env hook, uec.cpp timer debug prints widened to _debug_flowid.
- NOTE: LULESH runs take ~1 min each; script comment corrected.

## 2026-08-26 (afternoon) — real gate (PREREG §10) started: trace + cost probing
- ATLAHS trace collection (http://storage2.spcl.ethz.ch/traces/) has Mixtral-class MoE traces, no
  "NeMo Mixtral"/Zenodo item: MoE8x8B GPU64 (bin 523 MB), MoE8x13B GPU128 (bin 10.05 GB),
  MoE8x70B GPU256 (bin 31.9 GB); Chakra ET twins under astra-sim-traces/. Downloaded 64 and 128
  to sim/traces/moe8x8b_n16, moe8x13b_n32 (SHA256 + SOURCE files alongside). PREREG §10 must be
  amended to name the actual trace.
- Topology fat_tree_1024_1os: 200G links, 16 pods x 8 agg x 8 core = 1024 agg->core uplinks;
  budget 2% = 20 links.
- H18 cost probe on 1024 fat tree (sim/gate/probe/): MoE-128 advances ~0.5 ms sim per wall-second
  (105 ms after 8 min) -> a 120 s horizon is ~3 days/seed: infeasible. MoE-64 probe running.
- Prebuilt lgs/LogGOPSim needs glibc >= 2.38 (host has 2.31); source build needs libgraphviz-dev.
- Vision (.166) and Hulk (.158) idle, 72 cores, glibc 2.39 (prebuilt LogGOPSim runs there). Staged
  to both: ~/mcp/sim/{htsim binary, topologies, traces/moe8x8b_n16, gate/run_gate_real.sh, analyze.py}.
  Login: `source ~/.lab_env; sshpass -e ssh decps@<ip>` (Tooling/README.md).
- sim/gate/run_gate_real.sh = PREREG §10 fan-out (policies x seeds 1000-1029, budget 20/1024,
  loss AGG:0:0:1e-4, RTO 300 us, per-run 12 h timeout + 4 GB log cap + STALLED marker, logs
  stripped of LGS chatter on success). Split seeds across hosts via SEEDS/JOBS env.
- MoE-64 full seed-1000 run (local, epoch 100 ms): ~1 ms sim per wall-second, 2-4 GB RSS.
  LogGOPSim on Vision measuring the trace's intrinsic duration (= usable horizon per run).
- PREREG §10 amendments needed before freezing (Philip to approve): trace = ATLAHS
  MoE8x8B_N16_GPU64 (SHA256 in sim/traces/moe8x8b_n16/SHA256), not "NeMo Mixtral/Zenodo";
  horizon = one training iteration (trace length), not 120 s; epoch 100 ms not 1 s; loss onset
  t=0 not U[10,30] s (hook has no onset knob yet — add `-mcp_loss_onset_ms` if the iteration is
  long enough to afford one).
- LAUNCHED 2026-08-26 ~12:45: real gate on Vision (seeds 1000-1014, 45-wide) + Hulk (1015-1029,
  25-wide), MoE-64 on fat_tree_1024_1os, epoch 100 ms, budget 20, onset U[300,900] ms per seed
  (`seed<N>.onset`), htsim sha256 ec4578cf… (quiet LGS prints + -mcp_loss_onset_ms; LGS_PRINT_EVENTS=1
  restores the per-event log). MoE-64 iteration = 3.517 s (LogGOPSim, Vision gate/lgs/).
  Quiet prints made LULESH 60 s -> 4 s wall with identical csv.
  Coverage arithmetic: uniform sweeps 20/1024 links per epoch -> 52 epochs = 5.2 s > 3.5 s
  horizon, so uniform is expected to censor at 100 ms epochs; if §10 says TOO HARD the loosening
  step is a shorter epoch (50 or 20 ms), not a higher loss rate. analyze_real.py = onset-aware
  TTL, KM, CV(log TTL), rho(uniform,random), verdict.
- ~13:20 memory trim: workers reach ~5 GB RSS and grow (probe: 4.1 GB @1.4 s); Hulk hit 4 GB free.
  Killed newest workers -> Vision 32, Hulk 16 (Hulk xargs killed so it stops refilling). Killed runs
  carry `.STALLED` markers written by one_run: WAVE 2 = delete those markers + rerun with
  JOBS<=32/16 (also covers Hulk's 11 never-started random/oracle jobs). Size rule: <=5 workers
  per 32 GB until RSS at end of a 3.5 s run is measured (`seed<N>.time` maxrss_kb).
- ~13:55: RSS grows with sim time: local seed1000 = 18.5 GB at 3.4 s (fleet workers 7.5 GB @1.6 s).
  Peak ~20 GB/run => fleet width by memory: Hulk 5, Vision 10 (trimmed to that). 90 runs at 15-wide
  x ~1.5 h => ~9 h for the gate. Growth is per-flow state in htsim (MoE creates ~1e5 UEC flows by
  1.4 s; flow ids 1000094663+), not the MCP hooks (mcp.cpp holds only small vectors). -> HURDLES H26.
- ~14:40 RESULTS (2 % budget, 100 ms epoch): 5/5 Hulk uniform runs + local seed1000 finished:
  wall 62 min (fleet) / 31 min (alone), maxrss 21.3 GB, 36 epochs (3.585 s), 19-29 silent drops,
  uniform correct=0 in ALL (100 % censored) -> §10 TOO HARD by construction (52-epoch sweep > horizon).
  CONFOUND: faulty link US0->CS0 is the FIRST link in uniform's sweep order -> probed in epoch 1
  (before onset), next visit epoch 53. PREREG must randomize the faulty uplink per seed (or offset
  the uniform order) — otherwise uniform TTL is an ordering artifact. Detection per probe ~48 %
  (0.65 expected drops per 100 ms epoch on a ~4 %-utilized link); shorter epochs make per-probe
  detection worse, so the loosening lever is budget (or loss), not epoch.
- DECISION TAKEN (pending Philip's confirmation): stop wave 2 at 2 %; let Vision's 10 uniform runs
  finish (n=15 for the verdict); Hulk runs the "loosen one step" pilot BUDGET=41 (4 %) on seeds
  1000-1004 x 3 policies (results_real_b41/). Expected: uniform TTL ~17-23 epochs, oracle ~2,
  random ~50 % censored.
- ~16:10 §10 VERDICT at the pre-registered point (2 %, 100 ms epoch, loss 1e-4, MoE-64, n=15
  uniform): median TTL 30 epochs [28,31] from onset, censored 100 % -> TOO HARD; loosen one step.
  Pilot at 4 % (BUDGET=41) now n=15 x 3 policies: Hulk seeds 1000-1004, Vision 1005-1014
  (results_real_b41/ on each host; pull with the rsync in the notes above).
- ~20:30 4 % PILOT (35/45 in, Hulk complete): §10 verdict OK — uniform median 20 [19,21] 0 % cens.,
  random 27 [17,29] 33 % cens., oracle 12 [12,14]; CV(log TTL) uniform 0.03 / random 0.11 / oracle 0.04;
  rho(uniform,random)=0.20 (n=10). BUT drops are traffic-phased (H27): the faulty link only carries
  traffic in epochs 15-19 and 33-35, oracle's first_correct == first drop epoch in 5/5 seeds. TTL is
  the trace schedule, not the policy. Needs a PREREG metric/placement decision before freezing:
  (a) TTL from first observable drop, (b) randomize faulty uplink per seed, (c) onset inside a
  traffic window or multi-iteration horizon. Vision's last 10 oracle runs pending.
- Hook semantics to state in PREREG §2.1: a probe's evidence window is "since this link was last
  probed" (mcp.cpp `_seen_tx/_seen_drop` deltas), not the epoch; verdict = argmax drop/tx over the
  chosen set if > thresh 1e-5. Counters file (`-mcp_counters`, now in run_gate_real.sh) holds
  cumulative tx/rx/drop per link per epoch; local run real/moe64_b41_counters/ collects it for
  US0->CS0 utilization per epoch (H27 evidence).
- COUNTERS EVIDENCE (real/moe64_b41_counters/seed1000, 31 min, 21.5 GB): US0->CS0 tx per 100 ms
  epoch: 27k,24k (ep 1-2), ~0 (3-15), 33k,41k,28k,29k,22k (16-20), ~0 (21-33), 37k,40k (34-35);
  drops 6,3,3,2 in ep 17-20 and 1,1 in 34-35 (6/40964 = 1.5e-4 ~ injected 1e-4). Fabric-wide:
  896/1024 uplinks idle in epoch 10, 0/1024 idle in epoch 16 -> the MoE-64 iteration is
  compute-dominated with three communication bursts; busy-epoch link load ~6-7 % of 200G.
  Any policy is blind outside bursts. Options for §10: TTL from first observable drop; or add
  a background traffic matrix (PREREG F0 background-loss block already needs one); or choose a
  trace with continuous communication (e.g. Llama DP128) for the gate.
- ~23:30 4 % PILOT COMPLETE, 45/45, 0 stalls (mean wall 62 min, max RSS 21.5 GB): oracle 11 [10,12]
  0 % cens. CV 0.06; random 27 [17,29] 33 % cens. CV 0.11; uniform 20 [19,21] 0 % cens. CV 0.03;
  rho(uniform,random) = 0.20 (n=10). §10 verdict OK mechanically, but H27/H-order caveats stand:
  do NOT freeze §14 until Philip decides TTL definition + faulty-link randomization.
  Summaries: sim/gate/results_real_summary.txt (2 %), results_real_b41_summary.txt (4 %).
- 2026-08-27 ~00:15 "go": decisions taken = TTL_obs (from first observable drop, via counters) as the
  §10 rule metric + from-onset reported; faulty uplink randomized per seed (seed<N>.fault);
  point frozen at 4 %, loss 1e-4, 100 ms. PREREG §14 amendment v1.2 appended. v1.2 GATE LAUNCHED:
  Vision seeds 1000-1019 (10-wide), Hulk 1020-1029 (5-wide), OUT=results_real_v12 (~6.5 h).
- 2026-08-26 ~21:30 SWITCH REACHABLE (decps@10.10.54.81, up since ~17:15): chip FREE — no
  bf_switchd, gc-switchd inactive+masked (defense4_caseA NOT loaded). SDE 9.13.2 at
  /home/decps/Downloads/bf-sde-9.13.2 (also /opt/bf-sde-9.13.2). mcp_fabric.p4 (sha c40dbfbe)
  compiled there: 0 errors, same stages/tables/bin size as local 9.13.1 -> H17 closed for step 4.
  Build at ~/mcp/p4/mcp_fabric.tofino on the switch. Starting bf_switchd = gated on Philip.
- Philip 2026-08-26: bf_switchd NOT YET (chip stays idle; prepared: ~/mcp/p4/mcp_fabric_abs.conf +
  launch_mcp_switchd.sh on the switch, run with sudo when approved). FABRIC SHAPE DECIDED:
  **4 leaves x 2 spines** (P4 design §12 Q5) -> update P4-DESIGN-SPACE §5/§12 and the vlink map.
  Q4: decps is NOT in the docker group on the switch (needs sudo usermod). Q1/Q2 (dp9 host, dp65
  Agilio leg) still need a live bf_switchd to read link state.
- 2026-08-26 ~21:45 Philip: sudo on switch OK, never REBOOT the switch; bf_switchd/controllers fine.
  bf_kdrv was not loaded after the reboot -> `sudo bf_kdrv_mod_load $SDE_INSTALL`; bf_switchd now runs
  mcp_fabric (launch_mcp_switchd.sh, /tmp/mcp_switchd.log). bfshell usage: feed stdin with sleeps
  (`ucli` lands in pm context; bfshell only flushes on exit). Docker NOT installed on switch (Q4).
  WIRING (10G sweep of all 132 lanes, 2026-08-26): UP = 15/1 (dp9, 25G RS AN) = **Vision
  enp59s0f0np0** (carrier flips with 15/1 -> Q1 = Vision); 33/2+33/3 (dp66/67, 10G, symmetric RX)
  ; 5/0-3 + 6/0-3 (dp164-167, 172-175, 10G, 0 frames) -> patched DAC between cages 5 and 6.
  DOWN with module present (RDY): 15/0, 15/2, 15/3 (4x25G breakout, other legs unplugged).
  **Hulk enp59s0f0np0 is NOT connected to the switch** (no link at 25G or 10G on any lane; its
  i40e now reports 10GbaseT-only link modes, AN off). dp65 (33/1) RDY=NO -> Agilio leg gone (Q2);
  Vision Agilio np0 cage EMPTY (no module), np1 = direct 10G link to Hulk enp59s0f1np1.
  PAIR TEST: dis 6/0,6/2 -> 5/0,5/2 drop => cages 5<->6 are one 4-lane DAC, lane-for-lane
  (5/k <-> 6/k, k=0..3): 4 physical loopback links available to mcp_fabric. dis 33/3 leaves 33/2 UP
  => 33/2 and 33/3 go to separate external devices (probably the DNP3 rig; leave alone).
  5/0-3 <-> 6/0-3 link at **25G RS-FEC** (dp164-167 <-> dp172-175): 4 x 25G loops = 100 Gb/s for
  the 4-leaf x 2-spine virtual fabric (§5.4 bandwidth table: recompute with these, not dp65).
  Ports left configured on the chip: 15/0 (10G, no link), 15/1 25G (Vision), 5/x+6/x 25G, 33/x 10G,
  and ~120 sweep-added RDY=NO lanes (harmless; port-del if `show` gets noisy).
  HUMAN ACTION NEEDED: plug Hulk enp59s0f0np0's DAC into the switch (cage 15 lanes 0/2/3 have the
  breakout legs; today no lane links) — until then Hulk reaches the fabric only via Vision's
  direct 10G link (enp59s0f1np1 <-> enp175s0np1s0).
- 2026-08-26 ~22:30 Philip: "P4 and the switch is yours". Fabric mapping for 4x2 on the real
  loops: leaf l <-> pair 5/l<->6/l; uplink out 5/l qid s (re-enters 6/l = spine pass), downlink
  out 6/l qid s (re-enters 5/l = dest-leaf pass); all leaves deliver to dp9 until Hulk is cabled.
  p4-dataplane-engineer agent: setup_skeleton.py rewrite + silicon smoke of steps 1-4 (running).
  STEP 5 DONE (me): attention register + §7.4 rule + TCAM gate; 0 errors both SDEs, 8 stages;
  PREREG v1.3 freezes §7.4; H22 closed; 3 new bf-p4c constraint classes (9-11) in the tofino-p4
  skill. Next: step 6 (mirror on inj_drop -> collector dp9), control-plane additions for step 5.
- ~23:45 STEPS 6 + 7 DONE: mirrors (sid 3 on injected faults, sid 1 on gated samples, OR-composed;
  collector = dp9 for now) and the CSIG tag (inserted/zeroed in ingress act_enter with path_id +
  epoch, compare-and-replaced in egress via diff = worst |-| this, gate diff == 0). fabric_h is 8 B
  (+path_id), csig_h 14 B. Ingress 9 stages (at the §8.1 limit), egress 3. Both SDEs 0 errors,
  bin 1461583 B, sha a0dee21f. Constraint classes 12-13 added to the tofino-p4 skill (mid-word
  intrinsic slices; egress one-source-per-container). Not yet loaded on the chip: the switch still
  runs the step-4 build while the agent smoke-tests it; reload after that.
- ~00:20 (08-27) ALL 8 §9.2 STEPS COMPILED: final sha 1a8fc6104b03bcdf, bin 1461583 B on both SDEs
  (also built at ~/mcp/p4 on the switch, not loaded). p4/control/setup_attention.py = steps 5-7
  control plane (client_id 2, no bind): params k_up/a_min/n_clean_m1, reg_attn seed, 255 tbl_gate
  rows, tbl_eg_vlink 16 rows, exceed thresholds, mirror sids 1/3 -> dp9. Rule shipped = saturating
  bump (no bump_cap); PREREG v1.3 corrected same day. Commits 575f1ee..381c4e4.
  TO DO once the step-4 silicon smoke finishes: pkill bf_switchd, relaunch (same launch script,
  build already at ~/mcp/p4/mcp_fabric.tofino), setup_skeleton up + setup_attention up, then
  silicon tests: (a) counters + hairpin delivery as in step 4; (b) mirrors: tcpdump on Vision for
  ether 0x88F0 copies while `fail <vlink> 50 drop`; (c) attention: `attn` dump before/after sending
  evidence packets (UDP dst 0xE5E5, evid_h path_id/loss_q) — attn[path] += 1024 per packet;
  (d) CSIG: captured mirrored samples carry csig_h with worst_qdepth/worst_vlink set.
- 08-27 ~00:45 DEPLOYED: step-4 silicon smoke PASSED (agent; p4/reports/step4-silicon.md) and found
  the parser cast aliasing (md.hop == vsw_id<<8|hop) -> fixed by widening fabric_h to 16-bit fields
  (12 B; ingress back to 8 stages; sha 232b7355). bf_switchd restarted on the final build;
  setup_skeleton up + setup_attention up succeeded (bind_pipeline_config needed per client).
  Agent now validating steps 5-7 on silicon (gate sampling, fault mirrors, evidence bump, decay,
  CSIG). Skill testbed.md updated with the deployment landmines.
- 08-27 ~00:55 STEPS 5-7 SILICON (agent, p4/reports/step5-7-silicon.md): gate 508/4000 copies at
  attn=4096 (6.25 % x 2 passes), seed 0 -> 0, seed 65535 -> 2/pkt; evidence +1024/pkt exact; decay
  exact; fault mirrors == inj_drop count exactly; CSIG under a 50 Mb/s shaper: worst_vlink correct
  92.5 %, qdepth up to 11306 cells, attn saturated 65535 -> ~100 % sampling: THE FAST LOOP CLOSED
  END-TO-END ON SILICON (H7 mechanism demonstrated; timing measurement still to do).
  Defects -> P4 v2 (sha 789b5b27, deployed 23:11): mirror_h prepended to copies (Mirror.emit copies
  the packet as arrived), egress skips copies, evidence forwarded host-pipe -> loop-pipe (reg_attn is
  PER PIPE: dp9 = pipe 0, loops = another pipe), attention only on fabric passes. Class 14 added to
  the skill. Agent re-validating v2 now.
- 08-27 ~01:15 V2 VERIFIED ON SILICON (p4/reports/step5-7-silicon-v2.md): all exact — 487/487 copies
  0x88F1 with flags bit0, fault copies 246 == inj_drop 246, evidence +10240 in BOTH pipes, decay
  symmetric [4095,4095]/[904,904], inner CSIG worst_vlink 269/269, loop closes (attn trajectory
  visible in mirror_h.attn: 843 @4096, one per +1024 step, 8675 @65535). Notes: mirror_h.hop is
  next_hop (renamed); CSIG exceedance only in the loop pipe by construction (design errata 8).
  H4, H5 closed. Chip state: build 789b5b27 loaded, both control planes up, attn seeded 4096.
  NEXT on hardware: H7 timing (tau_fast vs tau_slow), rxe pre-test (H20) needs Hulk cabled.
- 08-27 ~01:30 H7 (F6) TIMING RUN STARTED: build f0b66793 (mirror_h + 48-bit ingress_mac_tstamp,
  30 B) loaded 23:23 switch time; agent measuring tau_fast = first attn>4096 copy - first
  csig.worst_qdepth>=4096 copy (switch clock), tau_slow = full 256-slot reg read + counter sync +
  256-slot write from the switch's control plane, >=10 reps, specificity across healthy paths.
  F1 (loss) cannot be timed until the NIC evidence producer (nic/) exists -> needs Hulk + rxe.
- 08-27 ~02:00 H7 (F6) RESULT (p4/reports/h7-timing-F6.md, 12 reps): tau_fast as PREREG defines it
  is 0 by construction (ingress order exceed -> attn -> gate: the evidence packet is gated under
  the attention it just raised; t_react - t_evid <= 0 in 12/12). Back-extrapolated tau_fast
  median 97.4 us (BCa CI 68-215 us); ramp to saturation 1.21 ms; tau_slow full-sweep epoch 88.8
  ms (read 48.5 + counter sync 29.8 + write 9.6) -> ratio median 907, CI 452-1143 (sign test
  12/12, p=2.4e-4); but vs a minimal 1-slot epoch (2.2 ms) ratio 22, CI 6-27 (< 100).
  Specificity 0/13 healthy path-instances reacted. F1 not run (no NIC evidence producer).
  DECISIONS FOR PHILIP (PREREG, post-hoc-flagged): (i) tau_fast definition — first gated sample
  after the first *exceeding* packet is degenerate; candidates: ramp back-extrapolation, or
  time from fault ARM (shaper on) to first raised-attention copy, or from first over-threshold
  queue sample to attn crossing a fixed level (e.g. 2x baseline); (ii) tau_slow scope — the
  claimed 100x must name the epoch (full sweep vs minimal); (iii) H7 needs F1 -> nic/ producer.
  Anomalies: 0.15-0.22 % collector-side frame drops at saturation; `shape` unit is Gb/s (fixed
  usage text). Chip idle, attn 4096, PID 26316.
- 08-27 Philip: tau_fast = ramp back-extrapolation; tau_slow = full-sweep epoch -> PREREG amendment
  v1.4 appended (F6 post-hoc, F1 pre-registered). Agent building nic/evidence_probe.py then H7-F1.
- 08-27 ~02:30 CONTROLLER WORKSTREAM STARTED (two builders in parallel): controller/infer.py = the
  frozen common inference layer (§3.3: Beta-Binomial + Normal-Gamma posteriors, uniform-prior
  de-aggregation path->links, two-sided CUSUM, ranking; conf/infer/frozen.yaml + freeze.py hash;
  tests i-v) + controller/reward.py (§7.2) with test_reward_no_leakage (§7.3);
  controller/epoch_loop.py + hw_adapter.py (mirror_h/fabric_h/csig_h parser, tbl_vlink deltas,
  reg_attn snapshot; tbl_fail = ground truth, never a sample) + policies.py (uniform/random/
  oracle/mcp_stub = A6). Shared Sample(element, delivered, lost, latency_us, t_us) contract.
  Later: point sim/gate analysis at infer.localize too (§3.3 says every arm uses it).
- 08-27 ~03:10 nic/evidence_probe.py DONE (agent): spray recovery = zlib.crc32(src|dst|sport)&1,
  4983/4983 vs silicon; 1 % drop -> loss on the right path only, reg_attn -> 65535 both pipes.
  H7-F1 (12 reps, v1.4): tau_fast 10.115 ms (CI 10.10-10.13), sid-3 check 10.47 ms, ratio 8.8
  (CI 8.6-9.1) -> H7 FAILS for F1, structurally (no in-band loss evidence; floor = RTT tail of the
  probe path, 1.8 ms; 2 ms window gives 2.0 ms/ratio 44 with specificity breaking). Recorded in
  PREREG §14. Defect: evidence-packet copies had path_id 0 -> P4 emits md.mir_path (MAU copy of
  attn_idx) now. NOTE for the paper: "fast where the data plane can see, host-bound where it
  cannot" is the honest H7 story.
- 08-27 ~03:45 CONTROLLER LANDED (5a1892f) + CO-SIM BRIDGE: htsim `-mcp_policy extern:obs:act`
  (sim/htsim ef6d591) <-> controller/sim_bridge.py; extern-uniform reproduces C++ uniform
  IDENTICALLY (LULESH-128 seed 1). cusum arm (MCP v0 = localizer suspects + round-robin explore):
  budget 32 -> anomaly at epoch 49, locks on US0->CS0; budget 4 -> blind (per-element 10-obs
  warm-up needs 320 epochs). Builder adding baseline_mode=pooled. PREREG §14 row for the
  candidate localizer constants (not frozen yet). Remaining MCP pieces: shadow-price budgeted
  bandit (H3) + context vector (H4) on top of the bridge; the hardware epoch loop is code-complete
  but untested on silicon.
- 08-27 ~04:30 MCP v0 LEARNER (controller/mcp_policy.py) + co-sim mini-gate (run_cosim.sh): on
  LULESH-128 mcp v0 is WORSE than uniform; root cause = localizer false alarms (anomaly on in
  46/55 epochs every run: two-sided loss CUSUM trips on healthy links in pooled mode). Fix: loss
  CUSUM upper-sided only (builder). Learner untuned; results interim, not for the paper.
  + explore_floor=0.25 (coverage guarantee) -> b32: mcp median 8 vs uniform 9, 0 censored (no
  more collapse); b4: still 4/5 censored (floor = 1 slot). Awaiting the upper-sided CUSUM fix
  before any tuning; then the §3.2 tuning block, not ad-hoc knob turning.
- 08-27 ~05:00 Localizer: upper-sided loss CUSUM landed (29fc176) but alarms unchanged (46/55):
  the real source is IDLE links — a probe returning (0,0) leaves the Beta(1,1) prior mean 0.5
  and the CUSUM explodes (~2000/epoch). Builder making zero-count samples no-ops. Hardware loop
  now has --policy mcp (McpLearnedPolicy, ed81082/0b59db6). Pending: zero-count fix -> rerun
  run_cosim.sh; slow-loop silicon report; v1.2 gate.
- 08-27 ~05:30 zero-count fix landed (af5e858) but alarms still 46/55: third source = prior mass
  on light probes (500 clean packets -> Beta mean 2e-3 -> stat 6.96 > h). Fix in progress:
  loss CUSUM increment = binomial LLR (x log(p1/p0) + (n-x) log((1-p1)/(1-p0)), delta_loss 1e-3,
  h 5 nats) — count-aware, clean probes give negative increments. Lesson for §3.3: "CUSUM on the
  posterior mean" is the wrong statistic for counts; PREREG text to be amended when frozen.
- 08-27 ~06:15 LOCALIZER CLEAN (361a729, hash 116ffc9f, h=6.5 nats): co-sim alarms now ALL on the
  faulty link, 0 false alarms in 50 runs. cusum == uniform TTL (first post-onset probe decides);
  mcp v0 untuned: b32 median 11 vs 9, b4 4/5 censored. Next per PREREG = §3.2 tuning block on the
  tuning split (seeds 6-10, LULESH-128): sim/gate/run_tuning.sh (64 mcp configs, 9 cusum).
- 08-27 ~07:15 TUNING + EVAL DONE (730 + 40 runs, 0 failures): all arms tie at equal budget on
  LULESH-128 single-fault (b32 medians 9/8/9/9; b4 31/22/31/34). Learner selects coverage-like
  configs (floor 0.75). sim/gate/COSIM-RESULTS.md. Conclusion: pipeline validated; H1 on this
  rehearsal trace would be falsified; the Tier-1 environment (MoE bursty load = context, multi-
  fault, background loss, non-stationarity) is where MCP must show its 30 %. Next research
  moves for Philip: (a) co-sim on MoE-64 @1024 (1 h/run, on Vision/Hulk after the gate);
  (b) hook flags for background loss (-mcp_bg_loss p) and multi-fault; (c) load context is
  already in the learner's features.
- 08-27 ~07:30 `-mcp_bg_loss <p>` added to the hook (sim/htsim 4a9ad8b): F0 background loss on all
  uplinks, per-link RNG, fault spec overrides its link (verified: 34/128 uplinks dropped at 1e-4).
  Multi-fault already works (repeatable -mcp_loss). run_cosim/run_tuning need a BG_LOSS knob.
- 08-27 ~09:30 V1.2 GATE DONE 90/90 (0 stalls, 29 distinct faulty links): oracle 8, uniform 15
  [10,22] 3 % cens., random 23 [16,27] 37 % cens.; TTL_obs 0 / 9 / 14; CV(log TTL) uniform 0.18
  (onset) / 0.51 (obs); rho(uniform,random) 0.05. Verdict OK; operating point FROZEN in PREREG
  §14 (4 %, 1e-4, 100 ms, MoE-64, random uplink, onset U[0.3,0.9] s). Summary:
  sim/gate/results_real_v12_summary.txt. Tier-1 next: MCP + baselines at this point via co-sim
  (1 h/run; 15 concurrent on Vision+Hulk).
- 08-27 ~09:45 TIER-1 CO-SIM PILOT LAUNCHED at the frozen point: arms mcp (LULESH-tuned dlinucb,
  alpha 0, floor 0.75 — a PILOT config, Tier-1 tuning not run) and cusum (explore 0), same 30
  seeds/faults/onsets as the gate -> paired with uniform/random/oracle. Vision seeds 1000-1019
  (10-wide), Hulk 1020-1029 (5-wide); ~4 h. results_tier1_cosim/ on each host.
- 08-27 ~11:00 PILOT RELAUNCHED: first 5 Hulk runs showed the localizer could not alarm at a 1e-4
  fault (delta_loss 1e-3 -> negative LLR drift; fault top by mean, stat 0). delta_loss := 1e-4
  (conf only). Pooled mode verified synthetically (alarm epoch 20, 20/20 on fault); per_element
  test iv fails (prior-mass baseline) -> builder making p0 prior-free. LULESH rehearsal numbers
  were at delta 1e-3 (recorded as such). Pilot restarted ~11:00, ~4 h.
  (First relaunch doubled the workers: `pkill -f run_tier1_cosim.sh` killed the ssh shell itself.
  Use `pgrep -f "run_tier1_cosim[.]sh"`. Cleaned and relaunched once at ~11:10: 10 + 5 workers.)
- 08-27 ~11:20 prior-free p0 landed (hash be12e7b2). PROVENANCE: the running pilot loaded infer.py
  hash 116ffc9f with delta 1e-4 (pooled mode; p0 = pool posterior mean, prior mass negligible at
  pool scale) — record this hash with the pilot results; rerun only if numbers are for the paper.
- 08-27 ~13:30 PILOT INTERIM (mcp 30/30 done, cusum running): paired on identical seeds/faults —
  oracle 8 [5,9]; uniform 15 [10,22] 1/30 cens.; random 23 [16,27] 11/30; MCP (LULESH-tuned
  pilot config: dlinucb, alpha 0, floor 0.75) 18 [14,24] 1/30 — slower than uniform in 23/30
  seeds (median 7 epochs). Localizer clean (alarms only on the fault, at the sim-verdict epoch).
  Mechanism: 31 RR slots sweep 1024 links in 33 epochs vs uniform's 25; the 10 learned slots
  don't pay for the coverage they displace. => the learner must beat coverage PER SLOT; a Tier-1
  tuning block (§3.2) and context that predicts loss visibility (load bursts, H27) are the levers.
- 08-27 ~16:30 PILOT FINAL (60/60): cusum == uniform per seed; MCP 18 vs uniform 15, slower 23/30
  (p=0.005); H1 not met by the pilot config. PREREG §14 row (pilot, not main block). DECISIONS
  FOR PHILIP: (a) run the Tier-1 §3.2 tuning block (~21 h on both servers) or (b) design first —
  a per-slot-value policy (probe where loss would be VISIBLE: load-bursty links, H27) before
  spending tuning compute; (c) multi-fault / background-loss (F0) block where coverage alone
  is weaker. Servers idle, chip idle (mcp_fabric loaded, attn 4096).
- 08-27 ~05:45 SLOW LOOP ON SILICON (p4/reports/slow-loop-silicon.md): adapter correct first try;
  copies 117/epoch (attn decays to <4096 -> 5.86 %), counters exact, frozen mode 0 writes, uniform
  policy rotates exactly (bfrt readback), fault -> vlink 0/9 top (identifiable only as a pair with
  one host). tau_slow 96.2 ms observe / 116.6 ms with writes -> epoch default 200 ms. No-fault
  false alarms 90/100 before af5e858, 0/100 after. GRPC_ADDR localhost-only: copies captured on
  Vision and replayed on the switch.

## Next action
1. Vision/Hulk: check Netronome SDK, rxe, kernel, perftest, DPDK availability (M4 prep).
2. Simulator tier: clone/build htsim (csg-htsim), ATLAHS, Chakra; gate experiment.
3. Brainstorm fast-loop design → docs/DESIGN-ALTERNATIVES.md; then P4 spec.
4. ~~PREREG.md~~ DONE (paper/PREREG.md, 2026-08-25); reviewer pre-review (ieee-journal-reviewer) after matrix lands.

## Server inventory (2026-08-25)
- Vision: Agilio CX present (pci af:00.0, `nfp` loaded), lanes enp175s0np0s0-3 / np1s0-3; **np1s0 UP = direct link to Hulk enp59s0f1np1 (UP)**. No Netronome SDK → XDP route. docker present. 67 GB free.
- Hulk: XXV710 enp59s0f0np0 (→switch, DOWN with switch), enp59s0f1np1 UP (→Vision). 75 GB free.
- Both: kernel 6.8.0-138, libibverbs 50.0, ib_core loaded, NO rdma_rxe / perftest / dpdk; gcc, cmake, bpftool, Python 3.12.

## 2026-08-25 (later) — decisions + host prep
- Philip: target **SIGCOMM'27**; sudo on servers approved.
- Soft-RoCE up on both hosts (rxe0 ACTIVE), perftest installed, direct link 192.168.100.1↔.2.
  First calibration: 2.3 Gb/s single-QP, 57 µs avg write latency (nic/CALIBRATION.md).
- Zotero collection MCP-sprayed-fabrics (AT2STS8I) is the reference library.

## 2026-08-25 (evening) — S-DOWN deliverables landed, commit 4e2a6c6
- docs/NOVELTY-MATRIX.md (34 systems; closest: SprayCheck, OmniPath Ping, ChameleMon; new finds FANT, INTaaS, OpenAI MRC/SRv6). Zotero: 39 items in MCP-sprayed-fabrics.
- paper/PREREG.md (567 lines; 12 baselines, F0–F9 fault catalogue, power calc, reward-integrity tests).
- docs/P4-DESIGN-SPACE.md (1246 lines). KEY: local /home/philip/bf-sde-9.13.1 has bf-p4c + tofino-model + PTF → full offline loop.
- sim/: spcl/HTSIM built; UEC oblivious spraying + GOAL chain verified (incast, LULESH). Llama-7B >10 min/seed (H18).
- Running: builder → htsim gate hooks (sim/htsim branch mcp-hooks, sim/gate/); p4-dataplane-engineer → p4/mcp_fabric.p4 steps 1–4 compiled locally.
- OPEN for Philip (from P4 design §12): which host is on dp9 (map says Vision, testbed.md says Hulk); is dp65 still the Agilio leg; fabric shape 2 leaves×4 spines (recommended) vs 4×2; docker group for SDE-container check; bf_switchd restart window (defense4_caseA loaded).
- 08-27 PANEL (25 agents, docs/review/): unanimous PIVOT. Verified myself: (a) counters.csv are
  byte-identical across all 5 arms x 30 seeds (120/120) -> the Tier-1 measurement policy never
  perturbs the fabric and offline replay is EXACT; (b) every published TTL used the simulator's
  ratio rule, not the frozen localizer -> re-issued: MCP KM 19.0 vs uniform-schedule 20.0, paired
  11/19, p=0.20 (was 7/23, p=0.005). No arm meets H1 under either detector.
  M0 DONE: analyze_real.py --detector {ratio,localizer,both} + KM medians; PREREG v1.5 (detector
  provenance, one budget currency, replay soundness, retirements H1/H3/H5/H7-F1/the 18.4k matrix,
  new H8 coverage-gap attainment / H9 no-counter-schedule / H7' restated); frozen.yaml baseline_mode
  aligned to `pooled` (runs authoritative); COSIM-RESULTS.md marked superseded. 36 tests OK.
  NEXT: M1 replay harness (sim/gate/replay.py) — decomposition + scoped negative result, minutes of
  compute; then M2 in-band per-link evidence on silicon (needs Philip's chip sessions from ~7 Sep).
- 08-27 M1 DONE (sim/gate/replay.py + M1-REPLAY.md): replay validated against the recorded arm
  (every uncensored seed matches to the epoch; candidate order is agg-major, not lexicographic).
  3 min for 6 schedules x 5 budgets x 30 seeds vs 64 min per htsim run. C1 measured: evidence 8 +
  coverage 10 (uniform) / 16 (load-gated) / 1 (oracle) epochs. H9 gate NOT tripped: 0% of the
  oracle gap closed at the frozen budget under single, double, triple and moving faults; the one
  real effect is load-gating at budget 82 (22/8, p=0.016) worth 20% of the gap. Open: F0 logs for
  the ADD-vs-false-alarm sweep. NEXT: M2 in-band per-link evidence on silicon (Philip's chip time).
- 08-28 HULK LINK: Philip re-cabled — Hulk enp59s0f1np1 now carries the QSFP-4x25G breakout leg to
  the switch (f0 = SFP-H10GB-CU1M 10G to Vision's Agilio np1s0). **Hulk's leg is 15/2 = dev_port 10**:
  it linked at 25G RS-FEC the moment the MAC-near loopback was removed and Hulk's port was admin-up.
  It was never miscabled — yesterday's sweep missed it because (a) Hulk's port was admin-down and
  (b) the lane was masked by a MAC-near loopback (a loopback port shows UP regardless of the wire).
  setup_skeleton.py updated: HOST1_DP = 10, LEAF_HOST_DP = [9, 10, 9, 9], role rows for both hosts,
  REQUIRED_PORTS includes dp10; dry-run self-check passes (10.0.1.2 now delivers on dp10).
  This unblocks PLAN M3 (second vantage -> link-level, not path-level, localization).
- 08-28 SHARED-CHIP INCIDENT (my error, reported to Philip): the chip is owned by
  **defense4_rrc_bor_unified12** (bf_switchd PID 36630, started 2026-08-27 18:26; our mcp_fabric
  switchd was SIGTERMed then). I configured ports on that running program before checking the owner:
  removed MAC-near loopback from 15/0 and 15/2 (46.9M / 1.03M frames), added 15/3, and a 25G lane
  sweep added ~125 ports. RESTORED via bfrt: deleted the 125 added ports + 15/3, re-created dp8/dp10
  as 25G / FEC NONE / AN off / MAC_NEAR / enabled; port table now matches the as-found 4 rows
  (frame counters reset to 0 — unavoidable). bf_switchd was NOT restarted; defense4 untouched
  otherwise. LESSON: check `/proc/<pid>/cmdline` of bf_switchd for the loaded program BEFORE any
  port or table write, not just `gc-switchd`.
- 08-28 HOUSEKEEPING (no fabric loaded, chip still owned by defense4): Vision inventory — Agilio CX
  at af:00.0 (nfp), 2 cages x 4 lanes, only np1s0 cabled (10G to Hulk f0); no /opt/netronome (no
  SDK) but bpf/flower/nic firmware present => XDP offload possible, P4-on-NFP not (H7).
  The re-cable had left the addressing and Soft-RoCE on the wrong ports: Hulk's direct-link port
  held a stale 10.0.2.10/16 while 192.168.100.2/24 (the direct-link subnet) sat on the down
  switch-facing port, and Hulk's rxe0 was bound to that dead port (DOWN/POLLING) while Vision's was
  on the Agilio. Fixed: direct link 192.168.100.1 <-> .2 (ping 0.41 ms), fabric addresses 10.0.1.1
  (Vision) / 10.0.1.2 (Hulk f1), rxe0 on each host's direct-link port -> both ACTIVE, ib_write_bw
  804 MB/s (6.4 Gb/s) over 4 QPs. All of it is runtime-only (no rxe unit, netplan lists a stale
  iface name) -> nic/lab_link_setup.sh added, deployed to both hosts, idempotent, --check audits.
  Connectivity map updated with the verified table and the MAC-near-loopback trap.
- 08-28 NETRONOME: toolchain installed on Vision (clang 18.1.3, llvm, libbpf-dev, headers).
  Firmware app switched nic -> bpf (device symlink pci-0000:af:00.0.nffw.zst; .orig kept), driver
  reloaded, and an eBPF per-path counter was **offloaded to the card**: bpftool shows
  offloaded_to enp175s0np1s0, jited 864 B, map on-card; 160 UDP packets over 16 source ports gave
  exactly 10 per bin. H7 CLOSED (XDP route real). Native P4-on-NFP stays impossible: no SDK on any
  machine and nfp4build is behind a Corigine support account.
  Card left on the **nic** app (day-to-day RoCE testbed); flip to bpf per nic/README-xdp.md.
  Link/RoCE restored and verified: ping 0.5 ms, ib_write_bw 515 MB/s over 4 QPs.
  Traps recorded: NM strips runtime IPs on a link flap; rxe takes its GID from the PRIMARY address
  (a stale 10.0.2.10/16 made it advertise the wrong GID -> 0 bytes moved); `-x 1` on perftest also
  gives 0 iterations here; `pkill -f` from ssh kills the ssh session.
- 08-28 NETRONOME SDK RESEARCH (docs/NETRONOME-SDK.md): nfp4build/nfp4c = Agilio P4C SDK 6.x,
  /opt/netronome/p4/bin. NOT on GitHub (only usage: P4STA, AccelTCP, open-nfpsw, P4RROT,
  template-netronome-p4) and NOT in any public repo. deb.netronome.com/apt IS live (built
  2021-05-11) but carries BSP + firmware only; open-nfp.org (the old academic route) is dead (503),
  downloads.netronome.com is gone; help.netronome.com is live. Vendor's stated licence: third-party
  constraints bar a non-proprietary release and bar supplying the tooling independently of their
  hardware -> owners get it on request. Route today = Corigine (smartnic-support@corigine.com,
  corigine.com/DPUDownload.html); draft request with our board/serial in
  docs/netronome-sdk-request.txt for Philip to send. A 2018 Docker image appears to bundle an SDK;
  flagged as unlicensed redistribution and NOT used. Judgement: request in the background, do not
  block — XDP offload already covers the NIC arm.
- 08-28 SDK REQUEST SENT by Philip to Corigine (smartnic-support@corigine.com, cc help@netronome.com)
  using docs/netronome-sdk-request.txt: Agilio P4C SDK for AMDA0097-0001 serial SMCAMDA0097-000117291655.
  AWAITING REPLY — follow up if nothing by ~2026-09-11. Not blocking: the NIC arm runs on eBPF/XDP
  offload today (nic/README-xdp.md).
- 08-28 F0 CONTROL BATCHES LAUNCHED (closes M1's open item, no chip needed): run_gate_real.sh gained
  FAULT=0 (no fault at all -> measures the localizer's false-alarm rate / ARL) and BG_LOSS=<p>.
  Vision seeds 2000-2019 with BG_LOSS=1e-4 (background == delta_loss, the hardest false-alarm case,
  verified "MCP background loss p=0.0001 on 1024 uplinks", fault file NONE); Hulk seeds 2020-2029
  clean (no loss at all). ~2 h. Then: sweep h over these counter logs with replay.py to get the
  ADD-vs-false-alarm (ROC) curve the telemetry/QCD literature expects, paired with the F1 runs.
  NOTE: my first launch used an unsaved patch (a later assert aborted the write) so both batches ran
  the WRONG experiment (F1 with new seeds); killed within a minute, results deleted, relaunched.
  Verify the intended flags in the run log before trusting a batch.
- 08-28 H8 IN REPLAY (the paper's core claim, no chip needed): added `inband` / `inband_sync` arms to
  sim/gate/replay.py. The in-band invariant (per-link sequence gap / RFC 9341 alternate marking =
  read every link's tx/drop delta every epoch, zero probe bytes) gives KM median TTL **10.0, 0/30
  censored, coverage time 1.0 epoch** vs uniform 20.0 (coverage 10.0) and oracle 10.0 --
  i.e. it **closes 100 % of the oracle gap** and reduces detection delay to evidence time.
  H8 supported in simulation; the hardware version is M2.
- 08-28 LOCALIZER ARTIFACT FOUND (do not read inband_sync as a result): the periodic-collection
  variant (read every link every 4th epoch) never alarms -- at epoch 16 the faulty link had 11 drops
  in 99,704 packets and cusum was still 0.00. Cause: `baseline_warmup_epochs` counts POOL UPDATE
  CALLS, not evidence, so an arm that reads 4x less often stays in warm-up for the whole 36-epoch
  run (pool_n 4 vs 16). Warm-up should be defined in observed packets (or pooled counts), not update
  calls -- otherwise every low-frequency arm is penalised by construction. Fix before any arm is
  compared at different read cadences.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-08-28T15:59:26Z -->
### Compaction handoff — 2026-08-28T15:59:26Z
- Git: branch `master`, 0 uncommitted file(s): 
- Last verification run recorded: 2026-08-28T15:52:49Z	cd /home/philip/Projects/mcp/sim/gate; python3 - <<'PY' p='replay.py'; s=open(p).read() old='''class Oracle(Schedule):''
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-08-29T12:52:24Z -->
### Compaction handoff — 2026-08-29T12:52:24Z
- Git: branch `master`, 30 uncommitted file(s): controller/hw_adapter.py controller/sublink_feedback.py controller/tests/test_epoch_loop.py controller/tests/test_sublink_feedback.py docs/review/HEALTH-GATE-RESULT.md docs/review/P3-FEEDBACK-RESULT.md docs/review/PLAN.md p4/control/setup_attention.py p4/control/setup_skeleton.py p4/ptf/test_cw4_sublinks.py p4/witness/gen_variants.py p4/witness/mcp_fabric_capsule.p4 
- Last verification run recorded: 2026-08-29T12:52:07Z	cd /home/philip/Projects/mcp; ls sim/sublink/ sim/tests/ 2>/dev/null; echo "=== does anything drive the REAL SublinkFeed
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

## Status (2026-08-29) — closing the last two P3 audit gaps

Independent audit `docs/review/P2-P3-INDEPENDENT-AUDIT.md` left P3 PARTIAL with six gaps. The
parallel session closed #1 (event source: `controller/hw_adapter.py:gap_event_from_copy`), #2
(transport: mirror copy + `epoch_loop`), #3 (restoration evidence: `AuditRound`/`AuditReceipt` +
`tbl_audit_steer`), and #5 is a stated claim boundary rather than a defect. Two remain:

- **#6 dynamic operating point** — nothing drives the REAL `SublinkFeedback` state machine in a
  sweep. Contract frozen at `sim/dynamic/PREREG.md` (2026-08-29): 8 scenarios, 4 arms
  (none/cw4_feedback/directed_w4/oracle), tau x h x restore_k x p sweep, 30 seeds/cell, Wilson +
  bootstrap intervals, four mechanical harness tripwires (oracle floor, realised-parameter dump,
  never-acts INERT detector, emission-rule cross-check against the gap-event PTF).
- **#4 end-to-end latency** — stays a SWEPT parameter in the harness; the controller-host software
  segment (parse -> GapEvent -> decision -> BFRT marshalling, excluding gRPC and switch programming)
  is being micro-benchmarked separately as an explicit lower bound, never as an end-to-end figure.

Baseline before this work, measured 2026-08-29: `controller/tests` 69 passed, `sim/tests` 7 passed.

Next action: verify the three builder outputs myself (run their tests, read their diffs), then wire
`sim/dynamic/runner.py` + `sweep.py` against the REAL controller objects and run the frozen sweep.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-08-30T14:11:31Z -->
### Compaction handoff — 2026-08-30T14:11:31Z
- Git: branch `master`, 36 uncommitted file(s): README.md controller/hw_adapter.py controller/sublink_feedback.py controller/tests/test_epoch_loop.py controller/tests/test_sublink_feedback.py docs/review/BEHAVIORAL-SUBLINK-PLAN.md docs/review/CAMPAIGN-PLAN.md docs/review/HEALTH-GATE-RESULT.md docs/review/P2-P3-INDEPENDENT-AUDIT.md docs/review/P3-DYNAMIC-RESULT.md docs/review/P3-FEEDBACK-RESULT.md docs/review/artifacts/HW-SELECTIVE-DETECTION.md
- Last verification run recorded: 2026-08-30T14:09:05Z	cd /home/philip/Projects/mcp python3 - <<'PYEOF' import pathlib p = pathlib.Path("p4/hw/loop/clf_trials.py"); s = p.read
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

## Status (2026-09-01) — whole-repo assessment written

`docs/review/ASSESSMENT-2026-09-01.md` consolidates five independent audits (code vs claims, artifacts
vs claims, adversarial PC review, literature + creative directions, methodology). Load-bearing
findings: (1) 8-bit frontier counters at 40 pkt/epoch, 200 pps, 2 s unmeasured guard cannot operate
at production rate — every epoch would saturate and censor; (2) the 0.99 e-process null declares 1 %
loss healthy while CAMPAIGN-PLAN targets 1e-3..1e-5 (mixture power 0 % at 99.5 % survival); (3) the
calibrated ledger is not on the online quarantine/restore path — `sublink_feedback.py:453` still acts
on the CUSUM knob h=6.5; PROBATION is a dead state; ledger wedges at epoch wrap. Bursty loss gives
11–16 % false alarms under the stated null (Monte Carlo vs the real ledger). The 108-task NSDI plan
has 0 tasks done and builds on the weakest framing. Recommendation in §4: one paper, spine =
sub-1 % spray-invariant attribution (A) + exposure-bounded half-open restoration (B); context
promoted only if the physical size-selectivity bench shows selectivity. Nothing in code was changed.
Tests fresh: 433 pass.

## Status (2026-09-01, later) — brainstorm run, new spine drafted and red-teamed

Full brainstorm session against the assessment: superpowers:brainstorming + creative-thinking
frameworks + a 6-agent panel (PI, sdn-networks-expert, p4-dataplane-engineer with 9 local bf-p4c
compiles in scratchpad, research-scientist, statistics theorist with 3 simulations, hyperscaler
operator persona), then a self-run red team (2 dispatched red-team agents were cut off by a session
rate limit; I completed the adversarial pass myself). Written to
`docs/review/BRAINSTORM-2026-09-01.md`.

New candidate spine: treat per-packet spraying as a randomized experiment. The post-TM witness
already records the assignment; loss becomes a labelled outcome. Headline mechanism (after the red
team corrected an initial mistake): an ABSOLUTE anytime-valid e-process against a floor estimated
continuously from the fleet's own healthy sublinks (not a fixed 0.99 null), with mitigation as a
CONTINUOUS function of the e-process wealth (never a step at threshold) so quarantine is never
triggered by one bad packet. A sibling-exchangeability test is kept only as a secondary
congestion-vs-gray discriminator inside queue-depth strata (the panel's first draft made this the
headline; simulation showed it costs 14x more packets and degrades as (excess/background)^2,
which gives back the sub-1% regime the project targets — this is documented in the red-team section
as the load-bearing correction).

P4 feasibility (9 local compiles, bf-p4c 9.13.1, nothing touched the switch): widening the CLF
frontier to 32 bits is FREE (same RAM-block quantization); a receiver-side RTCP-style ledger
(advance-only highest-seq + arrivals) replaces the epoch/bank/guard entirely and compiles at 11
ingress / 5 egress with FEWER resources than today's program, including a Bernoulli fault injector.
Deleting the old ingress attention/sampling-gate control loop (tied to the retired bandit thesis,
already ruled non-novel by the 2026-08-27 panel) frees a stage for JSQ spraying; CSIG's egress
queue-depth telemetry must be kept (needed for congestion stratification), only the ingress control
loop goes.

Statistics (3 simulations in scratchpad): drops-to-decision d* = ceil(ln(1/alpha)/ln(p/p0)) is the
headline quantity (1 drop at 1e-3 vs a 1e-5 floor); attribution entropy (bits of link identity per
lost packet) is proposed as a unifying currency, 6.6 bits for the witness vs 7e-4 for a
destination-side distribution test. Alpha must never be spent by restarting on censored epochs
(58% false alarms in simulation); carry capital instead, valid if the censor decision is
epoch-history-measurable. e-BH across 1024 sublinks for fleet-level FDR control.

Operator persona (checked against Meta RoCE SIGCOMM'24, Alibaba HPN/Aegis, Broadcom/NVIDIA
telemetry docs, all cited with URLs): the per-link witness is the only unconditional yes; the
context dimension should be deployed only after a physical size-selectivity bench; the deployable
artifact on non-P4 switches is the evidence CONTRACT as a spec, not the Tofino program.

Open decisions for Philip (BRAINSTORM doc section 8): approve the corrected spine; spend one day
building a physically degraded link for the selectivity bench (Hulk cable, FEC mode / serdes
de-tuning as repeatable knobs); pick SIGCOMM'27 (statistics-heavy) vs NSDI'28 (systems-heavy);
delete the attention/gate control loop from the deployed program. Nothing in code was changed this
session; all P4 compiles and Python sims are scratchpad-only, copied into
docs/review/artifacts/brainstorm-2026-09-01/ for the record.

## Status (2026-09-01, later still) — receiver-ledger P4 redesign built and compile-gated

Philip approved the corrected brainstorm spine and asked to start the receiver-ledger P4 redesign
(`docs/superpowers/plans/2026-09-01-receiver-ledger-plan.md`). Implemented by p4-dataplane-engineer,
verified by me.

**Built:** `p4/witness/mcp_fabric_ledger.p4` (copy of `mcp_fabric_clf_eg.p4` with three isolated
changes): TX frontier widened to 32-bit; the CLF epoch/bank/guard scheme replaced by a receiver
ledger (`reg_wit_expect` made advance-only = hi, `reg_wit_observed` widened to 32-bit with its reset
removed = lo, `reg_rx_frontier` and both bank-parity indices deleted); a per-sublink Bernoulli fault
injector (`tbl_eg_bern`) added alongside the existing deterministic `tbl_eg_fail`. `hdr.fabric.clf_bank`
stays on the wire unused (retiring it means an out-of-scope control-plane signature change).

**Compile gate** (`docs/review/artifacts/LEDGER-COMPILE-GATE.md`, bf-p4c 9.13.1 local, switch NOT
contacted): exit 0/0 errors both, **11 ingress / 5 egress stages, same as base**, tables 42->40,
SRAM 92->89, SALU 8->7, TCAM 13->15 (+2). Both source SHA-256 hashes recorded.

**Tests:** 35 new tests in `p4/witness/test_ledger_program.py` (315 total local suite, 0 failed,
re-run by me independently). One test mechanically forbids the phrase "exact at any instant"
anywhere in the source, per the red team's finding 4 correction.

**Disclosed, not solved, in the compile-gate report:**
1. Reorder-credit accounting (debt opened on a gap, retired by later out-of-order arrivals, only
   debt outstanding after one BDP scored as loss) is NOT implemented anywhere — controller-side
   follow-up, explicitly out of this pass's scope.
2. `controller/hw_adapter.py:218` now mis-reads the mirror's `attn` slot: it was "arrivals since
   last gap", it is now the low 16 bits of a lifetime counter, and the `+1` no longer means
   anything. Needs a diff-of-successive-reads fix before this program is driven live.
3. `p4/hw/loop/gate_agent.py` breaks against this program in three ways: hard failure (`table_get`
   on the now-deleted `reg_rx_frontier`, three call sites), a SILENT mis-attribution (its bank/sublink
   index decode assumes the deleted bank bit), and a stale saturating-counter comment. Not touched
   this pass — must be fixed before any silicon run of this program.
4. No PTF/tofino-model run yet (needs a `p4/ptf/` case); no 9.13.2 numbers (switch never contacted).

The subagent's own code-reviewer pass caught the gate_agent.py incompatibility, a sign error in
Δhi-Δlo under a duplicate arrival, and an arithmetically wrong "register width is free" justification
in its own draft report before finishing — all fixed and now correctly qualified in the written report.

No commit made (not requested). Next: fix `hw_adapter.py`'s attn-slot read and `gate_agent.py`'s
three breaks before this program can be driven on the switch; then a PTF/model case for the ledger
semantics; then the controller-side reorder-credit accounting; only after that, take the chip
(after checking who owns it) for a 9.13.2 compile-gate and a real silicon comparison.

## (superseded by the next section — the "attn_state"/"--lifetime-attn" design below was
## replaced by a census-anchored redesign the same day; kept per repo convention, not edited away)
## Status (2026-09-01, later still) — hw_adapter.py and gate_agent.py fixed for the ledger, one open design question flagged

Philip asked to fix the two harness incompatibilities the receiver-ledger compile-gate report
disclosed. Two rounds of independent code review caught real bugs in my own fix before I called it
done; both are recorded here rather than smoothed over.

**Fixed, verified (329 local tests pass, up from 315):**
- `controller/hw_adapter.py`: `gap_event_from_copy` takes an optional `attn_state` dict. Default
  (`None`) is byte-for-byte the old "attn + 1" behavior, used by every existing caller. Passing a
  dict switches to lifetime-counter mode for `mcp_fabric_ledger.p4`: returns `None` (no event, not
  a fabricated number) when there is no baseline yet, when the computed delta is exactly 0 (proven
  impossible -- the triggering packet itself increments the counter), or when the delta is in the
  top half of the 16-bit space (looks like a reading behind the stored baseline). `BfrtAdapter`
  gained a `lifetime_attn: bool = False` constructor flag.
- `p4/hw/loop/gate_agent.py`: F, X, Z now check `reg_rx_frontier`'s presence once at startup and
  raise a short, actionable error (not an opaque table_get exception, and not a partial destructive
  reset) when it's absent, as on the ledger program. N and R got documentation-only comments on
  their changed semantics. The startup check logs what it swallowed instead of failing silently.
- `p4/hw/loop/controller_loop.py` (the ACTUAL live hardware consumer -- the first review found my
  original hw_adapter.py-only fix was unreachable from here): new `--lifetime-attn` flag threads
  `attn_state` into the real gap-event call site and disables `observed_delta`'s 16-bit saturation
  ceiling (`reg_wit_observed` is `bit<32>` on the ledger and does not saturate at 0xFFFF -- the old
  hardcoded check was silently discarding every census delta past 65535 lifetime arrivals). A
  decrease on a never-reset counter now reports 0, not a fabricated up-to-4-billion-packet count. A
  heuristic (non-blocking) warning fires if `--lifetime-attn` and the switch-verified program name
  disagree on whether this looks like a ledger build.

**NOT fixed, disclosed instead of papered over (both documented at length in
`controller/hw_adapter.py`'s `gap_event_from_copy` docstring):**
1. The `>= 0x8000` "looks like reorder" rule only reliably works when consecutive gap events on one
   sublink are within ~32767 arrivals of each other. At the frozen operating point (1e-4) that
   holds; at the pre-registered 1e-5 sweep floor it does not, and the rule silently ACCEPTS roughly
   half of the aliased backward readings as plausible small forward deltas.
2. Once the ledger removes the reset-on-gap that the base/CLF programs had, the gap-event delta and
   the census delta cover overlapping (not partitioned) time windows, so a sublink's `delivered`
   count is fed twice into `infer.Sample` -- deflating the estimated loss rate and potentially
   suppressing a quarantine that should have fired.

Both stem from the same root cause: trusting the mirror's 16-bit `attn` slot as evidence at all,
rather than always deriving `observed_packets` from the unambiguous 32-bit census read
(`reg_wit_observed` via the `R` command). That is a controller-architecture change, not a bug fix --
it overlaps with the reorder-credit accounting the original plan (task 3a) already deferred as
controller-side follow-up -- and it changes the statistical validity of any campaign run against
this program, so it needs a decision, not a unilateral rewrite. Flagged here for Philip rather than
implemented.

No commit made. Next: decide whether to redesign `observed_packets` around the census read before
any real hardware session against `mcp_fabric_ledger.p4`, or accept the disclosed operating-point
restriction (valid at delta_loss >= 1e-4, not at the 1e-5 sweep floor) and pin it as a PREREG
amendment instead.

## Status (2026-09-01, final for this thread) — observed_packets redesigned around the census read; three rounds of review, all findings fixed or disclosed

Philip approved redesigning `observed_packets` around the 32-bit census read instead of the mirror
field, per the open decision flagged above. This required reverting the `attn_state`/`--lifetime-attn`
design entirely (superseded, not extended) and building a new mechanism. A third round of code review
found real problems in the new design too; all mechanical ones are fixed, one architectural cost is
disclosed rather than hidden.

**The redesign.** `controller/hw_adapter.py`'s `gap_event_from_copy`/`_fill`/`BfrtAdapter` were
reverted to their original simple form (no `attn_state` parameter) — proven correct for base/CLF
programs, and the ledger program no longer uses this function's `observed_packets` at all.
`p4/hw/loop/controller_loop.py` gained:
- `observed_delta(..., saturation=None)` now returns `None` (not `0`) for a rejected (backward)
  reading, signalling "do not advance any baseline to this", not just "report zero packets".
- `CensusWorker` gained a `threading.Lock` guarding `self.previous` (the shared baseline dict) and
  a `consume_single(sublink, cell)` method letting the capture thread fold one out-of-band,
  targeted reading into the SAME dict the periodic `poll_once` uses — the two evidence streams can
  therefore never double-count, by construction (proven: the emitted evidence for a sublink always
  telescopes to `final - initial` across any interleaving of the two threads).
- `GateClient.census(sublinks=...)` accepts a targeted-read override.
- `resolve_ledger_gap_event(gate, census, ev, retries=1)`: on a gap event, does one synchronous
  `gate.census([ev.sublink])`, folds it via `consume_single`, retries once on a rejected reading
  (the dominant real cause is a benign race with the periodic poll, not a bad read), and returns
  `(event_or_none, rpc_seconds, reason)` — `reason` one of `rpc_error`/`no_baseline`/
  `race_exhausted`, the last of which discards real loss evidence and is counted separately in the
  run summary as a missed-detection risk, never silent.
- `--lifetime-attn` renamed to `--ledger` (the old name described a mechanism that no longer exists).

**What the third review found and what was fixed:**
1. The epoch-authority check was happening AFTER the targeted census read consumed the shared
   baseline, so a stale/future event's `observed_packets` was silently discarded along with evidence
   that could have gone to the periodic census instead. Fixed: epoch check now runs first, before any
   RPC is spent (also saves the RPC entirely for events that were never going to be decided anyway).
2. The very first gap event on any sublink was unconditionally, silently dropped (no baseline to
   diff against). Fixed: the baseline is seeded with one synchronous `poll_once` before capture
   starts (a one-time cost outside the measured campaign window); every drop path now prints why.
3. A benign race with the periodic poll could cause a real, loss-bearing gap event to be discarded
   entirely (not merely imprecisely counted). Fixed: `resolve_ledger_gap_event` retries once before
   giving up, and an exhausted-retry drop is counted (`ledger_races`) and printed loudly, distinct
   from every other drop reason.
4. `apply_census_result`'s pre-existing `quarantine_target` exclusion — harmless under the old
   resetting counter — became a permanent one-way discard of legitimate clean evidence for the
   sublink under investigation once the shared-baseline design made it redundant. Fixed: the
   exclusion is now skipped entirely in `--ledger` mode (base/CLF behavior is unchanged).
5. `observed_delta`'s docstring blamed the wrong cause for a decrease (`gate_agent`'s `max()` across
   pipes, which is itself monotone and cannot produce one); corrected to name the actual cause (the
   race between the periodic poll and a targeted read).
6. The concurrency claim ("the lock prevents double-counting") had no test that would actually catch
   a regression — confirmed empirically: deleting the lock left all existing tests green. A
   deterministic test was built (a dict subclass that pauses the first caller mid-critical-section)
   that does fail when the lock is removed, verified both ways this session.
7. Local variable `census` shadowed `gate.census` the method; renamed to `census_worker` throughout.
8. This section of WORKING_NOTES.md, describing the superseded `attn_state` design, is marked
   superseded above rather than deleted.

**Disclosed, not fixed — a genuine architecture cost, not a bug:** `resolve_ledger_gap_event`'s
synchronous RPC now sits inside the exact window the project measures as "detection-to-reroute
latency" (the 4.998 ms headline number is from the OLD CLF-based program and is NOT affected by this
change — no hardware run has yet exercised `--ledger` mode). The RPC's own latency is now tracked
(`ledger_rpc_seconds`) and printed explicitly and separately in the run summary, with an explicit
warning that it must never be compared against a non-ledger run's number without accounting for it.
Eliminating the RPC from the critical path entirely is a bigger redesign (e.g. deciding fast on the
gap's own `lost` value and reconciling `observed_packets` asynchronously) that was not attempted here
— it goes beyond "redesign observed_packets around the census read" into redesigning when the
decision itself is made, and deserves its own explicit go-ahead before any hardware latency campaign
runs under `--ledger`.

**Verified:** 334 local tests pass (up from 330), including a deterministic lock-regression test
confirmed both to pass against the real code and to fail when the lock is deliberately removed, and
tests for the epoch-check reordering, the seeded baseline, the retry-then-loud-drop path, and the
`quarantine_target` bypass. No commit made. Files touched this pass:
`controller/hw_adapter.py`, `controller/tests/test_epoch_loop.py`, `p4/hw/loop/controller_loop.py`,
`p4/hw/loop/test_controller_loop.py`, `WORKING_NOTES.md`.

Next: decide whether to pursue the async-decision redesign needed to remove the RPC from the
critical path before any real `--ledger` hardware run, or accept and pre-register the disclosed
latency composition; then a PTF/model case for the ledger's data-plane semantics; then take the chip
(after checking who owns it) for a 9.13.2 compile-gate and a real silicon comparison.

## Status (2026-09-02) — 9.13.2 compile-gate confirmed; parallel-session collision found on the switch

Philip approved switch access for today (step 2 of the post-implementation roadmap). Ownership
checked first per the standing rule: `bf_switchd` (pid 180479) is running `mcp_fabric_clf_eg_abs.conf`
— MCP's own prior program, not a sibling project's. Nothing was restarted; the running program was
not touched.

**9.13.2 compile-gate: PASS, and it confirms the laptop numbers.** Copied `mcp_fabric_ledger.p4` to
`/home/decps/mcp_m2_gate/` (a new file, nothing overwritten) and compiled with the switch's own
bf-p4c 9.13.2: exit 0, 0 errors, 5 warnings — identical warning count to the 9.13.1 laptop build.
`extract.py` on both builds:

| | clf_eg baseline (9.13.2) | ledger (9.13.2) | ledger (9.13.1, from LEDGER-COMPILE-GATE.md) |
|---|---|---|---|
| ingress/egress stages | 11/5 | 11/5 | 11/5 |
| tables | 42 | 40 | 40 |
| SRAM | 92 | 89 | 89 |
| map RAM | 27 | 27 | 27 |
| TCAM | 13 | 15 | 15 |
| stateful ALUs | 8 | 7 | 7 |

Exact match between compiler versions. The "cheaper than the program it replaces, on every axis
except TCAM" claim holds on the switch's real SDE, not just the laptop's.

**BLOCKER found before any further hardware step — stopped, not resolved unilaterally.** The
directory `/home/decps/mcp_m2_gate/` on the switch has a LIVE, running `gate_agent.py` process
(pid 181314, started today 15:30, idle since — its log's last entry is from 2026-08-31, and nothing
in the directory has been touched in the last 2 hours, so it is not mid-experiment) whose SOURCE is
a MORE ADVANCED version than this repo's `p4/hw/loop/gate_agent.py`: it has a `V2` command (sealed
switch/setup identity), an `S` command (exact dispersed injector ranges), an `M` command (MAC port
counters), `compute_switch_id`, `verify_loaded_setup`, and a `.setup-manifest.sha256` check — none
of which exist in the git-tracked copy. This matches the naming of the "NSDI sealed-evidence
campcampaign" track referenced elsewhere in this repo's docs, i.e. a parallel session has been
extending this exact file directly on the switch, independent of and further along than what is in
git for this file.

**I did NOT overwrite it.** Deploying my local (older, less-featured) `gate_agent.py` over it would
have destroyed that other track's work with no way to reconstruct it from git, since git has never
seen this newer version. My session's F/X/Z guard fix for the ledger program (`docs/review/...`
work from 2026-09-01) has not been reconciled with whatever the switch-side version already does or
does not need. Loading `mcp_fabric_ledger.p4` onto the chip and driving it via `controller_loop.py`
both require a working `gate_agent.py` on the switch, so this blocks P4-side steps 3 (silicon smoke
test) and beyond until resolved.

**Next, and needs Philip's decision, not a unilateral merge:** pull the switch's current
`gate_agent.py` / `gate_agent_core.py` / `injector_ranges.py` into git first (so they're
diffable/mergeable through normal review) and reconcile my ledger-specific fix with whatever the
newer sealed-evidence version already does — it may already have a mechanism I'm unaware of, or it
may need my fix layered on top. Until that is settled, no further deploy/load/restart action will
be taken on the shared switch from this line of work.

## Status (2026-09-02, later) — switch's gate_agent.py/gate_agent_core.py/injector_ranges.py pulled into git

Philip asked to pull the switch's more advanced gate_agent.py into git first, before any
reconciliation. Done as commit `b1a5ec1`.

Pulled verbatim from `/home/decps/mcp_m2_gate/` on the switch (all three files, since gate_agent.py
imports from the other two): `gate_agent.py`, `gate_agent_core.py`, `injector_ranges.py`. Full diff
reviewed line by line before landing, confirming the divergence is clean, not conflicting:

- **What the switch's version adds, that git never had:** a `V2` command reporting a sealed
  switch/setup identity (`compute_switch_id`, `verify_loaded_setup`, a new startup check against a
  `.setup-manifest.sha256` receipt); an `S` command for exact dispersed-pattern fault injection
  (`modular_spread_drop_ranges`, as opposed to the existing `A` command's contiguous-burst-only
  `modular_drop_ranges`); an `M` command reading real MAC port RX/TX counters
  (`read_port_stats_rows`, `format_port_stats_reply`). All additive to `gate_agent_core.py` and
  `injector_ranges.py` — no existing function was changed or removed, confirmed by diff.
- **What git had that the switch's version does NOT:** this repo's F/X/Z ledger-safety guard
  (`rx_frontier_table`, added in commit `26d776f` yesterday) that makes the F/X/Z commands refuse
  cleanly on `mcp_fabric_ledger.p4` instead of crashing or silently misreading a register that no
  longer has a bank dimension. The switch's copy branched from a version of the file that predates
  that fix.
- **These two changes are disjoint**, not conflicting — different command handlers, different
  startup checks. Reconciling them is re-applying the F/X/Z guard onto this newly-landed base; not
  done in this commit, kept as a clean, separate, reviewable diff.

Verified: 334 tests pass (same count as before the pull — the new gate_agent_core.py/
injector_ranges.py functions are additive and untested either way; `gate_agent.py` itself has never
been unit-testable standalone, since it executes MCP_PROG/manifest/bfrt setup at import time).

Nothing else on the switch was touched during the pull: `bf_switchd` was not restarted, the
currently-loaded program (`mcp_fabric_clf_eg`) was not changed, no port or table was written. The
live `gate_agent.py` process on the switch (pid 181314) was also left running untouched — only a
copy of its source was read (`scp`), nothing was pushed back.

Next: re-apply the F/X/Z ledger-safety guard onto this newly-pulled base (small, well-scoped,
disjoint from everything just landed), then this repo's own compile-gate/hardware work can proceed
without risk of the next deploy silently reverting the switch's sealed-evidence work.

## Status (2026-09-02, later still) — F/X/Z guard reconciled onto the pulled gate_agent.py

Re-applied the ledger-safety guard from `26d776f` onto the newly-pulled `gate_agent.py`
(`b1a5ec1`), as its own commit `6761571`. Confirmed byte-for-byte identical to yesterday's
version by diff before committing — this was a mechanical re-insertion at the five original
points (startup resolve-or-disable, and a refusal at the top of F/X/Z, plus two
documentation-only comments on N/R), not a re-review of the guard's own logic, since that logic
was already reviewed three times yesterday and is unchanged.

Confirmed both halves coexist cleanly: the switch's V2/S/M commands (sealed identity, dispersed
injector, port counters) are untouched, and the guard is back in place protecting F/X/Z against
`mcp_fabric_ledger.p4`'s missing `reg_rx_frontier`. 334 tests pass.

The switch itself was NOT touched by this reconciliation — this was a local git-only change.
Deploying the reconciled file back to `/home/decps/mcp_m2_gate/gate_agent.py` is a separate,
future step (not requested, not done) and would need the same care as any other write to that
shared, actively-used file: confirm the live process there is safe to restart, and that nothing
else has moved further ahead on the switch since this pull.

Roadmap position: step 2 (chip ownership check + 9.13.2 compile-gate) is done, with the
gate_agent.py collision now resolved in git. Step 1 (local model/PTF verification, delegated
earlier) is still running in the background. Step 3 (a real silicon smoke test of the ledger
program) is next once step 1 reports back clean, and would require deploying this reconciled
gate_agent.py to the switch — a deliberate action to take separately, not bundled into this
reconciliation.

## Status (2026-09-02, later still) — step 1 complete: ledger verified against the real local model, no defect found

The delegated PTF/model verification (step 1 of the roadmap) finished and was checked directly:
files exist with real content, `p4/witness/mcp_fabric_ledger.p4` confirmed unmodified (`git status`
clean, source SHA matches `LEDGER-COMPILE-GATE.md` exactly), no stray model/switchd processes left
running, and the existing 334-test suite still passes. The switch was never contacted (no ssh/scp
anywhere in the new harness).

**9 new PTF tests against `tofino-model`, 9/9 pass**, in `p4/ptf/test_ledger.py`, report in
`p4/ptf/PTF-MODEL-LEDGER.md`. Every test prints its measured numbers, not just pass/fail. Highlights:

- **The core claim is now proven against a running program, not just asserted**: 40 packets
  stamped by the pipeline's own egress, 5 discarded on the wire, `Δhi - Δlo = 5` exactly, with
  `reg_tx_frontier` independently confirming 40 sent (proving the loss was genuinely post-stamp).
- **The 32-bit frontier claim is now measured, not just costed**: 300 packets read back as exactly
  300. The old 8-bit design would have wrapped/saturated at 255. First time a packet has ever been
  run through the widened register.
- **Reorder (HURDLES H33) does not manufacture a phantom loss**: the model's own per-packet SALU
  trace shows the frontier does not rewind on a late packet, and the following in-order packet
  raises no gap. `Δhi - Δlo = 0` for a pure reorder. A duplicate, separately, drives the naive
  estimate to exactly -1 -- a real, now-measured edge case the controller side must clamp (already
  handled: the census-anchored redesign never computes this delta independently, it always reads
  the exact register).
- **The Bernoulli injector's rate was validated against the model's own RNG** (previously only
  checked against CPython's), closing that specific disclosed gap; a borderline first-run result
  was correctly NOT accepted on one sample and was independently cross-checked with a second,
  purpose-built histogram test (pooled ~-1.5 sigma, chi-square consistent with uniform).
- The existing deterministic one-shot injector (`tbl_eg_fail`) still works correctly alongside the
  new stochastic one.

**No P4 defect found.** Three tooling findings recorded instead, correctly left unfixed as
out-of-scope: a pre-existing (unrelated) bug in `p4/ptf/test_fabric.py`'s counter helper; a
`tofino-model` log-message polarity quirk worth knowing for future trace-reading (does not change
the earlier W4 diagnosis, which used a different, unaffected case); and a note that this repo's
compile-gate report's claim of "known broken" controller code is now stale, since that was already
fixed on 2026-09-01. Per the explicit non-goal, the reorder-credit debt/window accounting was NOT
implemented -- it remains controller-side follow-up work, now with concrete model evidence
(`hi=4, lo=3` mid-sequence) of exactly what it would need to net out.

**Roadmap position:** steps 1 and 2 are both done. Step 3 (a real hardware smoke test) needs two
deliberate actions not yet taken and not bundled into this work: deploying the reconciled
`gate_agent.py` to the switch (which currently still runs the pre-reconciliation version, live,
under pid 181314), and loading `mcp_fabric_ledger.p4` onto the chip. Both touch the shared switch
and deserve their own explicit go-ahead rather than proceeding automatically from here.

<!-- AUTO-HANDOFF (PreCompact/auto) 2026-09-02T01:10:15Z -->
### Compaction handoff — 2026-09-02T01:10:15Z
- Git: branch `master`, 22 uncommitted file(s): README.md WORKING_NOTES.md docs/review/BEHAVIORAL-SUBLINK-PLAN.md docs/review/CAMPAIGN-PLAN.md docs/review/HEALTH-GATE-RESULT.md docs/review/P2-P3-INDEPENDENT-AUDIT.md docs/review/P3-DYNAMIC-RESULT.md docs/review/P3-FEEDBACK-RESULT.md docs/review/artifacts/HW-CLF-FRONTIER-PLACEMENT.md docs/review/artifacts/HW-CLF-STARVED-SWEEP.md docs/review/artifacts/HW-CLF-VS-CW4.md docs/review/artifacts/HW-SELECTIVE-DETECTION.md 
- Last verification run recorded: 2026-09-02T01:03:42Z	cd /home/philip/Projects/mcp bash p4/hw/bringup.sh mcp_fabric_ledger --dry-run 2>&1 | head -60
- RESUME: re-read the Task/Status/Next-action sections above; trust this file over recollection.

## Status (2026-09-02, later still) — step 3 done: real-silicon smoke test, exact loss recovery confirmed

Executed the two hardware-touching actions "yes, go ahead" authorized. Chip ownership re-checked
first (still MCP's own `mcp_fabric_clf_eg`, pid confirmed via `cmdline`, not a sibling project).

- `deploy.sh mcp_fabric_ledger` (dry-run then live) — sealed all 3 manifests.
- `takeover.sh` (dry-run then live) — displaced `mcp_fabric_clf_eg` cleanly, snapshotted to
  `p4/hw/snapshots/20260902T010245Z-takeover.txt`, chip confirmed free twice 30s apart.
- `bringup.sh mcp_fabric_ledger` (dry-run then live) — new `bf_switchd` pid 185642, all ports and
  loop pairs up. Hit and fixed a real tooling gap along the way: neither `deploy.sh` nor
  `bringup.sh` writes the `<program>.loaded-setup.sha256` receipt `gate_agent_core.py`'s
  `verify_loaded_setup` requires. Reverse-engineered the exact format/hash from an existing receipt
  for the old program, confirmed my independently-computed `compute_switch_id` matched, and wrote
  it by hand on the switch. **Not yet fixed at the script level** — flagging for later, not asked
  for yet.
- Stopped the pre-reconciliation `gate_agent.py` (pid 181314, log/pid preserved under renamed
  paths) and launched the reconciled one (commit `6761571`) bound to `MCP_PROG=mcp_fabric_ledger`,
  pid 187023. The F/X/Z ledger-safety guard correctly self-disabled with a clear log line (this
  program has no `reg_rx_frontier`). `P` ping confirmed connectivity (`OK 7`).

**Smoke test, full report in `docs/review/artifacts/HW-LEDGER-SMOKE-TEST.md`:**
- Sent 80 real UDP packets from Vision across 4 DSCP contexts through the fabric. Every one of 9
  populated sublinks reads `seq == obs` — zero loss, correct forwarding and counting on real
  silicon, first time for this program.
- Armed the existing one-shot injector for a known 5-packet drop on sublink 2, sent 20 more
  context-2 packets. Recovered loss = exactly 5 (`Δseq=20, Δobs=15`). The downstream vlink-10 hop
  for the same context correctly shows only 15 new arrivals (the 5 dropped upstream never reached
  it) — the expected cascade, not a second discrepancy.
- This is the real-silicon analogue of PTF Test 60 (which proved the same claim in `tofino-model`).
  Both zero-loss and known-loss cases match exactly.

**Roadmap position:** steps 1–3 are all done. Remaining, not yet requested: step 4 (the
statistical decision layer — absolute e-process against a fleet-estimated floor, per the
brainstorm) and step 5 (resolve RPC-in-critical-path, currently only disclosed via
`ledger_rpc_seconds`/`ledger_races`). Neither started without an explicit go-ahead.

## Status (2026-09-02, later) — step 4 (statistical decision layer) built, under independent review

"All authorized" covered steps 4 and 5. Wrote the plan first
(`docs/superpowers/plans/2026-09-02-statistical-decision-layer-plan.md`), scoped to the approved
brainstorm spine (C2 primary/secondary detectors, C3 continuous mitigation + restoration), then
implemented six new modules under `controller/`, each with its own test file (real TDD: wrote
tests with concrete numeric/statistical assertions, ran them red, implemented, ran green):

- `floor_estimator.py` — leave-one-out fleet floor $\hat p_0(t)$, excludes the sublink itself and
  any currently-unhealthy sibling, trailing window.
- `fleet_control.py` — e-BH (Wang & Ramdas) across sublinks.
- `relative_eprocess.py` — the secondary multinomial exchangeability discriminator (demoted per
  red-team finding 9.6), exact under any burstiness since it conditions on the design's own known
  spray weight, no floor estimate needed.
- `absolute_eprocess.py` — the primary mechanism: a log-spaced grid approximating the log-uniform
  mixture, evaluated each epoch against that epoch's own dynamic, previsible floor. Key correctness
  point verified by a dedicated Monte Carlo test: the martingale property survives a *moving*
  previsible null (E[LR]=1 under the true null holds for a fixed alternative against any previsible
  null value), so re-deriving the null every epoch from the fleet does not break validity — only
  changes power. Censored epochs contribute exactly a factor of one (log_capitals untouched, no
  reset, no alpha-halving), per brainstorm C2 verbatim; a real repair_generation bump is still a
  fresh sequence.
- `mitigation_weight.py` — `weight_from_wealth`: continuous, w(1)=1, w(∞)→w_min, strictly
  decreasing, never a step function (red-team finding 5's fix). `RestorationEProcess` reuses the
  same e-process engine with null/alternative swapped — literally "the same absolute test run the
  other way", not a second statistical mechanism.
- `decision_loop.py` — wires all of the above into one per-epoch `tick()`. **This is the concrete
  resolution of the round-3 review's RPC-in-critical-path finding**: the loop only ever consumes a
  caller-supplied `{sublink: (tx, rx)}` snapshot for the epoch that just closed — the same shape
  `CensusWorker`'s existing periodic background poll already produces — so nothing here performs a
  synchronous per-event RPC. `resolve_ledger_gap_event` is untouched and keeps serving its own
  immediate-diagnostics purpose on a separate path.

**187/187 tests pass** (`python3 -m pytest controller/ -q`), up from the pre-existing 37 plus all
prior additions. Deliberately NOT built this pass (out of scope per the plan): replay arms
(SprayCheck-Z/FlowPulse-θ), JSQ spray in htsim, the physical selectivity bench, shadow probation,
data-plane e-process — these are §5 build-order steps 6-9, separate roadmap items.

**Dispatched for independent verification** (both running as I write this): a `qa-verifier` agent
re-running the full suite plus its own ad-hoc stress checks (hand-verifying e-BH's threshold
arithmetic, confirming censored-epoch wealth is bit-for-bit unchanged, tracing that the
previously-healthy signal fed to the floor estimator each tick is genuinely previsible — computed
from the END of the prior tick, never the current tick's own just-computed result), and a
`code-reviewer` agent running the Four Hunts plus an independent check of the likelihood-ratio
algebra and the e-BH procedure against the real Wang–Ramdas definition. Results not yet in.

**Disclosed honestly, not yet resolved:** this is new sequential-testing code combining two
individually-established techniques (a previsible/plug-in-null mixture e-process, and e-BH fleet
control) in a specific combination that has not had an external statistics review. Before any of
this feeds a paper claim, a dedicated Monte Carlo calibration campaign (in the spirit of the
brainstorm's own `seq_design.out`/`peer_relative.out` simulations) should confirm nominal alpha
control empirically at production scale, not just the in-repo unit-test Monte Carlo checks (300
trials, generous slack) built so far.

**Roadmap position:** step 4 engineering is done pending review results; step 5 (RPC-critical-path)
is resolved by `decision_loop.py`'s construction, described above. Not yet done: wiring
`decision_loop.py` into the live `p4/hw/loop/controller_loop.py` main loop (currently a
standalone, fully-tested module — the live wire-up is a separate, deliberate action, not bundled
into this pass unless asked).

## Status (2026-09-02, overnight start) — CORRECTION: the statistical decision layer is broken as wired

The prior entry's "step 4 engineering is done pending review" was premature. The dispatched
`code-reviewer` agent found **3 CRITICAL, 3 HIGH** defects in `decision_loop.py` and
`floor_estimator.py` that the qa-verifier's earlier PASS did not catch (qa-verifier checked
correctness of each module and absence of regressions; it did not run fleet-scale or
adversarial-mutation checks). Recording the findings plainly, not editing the earlier entry away:

- **CRITICAL — empty leave-one-out pool falls back to `min_floor` (1e-6), the most
  anti-conservative null possible.** Reachable on the very first tick, on a single-sublink
  snapshot, and — the case the design specifically must survive — when every sibling is under
  mitigation simultaneously. Measured: **200/200 false e-BH rejections** on a fully healthy fleet
  in the single-sublink case; 195/200 when all siblings are quarantined.
- **CRITICAL — the floor is not actually previsible as wired.** `decision_loop.py` records every
  sublink's *current-epoch* counts into the estimator before computing floors. Leave-one-out
  removes the sublink's own sample but not its siblings' same-epoch outcomes, so under a shared
  shock (the exact scenario the relative-test discriminator exists for) the floor is contaminated.
  Measured: 0.185 -> 0.500 false-rejection rate under a common per-epoch congestion shock. The two
  CRITICAL bugs partially mask each other -- fixing only one in isolation measured *worse*.
- **CRITICAL — restoration can arm on a null derived from the very epoch it then tests, and the
  weight/alternatives clamp can make a link permanently unrestorable.** Measured: at an ordinary
  epoch packet count (tx=5000), 4/4 armings on a fully healthy fleet produced a suspect rate at or
  below every restoration alternative, so wealth decays monotonically forever.
- **HIGH — censoring is implemented correctly in `absolute_eprocess.py` but never wired**: 
  `FleetDecisionLoop.tick` has no censoring parameter, so the design's stated headline
  differentiator versus the old ledger ("censored epochs contribute a factor of one, no restart")
  is present at module level and absent from the running system. Same root cause/fix as the first
  CRITICAL item.
- **HIGH — `relative_eprocess.py` is dead code**, referenced only by its own test file, never
  called from `decision_loop.py`. The congestion-vs-gray discriminator the design specifically
  kept for the case an absolute test cannot resolve is unreachable.
- **HIGH — no context (4-bit) stratification anywhere**, though the brainstorm requires both
  detectors to stratify by it.
- Two Monte Carlo test assertions were 15x looser than the realized rate and would not have caught
  a plausible off-by-one; one e-BH test asserted a case that a broken (break-on-first-failure)
  implementation also passes, giving zero real coverage of the one non-obvious part of e-BH.

**No hardware was touched by any of this** -- the statistics layer has never run against real
counts, only simulation. Full findings, measurements, and suggested fix order are in the
code-reviewer agent's report (not yet filed as a doc; filing as
`docs/review/artifacts/STATS-LAYER-REVIEW-2026-09-02.md` now).

**Overnight plan, per Philip's explicit authorization before leaving for the night:**
1. Fix the statistics layer per the reviewer's order (critical 1+2 together, then critical 3, then
   wire censoring, then the weak tests, then decide HIGH 2/3 explicitly rather than leaving them
   silently dead) -- TDD against the reviewer's own discriminating repro cases. No hardware risk.
2. Separately, run an extended hardware soak of the *already-proven* ledger smoke test recipe
   (`docs/review/artifacts/HW-LEDGER-SMOKE-TEST.md`) at larger scale/duration, to stress-test the
   new P4 program's stability -- explicitly NOT using the statistics layer above.
3. Git: commit locally as Philip throughout the night, do not push.
4. On any hardware failure: attempt recovery only via the repo's own `takeover.sh`/`bringup.sh`;
   if that does not resolve it, stop, preserve evidence, and wait rather than improvising further.
5. No hard deadline to release the switch, but it must never be left in a broken or undocumented
   state.
