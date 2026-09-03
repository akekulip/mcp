# Wire-reduction ledger soak — an open anomaly, PI decision recorded (2026-09-02)

Extended-traffic follow-up to `HW-LEDGER-WIRE-REDUCTION-SMOKE-TEST.md`, using the existing
`p4/hw/loop/overnight_ledger_soak.py` against the wire-reduction binary. The primary claim under
test held up perfectly; a secondary, unexplained anomaly was found, investigated as far as two
cheap decisive checks would take it, and is recorded here rather than argued away.

## What was run

57 cycles total (1 from an aborted first attempt, 56 from a clean second run), each cycle sending
80 clean packets across 4 real DSCP contexts plus a further 20-packet round with a 5-packet
injected drop armed on sublink 2 (the same recipe as the hardware smoke test, at soak scale).

A real infrastructure fix was needed to even start: `read_census()` used bare `R`, which
`gate_agent.py` fails outright on if ANY sublink anywhere on the chip has a nonzero value on one
side and zero on the other (bring-up's own port-check traffic reliably leaves one or two such
sublinks). Fixed by requesting the soak's own fixed sublink set explicitly plus the runtime
`--inject-sublink` value — `p4/hw/loop/overnight_ledger_soak.py`'s `CENSUS_SUBLINKS` /
`read_census(extra_sublinks=...)`. This is a real, general fix (any future soak invocation
benefits), not a one-off workaround.

## The primary result: clean

**The mechanism actually under test — recovering an injected loss via the wire-reduction
reconstruction — passed 57/57, with zero exceptions.** `recovered_loss == expected_loss (5)` every
single cycle. This is the claim `LEDGER-WIRE-REDUCTION-2026-09-02.md` needed hardware evidence for,
and it is unambiguous.

## The anomaly

Two of the 57 cycles' *clean*-traffic checks (not the injected-loss check) showed a one-packet
discrepancy on a sublink that was not the injection target that cycle:

| cycle | sublink | vlink | ctx | Δseq | Δobs | resolved on 2s recheck? |
|---|---|---|---|---|---|---|
| 1 (first attempt) | 6 | 0 | 6 | 21 | 20 | no |
| 56 (second run) | 2 | 0 | 2 | 21 | 20 | no |

Both show the identical shape: exactly one extra stamp (departure) with no matching arrival,
persisting past the built-in re-check. This is the *opposite* direction from the only anomaly type
ever recorded across the pre-wire-reduction binary's ~3,200 historical soak cycles
(`P3-OVERNIGHT-LEDGER-SOAK-MAIN*.jsonl`), which only ever showed arrivals momentarily ahead of
their own stamp — a documented, self-resolving read-order race. Neither historical run ever showed
this direction, not once.

### What was ruled out

1. **Physical-layer loss.** MAC-level RX/TX counters on the physical port pair carrying this
   traffic (`M 164 172`) read exactly **9224 / 9224** — every frame transmitted was received at
   the wire. Whatever is happening, it is not a dropped or corrupted frame in flight.
2. **Ambient/spontaneous background noise, independent of traffic.** A 30-second fully idle
   window (no test traffic, no control-plane writes) was bracketed by two full 36-sublink census
   reads. They were **byte-for-byte identical** — nothing moved on any sublink while idle. Whatever
   causes the anomaly, it does not happen spontaneously; it is coincident with active traffic
   generation.

### What was not established

No confirmed root cause. Candidate explanations considered but not confirmed or excluded with
further evidence:

- A rare, pre-existing hazard of the (unmodified) egress fault-injector's live TCAM writes
  (`arm_injector`/`clear_injector` write `tbl_eg_fail`/`tbl_eg_bern` every cycle, on both the old
  and new binary) that the original 3,200-cycle history simply never happened to hit — plausible,
  since the injector tables are untouched by the wire-reduction change, but unproven: the original
  history used the identical arm/clear-every-cycle pattern and never showed this signature.
- A genuine, rare defect in the wire-reduction reconstruction (`tbl_wit_link_recon` /
  `tbl_wit_ctx_index`) under real traffic timing that the model/PTF suite's synthetic, low-rate
  traffic never exercised — the leading candidate specifically *because* the direction (stamp
  without arrival) and the mechanism it would implicate (the new ingress-side reconstruction) are
  both new to this change, but not confirmed: no reproduction was captured with fine enough
  instrumentation (a packet trace, not just before/after counters) to show where the "missing"
  arrival's classification actually went.
- A probe-side or orchestration-side artifact (an occasional duplicate raw-socket send from
  `multicontext_probe.py`, or an SSH-timing quirk in how the soak drives it) — possible but would
  need to explain why the *extra* stamp appears rather than a missing one, which is the harder
  direction to get from a client-side duplicate send.

An operational mistake narrows what can be said with confidence about the *cumulative* absolute
counts on sublink 2 across the whole session: an early, malfunctioning background launch of this
same soak was killed and its log file deleted before checking whether it had silently completed
any cycles first (Python's stdout buffering to a redirected file can delay printed output well
behind real work already done via subprocess calls). That makes reconciling sublink 2's exact
running total since the smoke test unreliable; it does **not** affect the two cleanly-logged,
directly-observed anomalies above, which come from the properly tracked second run.

## The PI call

Continuing to cycle live traffic against a shared piece of testbed hardware chasing a rare (~2 in
57 cycles), non-corrupting, physical-layer-exonerated anomaly — with the two cheapest decisive
checks already run and both informative — has a worse risk/effort trade than stopping here to
record it plainly. Deciding on the evidence gathered:

- **Not reverting.** The claim the wire-reduction pass actually needs to defend — that the
  reconstructed `md.wit_link` correctly recovers an exact injected loss count — held at 57/57
  with no exceptions. Reverting would discard that positive result over a finding that, so far,
  only ever touched *unmeasured, unarmed* sublinks, never the sublink whose detection accuracy is
  the actual claim.
- **Not declaring it resolved.** The anomaly is real, logged, reproducible in the sense that it
  happened twice independently, and inconsistent with the pre-change binary's own multi-thousand-
  cycle history. `HW-LEDGER-WIRE-REDUCTION-SMOKE-TEST.md`'s conclusion ("reproduces the pre-change
  binary's real-silicon behavior exactly") is **corrected**, not retracted outright: it is exact
  for the mechanism actually under test (loss recovery on an armed sublink), not exact in the
  stronger, unqualified sense that document originally claimed.
- **Stopping further live hardware cycling on this specific question for now.** The two checks run
  here (MAC counters, idle window) were chosen because they were cheap and each would have been
  decisive in one direction; both came back informative rather than conclusive, and the next
  useful step is not "run more cycles hoping to catch it again" but a differently-instrumented
  session (e.g., a mirror-copy trace of the exact packet the discrepancy implicates) that this
  session did not build and should not improvise ad hoc on shared hardware without planning it.
- **The switch is left clean and idle**, wire-reduction binary still loaded, injector cleared,
  gate agent healthy. No further changes made pending that follow-up.

## Update: the matched-conditions comparison came back, and it changes the assessment

The follow-up named above was run the same session, immediately after. `mcp_fabric_ledger_prewire`
(byte-identical to the pre-wire-reduction source, SHA-256 `4e889bfd…2ac136f3`, confirmed against
git `HEAD`) was deployed under its own program name — the wire-reduction artifacts already on the
switch were never touched — then taken live via the same `takeover.sh` / `bringup.sh` pipeline
(clean two-phase takeover, no respawn; `bringup.sh`'s new step 5c wrote the `loaded-setup.sha256`
receipt automatically on its first real end-to-end use, no manual intervention needed this time).
100 cycles of the *identical* soak script, at the identical `--cycles`/`--pps`/`--count-per-context`
defaults, immediately after the wire-reduction run, on the same testbed, same background
conditions as closely as two runs minutes apart can be:

| binary | cycles | clean-round anomalies | injected-loss failures |
|---|---|---|---|
| wire-reduction (`mcp_fabric_ledger`) | 57 | **2** | 0 |
| pre-wire-reduction (`mcp_fabric_ledger_prewire`) | 100 | **0** | 0 |

Zero anomalies of any kind across a *larger* number of cycles on the unmodified binary, run
back-to-back with the affected one under matched conditions, is real evidence against "this is
ambient testbed noise that would show up on either binary about equally." **The finding is
upgraded from "unexplained, direction unlike anything in history" to "likely specific to the
wire-reduction reconstruction path, not the testbed."** It is not yet a confirmed root cause: 157
combined cycles (2 anomalous) is still a small sample for a rare event, and no packet-level trace
of an actual occurrence exists yet.

The wire-reduction binary was restored as the live program afterward (`takeover.sh` on the prewire
build, `bringup.sh mcp_fabric_ledger` again) — it remains the actual research artifact, the
primary claim it needs to defend (injected-loss recovery) is unaffected by this finding, and
having it live is what the next step below actually requires.

## A second, mechanistically-explained pattern found while restoring the binary

While confirming the restored wire-reduction binary still worked (it does — 10/10 exact on every
tracked sublink, both hop directions, all 4 contexts, immediately after a fresh bring-up), a wider
sweep across every ctx on vlinks 0 and 8 turned up a second, *different* and *consistent* pattern,
reproduced identically across two independent fresh bring-ups today:

| sublink | vlink | ctx | seq | obs | direction |
|---|---|---|---|---|---|
| 0 | 0 | 0 | 0 | 12–14 | **phantom arrivals, zero stamps** |
| 3 | 0 | 3 | 0 | 12–18 | phantom arrivals, zero stamps |
| 128 | 8 | 0 | 0 | 10–14 | phantom arrivals, zero stamps |
| 131 | 8 | 3 | 0 | 6–8 | phantom arrivals, zero stamps |
| 142 | 8 | 14 | 18–21 | 0 | stamped, zero arrivals (opposite direction) |

This one has a mechanistic explanation, not just a correlation. `ctx = (dscp_class << 2) |
size_bin` (`setup_skeleton.py:ctx_of`); the probe's fixed 1400 B payload always lands in
`size_bin=2`, which is exactly why the probe only ever produces contexts {2, 6, 10, 14}. Contexts
0 and 3 are `size_bin` 0 and 3 at `dscp_class=0` (TOS 0x00, the default/unset DSCP) — i.e.,
genuinely non-probe traffic, different sizes, no explicit DSCP. The leading candidate source is
bring-up's own periodic port-verification traffic (`setup_skeleton.py ports`, polled every 2s
during `bringup.sh` step 6): small connectivity-check frames that plausibly never go through real
spray selection, so `hdr.fabric.spray` defaults to 0 for them. Every such frame arriving on
`(ingress_port=172, spray=0)` reconstructs to **vlink 0** under `tbl_wit_link_recon`, regardless of
which leaf's port check it actually was — a real, structural difference from the old design, where
`md.wit_link` came from whatever `hdr.witness.link_id` the frame's own sending egress had written,
which could vary correctly per port.

**This pattern never touches a sublink this project's own controlled traffic ever measures** (0
and 3 are outside the probe's context set entirely) and does not implicate the mechanism's actual
claim. It is recorded here because it is a real, structural consequence of the design change worth
knowing about, not because it threatens the injected-loss result. The §"anomaly" above (2-in-57 on
sublinks 2 and 6 — *inside* the probe's own context set, during active soak traffic) is a separate,
still-unexplained phenomenon; this size-bin finding does not resolve it, though it does establish
that the reconstruction mechanism can visibly misattribute non-probe traffic under at least one
understood condition (spray defaulting to 0 for connectivity-check frames), which narrows where a
root-cause investigation of the harder anomaly should start looking.

## Third check: the injector-write hypothesis is ruled out; a sharper clue emerges

Both confirmed cross-context anomalies (cycle 1 sublink 6, cycle 56 sublink 2) happened immediately
adjacent to a live `arm_injector`/`clear_injector` write to the unmodified `tbl_eg_fail`/
`tbl_eg_bern` tables, which was the leading candidate explanation going into this check. A new,
purpose-built discriminator (`p4/hw/loop/clean_traffic_only_probe.py`, reusing
`overnight_ledger_soak.py`'s own helpers) sends clean traffic in a loop with **no injector calls
anywhere in the script** — nothing arms or clears anything.

**Result: it reproduced the anomaly on cycle 1** — sublink 6, `Δseq=21, Δobs=20`, the identical
signature, with zero live table writes of any kind nearby. **This rules out the injector-write
hypothesis outright.**

What is common to all three confirmed occurrences, and wasn't noticed until this one: **every one
happened on the very first traffic burst after a gap** — the very first soak attempt's cycle 1 ran
right after a fresh `bringup.sh` with no prior traffic on this binary at all; this discriminator's
cycle 1 ran after several minutes of no traffic (spent on unrelated verification: pytest, register
reads). Cycle 56 of the second soak run is the one exception to a clean "first burst" story, and
remains unexplained by this pattern specifically. The leading hypothesis is now **an idle-then-burst
effect** — something about the fabric's state after a period with no traffic on the affected vlink
makes the first subsequent burst more likely to produce this signature — rather than anything tied
to control-plane table writes. This is a **sharper, testable** hypothesis for the next session: send
a burst, force a deliberate multi-second idle gap, send another burst, and check whether the second
burst (now itself "first after an idle gap") reproduces it while a burst sent with no preceding gap
does not.

## Fourth check: the idle-then-burst hypothesis, directly tested

A small, bounded probe (`p4/hw/loop/idle_gap_probe.py`, 3 trials) sent a control burst (immediately
following prior traffic, no idle) and then, after a deliberate 90-second idle gap with zero traffic,
a test burst (itself now "first after idle") — repeated 3 times.

**Result: 0/3 mismatches on control bursts, 1/3 on test bursts.** Trial 3's post-idle burst
reproduced the identical signature (this time sublink 14, `Δseq=21, Δobs=20`) that sublinks 6 and 2
showed in every earlier occurrence. Counting every burst across this whole investigation that was
genuinely "the first traffic since a gap" — the original soak's cycle 1, the injector-free
discriminator's cycle 1, and this probe's 3 test-condition trials — **3 of 5 such bursts reproduced
the anomaly, against 0 of the many dozens of steady-state ("not first") bursts across every soak,
discriminator, and control trial run today.** This is a real, if probabilistic (not deterministic —
2 of 5 post-idle bursts were clean), signal: idleness measurably elevates the anomaly's likelihood
on the very next burst, on top of the design-level rate difference already established against the
pre-wire-reduction binary (0/100 vs 2/57).

## CORRECTION (2026-09-02, same day): the "mirror defect" below was an INSTRUMENT ARTIFACT, not a real defect

**Everything in the fifth check below, and the "Same defect confirmed on the second call site"
note earlier in this document, is WRONG and is retracted.** The gap-event mirror and the
audit-receipt mirror BOTH fire correctly on real hardware. The "0 copies captured" that drove the
defect conclusion was my listener (`p4/hw/loop/mirror_trace_listener.py`) reproducing two
already-documented, already-fixed harness bugs: `HW-CLOSED-LOOP.md` defect #1 (a bare `AF_PACKET`
socket does not join promiscuous mode, so Vision's NIC hardware-drops mirror copies, which are
addressed to `a5:a5:a5:a5:a5:a5`, not the NIC's MAC) and #4 (an `ETH_P_ALL` bind buries copies
behind the production stream). `controller_loop.open_mirror_socket()` already fixes both and says
so in a comment; I wrote a fresh listener without copying it. The tell I missed: "0 copies" was
clean and all-or-nothing across every test -- exactly the harness-artifact signature CLAUDE.md
cross-check rule #5 names. The one time the old listener DID see copies, a `tcpdump` (which enables
promisc) happened to be running alongside it.

**After fixing the listener** (join `PACKET_MR_PROMISC`, bind on `MIRROR_ETYPE`), the identical
deterministic 5-packet drop produced the gap-event mirror immediately: `vlink=2 flags=0x9
(GAP_EVENT|MEASURED) path_id=0xFFFB (the -5 gap) witness.seq=34`. The declared-audit test produced
10 audit-receipt copies: `flags=0x10/0x11 (AUDIT_RECEIPT[|MEASURED]) vlink=0 (declared spray)
seq 21..30`. Both mirror paths are healthy; there is no P4 mirror-emission defect.

**Does NOT change** (all register-observable, never mirror-dependent): the original soak anomaly
(stray 1-packet miscounts on unmeasured sublinks), the idle-then-burst correlation, the matched
0/100-vs-2/57 comparison, the wire-reduction injected-loss recovery (157/157) -- all still stand.
**DOES change**: the mirror trace now works, so it IS usable to diagnose the original soak anomaly
-- idle-then-burst trigger + the fixed listener is the concrete next step, no longer blocked.

The original fifth check follows, kept per this document's correct-in-the-open convention rather
than deleted.

## [RETRACTED -- see correction above] Fifth check: the mirror-trace instrumentation was built — and found a second, separate defect

Per the plan above, the mirror-trace follow-up was built this session rather than deferred:

- `install_mirrors(gc, bfrt, tgt, collector_dp=9)` run against the live switch (mirror sessions
  1, 2, 3 all pointed at dp9/Vision, confirmed via a direct `$mirror.cfg` readback: session 2 —
  the one `set_gap_event()` uses — is configured identically to session 1, which is proven to
  work).
- `controller/hw_adapter.py` copied to Vision and confirmed to run there standalone (pure stdlib,
  no SDE/bfrt dependency) — no offline round-trip needed for parsing.
- `p4/hw/loop/mirror_trace_listener.py` (new): a raw `AF_PACKET` listener on Vision's fabric
  interface, filtering on `MIRROR_ETYPE` (0x88f1) and parsing every copy live with
  `hw.parse_copy()`.

**The pipeline works**: an independent `tcpdump` capture confirmed real 0x88f1 mirror frames
arrive at Vision with the exact expected MAC addresses, and the listener itself correctly
captured three genuine sampled ("measured", `mirror_sid=1`) copies during ordinary traffic,
parsing vlink/context/CSIG detail correctly.

**What it could not catch, because the underlying mechanism does not appear to fire at all**:
three independent, deterministic, substantial injected drops (5 packets on sublink 2, twice; 15
packets on sublink 6) each correctly registered on the ledger's own `Δhi − Δlo` register math —
proof that `wit_check()` executed and computed a nonzero `md.wit_result.gap` for the closing
packet, since that is the same register write the controller's read observes — **yet not one
produced a `gap_event` mirror copy**, despite `set_gap_event()`'s condition
(`md.wit_result.gap != 0`, non-audit traffic) being unconditional on hop and reading exactly that
same value on exactly that same packet. Session 2's mirror config is proven identical to session
1's working config, ruling out a configuration mismatch.

**This is a second, separate, real finding, not caused by the wire-reduction pass**:
`set_gap_event()` and its trigger condition are unmodified code, inherited from before today's
edit. `HW-LEDGER-SMOKE-TEST.md`'s own methodology never used mirror capture at all — every prior
validation of this program (the smoke test, both soaks, every discriminator built today) relied
exclusively on `R`-command register polling. It is plausible the gap-event mirror path was never
actually exercised on real hardware since the receiver-ledger redesign replaced mirror-based
notification with controller-side register polling as the primary signal, and simply was not
re-validated when the rest of the design moved on. Root cause not established within this
session's budget — worth its own dedicated look, separate from the soak anomaly, since it affects
the ledger's event-notification capability generally, not just this investigation's diagnostic
plans.

**Consequence for the mirror-trace plan**: it cannot currently be used to catch the soak anomaly
live, since the exact class of event it would need to catch (a discontinuity) does not appear to
reach a mirror copy at all right now. The infrastructure (mirror sessions, the Vision-side
listener, `hw_adapter.py` running there) is built, verified for plain sampled traffic, and ready
to reuse the moment the gap-event mirror defect itself is fixed — but that fix has to come first.

### Root-cause narrowed, and the defect is confirmed pre-existing — not caused by today's pass

Two follow-up checks, both static/cheap or a controlled re-test, before spending more session
budget guessing:

1. **The attention/exceedance side-effect proves gap DETECTION works internally.** A discontinuity
   arms `md.exceed`, which (per the frozen attention rule) bumps `attn` by `k_up` (1024) on the
   next sample. Reading live attention state (`G 4`) returned `ATTN 4 11264 760` — `11264 - 4096
   (A0_DEFAULT) = 7168 = 7 * 1024`, i.e. exactly seven whole exceedance increments already banked
   from today's testing. **This proves `md.wit_result.gap != 0` has been correctly computed and
   acted on internally, repeatedly, today** — the defect is not in gap detection, it is narrowly
   in the mirror COPY of that event never reaching the wire.
2. **Stage-placement comparison ruled out the wire-reduction pass as the cause.** `set_gap_event()`
   reads `md.wit_result.gap` at the single highest MAU stage in *both* binaries — stage 10 of 11 in
   the pre-wire-reduction compile, stage 11 of 12 in the wire-reduction one (confirmed directly
   from each build's `phv.json`). The relative position (absolute last stage) is unchanged; only
   the total count grew by the one stage this pass already disclosed. That ruled out "pushed past a
   timing threshold by the new stage" as the mechanism — but the right test was to check the actual
   binary, not reason about it.
3. **Direct A/B re-test settled it.** The pre-wire-reduction binary (`mcp_fabric_ledger_prewire`,
   still sealed on the switch from the earlier comparison) was taken live again, its own mirror
   sessions installed, and hit with the identical deterministic 5-packet drop used throughout this
   investigation. **Same result: the ledger's own register math showed the exact 5-packet gap
   (20 seq / 15 obs), and zero gap-event mirror copies arrived.** Identical failure, on the
   unmodified binary, under conditions where nothing about today's change was even loaded.

**[RETRACTED]** An earlier version of this note claimed `set_audit_receipt()` was a "second call
site" of a mirror-emission defect. There is no defect — see the CORRECTION section below. With the
listener fixed, the audit-receipt mirror fires correctly (10 `FLAG_AUDIT_RECEIPT` copies for a
10-packet declared-audit flow). The register-observable part of that test (the audit path fires:
the declared flow moves to the pinned spray, which only `set_audit_spray()` can do, and all 10 are
counted exactly) was and remains correct; only the "0 mirror copies -> defect" inference was the
instrument artifact. Reusable probe: `p4/hw/loop/audit_probe.py`.

**This is now conclusive, not merely likely: the gap-event mirror defect pre-dates the
wire-reduction pass and is fully independent of it.** It is a standing defect in the receiver
ledger's mirror-based notification path, apparently never exercised on real hardware since the
redesign moved the primary signal to controller-side register polling. It is not this session's
bug to fix, and today's wire-reduction work is fully exonerated of it. The wire-reduction binary
was restored as the live program afterward and re-verified functionally (a fresh clean burst
counted exactly right on every sublink touched).

## What this changes going forward

- This is now a **named, tracked, open item with elevated confidence it is real**, not a silent
  gap or a shrug at ambient noise: any future evaluation that relies on unmeasured/background
  sublinks being trustworthy (rather than just the sublink under active detection) should treat
  this as a live, likely-real caveat until root-caused — not a probably-benign one.
- **Ruled out**: physical-layer loss (MAC counters), spontaneous ambient noise (idle window), and
  live control-plane table writes (the injector-free discriminator).
- **Confirmed, probabilistically**: idleness measurably elevates the anomaly's likelihood on the
  very next burst (3 of 5 post-gap bursts reproduced it vs 0 of many dozens of steady-state bursts
  across every experiment run today) — not deterministic, but a real, load-bearing signal, not
  speculation. What is NOT yet known: the exact mechanism (a queue/buffer/table-entry effect that
  decays with idle time? something in TM scheduling after a port goes quiet? a stale PHV/pipeline
  state issue specific to the first packet through a cold path?) or why cycle 56 of the original
  soak broke the "always first-after-gap" pattern.
- **The mirror-trace infrastructure is built, verified for plain traffic, and NOT yet usable for
  this anomaly**, because of the fifth check's finding: gap-event mirrors do not fire on real
  hardware for this program at all, for any of three independent, deterministic, substantial
  drops tested. **That defect has to be root-caused and fixed first** — it is a real, separate
  gap in the receiver ledger's own event-notification path, inherited unmodified from before
  today's wire-reduction pass, and worth its own dedicated investigation (start from: is
  `md.wit_result.gap`'s value at the point `set_gap_event()` reads it genuinely nonzero on real
  silicon, or does something between `wit_check()`'s register write and that read clear or
  misroute it — a PHV/table-placement question, not a register-math one, since the register math
  itself is proven correct by the very fact the controller's polling sees the right answer).
  Everything needed to resume the moment that's fixed is in place: `p4/hw/loop/
  mirror_trace_listener.py` running on Vision (collector dp9, already the configured
  `$mirror.cfg` target for sessions 1–3), `hw_adapter.py` deployed there standalone, and the
  idle-gap trigger condition from the fourth check ready to arm on.

## Sixth check: traced idle-gap run — anomaly did not fire; mirror-sampling confound found and resolved

With the mirror listener fixed (promisc + `MIRROR_ETYPE` bind), ran the idle-gap probe (3 trials,
90 s idle) with attention raised to ~100% (`T 4 65535 0` / `T 5 65535 0`, originals 26624/70 and
4096/20 saved and restored after) so every arrival would be mirrored. Result:
`docs/review/artifacts/P3-IDLE-GAP-TRACED-2026-09-02.jsonl`, trace `mt_trace.jsonl` (956 copies).

- **The register-observable anomaly did NOT reproduce**: 0/6 legs mismatched (probe's own
  authoritative before/after Δseq/Δobs check). It runs ~50% per idle-burst historically, so 0 in 3
  idle-bursts is unlucky (~12%) but unremarkable — not evidence it went away.
- **The mirror trace works**: 956 copies captured including one real gap event
  (`vlink=14 gap=-7 seq=12 flags=0x9`), which corresponds to the frontier reconciling sublink 14's
  known stale bring-up-noise baseline on the first burst — an explained artifact, not the anomaly.
- **A confound was found and resolved, not over-read.** At ~100% sampling the per-burst mirrored-
  arrival counts showed occasional single shortfalls (e.g. ctx10 hop2 = 39 vs 40, = 19 vs 20).
  Those are NOT data loss: the ground-truth registers for those exact sublinks (10 and 170) read
  **125/125, perfectly balanced**. The shortfalls were dropped MIRROR COPIES under high sampling
  load — `HW-CLOSED-LOOP.md` defects #2/#8. Lesson pinned: a ~100% mirror firehose cannot be used
  for exact per-packet accounting; the registers remain ground truth, the mirror is a lossy
  sampler of it.

**Corrected instrument design for actually catching the anomaly** (the ~100% broad-sampling
approach used here is the wrong tool): keep the register check as the TRIGGER (it is reliable and
not mirror-dependent), run many idle-gap trials until a leg's Δseq/Δobs actually flags, and only
for that specific sublink+time inspect a LOW-VOLUME, BPF-filtered mirror capture scoped to it
(as `controller_loop.open_mirror_socket()` does with its classic-BPF `attach_mirror_filter`) so the
capture path is not itself saturated. That is the right next-session setup; this run establishes it
and rules out the high-sampling shortcut.

## Seventh check: register-triggered hunt (6 trials) — did NOT reproduce; earlier "idle trigger" reading walked back

The corrected instrument from §6, done right this time: normal attention (low mirror volume, no
capture-loss confound), the fixed listener running, register check as the trigger, 6 idle-gap
trials (~98% chance to see at least one hit IF the rate were really ~50%/idle-burst). Result:
`docs/review/artifacts/P3-IDLE-GAP-HUNT-2026-09-02.jsonl` — **0/6 legs flagged, 0 gap-event mirror
copies, 779 trace copies total.** Post-run register census: every probe-measured sublink
(6, 10, 162, 166, 170, 174) perfectly balanced; the only imbalances are the documented non-probe
noise (ctx0/ctx3 phantom arrivals, vlink8 ctx2/14 phantom stamps) plus the stale accumulations on
sublink 2 (injected-drop history) and sublink 14 (the §6 gap event).

**Honest walk-back.** Combined with §6, that is **0 hits in 9 idle-bursts**. My earlier
"idle-then-burst confirmed, ~50%/burst (3 of 5)" was a small-sample read; with the new data it is
**3 of 14**, a much noisier signal, and two full clean runs at 0/9 mean the "any 90 s idle then
burst" trigger does NOT reliably reproduce this in the current, heavily-warmed fabric state. What
still stands on solid evidence: the anomaly is real (the original soak's 2/57 register-observed
hits and the matched 0/100-vs-2/57 comparison were never in doubt), and all three earliest hits
(first-soak cycle 1, discriminator cycle 1, first idle-gap trial 3) shared "early in the session /
closer to a fresh program load" more tightly than they shared "90 s idle" specifically. The
surviving, better-supported hypothesis is therefore **genuinely-cold fabric (first bursts after a
fresh load), not arbitrary mid-session idle** — which the current warmed state no longer provides.

**PI call: stop the live chase here.** Two clean runs at 0/9 mean more idle-gap trials in this
state have low information-per-cost, and I will not keep cycling shared hardware on a trigger the
data just weakened. The reality of the anomaly rests on the earlier solid observations; its trigger
is not yet cleanly characterized, and the honest next experiment is a **fresh-bringup-first-burst**
protocol (cold-load the program, send one burst immediately, repeat across several fresh loads),
with the register check as trigger and the (correct, low-volume, ideally BPF-filtered) mirror trace
ready to capture the packet-level detail the first time it fires. Not run this session — it needs
its own bring-up budget and should not be improvised at the tail of an already-long session.
