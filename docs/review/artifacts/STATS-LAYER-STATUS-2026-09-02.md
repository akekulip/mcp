# Statistical decision layer: consolidated status after three review rounds (2026-09-02)

**Bottom line: not production ready. No production caller exists anywhere in the repo (confirmed
by grep in round 3) so nothing live is at risk, but this needs a design pass, not another
autonomous patch cycle.** Full round-by-round detail is in `STATS-LAYER-REVIEW-2026-09-02.md`
(rounds 1-2); this document adds round 3 and gives the overall picture in one place.

## What this is

Six new, previously-nonexistent modules under `controller/` implementing the fleet-level
statistical decision layer from `docs/review/BRAINSTORM-2026-09-01.md` §2 (C2/C3): a fleet-estimated
floor, a primary absolute e-process, e-BH fleet control, a secondary relative discriminator
(unwired), and a continuous mitigation weight with restoration. Built and reviewed across one
overnight session, 2026-09-02, under Philip's explicit "all authorized" instruction to run
autonomously through the night.

## What is genuinely solid

- **Every individual statistical primitive is mathematically correct**, independently re-derived
  and confirmed by two different reviewer passes: the Bernoulli/Binomial likelihood-ratio formulas,
  the mixture-martingale construction, the Wang-Ramdas e-BH procedure (including its one
  non-obvious property, the "largest qualifying k" search), and the moving-but-previsible-null
  argument (a fixed alternative against ANY previsible null value preserves `E[LR]=1`).
- **The engineering hygiene is real**: no scope creep across three rounds (every fix stayed inside
  the six files), no fake progress, no fabricated results, honest disclosure of every known gap in
  module docstrings and WORKING_NOTES rather than silence.
- **206/206 unit and integration tests pass** at every commit along the way.
- **Three CRITICAL findings from round 1 and round 2 are genuinely fixed and independently
  re-measured**: the anti-conservative floor fallback (round 1 CRITICAL 1), the previsibility leak
  under a non-shared-shock scenario (round 1 CRITICAL 2), and the arming crash on a blackholed
  sublink (round 2 CRITICAL A).

## What is not solid: the control loop does not work end-to-end

Three review rounds, each finding a *deeper* problem than the fix that preceded it -- the pattern
itself is the signal, not just any single finding:

1. **Round 1** (`STATS-LAYER-REVIEW-2026-09-02.md`): 3 CRITICAL + 3 HIGH in the initial wiring.
2. **Round 2** (same file, second half): confirmed 2 of round 1's 3 CRITICALs fixed with real
   measurements, but found a NEW crash bug (blackhole -> suspect_rate exactly 1.0, uncaught), found
   the third CRITICAL's fix insufficient (a restoration grid fixed at construction can sit below
   the current floor, passing its arm-time guard but never actually letting a recovered link look
   like any alternative -- measured wealth decaying to exactly 0.0 over 2000 epochs), and found the
   round-1 previsibility fix itself regresses under a shared/common-mode shock across siblings
   (false-rejection rate up to 1.00, worse than the original leaky code's 0.15 in that adversarial
   configuration) -- this is CRITICAL C, requiring the (currently unwired) relative discriminator.
3. **Round 3** (this session, just completed): confirmed the blackhole crash and the
   restoration-grid coupling fix both hold at the unit level. But surfaced two more severe problems
   that make the whole mechanism non-functional in practice:
   - **A single degraded link can drive the ENTIRE fleet into a permanent, unrecoverable absorbing
     deadlock.** A newly-degraded link's first bad epoch is (correctly, previsibly) still tagged
     healthy, so it pollutes its siblings' floors upward for one epoch; because the primary
     detector's alternatives grid is fixed while the floor can rise, clean traffic against an
     inflated floor can itself alarm (measured wealth 1.2e+74 from perfectly clean 1e-3 traffic once
     the floor rose to 0.1). This cascades sublink by sublink until the whole fleet is mitigated,
     every leave-one-out pool is empty, every epoch censors, and wealth freezes -- measured still
     100% mitigated 4800 epochs after the single triggering fault was repaired.
   - **Restoration's action rate measured at 0/8 against the design's own required >=0.9**
     (brainstorm H2/H3). The windowed suspect-rate estimate (this session's own HIGH D fix) still
     arms on the same tick the primary detector first reacts, when the window contains zero
     degraded epochs -- measured understatement of the true degraded rate by 9x to 194x, arming
     restoration against a null barely different from healthy. Window size does not fix this; it is
     a wrong-anchor problem, not a wrong-window-length problem.
   - A config trap: `restoration_grid_low` is never validated against `floor_min`, and when there's
     no headroom, arming silently no-ops with no error or log -- a mitigated sublink can be pinned
     at `w_min` forever with no visible cause.
   - Two of this session's own regression tests do not kill the mutants they were written for (a
     full revert of the restoration-grid coupling, and a full revert of both suspect-rate clamps,
     both leave the 206-test suite green) -- the test suite currently overstates how protected these
     fixes are.

## Why this is a stop-and-replan point, not "one more fix"

Prime directive: after repeated failed attempts at the same class of problem, stop and re-plan
rather than keep patching. Three rounds have each found a problem one level deeper than the last:
round 1 was wiring bugs, round 2 was insufficient guards, round 3 is a genuine architectural gap
(the primary detector has no mechanism to track a moving floor without becoming self-alarming, and
suspect-rate estimation has no mechanism to anchor to "evidence since arming" rather than a fixed
window). Patching this incrementally, autonomously, at night, without a design conversation, has
diminishing returns and rising risk of a subtler fourth-order bug. This needs Philip's judgment on:

1. How should the primary detector's alternatives grid track a moving floor without itself becoming
   the source of false alarms (the same fix `_restoration_grid` uses for the secondary process --
   couple the grid to the current floor -- is the measured-to-work direction, but changes the
   primary detector's own validity argument and deserves review before it's applied there too).
2. How should suspect-rate estimation anchor to the evidence that actually triggered an arming,
   rather than any fixed trailing window measured from the arming tick.
3. What the loop's designed behavior should be when a large fraction of the fleet is legitimately
   unhealthy at once (an escape hatch from all-censored, and a decision on whether/how e-BH and the
   relative discriminator (CRITICAL C) should compose with that state).
4. Whether `PREREG.md` needs an amendment stating scope/preconditions before any of this is relied
   on for a paper claim, given how far the current implementation is from the design's own
   H2/H3 targets.

## What happens next

- No further autonomous code changes to this module tonight. The module's own docstring
  (`controller/decision_loop.py`) now states this status plainly, matching this document.
- The six modules, their tests, and all three rounds of review remain committed to git history
  (local commits, not pushed) as a complete, honest record -- nothing is hidden or reverted.
- The rest of the overnight session continues on the hardware track (healthy, unaffected -- see
  `WORKING_NOTES.md`) and on lower-risk brainstorming/framing work, not further patches to this
  module.
