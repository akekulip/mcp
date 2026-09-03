# Response to the referee report and its artifact-audit addendum (2026-09-03)

Reports: `review_two_byte_witness.md` (first report) and `artifact_audit_and_revised_verdict.md`
(addendum). Each item below states what was done, with the artifact that backs it, or why not.
Ordered by the addendum's revised checklist.

## Done in this revision

1. **App-impact NULL reported and the motivation reframed** (addendum §1). The 1.36 percent
   completion-time result, the missing-actuator caveat, and the four reframings are now in
   Section X (first paragraph) and in the introduction's first-ness paragraph and the
   conclusion. Source: `docs/review/artifacts/APP-IMPACT-HTSIM-MAKEBREAK-2026-09-03.md`.
2. **CounterPair-0B added, read skew measured, thesis retitled around in-band alignment**
   (first report §1.2, addendum §3). `sim/baselines/comparison.py:counterpair_tx` and
   `localization.py:CounterPairLocalizer` implement the arm with a documented skew model;
   `sim/baselines/run_comparison_sweep.py` sweeps σ ∈ {0, 1e-4, 1e-3, 1e-2, 2.6e-2, 1e-1};
   `docs/review/artifacts/READ-LOOP-BENCH-2026-09-03.md` measures 2.6 ms per sublink and
   350 ms per 1024-sublink census on the Tofino. Results: identical to the ledger at σ=0; FP
   0.28–1.00 at σ=1e-4; FP 1.00 at every rate from σ=1e-3 up, including the measured 2.6e-2;
   localization exact 0.00 at 2.6e-2. Sections IV (arm), V (Fig. counterpair), VI, X, XI;
   abstract and Contribution 2.
3. **`cumulative_packets` fixed, sweeps regenerated, Fig. 1 replotted, Table I and Section V
   restated** (first report §1.3, addendum §2). Origin is now the onset epoch, with the defect
   recorded in a code comment. Post-onset: ledger 2 M; SprayCheck 4/6/12/94 M; separation at
   10⁻³ is 47×. New JSON `BASELINE-COMPARISON-SWEEP-2026-09-03.json` (the 2026-09-02 file is kept
   for provenance). `test_counterpair.py::PostOnsetOrigin` pins the origin.
4. **Cost-scaling proposition stated; sweep extended to 10⁻⁵; floor swept** (first report §1.1,
   addendum §4). Proposition 1 in Section II-B with both bounds (s²/p² vs s²f/p²) and the sparse
   Poisson refinement. Rates 5e-5, 2e-5, 1e-5 added: the ledger's wall at 6 M / 36 M / none.
   `sim/baselines/run_floor_sweep.py` → `FLOOR-SWEEP-2026-09-03.json`, Fig. floor: the wall
   tracks f at 10⁻⁶, 10⁻⁵, 10⁻⁴. "Flat" is now qualified everywhere it appears.
5. **Anomaly paragraph rewritten from the evidence; spray-zero aliasing disclosed** (addendum
   §6). Section X now carries the matched 0/100 vs 2/57 comparison, the injector-write rule-out,
   the walked-back idle trigger (3 of 14, not 3 of 5, per the seventh check in the anomaly
   document), the cold-fabric hypothesis, and the spray=0 → vlink 0 aliasing as a correctness
   cost of the reduction. Section X also reconsiders 2 B vs 4 B in that light.
6. **Regime R4, congestion/incast, added** (first report §1.5, addendum checklist 6).
   `correlated.py` gained `elevated_links/elevated_rate`; `run_correlated_stress.py` adds four
   R4 cells → `CORRELATED-FAULT-STRESS-SWEEP-2026-09-03b.json`. The ledger names all eight
   congested downlinks (FP 1.00) and cannot isolate a culprit beside them (exact-all 0.00);
   SprayCheck holds (0.92–0.96). Section VIII-C, Table incast, Fig. correlated (d), Section X.
7. **e-process promoted to a subsection with α = 0.05** (first report §2.2, addendum §5).
   Section III-B: floor (leave-one-out, W = 20, censor rather than fallback), evidence (Eq. 3,
   ratio grid {2, 5, 10, 50, 200}), previsibility, censoring convention, e-BH at α = 0.05, and
   why observed FP is 0.00 rather than α.
8. **Wrap period and epoch bound** (addendum §7, first report §2.4). The "2 per packet" note in
   `WORKING_NOTES.md:137` is from the earlier C-W4 program, where both loopback passes hit one
   register; on the ledger program Δseq = N exactly (Table III: 5 000 → 5 000, 60 000 → 60 000),
   so the 2× correction is **declined** with that evidence. The read loop was measured instead
   (350 ms census, 2.6 ms per sublink) and Section IX now states the wrap bound: 30 ms per fully
   loaded 25 Gb/s sublink, so the two-byte width is unambiguous only under ~187 kpps per sublink
   at the measured cadence; both headers carry a 16-bit sequence, so the four-byte header does
   not escape the bound.
9. **Silicon claims scoped** (first report §2.3, checklist 9). Section VII and X state: virtual
   fabric on one switch, 20 kpps offered load (~1 percent of a port), register update at line
   rate asserted not measured, added load computed not measured. The line-rate soak is left as
   future work rather than claimed.
10. **Pre-registration and novelty gates cited; artifact named** (checklist 11). Section IV
    "Pre-registration and artifact". The repository is public at `github.com/akekulip/mcp`.
11. **`scaling_curve.pdf` regenerated from `_common.py`; `mcp`→ledger mapping in README**
    (addendum §8). `paper/ton/figures/fig_scaling.py`; README naming note. A code-wide rename is
    deferred: it touches the frozen localizer's callers and every sweep JSON key.
12. **Load as a range; blackhole and duplicate cases; per-sublink reordering** (checklist 13,
    first report §2.5, §3). Section IX (0.02–2.4 percent by packet size, wire denominator with
    framing); Section III "What the identity does and does not see".
13. **Section VI reframed around the baselines; degenerate McNemar removed** (first report
    §2.1). The ledger is the oracle row; ties are reported as "no discordant seeds".
14. **Spurious-intersection finding kept in VIII-A** and named in the contributions.

## Not done, and why

- **Line-rate soak and throughput/latency impact** (first report §2.3): needs a packet generator
  ramp on the switch (`P4-DESIGN-SPACE.md:1163`); not run on the shared chip today. Scoped in
  the text instead.
- **Stage budget in a production pipeline or on Tofino 2/3** (first report §2.6): no such
  program or device is available; stated as a limitation in Section X.
- **Root cause of the anomaly** (first report §1.4): the fresh-load first-burst protocol needs
  its own bring-up budget; the paper now reports exactly how far the evidence goes.
- **Re-measuring the one-packet gap with a guaranteed trailing survivor** (first report §3):
  requires arming the stochastic injector through bfrt with the gate agent stopped; not repeated
  today; Section X says so.
- **JSQ(2) spray for SprayCheck's calibration** (first report §2.7): disclosed as a
  constant-factor effect; not reimplemented.
- **Affiliation, date, acknowledgment, biography**: the author's.

## Verification for this revision
`python3 -m pytest sim/baselines/tests -q` → 65 passed (7 new). All figure scripts render; the
manuscript builds under IEEEtran. Every new number is transcribed in `NUMBERS.md` §"2026-09-03
revision".
