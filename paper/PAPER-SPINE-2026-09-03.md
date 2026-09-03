# Paper spine — MCP measurement paper (ToN / IMC), 2026-09-03

The evidence base is complete and committed. This is the writing spine: contribution statement,
section plan, and the exact committed artifact each section draws on. Structure follows the
`CONTRIBUTION-FRAMING-2026-09-02.md` guidance (measured characterization, lead with cost-scaling,
honest scope). Actual prose comes later via `systems-paper-writing` → `paper-voice` →
`academic-humanizer` → checks → `remove-ai-marks`.

## Working title
*What a 2-byte witness buys on a sprayed fabric: a silicon-measured head-to-head of in-fabric
grayhole localization against the passive state of the art.*

## Venue
ToN or IMC (measurement paper). NOT SIGCOMM/NSDI: the detector primitive is prior art and the
top-venue avenues are all closed (novel mechanism → prior art; healing → structural FAIL;
identifiability reframe → refuted by SprayCheck; application impact → NULL). Positioned as a
characterization, not a new primitive.

## Contribution statement (the claim that survives a hostile PC)
The first faithful, primary-source-grounded head-to-head of the two most recent passive
sprayed-fabric loss detectors (SprayCheck, FlowPulse) against an in-fabric per-directed-link
witness, on the sprayed AI-fabric regime all three target, quantified on real Tofino silicon:
what a 2-byte-per-packet witness **buys** — flat 100%/FP-0 detection where the passive arms'
packets-to-detect grows ~Θ(1/p) and collapses below 1e-3, and exact directed-link localization
where they alias to the {uplink,downlink} 2-set — and what it **costs** — 2 B/packet (~0.14% at
1400 B) and a 12-stage ingress footprint. The witness's disambiguating power is an
information-structure property (it holds each directed link's own tx count), stated as such, not
an inference advance. Scope: stationary, independent per-directed-link faults (PREREG v1.9).

## Section plan (with the committed evidence each uses)

1. **Introduction.** Grayhole localization on packet-sprayed AI fabrics is hard: spraying
   decomposes flows across k spines and mitigation removes the evidence. Lead with the measured
   result: passive detection cost scales ~Θ(1/p) and collapses below 1e-3, while an in-fabric
   per-link witness stays flat — measured on silicon. Contribution bullets = the statement above.
   → `SCALING-CURVE-A3-2026-09-03.md`, `BASELINE-COMPARISON-2026-09-02.md`.

2. **Background / threat model.** Sprayed leaf-spine fabric; per-packet spray; grayhole (silent
   partial loss) at 1e-3–1e-4; the {uplink,downlink} directed-link aliasing a single passive
   vantage faces. Independent stationary single-or-several faults in scope; common-mode out.
   → `paper/PREREG.md` v1.9, `CORRELATED-FAULT-STRESS-2026-09-03.md` (scope evidence).

3. **The receiver ledger (design, briefly — NOT claimed novel).** Per-directed-link (hi, lo)
   counters; loss = Δhi − Δlo; the 2-byte witness (link reconstructed at ingress from port+spray).
   State plainly this is the NetSeer/LinkGuardian primitive at reduced width; the paper measures
   it, does not claim it. → `LEDGER-WIRE-REDUCTION-2026-09-02.md`.

4. **Method — the fair replay harness.** One shared spray/survival stream; each detector sees only
   what its real switch would; faithful SprayCheck-Z (§3.6 intersection) and FlowPulse-θ (§5.3
   per-sender) replays validated against the papers; 50 seeds, Wilson CIs, FP=0 discipline.
   → `sim/baselines/`, `BASELINE-COMPARISON-2026-09-02.md`, `LOCALIZATION-COMPARISON-2026-09-02.md`.

5. **Detection.** The scaling separation (headline figure) + the flat-vs-collapse table; framed as
   cost, not capability. → **Fig 1** `figures/scaling_curve.pdf`; detection table.

6. **Localization.** Exact directed link (set size 1) vs the {uplink,downlink} 2-set / miss;
   honest null where SprayCheck ties at 1.0–1.5%; framed as the witness disaliasing directed
   links. → `LOCALIZATION-COMPARISON-2026-09-02.md`.

7. **On silicon.** MCP's own side measured, not modelled: exact recovery 1e-2→1e-4 (FP=0),
   stochastic Bernoulli recovery, exact single-directed-link localization uplink AND downlink.
   → `SILICON-DETECTION-LOCALIZATION-FIDELITY-2026-09-03.md`.

8. **Robustness (honest boundary).** Multiple INDEPENDENT faults: MCP holds and widens, baselines
   worsen. Common-mode shock: MCP's absolute-floor test fails and a relative passive test
   (SprayCheck) is better — reported openly; bounds the claim to the independent/stationary
   regime. → `CORRELATED-FAULT-STRESS-2026-09-03.md`.

9. **Cost.** 2 B/packet (~0.14% at 1400 B), 12/5 MAU stages, SRAM/TCAM — compile-gate measured;
   the honest trade vs the 0-byte passive baselines (continuous full-fabric coverage for the wire
   cost). → `LEDGER-WIRE-REDUCTION-2026-09-02.md`.

10. **Related work.** The two comparison tables + four-family positioning; primitive conceded to
    NetSeer/LinkGuardian/LossRadar/UEC; measured-characterization slot claimed.
    → `RELATED-WORK-COMPARISON-2026-09-03.md`.

11. **Discussion / limitations.** Common-mode (Q4, future); restoration on a spray-starved link
    (the healing survivor, gated NULL, cited not claimed); localization advantage is
    information-structure not algorithmic; overhead is a real trade.

12. **Conclusion.**

## Figures / tables
- **Fig 1** packets-to-detect scaling curve (`figures/scaling_curve.pdf`) — headline.
- **Fig 2** system/topology schematic (to build via `diagram-design` → `ieee-paper-figures`).
- **Tab 1** detection (action rate + packets, per loss rate, 3 arms, CIs).
- **Tab 2** localization (exact / set-size / wrong, 3 arms).
- **Tab 3** silicon fidelity (recovery + FP across rates).
- **Tab 4/5** prior-work comparison (from `RELATED-WORK-COMPARISON-2026-09-03.md`).

## What is NOT in the paper (and why)
- No novelty claim on the witness primitive (prior art; desk-reject risk).
- No healing/restoration result (gate FAIL / NULL).
- No identifiability-limit claim (refuted by SprayCheck).
- No application-impact/CCT claim (htsim make-or-break NULL, 1.36%).
- No common-mode robustness claim (A4 failure, scoped out).

## Reviewer attacks the draft must pre-empt (from the framing memo)
A1 mechanism-is-prior-art (own it in the abstract); A2 localization-is-definitional (say so; lead
with cost-scaling); A3 run-SprayCheck-longer (Fig 1 is a scaling law within a fixed budget);
A4 single-fault-only (§8 scopes it, backed by evidence); A5 overhead-loses (§9 states the trade);
A6 the soak anomaly on unmeasured sublinks (a bounded, documented caveat).
