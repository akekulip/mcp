# Referee Report, Round 2

**Manuscript:** "What a Two-Byte Witness Buys on a Sprayed Fabric" (revised, 16 pp.)
**Artifact:** `github.com/akekulip/mcp` @ `8a14743`
**Prior rounds:** `review_two_byte_witness.md`; `artifact_audit_and_revised_verdict.md`
**Author response:** `paper/ton/RESPONSE-TO-REFEREE-2026-09-03.md`
**Venue assessed:** IEEE/ACM Transactions on Networking

---

## 0. Recommendation

**Accept subject to minor revision.**

Every blocking item from both prior rounds is closed, and closed with evidence rather than with argument. I verified each against the artifact rather than against the response document. The response is accurate in every particular I checked — including where it declines a request, and including where it walks back one of its own earlier findings in the direction that weakens its disclosure.

One substantive objection remains. It is new, and the revision created it: moving the thesis onto the read-skew argument invites a reply the paper never considers. It is addressable in a paragraph plus a stage-count estimate, and I do not consider it grounds for another full round.

The paper has also become materially better science than the version I first reviewed, in three specific ways. The corrected metric raised the headline separation from 5× to 47×. Proposition 1 turned a false claim ("flat in `p`") into a true and stronger one — a dimensionless law in `p/f` with the wall located and shown to track the floor across three decades. And the counter-pair arm converted the contribution from "an instrument with more information wins" into a measured statement about *why* two bytes are worth spending. That last change is the difference between a comparison study and a result.

---

## 1. Verification of the response

Checked against code and data, not against the response text.

| Item | Claimed | Verified |
|---|---|---|
| App-impact NULL reported | §XI ¶1 | ✔ 1.36% figure, the missing-actuator ceiling, ~99.5% pipelining absorption, three bounded reframings |
| CounterPair-0B arm | fair implementation | ✔ `comparison.py:counterpair_tx` — differenced offsets, zero-mean, clamped at RX, **the ledger's own `FleetDecisionLoop`**, same shared stream, σ=0 as idealized bound |
| Read skew measured | 2.6 ms / 350 ms | ✔ `READ-LOOP-BENCH-2026-09-03.md`, 5 reps, raw output printed (306.3 / 347.5 / 357.5 / 304.5 / 352.0 ms) |
| Metric fixed | post-onset origin | ✔ `packets_origin: "post_onset"`; ledger 2 M, SprayCheck 4/6/12/94 M; 47× at 10⁻³; `test_counterpair.py::PostOnsetOrigin` pins it |
| Proposition 1 | both bounds | ✔ `s²/p²` vs `s²f/p²`, plus a sparse-Poisson refinement `1/(p log(p/f))` I had not asked for |
| Ledger's wall located | 6 M / 36 M / none | ✔ Sweep extended to 5e-5, 2e-5, 1e-5; action rate 1.00 / 1.00 / **0.00** |
| Floor swept | wall tracks `f` | ✔ Three decades; action rate 0.00 at `p/f = 1` for every floor; cost collapses by `p/f ≈ 5–10` throughout |
| Incast R4 added | ledger fails | ✔ Ledger names 8 congested downlinks + culprit (set size 9, FP 1.00, exact-all 0.00); SprayCheck exact-all 1.00, FP 0.00 |
| e-process subsection | α = 0.05 | ✔ §III-B: floor, Eq. 3, ratio grid, previsibility, censoring convention, e-BH at α = 0.05, and why observed FP is 0.00 rather than α |
| Anomaly rewritten | full evidence | ✔ Matched-binary 0/100 vs 2/57, injector rule-out, **idle trigger walked back from 3/5 to 3/14** |
| spray=0 aliasing disclosed | §XI | ✔ Named as "a correctness cost of the reduction that Section IX did not price" |
| Figure regenerated | from `_common.py` | ✔ `fig_scaling.py`; the "MCP" legend is gone |
| Test suite | 65 passed | ✔ Re-ran independently: `65 passed in 31.47s` |

I also spot-checked the counter-pair numbers the response summarizes as "FP 0.28–1.00 at σ=1e-4." Exact:

| p | σ=0 | σ=10⁻⁴ | σ=10⁻³ | σ=2.6×10⁻² (measured) |
|---|---|---|---|---|
| 1.5% – 0.5% | 1.00 / 0.00 | 1.00 / 0.28 | 1.00 / 1.00 | 1.00 / 1.00 |
| 10⁻³ | 1.00 / 0.00 | 1.00 / 0.94 | 1.00 / 1.00 | 1.00 / 1.00 |
| 10⁻⁴ – 2×10⁻⁵ | 1.00 / 0.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| 10⁻⁵ (= f) | 0.00 / 0.00 | 0.62 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |

(action rate / false-positive rate.) Note the σ=0 column reproduces the ledger exactly, *including its wall at `p = f`* — which is the cleanest possible demonstration that the two hold the same information. That row is worth calling out explicitly in §V; it is currently implicit.

Three items went beyond what was asked and deserve specific credit.

**The idle-trigger walk-back.** I cited 3/5 post-idle bursts from `WORKING_NOTES`. The revision reports that two further runs with a corrected instrument found 0 of 9, making the honest count 3 of 14, and replaces the mechanism hypothesis with "a genuinely cold fabric after a fresh program load." Revising a finding downward, in the direction that weakens your own disclosure, when no referee asked — that is what makes the rest of the paper's numbers credible.

**The 2 B vs 4 B reconsideration.** §XI now says the evidence "points that way rather than merely permitting it." The two-byte header is in the title. Conceding that the four-byte version may be the better engineering choice is not a small concession.

**The framing of what the stamp buys.** §XI: "Equation (1) contains no information a zero-byte counter pair lacks, and Section V shows the two are identical when the pair is read at one instant." That is exactly right, and stating it plainly is what makes the skew argument land instead of reading as special pleading.

---

## 2. Where I was wrong

**My 2× sequence-wrap correction is withdrawn.** I claimed the effective wrap period was 2¹⁵ rather than 2¹⁶, on the strength of `WORKING_NOTES.md:137` ("the witness sequence advances 2.0 values per packet … wraps every 32768 packets per sublink, not 65536").

The response declines the correction and is right to. That note is from the earlier C-W4 program, in which both loopback passes hit a single register. On the ledger program Table III shows `Δseq = N` exactly — 5,000 → 5,000 and 60,000 → 60,000 across nine cells. The evidence rebutting me was already printed in the submission I was reviewing; I misattributed a measurement from one program to another. That was a sourcing error on my part and I apologize for the wasted cycle.

The response also did the more useful thing, which was to measure the read loop instead of arguing about the width. §IX now states the bound that actually matters: with a 350 ms census the two-byte witness is unambiguous only below ~190 kpps per sublink, about 9% of a 25 Gb/s port at 1400 B, with the silicon cells at 20 kpps unaffected. Observing that both header widths wrap at 2¹⁶, so the four-byte version does not escape the bound either, is the right precision.

---

## 3. Remaining objection: a synchronized counter snapshot

This is the one item I would still require.

The thesis is now that the two bytes buy in-band epoch alignment, quantified by the counter pair's ~10 µs skew tolerance against a measured 2.6 ms pairwise read. I searched the full manuscript source for `PTP`, `synchron`, `snapshot`, `latch`, and `timestamp`. **No hits.** The paper never considers the obvious reply.

The reply is: do not *read* the two registers at one instant — *latch* them at one instant and read them lazily. Tofino has PTP and can timestamp in the data plane. If both switches snapshot their per-directed-link counters on a common PTP-derived epoch boundary into shadow registers, the controller may take its full 350 ms to collect them and the skew term is sub-microsecond — three to four orders below the tolerance your own harness establishes. The counter pair would then match the witness at zero wire bytes. RFC 6374, which you cite and whose Table VII row is where this thread began, is built around exactly this idea of synchronized loss measurement.

Your own numbers sharpen the objection rather than blunting it. By establishing that the tolerance is ~10 µs, and that PTP-class synchronization is a decade or more better than that, the revision hands a reviewer the construction.

There are good answers, and I believe they hold. The paper has to make them.

1. **The snapshot is not free in the data plane.** Atomically latching 2,048 registers needs shadow copies — double the state, plus bank-swap logic on an epoch signal, plus stages. You have direct evidence of what a small ingress addition costs on this platform: the reconstruction tables consumed the program's last stage. Price the snapshot the same way and the "zero-byte" alternative may not be zero-cost.
2. **You have already built and abandoned a banked double buffer.** The history shows `CLF banking: the double buffer was inert, and completing it explains items 2-4` and `CLF: carry the bank parity through transit, in a byte act_transit does not write`. Whatever that cost, and whatever broke, is directly relevant engineering evidence about epoch-aligned latching on this switch — and it is currently invisible to the reader.
3. **The witness needs no fabric-wide coordination.** No PTP distribution, no trusted common time base, no agreement between two switches about when an epoch began. That operational asymmetry is the strongest version of your argument.
4. **Scope it honestly.** If an operator has PTP and can afford a banked snapshot, the counter pair is the better choice and the witness is unnecessary. Saying so costs nothing and pre-empts the reviewer who will say it for you.

A paragraph in §XI plus a row in Table VII closes this. A stage-count estimate for the shadow-bank design closes it convincingly.

---

## 4. Secondary points

**4.1 The counter-pair arm is fair but not the strongest possible baseline.** Giving it the ledger's own absolute `FleetDecisionLoop` rule is the right choice for isolating the information difference, and it should stay the primary arm. But it is not the best counter-pair detector, and a reviewer may notice. A leaf's uplink TX registers all sit on the same switch, so their read offsets are *correlated*; a peer-normalized or differenced test across a leaf's uplinks would cancel much of the common skew, exactly as SprayCheck's relative normalization cancels a fleet-wide shift. A skew-aware counter pair is therefore strictly stronger than the arm you measured. Either add it, or state in one sentence that the arm is deliberately given the ledger's rule to isolate the information difference and that a skew-aware variant is the stronger baseline you did not build. The second option is cheap and honest.

**4.2 The boundary is now three regimes of four, and incast is not a corner case.** The ledger loses R2 (fleet-wide shift), R3 (culprit inside a shift), and now R4 (incast). §XI diagnoses this well — "the absence of any question about the cause of the loss" is exactly right, and pointing at egress queue depth as the fix is the right instinct. But the paper still frames the envelope as a *boundary* discovered in evaluation rather than as a *precondition* for deployment, and incast is the ordinary operating condition of a training fabric, not an unusual stress.

The honest framing: **the absolute-floor test requires a fabric where congestion loss is negligible on the measurement timescale** — a lossless RoCE/PFC fabric, or one provisioned so that queue drops are rare. Put that in §II-C beside the stationarity and independence assumptions, where a reader decides whether the instrument applies to them, rather than only in §VIII where they learn it failed a gate. Same information; the placement is what governs adoption.

**4.3 The read loop now limits both arms, for different reasons.** Worth one sentence, because it is a good observation currently split across §V and §IX: the same 350 ms census that makes the counter pair false-alarm also caps the witness at ~9% of a port. Neither works at line rate with this controller. What differs is the failure mode — the counter pair fabricates loss indistinguishable from real loss, whereas the witness's wrap ambiguity is a bounded modular-arithmetic condition the controller can detect and avoid by reading hot sublinks individually at 2.6 ms. Making that contrast explicit strengthens the skew argument at no cost.

**4.4 Guard against misreading the counter pair's action rate.** At σ ≥ 10⁻³ the arm shows action rate 1.00 with FP 1.00 — it "detects" because it names nearly every link. At σ=10⁻⁴ and `p = f` it shows 0.62/1.00, which is worse than the ledger's honest 0.00. The abstract handles this correctly ("it false-alarms on every trial"), but a reader scanning a table of 1.00s could take them for success. Add a footnote to the counter-pair table: for this arm the action rate must be read beside the false-positive rate, and a 1.00/1.00 cell is a failure, not a detection.

---

## 5. Minor items

- **§VII still says "we believe neither is a recovery error"** about the one-packet gap. Declining to re-measure is a reasonable resource call (it needs the injector armed through bfrt with the gate agent stopped). But in a section whose objective is silicon *fidelity*, replace the belief with the two mechanisms stated as testable claims plus a sentence saying the discriminating run was unavailable. You do exactly this in the anomaly paragraph; match its register.
- **Abstract vs §XI on localization.** The abstract says the witness "names the exact directed link"; §XI correctly calls the 1.00 score definitional and presents the ledger as the oracle row. Add four words to the abstract — "by construction, given per-link counts" — so a reviewer meets the concession before deriving it.
- **`fig_counterpair` and `fig_floor` are new and load-bearing.** Confirm both render legibly at their float widths, and label the σ axis in both fractional and millisecond units, since 2.6 ms is the number readers will carry away.
- **Code naming.** The `mcp` → ledger note in the README is adequate for review and deferring the rename is correct. Before artifact release, consider renaming `legacy/` to something like `legacy-measurement-control-plane/` so a reader does not have to work out that it holds a different paper.
- **Author metadata** — affiliation, manuscript date, acknowledgment, biography — remains unfilled. Blocking for submission.

---

## 6. Assessment for ToN

My first report said ToN was defensible only if the scaling claim and the counter-pair baseline were fixed, and that IMC was otherwise the better home. Both are fixed, and the paper now has what a ToN audience wants and previously lacked:

- **A general result.** Proposition 1 with the sparse-Poisson refinement, plus a floor sweep showing the cost collapses onto `p/f` across three decades. That is a dimensionless law, not a table of measurements on one fabric.
- **A measured cost.** Two bytes, one ingress stage, 0.02–2.4% by packet size, 6 B of state per sublink, and a read cadence with a stated rate ceiling.
- **A bounded, pre-registered scope.** Four objectives, four regimes, three of them lost and reported, with `PREREG.md` v1.9 cited so the boundary is verifiable rather than asserted.
- **An honest account of what the mechanism does not buy** — no inference advance, no information the counter pair lacks, and an application impact its own simulator bounds at 1.4%.

Against my round-1 reviewer predictions. **Reviewer B** (statistics) is converted and would likely advocate: the proposition, the located wall, the stated α, and the corrected metric are precisely what was missing. **Reviewer C** (operator) is converted on the counter-pair question and will now ask the PTP question instead; §3 above is what they need. **Reviewer A** (data plane) will accept the scoped silicon claims but will want the snapshot priced, since that is a data-plane question. All three are reachable with §3 plus §4.

One process note, since it was my last closing remark. The gap I flagged — a manuscript written from design documents rather than from gate verdicts — appears closed. Every gate outcome I can find in `docs/review/` is now either in the paper or explicitly scoped out with a reason, including the unfavourable one that had been omitted. The response document's "Not done, and why" section is the right artifact for that discipline, and it should ship with the submission as the cover letter.
