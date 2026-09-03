# journal-adapt Phase 2 — revision summary for paper/ton (2026-09-03)

The manuscript did not exist before Phase 1, so Phase 2 was applied at drafting time rather than as a
rewrite: every section was drafted against `dynamic_writing_skill.md`, checked with the paper-voice
checker, passed through the academic-humanizer audit, and re-checked for non-regression. This file is
the section log the skill asks for, condensed.

## Order of operations (per section, all twelve)
draft (systems-paper-writing blueprint + dynamic skill) → paper-voice Voice Card → `voice_check.py` →
academic-humanizer audit and edits → `voice_check.py` non-regression → build (tectonic, IEEEtran journal).

## Whole-paper checker result (after humanizer; before → after)
| metric | before | after | corpus band | status |
|---|---|---|---|---|
| words/sentence mean | 22.6 | 22.7 | 19.6–25.7 | ok |
| short / medium / long / very long % | 19.3 / 51.5 / 23.3 / 5.9 | 19.0 / 51.7 / 23.3 / 5.9 | in band | ok |
| "we" per 100 sentences | 18.8 | 19.6 | 15–41 | ok |
| boosters /1000 | 0.0 | 0.0 | ≤2.7 | ok |
| hedges /1000 | 5.92 | 6.37 | 7.7–20.9 | LOW, improved, justified below |
| citations /1000 | 14.68 | 14.63 | 5.1–8.3 | HIGH, justified below |
| Flesch / FK grade | 50.6 / 11.8 | 50.6 / 11.9 | 16–29 / 14–17 | HIGH/LOW, justified below |
| rhythm jaggedness | 14.73 | 14.64 | 8.5–13.0 | HIGH, justified below |
No hard check regressed; hedges improved. Section-level checks were run on 00–02, 03–06, 07–09 during
drafting and the rhythm bands were brought into range before moving on.

## Justified deviations (per the voice-gate rule: fix or justify each)
- **Citations high.** The Related Work comparison table carries 15 `\cite` calls in one float and the
  introduction concedes the primitive to four systems by name; the ToN corpus itself runs 16–49 references
  per paper (`format_metrics.md`). Removing citations would weaken the positioning the ToN profile
  requires (comparison table as the novelty device).
- **Readability above the security corpus.** The ToN measurement papers (ton_004, ton_005) are plain-
  register; the dynamic skill gives the ToN corpus priority on sentence length (15–28 words) and the
  paper-voice skill itself warns against densifying prose to move a readability dial. Left as is.
- **Rhythm jaggedness.** The concatenated check counts run-in bold headers ("Witness stamp.") and table
  cells as sentences; both are ToN- and paper-voice-native. Prose-only paragraphs were split until the
  four sentence-length bands were in range.
- **Hedges slightly low.** Findings with a number are unhedged by rule; hedges were added to every
  interpretive sentence found in the humanizer audit ("can", "may", "we expect", "we believe").

## Academic-humanizer audit (patterns found and fixed)
- "To the best of our knowledge" appeared three times; reduced to the single mandatory first-ness claim
  in the introduction (Related Work and Robustness rephrased as "we have found no prior system…" / "…that
  we have not found reported elsewhere").
- "robust" as praise (4 uses) → "held", "did not fail", "does not hold", "resistant"; kept only as an
  evaluation-target noun.
- Over-long clause-stacked sentences (14 flagged >45 words across VII–IX) split.
- "therefore" overused (3) → "Consequently," / restructured.
- Claim–evidence: every result paragraph carries a figure/table pointer and a "The reason is that"
  mechanism sentence; baseline wins (SprayCheck ties at 1.0–1.5 %; SprayCheck better under common-mode)
  stated before the ledger's wins in the same paragraph.
- No em dashes, no "novel", no boosters, no "Moreover/Furthermore" anywhere (checker: 0.0 boosters/1000).

## Priority-1 preservation audit
Every number was transcribed from the committed artifacts and is listed with provenance in `NUMBERS.md`;
three cross-document inconsistencies are flagged there (ledger median "22–24 M" prose vs 22.0 M table; the
4-byte overhead table superseded by the 2-byte compile gate; "40,000+" vs 42,050 clean packets), and the
draft uses the table/compile-gate/exact values. All 24 `\cite` keys resolve in `references.bib` (bibliography
compiles with zero undefined citations).

## ToN format conformance (`TON_GUIDELINES.md`)
IEEEtran journal class, two-column 10 pt; abstract 250 words (limit 250), one paragraph, no abbreviations;
five Index Terms; Roman-numeral sections with a roadmap paragraph; Related Work second-to-last; dedicated
Discussion and Limitations; tables captioned above, figures below; acknowledgment and biography blocks
present as author placeholders; 12 pages including references (target 13–14, ceiling 16, 10 free).

## Rule candidates for the dynamic skill (single evidence unless marked pattern)
| section | rule candidate | target | evidence |
|---|---|---|---|
| abstract | ToN's 250-word cap binds hard once numbers are spelled out (no abbreviations); budget 230 before the headline sentence | journal-only | single |
| intro | contribution bullets that end with a number keep the checker's citation density tolerable while carrying the results preview ToN expects | journal-only | pattern (ton_001, 003, 004) |
| eval | a `table*` comparison table with `p{}` raggedright columns is the only way to fit an 8-axis positioning table in IEEEtran | general | single |
| eval | reporting FP next to action rate in every table caption pre-empts the "safe but useless" attack | general | pattern (CLAUDE.md cross-check 4) |
| robustness | a dedicated boundary section that reports where a baseline wins reads as ToN-native (ton_003 candour paragraph, nsdi_002 named false negatives) | journal-only | pattern |

## Figures (added 2026-09-03, second pass; ieee-paper-figures + ToN caption rules)
One data figure per objective, each generated from the committed sweep JSONs or the silicon cells by a
script in `figures/` (utils_mpl IEEE sizing, Times, Okabe-Ito palette shared with the scaling curve,
one marker/hatch per arm for grayscale printing):
- Fig. 1 `scaling_curve.pdf` (O1 headline), Fig. 3 `fig_action_rate.pdf` (O1 action rate with Wilson
  intervals, single column), Fig. 4 `fig_localization.pdf` (O2, three panels, double column), Fig. 5
  `fig_silicon.pdf` (O3, recovery on log axes + per-sublink attribution, double column), Fig. 6
  `fig_correlated.pdf` (O4, three regimes, double column; the ledger's failure is drawn, not hidden).
- Captions follow the ToN profile: one sentence for single-result figures, panel-defining multi-sentence
  captions for multi-panel figures, every encoding named in the caption. Each figure is pointed to from
  the prose before its result is discussed. Tables are kept beside the figures, as the corpus does.

## Known gaps left for the author
- Three datacenter-flavoured ToN style cards (ton_006–008) were lost to API failures; the profile rests
  on five verified ToN papers plus two NSDI papers.
- Acknowledgment and biography blocks are placeholders.
- Figure 2 was produced with matplotlib (the diagram-design agent could not be kept alive); it is
  IEEE-column-sized and Times-set but may deserve an Inkscape pass before submission.
