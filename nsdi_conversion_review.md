# NSDI Conversion Review: Writing, Figures, and Tone

**Source audited:** `github.com/akekulip/mcp` @ `8a14743`, `paper/ton/` (IEEEtran journal, 16 pp., 14,435 words of body prose, 7 figures, 4 tables)
**Target assessed:** USENIX NSDI

---

## 0. The framing question comes first

Before any style work: **your own gate closed the NSDI path, and re-targeting reverses that decision.**

`docs/review/artifacts/APP-IMPACT-HTSIM-MAKEBREAK-2026-09-03.md` ends with:

> **Recommendation: ship the mechanism / localization contribution to ToN or IMC; do not build the full arm-differentiated application-impact campaign.**

And `docs/review/CONTRIBUTION-FRAMING-2026-09-02.md` plus the six novelty gates reached the same place. That judgment was correct for the paper as written, and no amount of copy-editing changes it. An NSDI PC wants a system, a mechanism, or a result that changes what people build. A paper whose introduction says "We claim no novelty for the witness itself" and whose §XI says the localization score "is close to definitional" will be read as a careful evaluation rather than a contribution. At ToN that is acceptable and even welcome. At NSDI it is the rejection.

**But there is an NSDI-shaped paper in this material, and it is a better paper.** Invert the framing. Right now the headline is "the witness wins." The revision's own evidence supports a stronger and more surprising headline: **in-fabric per-link witnesses are worth their wire bytes in a much narrower regime than the field assumes.**

Everything needed is already measured:

- A zero-byte counter pair is **informationally identical** and separated only by a 10 µs read-skew budget — so the entire case for stamping packets rests on controller read latency, not on information.
- The witness has a wall of its own at `p ≈ f`, and the cost law is a dimensionless function of `p/f` (Proposition 1, floor sweep across three decades).
- The witness **loses three of four boundary regimes** — fleet-wide shift, culprit inside a shift, and incast — and incast is the ordinary operating condition of a training fabric, not a corner case.
- The application impact of the regime it uniquely serves is **1.36% CCT**, with ~99.5% of drops absorbed by collective pipelining.
- The two-byte reduction that gives the paper its title introduced a reproducible hardware anomaly (0/100 vs 2/57) and a `spray=0` aliasing hole, and §XI now says the evidence favours the four-byte version.

That is a design-space result with a negative headline, quantified on silicon, against replayed state of the art. NSDI does publish those. It is also *true*, which the current framing only partly is.

Concretely, the retitle is close to free: drop the subtitle and keep **"What a Two-Byte Witness Buys on a Sprayed Fabric"** — that is already an NSDI title. Then let the abstract answer the title's question honestly: 47× on detection cost when faults are independent and the fabric is quiet, nothing over a synchronized counter pair, and a loss under congestion.

If you do not want to reframe, submit to ToN. The style notes below apply either way, but items in §1 are only required for NSDI.

---

## 1. Mechanical conversion — hard requirements

### 1.1 Template
`main.tex` is `\documentclass[journal]{IEEEtran}`. NSDI requires the current USENIX template (you have only the stale `legacy/Research/usenix-2020-09.sty`; fetch the current one from the CFP). Removals:

| Line | Remove |
|---|---|
| `main.tex:22–25` | `\author{}`, both `\thanks{}` |
| `main.tex:27–28` | `\markboth{IEEE/ACM Transactions on Networking}...` |
| `main.tex:37–39` | `\begin{IEEEkeywords}` block — USENIX has no Index Terms |
| `main.tex:56–58` | `\IEEEbiographynophoto` block |
| `main.tex:53` | `\bibliographystyle{IEEEtran}` → the template's style |

`\newtheorem{proposition}` and `booktabs` carry over fine.

### 1.2 Double-blind
NSDI is double-blind. Exactly one leak: **`main.tex:24`** (`P.~Akekulip is with [institution]. E-mail: akekulip@gmail.com.`). Delete it.

Credit where due: `04_method.tex:14` already routes the artifact reference through the acknowledgment ("in the public repository named in the acknowledgment") rather than printing the URL, so the pre-registration and artifact statement survives blinding intact. That was the right call and it is unusual to get right. Blind the acknowledgment itself and you are compliant.

### 1.3 Page limit — the real work
NSDI allows 12 pages of body excluding references and appendices. You have 16 pages of IEEEtran including references and biography, from 14,435 words plus 11 floats. USENIX two-column at 10pt runs roughly 900–1,000 words per page, so 12 pages with 11 floats supports about **9,500–10,000 words**. You need to cut **30–35%**.

Where the words are, and where I would cut:

| Section | Words | Cut |
|---|---|---|
| `01_introduction` | 1,485 | **−350.** The five-bullet contribution list restates results that arrive three pages later. Compress to three bullets or a paragraph. Delete the roadmap (§2.2). |
| `04_method` | 1,621 | **−450.** Longest section in the paper and it is setup. The two fidelity-check disclosures and the model-validation list belong in an appendix (NSDI permits appendices past the limit). Keep the shared-stream fairness argument and the four-arm interfaces in body. |
| `05_detection` | 1,590 | **−250.** Table + Figure + prose currently restate the same numbers three times. Let the table carry the numbers; the prose should carry only the reading. |
| `10_related` | 1,205 | **−500.** See §1.4 — the table is the problem. |
| `11_discussion` | 1,463 | **−200.** Strongest section in the paper; cut least. Trim the anomaly paragraph's procedural detail to the four findings and their verdicts. |
| `08_robustness` | 1,239 | **−150.** Four subsections of one paragraph each; merge R2/R3 into one, since they share a mechanism. |
| `02`, `03`, `07`, `09` | | Mostly leave. `03_ledger` earns its length now that §III-B exists. |

That is roughly −1,900 words from cuts plus another ~1,000 from moving methodology detail to an appendix, which lands you near 10,000 words. Achievable without losing a single result.

### 1.4 Table VII must go or shrink
`10_related.tex` contains a `table*` with seven `p{}` columns totalling ~14.4 cm of specified width and 15 system rows — roughly a full page of a 12-page budget. It is a good table for a journal and unaffordable here.

Options, best first: cut to the six systems that actually bound your claim (NetSeer, LinkGuardian, RFC 6374, SprayCheck, FlowPulse, OmniPath Ping) and four columns (Primitive / Per-DL / Under spraying / Low-loss cost); or move the full table to an appendix and keep a three-sentence prose version in body. The full table is genuinely useful — put it in the appendix, not the bin.

---

## 2. Writing register

The prose is good. Better than most NSDI submissions — no "utilize," no "leverage," no "In order to," no "it should be noted," no "Furthermore/Moreover," and the habit of naming a mechanism and then giving its measured number is exactly right. What follows is register, not repair.

### 2.1 Sentences run long
Mean sentence length is **26.9 words** across 492 sentences. NSDI prose sits in the low 20s. The cause is a ToN habit: subordinate clause, comma, consequence, comma, qualifier. Three real examples and how they read shortened:

> **Now** (`02_background.tex`): "A witness that observes each directed link's own transmit count compares the link's loss count against the background loss floor $f$ instead. Both comparisons are Poisson separations, and both scale the same way in $p$; what differs is the constant."
>
> **Tighter:** "A witness compares each link's loss count against the background floor $f$. Both tests are Poisson separations. Both scale as $1/p^2$. Only the constant differs."

> **Now** (`06_localization.tex`, 62 words): "Figure~\ref{} presents the exact-localization rate and the size of the named set for a downlink fault and for an uplink fault, over 50 seeds per cell on the two-hop fabric of Section~\ref{}..."
>
> **Tighter:** "Figure~\ref{} gives the exact-localization rate and named-set size, for downlink and uplink faults, over 50 seeds per cell."

The pattern to hunt: every semicolon that joins two independent clauses, and every "and we" that starts a third clause. Splitting those alone will drop the mean by 4–5 words and save 300–400 words, which is a third of your cut target.

### 2.2 "Consequently" appears 9 times
It is doing real work each time, but at that density it becomes a tic and it signals journal register. Keep three; for the rest, either delete the connective (the causal link is usually already obvious from the sentence order) or restructure so the consequence is the subject. NSDI prose tends to let adjacency carry causation.

### 2.3 Delete all three roadmap paragraphs
- `01_introduction.tex:25` — "The rest of the paper is organized as follows..." (95 words)
- `02_background.tex:4` — "In this section, we first describe..." (40 words)
- `04_method.tex:4` — "...In this section, we describe the harness, the three arms, the metrics, and the testbed." (final clause)

NSDI reviewers read these as padding; a numbered outline and good section titles do the same job. Free 150 words.

### 2.4 Move the (O1)–(O4) labels out of section titles
Section titles currently read "Detection Cost (O1)", "Localization (O2)", "The Ledger on Silicon (O3)", "The Boundary: Correlated Faults (O4)". The label-and-cross-reference apparatus is a technical-report convention and reads as bureaucratic at NSDI. Keep the four questions — they genuinely organize the evaluation — but state them once at the top of the evaluation and drop the parentheticals from the titles. "Detection Cost", "Localization", "On Silicon", "The Boundary" are better titles anyway.

### 2.5 One hedge to convert
`02_background.tex:36`: "We argue that this is a reasonable assumption for the physical-layer causes that dominate gray failures in production." You have a citation for this (CorrOpt). "Physical-layer causes dominate gray failures in production [5], and each is local to one link and persists until repaired" is stronger and shorter. Argue less, cite more.

### 2.6 Abstract
249 words is within range, but the result arrives in sentence 5. NSDI abstracts front-load. Move "detects on one epoch of two million packets ... where the passive cost has grown to ninety-four million" to sentence 2, and push the spraying setup into a single clause. If you take the §0 reframing, the last sentence ("The advantage fails under a fleet-wide shift and under incast") becomes the *first* claim rather than the closing caveat.

### 2.7 Three factual staleness bugs from adding the fourth arm
These are wrong now, not just stylistically off:

| Location | Says | Should say |
|---|---|---|
| `01_introduction.tex:25` | "the two passive baselines" | three comparators |
| `04_method.tex:4` | "the three arms" | the four arms |
| `04_method.tex:8` | "feeds the same draw to all three arms" | all four arms |

The `\subsection{The Four Arms}` heading is already correct, which makes the surrounding prose look worse. `00_abstract.tex` ("all three comparators") and `01_introduction.tex:12` ("All four arms") are both right.

---

## 3. Figures

### 3.1 What is already right
Worth stating because it is uncommon: `_common.py` uses the **Okabe-Ito** colourblind-safe palette, assigns **one marker per arm** and **one hatch per arm** so every figure survives grayscale printing, emits **vector PDF** for LaTeX alongside 400 dpi PNG, and centralizes labels so the arms are named identically everywhere. The hollow-marker/annotated-action-rate convention in `fig_scaling.py` is a genuinely good solution to plotting censored medians. Keep all of it.

### 3.2 Blocking: the figures do not build from the artifact
`_common.py:8–10`:

```python
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl
```

`utils_mpl` is **not in the repository** — I searched. Every figure script therefore fails on any machine but yours, and `utils_mpl.set_global()` sets the base font sizes, so the figures cannot be reproduced or rescaled by anyone else. NSDI runs artifact evaluation; this fails it, and it also blocks the width change in §3.3.

Fix: vendor `utils_mpl.py` into `paper/ton/figures/`, or inline the ~15 `rcParams` it sets. Ten minutes of work; without it the artifact claim in `04_method.tex:14` is overstated.

### 3.3 Widths are IEEE, not USENIX
Every multi-panel figure is `figsize=(7.16, …)`. 7.16 in is IEEEtran's `\textwidth`. USENIX `\textwidth` is **7.0 in**, and the column is ~3.33 in against IEEEtran's ~3.5 in.

Because the floats are included as `width=\textwidth` / `width=\columnwidth`, LaTeX will *rescale* rather than reflow — shrinking every font by 2% (full-width) or 5% (column). Combined with §3.4 that pushes your smallest text under 7 pt.

Regenerate at target width instead of rescaling: `figsize=(7.0, …)` for `figure*`, `figsize=(3.33, …)` for `figure`, and keep the LaTeX include at 1:1.

### 3.4 Font sizes are at or below the floor
`_common.py:setup()` sets legend 7.5, axis labels 8.5, ticks 8. `fig_scaling.py` then uses **6.5 pt** for the action-rate annotations, the budget label, and the floor label, and 7 pt for rotated x-ticks. After the §3.3 rescale the annotations land near 6.2 pt.

For a printed two-column page, treat **7 pt as the hard floor** and 8 pt as the target for anything a reader must read to follow the argument — and the action-rate annotations in `fig_scaling.py` are load-bearing, since §V explicitly asks the reader to read the action-rate collapse rather than the censored median. Raise legend to 8, labels to 9, ticks to 8, annotations to 7.5, and regenerate at 7.0/3.33 in.

### 3.5 The counter-pair arm has no visual identity
`_common.py:13–17` still defines `COLORS`, `MARKERS`, `HATCH`, `LABELS`, and `ARMS` for three arms only. `fig_counterpair.py:20` consequently draws the counter pair in `COLORS["mcp"]` (ledger blue), distinguishing skew levels by linestyle.

The counter pair is now a first-class comparator that carries the paper's thesis. It needs its own entry, and the docstring's own "one palette per paper, one marker per arm" rule says so. Okabe-Ito has two unused slots: `#CC79A7` (reddish purple) and `#56B4E9` (sky blue). Use `#CC79A7` — it stays distinct from ledger blue in grayscale. Add `MARKERS["counterpair"] = "D"`, `LABELS["counterpair"] = "CounterPair-0B"`, and extend `ARMS`.

Keeping the ledger's colour for the σ=0 case only, as the "same information" reference line, would actually be a nice touch — but then say so in the caption.

### 3.6 Stale shared constants
`_common.py:18` still has `RATES = (0.015, 0.01, 0.005, 0.0001)`-era five rates, while `fig_scaling.py:13` defines `RATES8` locally with the three new low-loss points. Any figure that imports `RATES` via `from _common import *` now silently uses the old set. Promote `RATES8` into `_common.py` as the single definition.

### 3.7 Float budget
Eleven floats — 4 `figure*`, 3 `figure`, 1 `table*`, 3 `table` — is a lot for 12 pages, and `fig_correlated.py` is a 2×2 grid at 7.16×4.3 in (nearly half a page). Candidates:

- **`fig_correlated`**: the four panels report four regimes, but panels (b) and (c) share a mechanism and (a) is a bar chart of four numbers already in Table IV. Cut to 1×2 (independent faults; correlated failures) and let the tables carry the rest.
- **`fig_action_rate`**: a second full figure showing action rate, when `fig_scaling` already annotates action rate on every hollow marker. Merge or cut — this is the most redundant float in the paper.
- **`scaling_curve.pdf`** is `\columnwidth` but is the headline figure with eight rotated x-ticks plus three text annotations. It is the one figure that deserves `figure*` and full width; trade `fig_action_rate` for it.

### 3.8 Minor
- `panel_label()` hard-codes `x=-0.18` in axes coordinates, so the (a)/(b)/(c) labels sit at different distances from the y-axis in 1×2 versus 1×3 versus 2×2 layouts. Use a figure-level annotation or scale by panel count.
- `fig_system.py` writes at `dpi=600` for PNG but the PDF path passes `dpi=None` with `bbox_inches=None` — fine for vector, but confirm the hand-laid coordinate system (`set_xlim(0,100)`, `ylim(0,67)`) still lands correctly at 7.0 in rather than 7.16.
- All scripts `savefig` into the current working directory, so they must be run from `paper/ton/figures/`. Add a `Makefile` or absolute output paths — artifact evaluators will run them from the repo root.

---

## 4. Priority order

**If NSDI:**
1. Decide the framing (§0). Nothing else matters until this is settled, and I would reframe around the boundary.
2. Template swap, de-anonymize `main.tex:24`, strip the five IEEE-only blocks (§1.1–1.2).
3. Cut 30–35% (§1.3), starting with Table VII to the appendix (§1.4) and the three roadmap paragraphs (§2.3).
4. Vendor `utils_mpl` (§3.2), then regenerate every figure at USENIX widths with raised fonts (§3.3–3.4).
5. Give the counter pair a colour and marker (§3.5); consolidate `RATES` (§3.6); cut two floats (§3.7).
6. Sentence-splitting pass targeting semicolons and "and we" (§2.1); thin "Consequently" (§2.2); drop the O-labels from titles (§2.4).
7. Fix the three stale arm counts (§2.7) — these are factual errors regardless of venue.

**If ToN after all:** items 7, 3.2, 3.4, 3.5, 3.6, and 2.7 still apply. The rest is venue-specific and the paper is already close.
