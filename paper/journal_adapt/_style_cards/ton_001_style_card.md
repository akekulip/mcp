## Paper Style Card: ton_001

HARD RULE: I will describe only structure and rhetorical patterns. I will not quote, paraphrase, or reproduce any content from this paper.

METADATA
- Paper ID: ton_001
- Authors: Mostafaei, H.; Pacut, M.; Schmid, S.
- Year: 2025 (IEEE/ACM Transactions on Networking; arXiv v3 dated late 2024)
- Corpus role: primary_target_journal
- Conversion status: converted_checked
- Method type: system+evaluation (algorithm design + short analytical section + P4 hardware prototype + packet-level simulation)

A. ABSTRACT STYLE
- Opening move: one-sentence statement that the task is a fundamental networking function that has recently regained attention in a specific hardware context.
- Structure (sequence of moves): (1) field importance and renewed relevance; (2) the canonical abstraction and its resource cost; (3) prior approximations of that abstraction and the limitation they still share; (4) "to address this, we design X" with an unusually concrete resource-footprint description (count of state elements and queues); (5) the design principle the mechanism is borrowed from; (6) simulation result with a headline speedup multiplier and the workload class where it is largest; (7) prototype claim stated as lines of code, scalability, and line-rate operation.
- Tense pattern: present throughout (problem in present, design in present, results in present "demonstrate").
- Contribution placement: sentence 4 of roughly 8; results occupy the last two sentences.
- Length (approx words): ~170.
- Register: technical, assertive, quantitative; one hedge word ("generally") on the performance claim.

B. INTRODUCTION ARCHITECTURE
- Hook type: textbook-style general statement of the function's importance, backed by a list of performance metrics and a citation cluster.
- Opening move: two paragraphs of background (what the function is; the programmable variant and its two-part decomposition) before any mention of the paper's own contribution.
- Contribution placement: the proposal sentence ("We present X") arrives in paragraph 6 of 8; a dedicated lettered subsection "A. Contributions" follows the prose paragraphs.
- Contribution format: bulleted list (5 bullets) inside a lettered subsection; the final bullet is an artifact-availability/reproducibility pledge.
- Literature positioning: both — paragraphs 3–5 walk through the canonical abstraction and two named approximations, then a positioning sentence ("this paper complements this line of research by ...") plus a short argument, with citations, about why the saved resource matters; a standalone Related Work section also exists at §VII.
- Roadmap: explicit, in a second lettered subsection "B. Organization", one paragraph, using § symbols for every section.
- Intro length (paragraphs): 8 prose paragraphs + subsection A (bullets) + subsection B (roadmap).

C. CONTRIBUTION EXPRESSION
- Voice: "we present / we find / our simulations report" — consistently first-person plural; the system name is also used as grammatical subject.
- Claim strength: moderate-to-strong. Speedup multipliers appear in the intro prose and in the bullets; softened by qualifiers such as "generally", "competitive", "robust", "up to".
- Number of contributions: 5 bullets (design; simulation results; robustness across distributions; proof-of-concept implementation with resource comparison; open artifacts).

D. LITERATURE REVIEW
- Structure: standalone section (§VII Related Work), placed after Evaluation and before Conclusion; plus a short §II Background that explains the abstraction and the canonical scheduler (with a footnote contrasting programmable vs. non-programmable notions).
- Organization: thematic — general programmable scheduling and its expressiveness (with a cited impossibility-style observation) → the canonical scheduler and its approximations (each described mechanistically in 2–4 sentences) → hardware-design proposals (grouped citation ranges) → extensions of the rank-based model.
- Critical engagement: moderate. Each approximation's mechanism is explained; the closest baseline's memory-reduction possibility is acknowledged along with the absence of a reference implementation; no extended attack on prior work.

E. METHOD / SYSTEM
- Entry point: goal statement first (one paragraph on what "resource efficiency" buys the operator), then an overview architecture figure (Fig. 1) placed at the top of the design section, then rationale, then algorithm.
- Notation density: low-moderate. Three numbered equations in design/implementation, a handful of unnumbered expressions in the analytical section; one pseudocode listing (Algorithm 1) with an initialization/ingress/egress structure.
- Exposition style: rationale subsection with run-in bold paragraph leads, then a numbered list of three core concepts (the third with lettered sub-conditions a/b), then a worked numerical example tied to a small figure. A separate analytical section (§IV) follows the design and precedes implementation: it names two design choices, states that they cost accuracy, then analyzes error with a first-order expansion, a distribution-discrepancy statistic, a concentration inequality, and a brief extreme-value-theory remark before falling back to an empirical plot.
- Assumption/design-choice justification: explicit and repeated — simplicity and resource footprint are the stated reasons; the normalization method is justified by citation to a decision-making literature; hardware constraints (no division, no floating point, queue length unavailable at ingress) are presented as "challenges" with a paragraph each explaining the workaround (recirculation, power-of-two lookup tables, ternary match), including a memory-cost accounting paragraph and a note that newer hardware removes one workaround.

F. RESULTS / EVALUATION
- Primary vehicle: two vehicles, stated in the section's opening paragraph — hardware prototype for resource consumption and a bandwidth-split demo; packet-level simulator for performance under workloads.
- Narrative style: figure-by-figure walk ("Fig. N(a) shows ... Fig. N(b) shows ..."), each observation followed by a one- or two-sentence mechanistic explanation ("the main reason is ..."). Multi-panel figures with (a)/(b)/(c) sub-captions.
- Setup-description depth: high. Hardware: switch model and capacity, NIC model and link speed, CPU models for sender and receiver, DPDK version, OS and kernel version, SDE version. Simulation: topology shape and counts, link bandwidths, simulator name, baselines named, workloads named, default parameter values stated, flow-size class thresholds stated.
- Mechanism emphasis: high — nearly every result paragraph ends with a causal explanation in terms of the admission mechanism or workload composition.
- Robustness/limitation signaling: present but inline — cases where the system is slightly worse are stated; a parameter sweep result that contradicts a prior paper's evaluation of a baseline is noted; sensitivity studies for each tunable parameter.
- Use of numbered evaluation questions or run-in bold paragraph leads: no numbered research questions. Uses run-in bold leads in the hardware subsection and numbered subsubsections 1)–7) in the simulation subsection (objective study, then three parameter-sensitivity studies, throughput, a second objective, an alternative traffic distribution).

G. DISCUSSION / LIMITATIONS
- Function: no separate discussion. The conclusion (§VIII, titled with "Future Directions") summarizes in one paragraph and then frames the work as a first step, listing two future directions.
- Scope of claims: bounded by qualifiers in the evaluation and by the analytical section's admission of accuracy loss.
- Limitation acknowledgment: minimal-to-moderate and distributed (analytical section admits approximation error; implementation section admits recirculation overhead and hardware constraints; evaluation notes worse tail cases).
- Separate Discussion or Limitations section: absent.

H. LANGUAGE STYLE
- Voice: active, first-person plural dominant ("we design / we implement / we observe / we note"); system name as subject is also frequent. "We note that" is a recurring signpost phrase (appears many times across design, implementation, and evaluation).
- Sentence length: medium (roughly 15–25 words); occasional long sentences with parenthetical clarifications.
- Hedging level: moderate — "generally", "up to", "may", "can", "likely"; claims about speedups are always attached to a condition (workload, load range).
- Transition style: explicit procedural transitions ("Let us now explain ...", "Next, we delve into ...", "We now repeat ...", "In this section, we ...").
- Mathematical density: low in design, moderate in the analytical section, low in evaluation.
- Use of first-person plural in evaluation: yes, consistently ("we conduct", "we observe", "we compare", "we set").
- Paragraph length: medium (4–8 sentences); some short 2–3 sentence paragraphs under bold leads.

I. IEEE/ToN FORMAT MARKERS
- Index Terms present: yes (4 terms).
- Section numbering style: Roman numerals (I–VIII), lettered subsections (A., B.), numbered subsubsections (1), 2), ...). Introduction itself carries lettered subsections for Contributions and Organization.
- Appendix usage: none.
- Where related work sits: §VII, after Evaluation, before Conclusion; a short §II Background sits after Introduction.
- Typical figure captions: mostly one-line; two mechanism figures (Fig. 2 timeline, Fig. 4 parameter effect) carry multi-sentence explanatory captions that restate the mechanism.
- Equations numbered: yes, (1)–(3); analytical expressions in §IV are left unnumbered.
- Subsections/subsubsections depth: three levels (Roman → letter → number), plus run-in bold paragraph leads as a fourth informal level.
- Other markers: one pseudocode listing; tables with small-caps captions; a footnote in Background; Acknowledgment with funding IDs and an in-memoriam line; author biographies with photos at the end.

J. WHAT THIS PAPER DOES NOT DO
- No numbered or bulleted evaluation questions at the top of the evaluation section.
- No separate Discussion or Limitations section; no formal threat model or assumptions section.
- No theorem/proof; the analytical section is informal error analysis plus an empirical plot.
- No appendix and no supplementary material pointer beyond the open-source bullet.
- No confidence intervals, repeated-trial variance, or statistical tests in results.

K. DISTINCTIVE PATTERNS
- Contributions and Organization are lettered subsections inside the Introduction, giving the intro a visible two-part tail (bullets then roadmap with § symbols).
- Run-in bold paragraph leads carry the structure of the design rationale, the implementation section (one lead per hardware challenge), and the hardware-evaluation subsection.
- A standalone analytical section is inserted between design and implementation, explicitly naming the two approximations the design makes and bounding their error before showing the hardware realization.
- Two-vehicle evaluation split (hardware for resource metrics and a demo; simulator for performance), with the hardware setup described down to software versions, and parameter-sensitivity studies given their own numbered subsubsections.
