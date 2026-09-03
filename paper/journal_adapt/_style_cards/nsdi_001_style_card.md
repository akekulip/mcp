## Paper Style Card: nsdi_001

HARD RULE: I will describe only structure and rhetorical patterns. I will not quote, paraphrase, or reproduce any content from this paper.

METADATA
- Paper ID: nsdi_001 (dShark)
- Authors: Yu, D.; Zhu, Y.; Arzani, B.; Fonseca, R.; Zhang, T.; Deng, K.; Yuan, L.
- Year: 2019 (USENIX NSDI '19)
- Corpus role: secondary_field_optional (topic-similar top-venue systems paper)
- Conversion status: converted_checked (two-column PDF-to-text; figure bodies are garbled but all prose, tables, captions, and footnotes are legible)
- Method type: software systems framework (programming model + distributed runtime for analyzing multi-hop packet captures), evaluated on production traces via case studies plus component and end-to-end throughput benchmarks; industry-academic co-authorship with the authors positioned as the operator

A. ABSTRACT STYLE
- Opening move: a status-quo assertion about current operator practice (a diagnosis technique framed as a last resort), followed immediately by a concession that recent progress on data collection has not solved the analysis side.
- Structure: (1) practice-status opening; (2) one long semicolon-chained sentence enumerating four practical obstacles; (3) "in this paper we propose X to address these"; (4) two sentences of capability description; (5) evaluation-on-production statement of ease-of-use; (6) closing sentence with quantitative throughput and scale-out claim.
- Tense pattern: present tense throughout; evaluation sentences in present ("we show", "our evaluation shows").
- Contribution placement: mid-abstract, after the problem enumeration; the system name is introduced with "we propose".
- Length: approximately 190 words.
- Register: practitioner-facing, moderately informal (phrases like "last resort", "one-off and urgent"); no formal notation.

B. INTRODUCTION ARCHITECTURE
- Hook type: importance-of-reliability hook with an outage anecdote cited from news coverage, then the claim that failures remain common despite verification research.
- Opening move: reliability matters → diagnosis is therefore an operator duty → taxonomy of existing tool families (host-based vs in-network) each with a one-clause limitation → hardware improvements exist but will not be adopted soon → therefore in-network capture is the fallback.
- Contribution placement: the system is named roughly halfway through the introduction after the obstacle list; the enumerated contribution list is the final paragraph.
- Contribution format: a single paragraph with inline numbered items "1) ... 2) ... 3)"; not a bulleted list. The first item carries the "first" claim; the second is a capability claim; the third is a breadth claim (a count of implemented tasks) plus a scale demonstration claim.
- Literature positioning: done inside the introduction by tool-family taxonomy with grouped citations; the authors position themselves explicitly as a major cloud provider whose existing internal pipeline falls short, which turns the gap statement into first-hand testimony.
- Roadmap: none. No "the rest of this paper is organized as follows" paragraph; navigation is done by inline section cross-references (§n) embedded in the contribution and design sentences.
- Intro length: about ten paragraphs, one of which is a paragraph on the design inspiration (a programming-model observation) and one on why the custom runtime enables optimization.

C. CONTRIBUTION EXPRESSION
- Voice: first-person plural ("we design", "we show"); the system is also frequently the grammatical subject ("X allows", "X provides").
- Claim strength: assertive and quantified — throughput on a commodity server, near-linear scale-out, a count of expressible tasks, a lines-of-code smallness claim. Ease-of-use is asserted via the task table rather than a user study.
- Number of contributions: three, inline-numbered.
- How "first" claims are worded structurally: the "first" claim is stated flatly as contribution 1 in the introduction with a qualifier pair (general + scalable) and the artifact class (software framework for distributed packet captures); it is then restated at the opening sentence of Related Work with the hedge "to the best of our knowledge" and an enumeration of the three difficulties it is first to handle together. The hedge appears in Related Work, not in the introduction.

D. LITERATURE REVIEW
- Structure + position: two-layer. A short review of trace-based diagnosis sits at §2.1 as the first subsection of Motivation (explaining why traces are still needed despite flow records and switch-side digests). The main Related Work is §8, penultimate section, after Discussion and Limitations and before Conclusion.
- Organization: §8 opens with the "first" restatement, names the two closest systems and differentiates them on a deployment-requirement axis and a fate-sharing axis, then presents four categories each introduced by a bold run-in lead (switch-hardware telemetry designs; inference-based algorithms; packet-drop detection work; failure resilience and prevention). Each category carries a bracketed multi-citation list.
- Critical engagement: every category is dismissed on one axis — requires infrastructure change, loses information through probing, lacks visibility or localization granularity, or addresses only one problem type. The trace-collection system they depend on is labeled "complementary". The resemblance between their summaries and a prior postcard abstraction is acknowledged and then differentiated (fixed vs flexible).

E. METHOD / SYSTEM
- Entry point: §2 Motivation → §3 Design Goals → §4 Design. §2 has a background subsection and a motivating real incident (§2.2) narrated as a customer report, with a topology figure whose path segments are numbered and a table of captured header formats per segment. The incident narration ends with the two questions operators had to answer, then three "Problem N:" bold run-in paragraphs, then a one-paragraph statement of what a good tool should be.
- Notation density: very low. The only formal apparatus is a two-variable probability table (real-drop probability vs capture-noise probability) with four cases and a correctness column for with/without end-to-end information.
- Exposition style: example-first. §4.1 opens with a concrete task and shows the two program pieces as code listings (a declarative JSON spec and an imperative C++ callback) before §4.2 describes the architecture. §4.3 then generalizes each spec section with bold run-in leads ("Summary", "Name", "Filter", query functions). §4.4 walks four grouping patterns, each a bold run-in lead. §5 is implementation, one subsection per pipeline component plus "supporting components in practice".
- Design-choice justification: by explicit alternative contrast ("we choose X over Y for Z", e.g., compiled library vs script, custom runtime vs general big-data engine, flexible imperative language vs high-level declarative query) and by appeal to observed operator practice ("inspired by how operators manually process"). Window sizing is justified by a network-specific timing assumption with a footnote.
- How the fault/failure model is introduced: the "failure" of interest is capture-pipeline noise (loss of mirrored packets), not fabric failure per se. It is first named as a design goal (§3.2, with an explicit one-sentence definition of "noise" and a prevalence claim with citation), then formalized in §4.5 with a figure distinguishing two path types (production path vs mirror path), the four-case probability table, an independence argument (paths are disjoint after the switch), and two mitigation mechanisms each with a bold run-in lead. The residual false-positive probability is derived as a product and argued to be negligible. Generalization from TCP to other reliable protocols is stated in a closing paragraph.

F. RESULTS / EVALUATION
- Primary vehicle: §6 has three parts — case studies (§6.1, three of the implemented tasks), per-component microbenchmarks (§6.2), and end-to-end throughput plus scale-out (§6.3). Figures are bar charts of throughput versus a varied factor; one scaling figure includes an ideal-linear reference line.
- Narrative style: bold run-in leads name each case study and each component ("Loop detection.", "Profiling load balancers.", "Packet drop localizer.", "Parser.", "Grouper.", "Query processor."). Each paragraph states the experiment design, the result, and a mechanism-based explanation of why the result has that shape.
- Setup depth: production traces from the authors' own cloud (with a footnote disclaiming customer-traffic use and stating internal-service clusters only); a controlled correctness experiment by injecting synthetic looping packets into a verified-clean trace; commodity-server representation via cloud VMs with stated core count, memory, and link speed; repetition count stated with a max-spread statement instead of confidence intervals.
- Mechanism emphasis: high. Throughput differences are attributed to header depth, group size and hash-table behavior, query type (size-check vs per-packet inspection), and shuffle networking cost; the scale-out result is explained via proportional scaling of components and even hashing.
- Robustness/limitation signaling: the drop-localizer case compares against a naive last-hop heuristic, restricts comparison to a subset where the naive method is applicable, then replays the trace under artificially increased capture-drop probabilities to show result stability, and closes with an explicit residual-miss rate estimate. Over-provisioning of instances is acknowledged as the practical response to unpredictable overhead.
- Numbered questions or bold run-in leads: bold run-in leads throughout; no numbered evaluation questions.

G. DISCUSSION / LIMITATIONS
- Function: §7 "Discussion and Limitations" is a separate section between Evaluation and Related Work. It states a key modeling assumption and where it breaks, justifies the clean-slate implementation against existing frameworks, and positions the work relative to programmable hardware.
- Scope: three bold run-in paragraphs — a 1:1 packet-mapping assumption violated by some layer-7 middleboxes and by fragmentation; alternative implementation choices; hardware offload as future direction.
- Limitation acknowledgment: candid but deflecting — the assumption violation is followed by a "not unique to us; all packet-based tools share it" sentence and a future-direction sentence; the offload discussion argues current sufficiency ("already delivers enough for our operators") before conceding hardware-based analysis is promising once switches are widely programmable, with a footnote hedging on when that will happen.
- Separate section? Yes, standalone §7, before Related Work.

H. LANGUAGE STYLE
- Voice: first-person plural, strongly operator-identified ("our operators", "our network", "our data center"); the system name is used as an agent.
- Sentence length: medium; occasional long semicolon-chained enumerations in the abstract and motivation.
- Hedging: light. Assumptions are stated declaratively with a footnote or cited caveat rather than hedged prose; a few softeners ("we believe", "it is promising").
- Transitions: heavy use of inline section cross-references (§n) as connective tissue; "Therefore", "Fortunately", "Unfortunately", "In practice, however"; enumerations "1) 2) 3)" inside sentences; "Problem N:" and "First/Second" structuring.
- Math density: near zero; one small probability table; no equations.
- Paragraph length: medium; many paragraphs open with a bold run-in lead and run four to eight sentences. Footnotes are used for caveats (identifier uniqueness, timing assumptions, data provenance, hardware availability).

I. FORMAT MARKERS
- Section numbering: numbered 1–9 (Introduction, Motivation, Design Goals, Design, Components and Implementation, Evaluation, Discussion and Limitations, Related Work, Conclusion) with x.y subsections; no third level.
- Appendix usage: none.
- Related-work position: penultimate (§8), after Discussion.
- Caption style: descriptive sentences; several captions carry an interpretive claim (e.g., that all injected events were caught, or that scaling is near-linear); the large task table has a multi-sentence caption defining column semantics with footnote markers.
- Subsection depth: two levels; bold run-in leads serve as an informal third level. Code listings appear inline with line numbers. No Index Terms; no keywords.

J. WHAT THIS PAPER DOES NOT DO
- No theorem, proof, or formal identifiability argument; the only probabilistic reasoning is a four-case table.
- No head-to-head quantitative comparison against prior published systems — the only baseline is a naive heuristic the authors define themselves.
- No user study or operator-time measurement to substantiate the ease-of-use claim; ease is argued via a task table with a lines-of-code column.
- No separate Background section and no roadmap paragraph; background is folded into Motivation §2.1.
- No confidence intervals or statistical tests; repetition is reported as an average with a max-spread statement.

K. DISTINCTIVE PATTERNS
- A single motivating production incident narrated with numbered path segments in a figure and a per-segment header-format table, culminating in the two operator questions and three "Problem N:" paragraphs — the motivation section is a story, not a survey.
- Design goals derived quantitatively from infrastructure parameters (link speed and packet size yield a packets-per-second target), giving the evaluation a pre-declared bar to clear.
- Generality is evidenced by a large table of implemented tasks classified by grouping pattern, with columns for whether each needs in-network visibility and header-transformation robustness plus lines of code — the table doubles as related-work coverage since many rows cite the prior tool they reproduce.
- Concrete code precedes architecture: the design section shows a complete example program before the pipeline diagram, and later subsections generalize from that example rather than the reverse.
