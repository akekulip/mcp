## Paper Style Card: nsdi_002

HARD RULE: I will describe only structure and rhetorical patterns. I will not quote, paraphrase, or reproduce any content from this paper.

METADATA
- Paper ID: nsdi_002 (NetBouncer)
- Authors: Tan, C.; Jin, Z.; Guo, C.; Zhang, T.; Wu, H.; Deng, K.; Bi, D.; Xiang, D.
- Year: 2019 (USENIX NSDI '19)
- Corpus role: secondary_field_optional (topic-similar top-venue systems paper; closest in problem shape — link/device failure localization from end-to-end probes on a production Clos fabric)
- Conversion status: converted_checked (two-column PDF-to-text; plot bodies garbled but prose, equations, pseudocode, result tables, captions, footnotes, and appendices legible)
- Method type: production active-probing failure-localization system combining (a) a probing mechanism built on a commodity switch feature, (b) a probing-plan identifiability theorem with appendix proof, (c) a regularized latent-factor inference algorithm, evaluated by simulation on a synthetic Clos topology, runtime measurement on a production trace, and multi-year deployment experience

A. ABSTRACT STYLE
- Opening move: stakes statement (service availability threatened by network incidents), then the core challenge phrased as localization at scale with scale expressed via counts of servers and devices.
- Structure: (1) stakes; (2) challenge; (3) "we propose X, a ... system that leverages ... to ..."; (4) framework-completeness claim (detects two failure classes); (5) algorithm claim (high-accuracy inference resilient to real-world data inconsistency by combining domain knowledge with machine learning); (6) deployment duration; (7) closing qualitative accuracy statement about false positives and false negatives in practice.
- Tense pattern: present for problem and system description; present perfect for deployment ("has been deployed"); past for practical outcome.
- Contribution placement: sentence three onward; the system is introduced with "we propose" and then described in two capability sentences.
- Length: approximately 130 words — short for the venue.
- Register: confident, deployment-led; no notation; one informal sentence-initial conjunction.

B. INTRODUCTION ARCHITECTURE
- Hook type: scale-of-cloud hook — critical services live in the cloud, hence enormous data centers, hence failures are inevitable, with a list of failure classes each backed by citations.
- Opening move: stakes → why localization is hard (path multiplicity, ECMP hides paths from routers) → the specific failure phenomenon that motivates the work (probabilistic, partial failures, cited to prior characterizations) → three numbered requirements a deployable localization system must satisfy, each paragraph naming which prior systems fail that requirement → "in this paper we introduce X" and how it meets the requirements → bulleted contributions → one-paragraph deployment claim.
- Contribution placement: last third of the introduction, after the requirements framing.
- Contribution format: three bullets. Each bullet opens with a noun-phrase headline ending in a parenthetical section pointer, followed by two to four explanatory sentences that name the mechanism and the key observation or proof behind it.
- Literature positioning: requirement-driven. Prior work is introduced only as counterexamples to the three requirements (needs special hardware; modifies hypervisor; repurposes header bits; localizes only to a region; suffers false positives under noise). No standalone survey paragraph in the introduction.
- Roadmap: none. §2 (Overview) functions as the roadmap by walking the three-phase workflow figure and pointing to sections.
- Intro length: about nine paragraphs plus the three-bullet list.

C. CONTRIBUTION EXPRESSION
- Voice: first-person plural for design decisions ("we design", "we prove", "we formulate"); the system as agent for capabilities ("X introduces", "X satisfies").
- Claim strength: strong on framework completeness and on the theorem ("proved to be identifiable"); strong-but-bounded on accuracy — the abstract and conclusion claim no false positives in practice and few false negatives, while §2, §8 and §9 explicitly say the system is not false-negative-free and not false-positive-free in theory.
- Number of contributions: three (probing mechanism; probing plan + device detection with theorem; inference algorithm against data inconsistency).
- How "first" claims are worded structurally: no "first" claim for the system itself in the introduction or abstract. The "to the best of our knowledge" hedge appears once, in the simulation comparison section, to justify which prior algorithm counts as state of the art — i.e., to legitimize baseline selection rather than to assert novelty. Differentiation is instead phrased as "what differentiates X from prior tomography systems is completeness of the framework" in Related Work.

D. LITERATURE REVIEW
- Structure + position: §10 Related Work sits after Discussions (§9) and before Conclusion (§11). Related-work content is additionally distributed into the body: §3 opens by contrasting conventional probing tools against the two probing requirements; §5.3 has a "Why not SGD?" run-in; §6.5 is a quantitative comparison against three prior inference algorithms with a paragraph explaining why each is the appropriate benchmark.
- Organization: three bold run-in categories — network tomography (Internet-targeted approaches, then heuristic inference algorithms, then regularization-based ones); other failure-localization approaches (switch-query monitoring, statistical mining, dependency inference, end-to-end reachability agents, header-bit tagging, decision-tree diagnosis); network troubleshooting (packet capture / summary systems, and systems needing software or hardware modification).
- Critical engagement: one or two sentences per system naming the specific limitation (exponential runtime, single-failure assumption, switch-CPU cost, unavailable header bits, cannot separate ECMP paths). The tomography contrast is made on two named axes (topology known but plan must be designed; a far stricter healthy-link threshold in data centers). Packet-capture systems are labeled complementary. The two systems the authors' own group previously built are cited as motivation and as detectors of wide impact, not as competitors.

E. METHOD / SYSTEM
- Entry point: §2 Overview with a workflow figure whose three circled phase numbers are walked in three bold run-in paragraphs (plan design; probing; inference), followed by a "targets and limitations" run-in paragraph that states scope (non-transient, loss-type incidents) and concedes missed cases with forward pointers to the deployment and discussion sections. §3 is the probing mechanism (a "basics" subsection on the tunneling primitive with a schematic, then the bouncing strategy with three numbered reasons it simplifies the model). §4 is the model and probing plan. §5 is the inference algorithm. Implementation is deferred to §7.1.
- Notation density: moderate. Per-link success probability x_i, per-path success probability y_j, one product equation, a formal problem statement (choose a subset of paths so the system has a unique solution), one theorem with an "if and only if" condition, one objective function with a regularizer, two pseudocode figures in the body and a full algorithm in the appendix with complexity analysis. Equations are numbered; the theorem is numbered and named.
- Exposition style: requirement → challenge → observation → mechanism. §4.2 poses the path-selection question, shows a small unsolvable example (figure plus four equations with a stated redundancy), then explains why such cases arise in practice. §4.3 states the key empirical observation (most links healthy), then the theorem, then the intuition, then a generalization remark (Clos as special case of layered networks), then a contrast with the literature's objective (minimizing probe count is explicitly not a goal; redundancy is reframed as validation). §5.1 lists two causes of data inconsistency as bullets and shows a worked false-positive example on a toy graph. §5.2 gives the objective and two bold run-in rationale paragraphs (why the regularizer has its shape; why the non-convex form is used). §5.3 justifies the solver choice.
- Design-choice justification: explicit alternative-rejection paragraphs ("Why not SGD?", non-convex vs convex, specialized vs standard regularizer, end-host probing vs switch probing), each of which is later validated by a dedicated simulation subsection (§6.4) — the design section promises evidence and the evaluation delivers it.
- How the fault/failure model is introduced: three stages. (1) Introduction: the target failure phenomenon (partial/probabilistic loss) is defined by contrast with fail-stop and cited to prior characterizations; the "differential observability" framing explains why switch-side counters cannot see it. (2) §2 scope paragraph: what is in and out of scope (persistence relative to the probing interval; loss-type incidents). (3) §4.1 formal model: an undirected graph, per-link success probabilities, independence of drops across links stated as an assumption with citations and a forward pointer to the discussion section where it is defended; the assumption that link probabilities are stable across measurements is declared at the top of §4 and explicitly relaxed at §5. Faulty link and faulty device are defined by threshold on the latent variable.

F. RESULTS / EVALUATION
- Primary vehicle: three sections. §6 Simulation studies (probing-plan sufficiency; device-failure detection necessity; design-choice ablations; comparison with existing algorithms). §7 Implementation and evaluation (component roles; a result-verification tool; the probing-epoch tradeoff; processor runtime on a production trace with stage-wise CPU breakdown). §8 Deployment experiences (before/after narrative; three numbered production cases; a false-negative/false-positive paragraph). Results tables are labeled as Figures.
- Narrative style: §6 opens with a single sentence listing what the simulations will demonstrate, each clause with a section pointer — a demonstration checklist. Subsections use bold run-in leads for each ablation pair ("A vs. B.") and for the tuning-parameter sweep. Every result paragraph pairs the number with a mechanism explanation (skewed log scale and boundary clipping; sparsity exploited by coordinate updates; a greedy method's tendency to under-blame; an assumption of at most one bad link per pair). Deployment cases follow a fixed shape: symptom → what prior monitoring could and could not tell → what the system output → root cause → mitigation.
- Setup depth: simulation on a synthetic three-tier Clos with stated switch/server/link counts, per-path packet count, faulty and healthy loss-rate ranges borrowed from prior work and deliberately tightened (with a footnote saying so and why), number of random faulty devices, a good-link threshold tied to the noise rate, and averaging over repeated executions. Runtime evaluation names the CPU, core count, memory, OS, trace size, and hourly window. Deployment: duration in years and a count of regions.
- Mechanism emphasis: high; the ablations exist precisely to show which design piece prevents which error type (device detection prevents false negatives; the regularizer shape prevents false positives; the solver choice yields speed).
- Robustness/limitation signaling: sweeps over faulty-link ratio and over the regularization weight, with the latter framed as a false-positive/false-negative tradeoff on a log-scale axis; a fairness disclosure that baselines were extended or given an unrealistic advantage before comparison; the probing-epoch choice framed as a three-way tradeoff with the chosen value justified and alternatives acknowledged; explicit false-negative cases from production described with root causes outside the model (NIC-side loss; narrow ACL-scoped loss); an on-demand verification tool presented as the source of confidence in the no-false-positive claim.
- Numbered questions or bold run-in leads: bold run-in leads throughout; rhetorical questions used as run-in heads in §5.3 and §9; production cases numbered "Case N:".

G. DISCUSSION / LIMITATIONS
- Function: §9 "Discussions" is a standalone section between Deployment experiences and Related Work. It states the two major limitations, reconciles theory with practice, defends the independence assumption from field experience, and answers a scoping question about congestion.
- Scope: four bold run-in paragraphs — limitations (probe traffic may not experience what application traffic experiences; zero-error guarantees are impossible in theory); theory vs practice (the theorem is necessary but not sufficient, which is what motivated adding a learning component); does the independence assumption hold (yes for enumerated fault classes, argued from experience rather than measurement); how congestion loss is handled (persistent congestion is treated as failure; transient congestion is filtered by the detection interval).
- Limitation acknowledgment: candid and repeated — limitations are flagged in §2 (forward pointer), demonstrated in §8 (named false-negative cases), and consolidated in §9; the "no false positives so far" claim is always paired with the theoretical caveat and the two mechanisms credited for it (regularizer plus a strict alarm threshold). The impossibility of a perfect guarantee is universalized to all real-world monitoring systems.
- Separate section? Yes, §9, before Related Work.

H. LANGUAGE STYLE
- Voice: first-person plural; operator-identified ("our data centers", "our experiences"); occasional contractions ("doesn't", "we've") and a sentence-initial "And" — the register is conversational for the venue.
- Sentence length: medium; some long sentences chaining a mechanism to its consequence with "which".
- Hedging: moderate — "we believe", "admittedly", "theoretically ... however in practice", "plausible", "highly confident"; strong claims are immediately followed by a bounding sentence.
- Transitions: "First/Second/Third" for requirements and reasons; "On one hand / On the other hand"; "Yet", "Nevertheless", "Indeed", "To sum up"; inline section pointers (§n) everywhere; rhetorical-question run-in heads.
- Math density: moderate — a handful of numbered equations, one theorem, two pseudocode figures, one appendix algorithm with complexity bounds; prose explains every symbol immediately.
- Paragraph length: medium; bold run-in leads open most body paragraphs in overview, design, evaluation, and discussion.

I. FORMAT MARKERS
- Section numbering: numbered 1–11 (Introduction, Overview, Path probing, Probing plan and device detection, Link failure inference, Simulation studies, Implementation and evaluation, Deployment experiences, Discussions, Related work, Conclusion) with x.y subsections; no third level.
- Appendix usage: three appendices — A the theorem proof (sufficient and necessary directions, case analysis), B the full algorithm with time and space complexity, C acknowledgements.
- Related-work position: penultimate (§10), after Discussions.
- Caption style: long, explanatory captions; result-table captions define every column abbreviation and the meaning of parenthesized baseline parameters; algorithm-figure captions define every symbol; some captions carry an interpretive sentence about what the figure shows. Tabular results are numbered as Figures, not Tables.
- Subsection depth: two levels; bold run-in leads and "Case N:" labels serve as informal third level. Footnotes are used for parameter changes relative to prior work and for minor implementation differences.

J. WHAT THIS PAPER DOES NOT DO
- No "first" novelty claim in abstract or introduction; novelty is framed as completeness of the framework and resilience of the inference.
- No comparison against prior systems on production data — head-to-head comparison is simulation-only, and only the inference stage is compared.
- No confidence intervals, significance tests, or per-run variance; results are averages over repeated executions.
- No separate Background or Threat/Fault Model section; the fault model is assembled across the introduction, the overview scope paragraph, and the formal model subsection.
- No roadmap paragraph and no separate Design Goals section; the three requirements in the introduction serve both roles.

K. DISTINCTIVE PATTERNS
- Three explicit requirements stated in the introduction become the lens for everything afterwards: prior systems are rejected per requirement, the system is introduced as satisfying all three simultaneously, and the probing section re-derives its own two sub-requirements the same way.
- Theory and learning are deliberately paired and then reconciled: a named theorem with an appendix proof establishes identifiability; a later discussion paragraph concedes that the theorem is necessary but not sufficient in practice, which justifies the regularized estimator — the paper narrates its own theory-to-practice gap rather than hiding it.
- A "targets and limitations" run-in paragraph appears at the end of the Overview (§2), before any mechanism is described, with forward pointers to the sections that show missed cases — scope and limits are declared early, not deferred.
- Every "why not alternative X?" rationale in the design section has a matching ablation subsection in the simulation section, and the simulation section opens with a one-sentence checklist mapping each demonstration to its subsection.
