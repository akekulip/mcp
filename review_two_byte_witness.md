# Referee Report

**Manuscript:** "What a Two-Byte Witness Buys on a Sprayed Fabric: A Silicon-Measured Comparison of In-Fabric Grayhole Localization Against Passive Detection"
**Author:** P. Akekulip (single author)
**Target venue:** IEEE/ACM Transactions on Networking
**Reviewer stance:** PI / area chair in datacenter networking and programmable data planes

---

## 0. Recommendation

**Major revision, and currently a likely reject at ToN in its present form.**

Not because the work is weak — the experimental discipline is genuinely above average for this area, and the honesty (survivorship-bias marking, null results reported as null, a failure gate the authors predicted and then ran, an unexplained anomaly disclosed rather than buried) is better than most accepted papers. It is a likely reject because **the paper's central claim is stated in a form that is provably wrong, and the one baseline that would establish the contribution is missing.** Both are fixable without new hardware. If fixed, this becomes a solid ToN paper. If not fixed, at least one of three reviewers kills it on novelty and a second kills it on the scaling claim.

I've ordered what follows by what determines the outcome, not by section order.

---

## 1. Blocking issues

### 1.1 The "flat cost" claim is wrong, and the correct claim is stronger

The paper's headline is that passive detection costs Θ(1/p) (Section II-B, Section V) while the witness's cost "should not depend on `p`" because "it counts the missing packets directly" and "does not compare against noise at all."

That last step does not hold. The witness's observable is a **count of lost packets**, and that count is itself a random variable. Over an epoch in which a link transmits `λ` packets, the ledger compares

- faulty link: `ℓ ~ Poisson(λ·(f + p))`
- healthy link: `ℓ ~ Poisson(λ·f)`

where `f` is the background floor (10⁻⁵ in the harness). Separating these at `s` standard deviations requires `λp > s√(λf)`, i.e.

```
λ_ledger  ≳  s²·f / p²        vs.        λ_passive  ≳  s² / p²
```

**Both arms scale as 1/p².** The witness does not change the exponent. What it changes is the constant, by a factor of exactly the background loss rate — here 10⁵. That is a five-order-of-magnitude improvement in required traffic, which is a far more impressive and far more defensible result than "flat," and it explains every number in Table I:

- The ledger looks flat across 1.5% → 10⁻⁴ because its own wall sits at `p ≈ s²f/λ` — with `λ ≈ 250k` packets per spine per epoch and `f = 10⁻⁵`, that is roughly `p ≈ 3–5 × 10⁻⁵`.
- **The sweep therefore stops less than half a decade before the ledger's own collapse.** Section V asserts "the ledger's flat line should not depend on the budget at all." It does not depend on the budget; it depends on the floor, and the paper never says so.

Two reviewers will find this. A statistically literate reviewer will find it in Section II-B and stop trusting Section V. Fix it as follows:

1. **State it as a proposition** with its assumptions (independent per-packet drops, known/estimable floor, Poisson spray) and a two-line proof. ToN wants this formalized; right now it is prose in a background section.
2. **Extend the sweep to 10⁻⁵ and 10⁻⁶** and show the ledger's wall. A paper that locates its own failure boundary is much harder to reject than one that stops just short of it. You already do this culturally in Section VIII — do it here.
3. **Sweep the floor `f`.** It is the load-bearing constant of the entire paper and it is currently a single unjustified harness setting. Production corruption floors vary by orders of magnitude across fabrics; cite measured values (CorrOpt has them) and show `p_min` moving with `f`.
4. Rewrite the abstract and Contribution 1. "Flat cost from 1.5% to 10⁻⁴" becomes "reduces the detection-cost constant by the background loss rate, ~10⁵× on this fabric, leaving the 1/p² scaling intact; within any operational regime where `p ≫ f` the cost is therefore set by epoch volume rather than by `p`."

### 1.2 The decisive baseline is missing: a zero-byte counter pair

This is the objection that will get the paper rejected on novelty, and the paper has the answer inside its own related-work table without noticing.

Look at what Equation (1) actually uses: `ℓ = Δseq − Δobs`. `Δseq` is the advance of the receiver's frontier over the epoch — which is *the number of packets the sender transmitted on that sublink*. `Δobs` is the number that arrived. **Equation (1) is a transmit/receive counter difference.** The per-packet sequence number is not used as a sequence: Section VII says explicitly that "the recovered loss is magnitude-based" and that the one-gap-per-discontinuity property is out of scope. No ordering information is consumed anywhere.

Now recall the paper's own justification for dropping the 16-bit link identifier (Section III): the receiver can already name the directed link from its ingress port plus the spray field, which is on the wire anyway. If that is true — and it is — then the receiver can bin arrivals per directed link **with no stamp at all**. And the sender already knows which spine it sprayed each packet to, so it can keep a per-directed-link transmit counter for free. A controller that reads registers once per epoch (which it does) can read both sides and compute `ΔTX − ΔRX`.

**So what do the two bytes buy?** Exactly one thing: they carry the sender's count in-band, so that the frontier at the receiver and the arrival count at the receiver are read *at the same instant on the same device*. The zero-byte counter pair is read at two devices at two times, and every packet in flight or transmitted between the two reads appears as loss. This is precisely the "epoch-skew limited" entry you already assign to RFC 6374 in Table VII.

That is a real contribution and it is quantifiable. Rough numbers: at 25 Gb/s with 1400 B packets, a sublink carrying ~550 kpps accumulates ~550 phantom losses per millisecond of read skew, against a true signal of ~6 packets at `p = 10⁻⁴` over a 65k-packet epoch. **Skew error exceeds signal by two orders of magnitude.** That is the paper's actual thesis, and it is currently unstated and unmeasured.

Required:

- **Add a fourth arm: `CounterPair-0B`.** Per-directed-link TX register at the sender, RX register at the receiver, zero wire bytes, same e-BH decision rule. Run it through the O1 and O2 sweeps under a realistic distribution of controller read skew (and at skew = 0 as the idealized bound).
- **Measure read skew on the Tofino.** How long does the controller take to read 2048 registers across the fabric? That single number is the paper's justification for existing.
- Reframe the title and thesis around it: what the two bytes buy is *in-band epoch alignment*, converting a skew-limited counter difference into an exact one. The comparison against SprayCheck/FlowPulse then becomes context rather than the whole argument.

Without this arm, Reviewer 2 writes: *"Equation (1) is a TX/RX counter difference. Per-link TX/RX counters exist on every switch at zero wire cost and are cited by the authors (RFC 6374, NetSeer). The paper does not evaluate them. The measured advantage over two host-side passive detectors is therefore uninformative about whether the per-packet stamp is needed at all."* That is a fatal review and it is correct as the paper currently stands.

### 1.3 "Packets to detect" contradicts its own definition

Section IV-C: *"Packets to detect is the fleet-wide packet count from the fault's onset to the first correct flag."* Section V: the ledger "did so on the first epoch after onset in every case," with a median of **22.0 M** and an IQR of 22–24 M. An epoch is 2 M fleet packets. First epoch after onset is therefore **2 M**, not 22 M.

The arithmetic says the reported figure includes the ten clean warmup epochs (10 × 2 M = 20 M) plus the detecting epoch. Every other cell fits: SprayCheck at 1.5% = 24 M = 20 M + 2 epochs; at 10⁻³ = 114 M = 20 M + 47 epochs. Meanwhile the budget is defined as *80 post-onset epochs = 160 M*, i.e. on a different origin from the reported costs, yet Figure 2 draws them on the same axis.

Consequences:

- **The metric definition and the numbers are inconsistent.** Fix one or the other.
- **The confound understates your own result by roughly an order of magnitude.** Post-onset, the ledger costs 2 M and SprayCheck's median at 10⁻³ costs 94 M. That is 47×, not the 5× the paper claims. You are currently hiding your strongest number under a constant offset.
- Figure 2's y-axis compresses everything into one decade because of the offset, which is why the separation looks visually modest. Replot on post-onset packets and the figure becomes the paper's best asset.

### 1.4 The unexplained silicon anomaly blocks the O3 claim

Section X: during a 57-cycle soak, two sublinks that were neither armed nor measured each showed one stamped packet with no matching arrival during clean traffic; not seen in ~3200 cycles of the four-byte program; cause unknown.

Disclosing this is the right call and I want to be explicit that I credit it. But a reviewer cannot let it stand next to a claim of "zero false positives" and "recovers injected loss exactly." At `p = 10⁻⁴` the signal is 6 packets in 60,000. A recurring unexplained 1-packet phantom loss is a ~17% perturbation on your smallest measured signal, appears *only in the two-byte program*, and is exactly the failure mode that produces false positives in production. It is also suspicious that it correlates with the version change that added the ingress reconstruction tables.

This must be root-caused before publication. Candidate leads worth ruling out in print: the two-table classification path mislabeling a packet into a neighbouring sublink (which would show as +1 on one sublink and −1 on another — check whether the two anomalous sublinks are adjacent in the key space); a race between the frontier write and the observed-count write for the epoch's boundary packet; resubmit/mirror paths touching the stamp; and packets crossing the loopback egress that are not part of the host-stamped sequence, which you already observed accounting for the 180–190 packet discrepancy in Section VII.

### 1.5 Congestion loss is unaddressed and is a deployability blocker

Section II-A dismisses congestion loss as "transient and shared by every link behind the congested queue." In an ML training fabric that is not true. Incast at a collective's reduction point produces **persistent, egress-queue-localized** loss on one directed link for the duration of the collective. The ledger counts all missing packets and cannot tell that loss from a grayhole. It will fire, repeatedly, at exactly the moments the fabric is busiest.

This is the same structural failure as the common-mode shift of Section VIII — an absolute test against a floor that the fault itself moves — but it is far more likely to occur in production than a uniform fleet-wide shift. Add a regime R4 to the correlated-fault gate: background congestion loss on a subset of links, with and without a real grayhole underneath. I expect the ledger to fail it and SprayCheck's relative test to hold, which strengthens rather than weakens the paper's boundary framing. Whatever the result, an operator reviewer will not accept the paper without it.

---

## 2. Substantial issues

### 2.1 O2 (localization) contributes almost nothing as designed

The paper concedes the 1.00 exact-localization score is "close to definitional." It is not close; it is definitional. Given a per-directed-link loss count, a detector that flags a link has localized it — there is no inference step and no measurement being made. Section VI is therefore ~1.5 pages establishing an identity, plus a null result against SprayCheck at high loss.

Keep the table (SprayCheck's degradation to the ambiguous pair is a genuine measured finding, as is the spurious-intersection behaviour in Table IV that you note is unreported elsewhere), but stop presenting the ledger's column as a result. Reframe the section as *"how far down in `p` can a passive vantage disalias, and what does it cost?"* — a question about the baselines, with the ledger as the oracle row. Also note that the McNemar test with zero discordant pairs is degenerate; reporting `p = 1.0` from it is not meaningful and invites a stats reviewer's irritation.

### 2.2 The e-process / e-BH decision rule is unspecified

This is the entire decision procedure, and Section III gives it three sentences. Nowhere in the paper can I find:

- the definition of the e-variable (likelihood ratio against what alternative? what `p₁`?),
- how evidence accumulates across epochs (product of per-epoch e-values? which stopping rule?),
- the target FDR level `α`,
- how the leave-one-out fleet floor is estimated (mean? median? trimmed? over what window?),
- whether the floor estimate's own uncertainty enters the test.

Every "false positive 0.00" in the paper is uninterpretable without `α`, and e-BH *controls* FDR rather than driving it to zero — observing 0.00 across 50 seeds × 64 links suggests either a very conservative `α` or e-values so large the multiplicity correction is inert. For ToN this is a reproducibility failure on its own. Give the rule in full, with a displayed equation, and report `α`.

### 2.3 The silicon evaluation is thinner than the framing implies

"Silicon-measured" is in the title, so this section carries weight it does not currently bear:

- **Table III is nine cells with duplicates** — two identical rows each at 10⁻², 10⁻³, 10⁻⁴. That is five distinct conditions and two clean controls, on **one sublink**.
- **The fabric is virtual.** Four leaves and two spines emulated on a single Tofino with a four-lane loopback, each directed link a traffic-manager queue. There is no real multi-hop path, no real spraying across physical spines, and no real cross-traffic. That is a fine way to validate register arithmetic; it is not a fabric measurement, and the paper should not let "on silicon" imply otherwise.
- **Offered load is ~1% of line rate.** 20 kpps of 1400 B is ~224 Mb/s against a 25 Gb/s port. The claim that the registers update "at line rate" is asserted ("both were on our switch"), not measured. Run a line-rate soak and report recovery fidelity under it.
- **No latency or throughput impact** is measured anywhere. Section VII concedes the added-load figure is computed from header size rather than measured as saturating throughput. For a title promising silicon measurement, that is the wrong thing to concede.

### 2.4 The 16-bit sequence does not survive line rate — and this is hidden by the low offered load

Section IV notes that "every cell also keeps `Δseq` below 2¹⁶, so that the sequence wraps at most once." At 20 kpps that is trivially satisfied for seconds. At line rate it is not: a sublink carrying ~550 kpps exhausts 2¹⁶ in ~120 ms, so the controller must read all 1024 sublinks faster than that or `Δseq` aliases and Equation (1) silently returns a wrong (possibly negative, possibly plausible) loss.

The paper never states the epoch duration in wall-clock time for the silicon setup, never measures the register-read latency for 2048 registers, and therefore never establishes that the two-byte version is viable at line rate. Given that the four-byte version was discarded specifically to halve wire cost, this is a live possibility: **the four-byte sequence may be the only deployable width, which would double the headline cost and free the ingress stage.** You must measure the read loop and state the epoch bound explicitly. If it fails, say so — it is a better paper for it.

### 2.5 A blackhole reads as zero loss

If a sublink drops *everything* in an epoch, no stamped packet arrives, the frontier does not advance, `Δseq = Δobs = 0`, and Equation (1) reports zero loss. The paper sets blackholes aside as testbed validation only, but the reader should be told that total failure is invisible to the ledger by construction and requires a liveness companion. Similarly, one duplicate plus one loss on the same sublink cancels to `ℓ = 0`, masking both — the `−1` duplicate signature only survives when duplicates are unaccompanied.

### 2.6 The stage cost is much more expensive than "one stage" sounds

Section IX reports 12 of 12 ingress stages on Tofino 1, with zero headroom, and the paper is admirably direct that any future addition must displace something. But the program being measured is a *stripped* one: forwarding plus the ledger. A production leaf program carries ECMP/spray, RoCE or UEC handling, ACLs, tunnelling, QoS, and often existing telemetry — that program does not have a spare stage. As written, the honest conclusion is that **the two-byte ledger does not fit on a Tofino 1 alongside a real switch pipeline.** Address this: report the stage budget on Tofino 2/3, or report the ledger's cost when compiled into a representative production P4 program, or state the limitation plainly. An operator reviewer will otherwise conclude the artifact is undeployable on the platform it was measured on.

### 2.7 Baseline fidelity concerns

- **FlowPulse is a 6-page HotNets workshop paper** with a fixed 1% threshold. Defeating it is not a strong result, and the paper's own explanation of its failure (a single sender's loss diluted by `1/n_senders` below a fixed threshold) means the arm is beaten by arithmetic, not by measurement. Keep it, but do not let it carry weight — and consider whether a charitably *retuned* FlowPulse (threshold scaled by senders per port) is the fairer comparator. You give it per-sender visibility already; extend the same charity to its threshold.
- **SprayCheck's sensitivity is calibrated under the wrong spray model.** The paper discloses this and argues it shifts the curve by a constant. Argument is not measurement: implement JSQ(2) spray and re-run, or bound the constant analytically. Also `s = 3.24` is calibrated at 2.5 M packets/spine while the harness delivers ~250 k/spine/epoch — a 10× mismatch in the operating point at which the sensitivity was set. Explain or recalibrate.
- **Neither baseline was validated by its authors, and neither has a public artifact in your repo.** Say explicitly that you contacted the authors (or could not), and publish your reimplementations.

### 2.8 The artifact does not exist publicly

I checked `github.com/akekulip/mcp` at current HEAD (three commits, latest 2026-04-15). It contains only the earlier measurement-control-plane project. Zero occurrences of `grayhole`, `spray`, `SprayCheck`, `FlowPulse`, `sublink`, `witness`, `e-BH`, or `reg_wit`.

Nothing in this paper is currently checkable: not the harness, not the 50-seed cells, not the e-BH implementation, not the P4 for the ledger, not the Tofino control plane, not the raw census logs, not the compiler resource reports behind Table VI (91/16 SRAM/TCAM blocks, 12/5 stages, SDE 9.13.2). ToN does not mandate artifacts, but a paper whose contribution is *a measurement* and whose most striking claims are exact integers from a switch will be asked for them, and a reviewer who checks the cited repo and finds a different project will be unimpressed.

Publish: the replay harness with seeds and a one-command reproduction of every table; both baseline reimplementations; the ledger P4 plus both compiler resource reports; the controller and the e-BH code; the raw silicon census logs including the soak that produced the Section X anomaly.

**And this leak has already cost you:** Figure 2's legend reads **"MCP (in-fabric witness)"** while Table I, Figure 3, Figure 4, Figure 5 and the entire text say "Ledger." That is stale naming from the prior project. Fix it — a reviewer who spots one inconsistency between figure and table starts checking every other number by hand.

---

## 3. Presentation and compliance

- **`P. Akekulip is with [institution]`** and **`Manuscript received [date]`** are unfilled. ToN is single-blind, so the affiliation must be real at submission.
- Acknowledgment and biography are placeholders. Fill or remove before submission.
- Table VI's "Added load (1400 B) 0.14%" uses `2/1404`. The wire denominator should include Ethernet framing (~1458 B with preamble, FCS, IFG), giving 0.137%; more importantly, **1400 B is the best case.** Report the range: at 256 B control/ack packets the stamp is 0.78%. In a fabric where a nontrivial share of packets are small, the honest figure is a range, not a single number.
- Section VII explains the one-packet gap with "we believe neither is a recovery error." Replace belief with a measurement — arm the injector so the last packet of the read window is guaranteed a later survivor, and show the gap disappears.
- Several claims are asserted where a displayed equation is expected (the `1/p²` bound, the e-process, the floor estimator). ToN's reviewers read for formalism more than a conference's do.
- The reordering discussion should note that per-sublink ordering is preserved by construction (same link, same queue), so the reordering-robustness property is weaker than it sounds under spraying — the interesting reordering is *across* sublinks, which the ledger does not need to handle. Currently reads as a stronger claim than it is.
- Consider a Figure 2 replot on post-onset packets with a log y-axis spanning the true separation (see §1.3).

---

## 4. What is genuinely good, and should be protected in revision

I want this on the record because a revision could easily sand it off in pursuit of a cleaner story.

- **The correlated-fault gate (Section VIII) is the best part of the paper.** Predicting your own decision rule's failure from analysis, pre-registering the scope, running the gate on fresh seeds, and reporting that the baseline wins in two of three regimes — that is how this should be done and it is rare.
- **The two fidelity checks that changed the harness (Section IV-A)** — the FlowPulse false-alarm rate at 200 k packets/epoch and the vectorization — are exactly the disclosures that build reviewer trust.
- **Survivorship-bias marking on censored medians**, with action rates annotated on the hollow markers and the explicit statement that the action-rate collapse rather than the censored median is the load-bearing signal. Most papers in this area get this wrong silently.
- **The spurious-intersection finding in Table IV** (SprayCheck's recall *falling* as faults multiply, adding 1.2–1.4 healthy links per seed) is, as you say, not reported elsewhere. This is a real contribution about the passive localizer and it is currently buried in a boundary section. Promote it.
- **The null result at 1.0–1.5% loss**, reported as a null with a McNemar test rather than spun.
- Refusing to claim novelty for the primitive.

---

## 5. Venue

ToN is defensible **only if §1.1 and §1.2 are fixed.** ToN reviewers want a generalizable result with formal grounding; a comparison study whose headline is "an existing primitive beats two baselines that lack its information" reads as incremental to that audience, and the paper currently invites that reading by conceding definitional results.

With the proposition of §1.1 (a proved cost-constant separation with the floor as the governing parameter, and the ledger's own wall located) plus the counter-pair arm of §1.2 (establishing that the two bytes buy epoch alignment, quantified), the paper has a general theoretical result, a measured cost, and a bounded scope. That is a ToN paper.

If you would rather not do the additional work: **IMC is the better fit as-is.** It rewards exactly this paper's virtues — honest measurement, negative results, boundary conditions, disclosed anomalies — and is more tolerant of "we measured an existing thing carefully." CoNEXT is a reasonable third option. I would not submit to ToN without §1.1–§1.4.

---

## 6. What each of your three reviewers will do

**Reviewer A — programmable data planes / systems.** Reads Sections III, VII, IX. Notices the 12/12 stage ceiling and asks whether this fits a production pipeline (§2.6). Notices the 20 kpps offered load against a 25 Gb/s port and asks for line rate (§2.3). Notices the 16-bit wrap constraint and asks for the epoch bound (§2.4). Finds the Section X anomaly and holds the "zero false positives" claim hostage to it (§1.4). Verdict without fixes: **weak reject**, "silicon claims not established at rate; artifact unavailable."

**Reviewer B — measurement / statistics.** Reads Section II-B and Section V. Derives `λ > s²f/p²` in the margin and concludes the flat-cost claim is wrong (§1.1). Recomputes 22.0 M against a 2 M epoch and finds the metric inconsistency (§1.3). Looks for `α` and the e-variable definition and finds neither (§2.2). Notes the degenerate McNemar. Verdict without fixes: **reject**, "central scaling claim incorrect; decision procedure unspecified; headline metric contradicts its definition."

**Reviewer C — datacenter operator / industry.** Reads the abstract, Section VIII, Section IX, Section XI. Asks immediately why per-link TX/RX counters were not evaluated, since every switch has them at zero wire cost (§1.2). Asks what happens under incast (§1.5). Asks whether two bytes on every fabric hop is acceptable when the alternative is free. Verdict without fixes: **reject**, "the paper does not show the stamp is necessary."

**Reviewer C is the one you must convert, and §1.2 is the entire conversion.** Reviewer B is convertible by §1.1 + §1.3 alone, and will likely become your advocate, because the corrected claim is stronger and the metric fix multiplies your headline separation by ~10×. Reviewer A is convertible by measurement work you can do on hardware you already have.

---

## 7. Revision checklist, in priority order

1. Add the `CounterPair-0B` arm; measure controller read skew on the Tofino; reframe the thesis as in-band epoch alignment. *(§1.2 — determines acceptance)*
2. Replace the flat-cost claim with the proved cost-constant proposition; extend the sweep to 10⁻⁵/10⁻⁶ to locate the ledger's wall; sweep the floor `f`. *(§1.1)*
3. Fix "packets to detect" — post-onset origin, replot Figure 2, restate the separation (~47×, not 5×). *(§1.3)*
4. Root-cause the Section X anomaly. *(§1.4)*
5. Add regime R4: congestion/incast loss, with and without a grayhole. *(§1.5)*
6. Specify the e-variable, the accumulation rule, `α`, and the floor estimator in full. *(§2.2)*
7. Line-rate soak; state the epoch bound implied by the 16-bit wrap; measure the register-read loop. *(§2.3, §2.4)*
8. Report the stage budget inside a representative production pipeline, or on Tofino 2/3. *(§2.6)*
9. Reframe Section VI around the baselines; promote the spurious-intersection finding from Section VIII. *(§2.1, §4)*
10. Publish the artifact — harness, seeds, both baseline reimplementations, ledger P4, both compiler reports, e-BH code, raw silicon logs. *(§2.8)*
11. Fix Figure 2's "MCP" legend; fill affiliation, date, acknowledgment, biography; report added load as a range. *(§2.8, §3)*
12. Note the blackhole-reads-as-zero and duplicate-cancels-loss cases explicitly. *(§2.5)*

Items 1–5 are the difference between reject and major revision. Items 6–8 are the difference between major and minor revision. Items 9–12 are polish that a reviewer will nonetheless list.
