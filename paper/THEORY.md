# The observation model and the coverage bound (M1 step 1, draft for adversarial review)

Status 2026-08-28, **revised after the gate**. This file was written to be attacked, and it was:
three independent reviews returned **DUPLICATE** on the coverage proposition and **REFUTED** on the
pooled-test argument (`docs/review/NOVELTY-GATE.md`). What follows is the corrected version. The
coverage result is retained as an **explanatory lemma with attribution** — it explains why the
system is built this way — and is not a contribution. §4 has been cut back to what survives.

## 1. Model

**Fabric.** A set $E$ of directed links, $|E| = n$ (in the pre-registered gate, $n = 1024$
aggregation→core uplinks of a 1024-NIC three-tier fat tree). Time is slotted into epochs
$t = 1, 2, \dots$ of fixed length.

**Traffic.** Link $e$ carries $N_e(t) \ge 0$ packets in epoch $t$. The process $N$ is exogenous: it
is produced by the collective schedule of the training job and is **not** affected by measurement.
This is not an assumption of convenience — it is verified: the per-link counter logs of the 30 gate
seeds are byte-identical across all five measured arms (120/120 arm–seed pairs), so replaying a
different read schedule over recorded counters is exact, not a model.

**Fault.** One link $f \in E$ becomes faulty at onset $\tau_0$ and thereafter drops each packet
independently with probability $p$ (the gate uses $p = 10^{-4}$). The fault is silent: it produces
no signal of its own. $f$ is drawn from a prior $\pi$ over $E$; the pre-registered gate uses $\pi$
uniform, and the adversarial reading takes the worst case over $f$.

**Spraying.** Every flow's packets are sprayed per-packet over all paths, so every flow traverses
every link of its layer with near-equal frequency. This is the property that makes the problem what
it is, and §4 is about what it destroys.

**Observation (action-local, selective, cumulative).** Each epoch the controller chooses
$S_t \subseteq E$ with $|S_t| \le B$ and reads the *cumulative* counters of those links. Reading $e$
at $t$ yields $(\Delta N_e, \Delta D_e)$ accumulated since $e$ was last read:
$\Delta D_e \sim \mathrm{Bin}\!\left(\Delta N_e,\; p \cdot \mathbb{1}[e = f \text{ and the interval
intersects } [\tau_0, \infty)]\right)$. For $e \notin S_t$ the controller observes **nothing** in
epoch $t$ — not a zero, nothing.

Two consequences, and the second is the one reviewers usually miss:

1. Evidence is **not destroyed** by not looking; it is *delayed and aggregated*. A link read at
   epoch $t$ surrenders every drop since its last read. So this is not a sampling problem in which
   unobserved information is lost — it is a *scheduling* problem in which information is deferred.
2. Therefore the whole cost of a schedule is delay, and a lower bound must be proved about delay,
   not about information.

**Policy class (counter-computable).** A policy is counter-computable if $S_{t+1}$ is a
(possibly randomised) function of $\{(e, \Delta N_e, \Delta D_e) : e \in S_1 \cup \dots \cup S_t\}$
— everything it has read, and nothing else. Uniform round-robin, random, load-gated, threshold-gated,
greedy-information, Thompson sampling, LinUCB and every bandit in the literature are in this class.
The oracle is not.

**Objective.** $T$ = the first epoch at which the detector's top-ranked element is $f$ and its
alarm statistic exceeds $h$. Delay is $T - \tau_0$.

## 2. The decomposition

Define $\tau_{\mathrm{ev}} = \min\{t \ge \tau_0 : \text{link } f \text{ has dropped at least one
packet by } t\}$ — the first epoch at which any detector *could* fire, fixed by the fault rate and
by whether the faulty link is carrying traffic at all. Then

$$T - \tau_0 \;=\; \underbrace{(\tau_{\mathrm{ev}} - \tau_0)}_{\text{evidence time}} \;+\;
\underbrace{(T - \tau_{\mathrm{ev}})}_{\text{coverage time}}.$$

Evidence time is a property of the fault and the workload; **no scheduler touches it**. Measured on
the 30 gate seeds it is 8.0 epochs for every arm including the oracle. Coverage time is the entire
compressible term, and at the pre-registered operating point it is the larger one (10.0 for uniform
against 1.0 for the oracle).

## 3. The coverage lemma (classical; attributed, not claimed)

This is the perfect-detection case of discrete search for a stationary target: **Bellman**,
*Dynamic Programming* (1957), Ch. III Ex. 3, p. 90, and **Blackwell's index rule** (in Matula 1964;
independently Black 1965). With equal priors and equal costs every Blackwell index ties, every
search order is optimal, and the expected number of looks is (n+1)/2 — which, batched B at a time,
is the expression below. The budgeted-policy-class version is **Chaudhuri, Fellouris & Tajer**,
IEEE TIT 70(12), 2024, Thm 3.1 and Thm 4.3(ii): round-robin is first-order asymptotically optimal
among all budget-respecting policies under a homogeneity condition that is the exchangeability
condition below; **Xu, Mei & Moustakides**, IEEE TIT 67(11), 2021, Thm 1 quantifies the same
coverage penalty as an additive term linear in the number of streams. It is stated here because the
paper's design decisions follow from it, and because a reader needs the constant.

> **Lemma (coverage delay; Bellman/Blackwell, batched).** Suppose the unread links are *observationally exchangeable*:
> conditioned on everything a counter-computable policy has read up to epoch $t$, the posterior over
> which unread link is faulty is the restriction of $\pi$ to the unread set. Then for uniform $\pi$,
> any counter-computable policy with budget $B$ has
> $$\mathbb{E}[T - \tau_{\mathrm{ev}}] \;\ge\; \frac{n - B}{2B} \quad\text{epochs},$$
> and no policy in the class does better than round-robin.

*Proof.* Let $A_t$ be the set read in epochs $\tau_{\mathrm{ev}} \dots \tau_{\mathrm{ev}}+t$, so
$|A_t| \le B(t+1)$. Under exchangeability $\Pr[f \in A_t] \le B(t+1)/n$, and
$\mathbb{E}[W] = \sum_{t\ge0}\Pr[W>t] \ge \sum_{k=1}^{n/B}(1-kB/n) = (n/B-1)/2 = (n-B)/2B$.
Localization cannot precede $f$'s first read: an element with no observations is **not ranked at
all** (`controller/infer.py:397` filters on `n_obs_loss or n_obs_lat`), so it cannot be the top
suspect. $\square$

Two hypotheses have to be stated or the lemma is false as written. First, the decision rule may
declare $e$ only if $e$ has been read since $\tau_{\mathrm{ev}}$ — otherwise a policy that eliminates
$n-1$ links may declare the last one unread, and strictly beats round-robin. The frozen detector
satisfies this by construction. Second, tightness needs $B \mid n$; when $B \nmid n$ round-robin gives
$(\lceil n/B\rceil-1)/2$, which is larger. At $(1024, 41)$ the two agree to 0.01 epochs.

**Why the first-read bound is also a delay bound.** This is the one step that is specific to this
fabric rather than to search theory, and it is what makes the lemma bind in practice. Because
counters are cumulative, a read after an interval $R$ carries $R$ epochs of packets, so the LLR
increment scales with $R$: with $p_0$ floored at $10^{-6}$ and $\delta = 10^{-4}$,
$\mathrm{inc} \approx 4.6x - 10^{-4}n$, which for a typical post-burst read (19 drops in ~154k
packets) is ≈ 72 nats against a threshold of 6.5. One read of the faulty link is therefore
essentially always enough, and E[delay] collapses onto E[first read].

**Tightness.** Round-robin attains it, which is the point: the most trivial schedule in the class is
optimal, and Blackwell's theorem says so for arbitrary priors and costs, not just this one. At
$(n, B) = (1024, 41)$ the constant is $983/82 = 12.0$ epochs.

**How it is validated.** Not by one number. A single point comparison is worthless here — the
per-arm coverage medians published earlier were complete-case medians that silently dropped
censored runs, which removes exactly the largest coverage times and biases the estimate *below* the
bound. The validation is the five-budget curve: the lemma predicts 50.7, 25.1, 12.0, 5.7 and 2.1
epochs at $B = 10, 20, 41, 82, 200$, and the measurement to compare against it is the
Kaplan–Meier median coverage **with censored runs included** at each budget (`sim/gate/replay.py`
prints both, `sim/gate/M1-REPLAY.md` tabulates them).

**When exchangeability fails.** It fails whenever the read history predicts observability — most
obviously through load: a link known to be idle cannot produce evidence, so skipping it is free.
This is real and measured: load-gated round-robin beats uniform at budget 82. It is also bounded:
the gain is 17 % of the oracle gap at $p = 0.56$, because in a sprayed fabric loads are nearly
equal across the links of a layer by construction. **Spraying is what makes the exchangeability
condition approximately true**, and the more perfectly a fabric sprays, the tighter the bound binds.

## 4. Singleton tests, and what spraying does *not* do

An earlier draft argued that per-packet spraying collapses the pooled-test design space, so that
group testing's $\Theta(\log n)$ cannot apply and only singleton counter reads remain. **That
argument is wrong and has been removed.** Spraying does not homogenize the pools: it decomposes one
flow into $k$ parallel per-spine tests, and because spraying randomizes only the middle hop, a
flow's pool is {uplinks of its source leaf} ∪ {downlinks to its destination leaf} — stratified by
endpoint before any scheduler acts. SprayCheck (arXiv:2605.03702) localizes faulty links from
exactly this passive pooled evidence *under* spraying, by intersecting reports that share a link
and differ in leaf. Boolean network tomography (Bartolini et al., IEEE/ACM ToN 2020) is the general
statement: identifiability is bounded by the routing scheme, not by the number of measurements.

What survives is narrower and is about our instrument, not about the fabric: **a per-link byte
counter is a singleton test**, and a controller that reads counters therefore pays the coverage
term of §3. That is a reason to change the observation, not the schedule — and changing the
observation is what a per-directed-link order witness does. That primitive is **not ours**: it is
NetSeer's inter-switch drop detection (SIGCOMM 2020 §3.3), LinkGuardian's per-port sequencing
(SIGCOMM 2023), and Ultra Ethernet 1.0.2 §5.1 Link Layer Retry. We instantiate and cost it; we do
not claim it. See `docs/review/NOVELTY-GATE.md`.

**A correction.** An egress-inserted witness is post-TM and therefore does **not** see the upstream
switch's own TM drops: a packet the TM discards never reaches egress, never receives a sequence
number, and creates no gap. It witnesses the losses that occur after egress processing — wire and
MAC loss on the link, and faults injected between sequence allocation and downstream validation.
NetSeer needs a separate mechanism (redirecting MMU-dropped packets to an internal port) for
exactly this reason.

## 5. What this does not claim

- It says nothing about evidence time, which dominates at low $p$ and is untouchable by any method
  in this paper, in-band included.
- It is proved for a single stationary fault under an exchangeability condition that a real fabric
  satisfies only approximately.
- Multi-fault and moving-fault results in `sim/gate/M1-REPLAY.md` are measurements, not theory.
- It is not a bound on bits or state, so nothing here licenses the word *minimal* or *optimal* for
  the witness; its cost is reported concretely (2 B or 4 B) instead.

## 6. The gate ran, and both halves failed

The reviews found the proposition to be Bellman/Blackwell with two modern restatements in IEEE TIT,
and the pooled-test argument to be refuted by SprayCheck; the M2 mechanism is NetSeer's. Details and
citations: `docs/review/NOVELTY-GATE.md`. Consequences, in force:

1. §3 is an **attributed lemma** in the Design section. Not a contribution, not called a theorem,
   never called "our bound".
2. The witness is an **instantiation of a known primitive**. M2's deliverable is its cost and
   robustness on this fabric, and a head-to-head against NetSeer's detection surface is mandatory.
3. The paper's claims are what is actually ours: the measured coverage/evidence decomposition on a
   sprayed AI training fabric, the **equal-cost frontier** against scheduled counter reading — which
   none of NetSeer, LinkGuardian, FANcY or the UEC spec has reported — and the hard-capped zoom.
4. SprayCheck is concurrent work occupying the same gap and needs its own delta section.

One modelling observation is worth keeping in the Design section, and it argues against depth rather
than for it: because switch counters are cumulative, not looking *defers* evidence rather than
destroying it, which places this problem in the perfect-detection stationary-target regime — the
1957 problem — and is why the additive constants of the sampling-control QCD literature, whose
models assume unobserved samples are lost, do not transfer.
