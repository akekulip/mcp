# The observation model and the coverage bound (M1 step 1, draft for adversarial review)

Status 2026-08-28. This file exists to be attacked. It states the observation model precisely,
proves the coverage claim, gives the matching construction, and then argues *against itself* — the
plan's novelty gate (`docs/review/PLAN.md`) requires an independent verdict on whether this is a
nontrivial result or a classical adaptive-search lemma wearing a fabric costume. Nothing here may
be cited as a contribution until that verdict exists.

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

## 3. The coverage claim

> **Proposition (coverage delay).** Suppose the unread links are *observationally exchangeable*:
> conditioned on everything a counter-computable policy has read up to epoch $t$, the posterior over
> which unread link is faulty is the restriction of $\pi$ to the unread set. Then for uniform $\pi$,
> any counter-computable policy with budget $B$ has
> $$\mathbb{E}[T - \tau_{\mathrm{ev}}] \;\ge\; \frac{n - B}{2B} \quad\text{epochs},$$
> and no policy in the class does better than round-robin.

*Proof sketch.* Under exchangeability the policy's read history carries zero information about
which unread link is faulty, so at every epoch each unread link is equally likely to be $f$. The
policy therefore cannot do better than to read unread links; the epoch at which $f$ is first read
after $\tau_{\mathrm{ev}}$ is then uniform over the $\lceil n/B \rceil$ rounds needed to cover $E$,
giving mean $(n-B)/2B$. Localization cannot precede that first read, because before it the
detector's statistic for $f$ is its prior value. $\square$

**Tightness.** Round-robin attains it: it covers $E$ every $\lceil n/B \rceil$ epochs, so the wait
for $f$ is uniform on that window and has exactly that mean. The bound is therefore tight and is
achieved by the most trivial schedule in the class. At the frozen operating point
$(n, B) = (1024, 41)$ it predicts $\approx 12$ epochs; uniform measures 10.0. **That agreement is
the strongest evidence for the claim and the strongest evidence against its depth**: nothing
cleverer than round-robin exists in this class, which is exactly what the replay measured across
five budgets and four fault regimes (H9, never tripped).

**When exchangeability fails.** It fails whenever the read history predicts observability — most
obviously through load: a link known to be idle cannot produce evidence, so skipping it is free.
This is real and measured: load-gated round-robin beats uniform at budget 82. It is also bounded:
the gain is 17 % of the oracle gap at $p = 0.56$, because in a sprayed fabric loads are nearly
equal across the links of a layer by construction. **Spraying is what makes the exchangeability
condition approximately true**, and the more perfectly a fabric sprays, the tighter the bound binds.

## 4. Why the fabric cannot be group-tested (the part worth arguing about)

Classical adaptive group testing localizes one defective among $n$ in $\Theta(\log n)$ tests, not
$\Theta(n)$, because a test may be applied to a *pool*. The obvious question is why that does not
apply here, and the answer is the interesting one:

- A per-link counter read is inherently a **singleton test**. It cannot be pooled.
- A flow's end-to-end evidence *is* a pooled test — the pool being the set of links the flow
  traversed. But under per-packet spraying every flow's pool is a uniformly random, near-identical
  subset of the layer. All pools have the same composition in expectation, so the pooled tests are
  mutually exchangeable and their outcomes are almost independent of *which* link is faulty. A
  design whose tests do not discriminate cannot localize, however many tests it runs.

So spraying — the property that makes these fabrics fast and gray failures hard — is precisely what
collapses the pooled-test design space and leaves only singleton tests, whose cost is the coverage
term above. The escape is not a better schedule but a **different observation**: make the loss
event itself name its link at the point of loss, which is what the post-TM order witness does
(H8/M2). Replayed, that observation ties the oracle at every budget from 1 % to 19.5 % and under
every fault regime that finishes within the horizon, because its evidence rides the packets and is
not budgeted at all.

## 5. What this does not claim

- It says nothing about evidence time, which dominates at low $p$ and is untouchable by any method
  in this paper, in-band included.
- It is proved for a single stationary fault under an exchangeability condition that a real fabric
  satisfies only approximately.
- Multi-fault and moving-fault results in `sim/gate/M1-REPLAY.md` are measurements, not theory.
- It is not a bound on bits or state, so nothing here licenses the word *minimal* or *optimal* for
  the witness; its cost is reported concretely (2 B or 4 B) instead.

## 6. The case against this being a contribution

Stated plainly, so a reviewer does not have to construct it:

1. The proposition is a coupon-collector / adaptive-search argument. Its proof is four lines and its
   tight construction is round-robin. If "adaptive inspection cannot beat exhaustive search when
   observations are uninformative about unexamined items" is already a lemma in the sequential
   analysis, controlled sensing, or active hypothesis testing literature — Chernoff's sequential
   design of experiments, Naghshvar–Javidi, Banerjee–Veeravalli's data-efficient quickest change
   detection with observation control, restless-bandit search — then this is a relabelling and must
   be demoted to an explanatory lemma in the design section.
2. The exchangeability condition is the only place the fabric enters, and it holds only
   approximately. A reviewer may reasonably say the honest statement is "loads are nearly equal, so
   nothing beats round-robin", which is an empirical observation, not a theorem.
3. The measured agreement (predicted 12, measured 10) is consistent with the bound but does not
   distinguish it from the trivial statement that you cannot find a thing before you look at it.

**The gate.** If an independent review finds only a textbook lemma, the coverage bound stays as the
explanation of *why the system is built this way* and is removed from the contribution list; the
paper then leads with the order witness, the equal-cost Pareto shift, and the bounded zoom. The
system claim does not depend on the theorem being novel — only on the decomposition being correct,
which it is, and measured.
