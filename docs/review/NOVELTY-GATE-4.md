# Novelty gate 4 — the CLF contract — 2026-08-30

Adversarial gate run BEFORE building the CLF evaluation. **Verdict: SERIOUS, one notch below
FATAL.** No system was found maintaining per-CLASS presence sets per link — that alone keeps this
alive. But the contract decomposes into four ideas and every one has separate published prior art,
including a granted patent covering the action half.

## 1. We were arguing against the wrong baseline

The contract's load-bearing sentence was that `TX & ~RX` catches a total context blackhole "which
sequence-continuity detection structurally cannot see". True, and beside the point. Nobody will
bring sequence continuity as the comparator. **They will bring two counters per (link, class)**,
where `TX_count > 0 && RX_count == 0` detects a dark context perfectly well — and per-class
link-scoped counters are standardised prior art we ourselves documented in `NOVELTY-GATE-3.md`
(RFC 6374 §2.9.1/§3.1, Y.1731 §8.1, published 2011).

Against that baseline the frontier is **a 1-bit-per-context lossy compression of a counter pair that
already exists in a standard**, and it buys exactly two things:

1. **Bit cost** — 1 bit versus 32/64 per context per epoch.
2. **Immunity to epoch-boundary skew — and this is the real argument, which the contract never
   made.** Counter differencing across a link is broken by packets in flight at the boundary. Both
   nearest systems say so themselves: LossRadar §3.4 — *"no matter how accurate the time-sync
   protocol can ensure, there could always be packets on the fly... batch disagreement is
   inevitable"*; FlowRadar §6.2 — *"there are always packets on the fly"*. **A presence bit is
   monotone within an epoch**: one arriving packet sets RX, so boundary skew cannot fabricate a
   blackhole. A counter difference can.

**We have measured exactly this.** `docs/review/artifacts/HW-CLF-CONGESTION-RACE.md` records the
IMPOSSIBLE state (`TX=0, RX=1`) produced by zeroing while packets were in flight, reproduced
deliberately from background traffic on an idle fabric, and eliminated by a guard interval. That is
a hardware demonstration of the precise phenomenon that makes presence bits better than counters. It
was recorded as a harness defect; it is also the strongest technical evidence for the design.

**Honest limit:** FlowRadar §6.1 already states the presence-beats-counters insight at FLOW
granularity — *"we do not need the counters, but only the flow information to detect blackhole"*
(NSDI'16). We are applying a known insight at a new granularity and must cite it in the sentence
where we make the argument, not in related work.

## 2. The action half is a granted patent, and this corrects gate 3

**US 9,161,259 B2** (Cisco, filed 2013, granted 2015). Abstract, verbatim: *"comparing the current
bandwidth characteristic with a preconfigured low watermark corresponding to a class-specific MTR
topology associated with a class of traffic traversing the link, and removing the link from the MTR
topology"*. Per-class quarantine of a directed link triggered by that link's measured degradation,
with other classes retaining it, shipping in Multi-Topology Routing (RFC 4915 / RFC 5120).

`NOVELTY-GATE-3.md` concluded that no standardised chain carries a (link x class) pair past the
counter stage into action. **That is true of the ITU-T G.803x chain it examined and false of the
IETF MTR chain.** Recorded here rather than edited away, per repo convention.

**What survives is one hinge:** the patent's evidence is a SCALAR link property (bandwidth under
fading); the class enters only through a class-specific *watermark*. The class never supplies its
own evidence. So our distinction reduces to exactly this — **the evidence must be per-class, or we
have nothing** — and that sentence must appear in the paper, with this patent cited.

## 3. Per-directed-link TX/RX set differencing is a named research family

ChameleMon (SIGCOMM'23) §1 names it: LossRadar, NetSeer, Dapper *"carefully designed to only obtain
the exact difference set"*.

**LossRadar (CoNEXT'16) is far closer than assumed.** §4.1: *"one upstream meter at each output port
of every switch, and one downstream meter at each input port... both directions of every link are
covered"*. It is per directed link, it is a set difference, and its cost scales with losses not
traffic (§3.2). Three real differences, all of which must be stated explicitly:

1. **Granularity** — its digest entry is a per-PACKET 120-bit signature, not a per-class presence
   bit. A reviewer will propose setting the signature to our context ID; that degenerates the IBF to
   16 counters, i.e. back to RFC 6374. Pre-empt this by name.
2. **Placement is the deliberate opposite of ours.** §4.1: meters go *"before the shared buffer"*,
   because LossRadar WANTS buffer drops inside the difference to classify congestion. Our post-TM
   placement excludes our own queueing so `TX & ~RX` is link-attributable. Claim this as SEMANTICS
   ("TX means committed to the wire"), not as novelty.
3. **It degrades in exactly our regime** — §3.3: above loss rate R *"we can still report the total
   number of losses per port, but may fail to identify individual lost packets"*, and *"it is much
   more crucial to take urgent action... (e.g., shut down the link)"*. One dark context of 16 is ~6%
   link loss, ~60x their R = 0.1% bound. **But be honest: that is a PROVISIONING argument, not
   impossibility.** LossRadar sized for it would recover the same information. Our claim is COST
   (3-4 orders of magnitude), not capability — and "cheap, clean and decisive" is exactly the shape
   this repo's own rule flags as suspicious.

## 4. Two claims to delete outright

- **The K-bit lower bound.** "Distinguishing 2^K subsets needs K bits" is pigeonhole, not a
  tomography result, and it is FALSE under sparsity: with at most d dark contexts, combinatorial
  group testing needs O(d log(K/d)) bits. A reviewer with coding-theory background will say the
  frontier is provably wasteful. Keep one sentence: uncompressed on purpose because K is small and
  decoding must be zero-cost in the data plane.
- **O(L) versus O(L x K) frontier traffic.** LossRadar's healthy-state upload is also O(links)
  (§7.1: 2.9 Mbps at 0.1% loss on 10 Gbps). We are contrasting against a strawman nobody built.
  Restate as bytes-per-link-per-epoch, where we genuinely win, or drop it.

## 5. The one FATAL vector still open

**dShark (NSDI'19) could not be retrieved** — four mirrors returned 403/404. Its grouping
abstraction takes user-defined group keys over header fields. **If its published query set includes
a per-link, group-by-DSCP loss query, the measurement half at class granularity is occupied by a
2019 NSDI paper.** Mitigating: it processes mirrored traces on commodity servers, not in-switch
state, and takes no action — which caps it at SERIOUS under our own rubric. **Retrieve the PDF and
read §3 plus the case studies before drafting.**

Also unretrieved: **dDrops** (paywalled; source at `github.com/AntLab-Repo/dDrops`). Our
characterisation of it in `VERIFICATION-2026-08-29.md` is consistent with the abstract but is NOT
verified against the paper. And **Speedlight (SIGCOMM'18)** — synchronised snapshots would
neutralise our epoch-skew argument for counter schemes if an operator deploys it; worth ten minutes.

## 6. The reduced claim that survives

> Loss evidence and loss mitigation are both routinely made class-aware, and independently: carrier
> and transport OAM measure frame loss per class on a link-scoped maintenance entity (Y.1731 §8.1;
> RFC 6374 §2.9.1-§3.1), while multi-topology routing removes a degraded link from one class's
> topology and leaves it in others' (US 9,161,259 B2). What is absent is the JOIN. In MTR the trigger
> is a scalar link property compared against a class-specific watermark; the class never supplies its
> own evidence. Symmetrically, the difference-set detectors that do produce link-local evidence —
> LossRadar's per-packet invertible-Bloom digests at each output and input port (§4.1), FlowRadar's
> per-flow presence sets across hops (§6.1) — key that evidence on packet or flow identity and
> terminate at a report. CLF is the join: a K-bit presence set per directed link per epoch over a
> SOURCE-DECLARED behavioural context, whose bits index the mitigation as well as the evidence. Two
> properties place it outside the prior constructions. First, the context is computed in the data
> plane from the packet's own properties INCLUDING SIZE, which no labelled scheme can express (MEF
> 35.1 §8.4 restricts a SOAM PM CoS ID to VLAN or VLAN+PCP). Second, we operate under per-packet
> spraying, the regime Y.1731 Appendix VII concedes its own measurement cannot attribute, and in
> which a fully dark context puts a link two orders of magnitude above LossRadar's design bound,
> where by its authors' account it degrades to a per-port loss count. The frontier costs K bits
> whatever the loss volume, and — unlike the counter pair it compresses — a presence bit is monotone
> within an epoch, so it is immune to the packets-in-flight boundary skew that both LossRadar (§3.4)
> and FlowRadar (§6.2) identify as the fundamental obstacle to differencing across a link.

## Required edits elsewhere

1. Amend `NOVELTY-GATE-3.md`: its no-action-past-counters conclusion is wrong for IETF MTR.
2. Stop using "sequence continuity cannot see a dark context" as the motivating contrast; use the
   counter baseline and the epoch-skew argument.
3. Delete the K-bit lower bound and the O(L) vs O(LK) claim from `sim/clf/PREREG.md` decision rule 6.
