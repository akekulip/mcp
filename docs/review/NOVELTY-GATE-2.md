# Novelty gate 2 — congruent probing and certified rehabilitation (2026-08-29)

Adversarial gate, run BEFORE building. Four claims tested; **three are dead or narrow**. The
decisive kill was verified independently by the PI against the primary source, not accepted from
the reviewing agent.

## Verdicts

| claim | verdict |
|---|---|
| 1. Congruence: probes cannot exclude failure modes they are not shaped like | **DEAD** |
| 2. Constant certification cost (`N*p -> ln(1/alpha)`) | **DEAD as stated**; survives as a lemma |
| 3. Counterfactual observability after selective mitigation | **NARROW** — composition survives |
| 4. Advance-only sequence resync | **DEAD** — RFC 3550 App. A.1 (2003) |

## Claim 1 is dead, and the killer is in our own venue family

**Aegis, "Evolution of Aegis: Fault Diagnosis for AI Model Training Service in Production",
NSDI'25 (Alibaba), §4.2.** Verified by the PI at
<https://www.usenix.org/system/files/nsdi25-dong.pdf>: they hit silent loss that **only drops
packets larger than 1 KB**, RDMA Pingmesh missed it because **all probing packets are 64 B**, and
their remedy was to **enhance Pingmesh to cover varied lengths of probes**. Premise, failure mode,
diagnosis and remedy, all published, on a production AI training cluster.

Reinforcing prior art: **Everflow (SIGCOMM'15)** already replays production packets as probes
preserving size and markings, already crafts probes with different 5-tuples specifically to test
whether drops are conditional, and already steers a probe across one chosen directed link.
**007 (NSDI'18)** and **Flock (2023)** both state that probe traffic is unrepresentative of data
traffic. **Gray Failure (HotOS'17)** names the general form: differential observability. **ITU-T
Y.1564 (2011)** standardises per-service test streams at the service's own frame size and CoS
markings. The observation is not ours to make.

## What actually survives, in order of strength

1. **Conditionality prevalence is unmeasured.** Aegis reports n=1 anecdotally, SprayCheck assumes
   uniform loss, CorrOpt models corruption as a scalar rate. What fraction of gray failures in a
   production sprayed fabric are size- or class-selective, and what is the miss rate of uniform
   probing against them? Empirical, unoccupied, and it is the motivation the paper needs.
2. **Directed-sublink congruent probe placement under per-packet spraying.** This is the one
   mechanism claim with a clean "the prior technique does not apply here" argument. Everflow steers
   by crafting 5-tuples and encapsulation-based source routing; under per-packet spraying,
   header-based path pinning no longer selects a path. Aegis's own remedy — more probe sizes from
   the host — diagnoses but cannot attribute to a directed link on a sprayed fabric, because the
   host cannot choose the link. Our capsule plus `tbl_audit_steer` place a size- and
   class-congruent probe on one chosen directed sublink from inside the fabric.
3. **Certified rehabilitation.** CorrOpt (SIGCOMM'17) §5.2 and Fig. 12 run the enable / observe /
   re-disable loop in production traffic and never price it. The safe replacement — a probe set
   declared BEFORE the drain so the receipt denominator is fixed, class-congruent because the
   mitigation that drained the link was class-scoped, and bounded by a stated confidence rather
   than an operator's judgement — is a composition nobody has assembled. Name it as a composition.

## Consequences for the write-up

- Cite Aegis, Everflow, 007 and Y.1564 in the INTRODUCTION, not buried in related work. A reviewer
  who knows Aegis and does not see it cited early will assume we do not know the area.
- Claim 2 becomes a lemma with the rule of three (Hanley & Lippman-Hanley, JAMA 1983) cited in its
  first sentence; BER confidence-level test time is standard telecom practice and ships in
  instrument manuals. In a contributions list it is a free rejection.
- Claim 4 becomes a footnote: "we apply the RTP §A.1 discipline to a dataplane witness." RFC 3550
  Appendix A.1 already has advance-only tracking, the permissible-gap credit, and a probation count
  before a source is declared valid. It remains worth IMPLEMENTING — it is free on silicon and makes
  our loss accounting exact — it is simply not a contribution.
- Behavioural sublinks as a controlled resource with selective mitigation (P1/P2) is untouched by
  this gate. Aegis diagnoses; it does not create a per-context resource that can be selectively
  rerouted.

## Verification quality

The Aegis quotes were confirmed by the PI against the USENIX PDF. CorrOpt, Everflow and Shadow
Configurations quotes were read from primary PDFs by the reviewing agent. The 007, Flock, SprayCheck
and Y.1564 wordings came from HTML renderings or search summaries and **must be checked against the
PDFs before appearing in a submission**. Deepview, NetBouncer, deTector, Y.1731 and proof-of-transit
were not assessed. **Y.1731 per-CoS OAM has since been assessed in full — see `NOVELTY-GATE-3.md`, verdict SERIOUS: per-(link, class) loss MEASUREMENT is standardised prior art and that half of the claim is deleted, but no standard acts on the pair.** deTector, Deepview and proof-of-transit remain secondary-only and are the next to check.
