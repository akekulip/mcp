# Novelty gate 3 — carrier/transport OAM vs the behavioural sublink (2026-08-29)

> **CORRECTION, 2026-08-30 (see `NOVELTY-GATE-4.md`).** This gate concludes below that the
> standardised chain never carries a (link x class) pair past the counter stage into ACTION. That is
> true of the ITU-T G.803x chain examined here and **FALSE of the IETF MTR chain**: US 9,161,259 B2
> (Cisco, granted 2015) removes a link from a class-specific multi-topology-routing topology on
> measured degradation, leaving other classes on the same physical link. The surviving distinction is
> narrower than stated below — in MTR the trigger is a SCALAR link property against a class-specific
> watermark, so the class never supplies its own evidence. Recorded, not edited away.

Closes the item `NOVELTY-GATE-2.md` listed as unassessed. Two adversarial passes, both reading
primary standards rather than secondary descriptions. **Verdict: SERIOUS, not FATAL.** The
measurement half of the primitive is prior art; the action half is not, and the standards say so
in their own words.

## What is prior art — the measurement half

**ITU-T G.8013/Y.1731 §8.1**: a MEP keeps transmit and receive counters *"for each priority class
being monitored in a point-to-point ME"*. **§6.2 Table 6-1** defines link-scoped maintenance
entities ("Access link ME", "Inter-domain ME"). So per-(link, class) loss MEASUREMENT is
constructible entirely from standard parts.

**IETF RFC 6374** states it outright, and this is the sharper threat. Verified by the PI directly
against rfc-editor.org, not taken from the reviewing agent:

- §2.9.1 — *"Broadly, a channel in an MPLS network may be either a link, a Label Switched Path
  (LSP), or a pseudowire."*
- §2.9.2 — *"Packet loss can be measured with respect either to the channel as a whole or to a
  specific traffic class."*
- §3.1 — *"T: Traffic-class-specific measurement indicator. Set to 1 when the measurement operation
  is scoped to packets of a particular traffic class (DSCP value), and 0 otherwise."*

Published 2011. The claim "nobody makes (link, behaviour) addressable" is **false for measurement**
and must be deleted. RFC 6374 contains **no** protection, rerouting or mitigation text — also
verified directly.

## What is not prior art — the action half

The standardised chain is per-priority counters -> degraded-signal defect -> protection switch, and
it breaks at the SECOND step, earlier than we assumed:

- **G.8021 §6.1.3.4**: dDEG is *"only defined for point-to-point ETH connections"*, computed from
  one-second counters against a single threshold set (MI_LM_DEGM, MI_LM_M, MI_LM_DEGTHR,
  MI_LM_TFMIN). **It carries no priority index.** §9.2.1.2 indexes the defect list by maintenance
  entity, and where the standard does vector a defect it writes `dLOC[]` / `dRDI[]` — dDEG is bare.
  The class enters only as a FILTER: §8.1.7.4 counts frames *"with priority (P) ... equal to
  MI_CC_Pri"*. One priority in, one defect out, one `ETH_AI_TSD`.
- **§8.1.9.1** does keep per-CoS LM *results* — *"each result is independently managed per CoS
  level"* — but that is performance reporting to management. It produces no per-class defect and no
  per-class TSD.
- **G.8031 §7**: *"Other entities to be protected are for further study."* Protection acts on the
  whole VID-identified subnetwork connection.
- **G.8032 §7.1**: a transport entity is *"either failed [i.e., signal fail (SF)] or non-failed
  (OK)"*. There is no degraded state at all, and its subset behaviour is per-VID, never per-priority.

So the accurate statement is stronger than "detection standardised, action not": **the standardised
chain never carries a (link x class) pair past the counter stage, in either detection or action.**
To get per-class dDEG today you must instantiate a separate maintenance entity per class — at which
point the protected object is again a connection named by a label, which is exactly our point.

## Two gifts from the standards

**MEF 35.1 §8.4**: *"A SOAM PM CoS ID is limited to mechanisms that can be carried by a SOAM PM
Frame"*, and the permitted IDs are VLAN ID or VLAN+PCP. Standardised per-CoS OAM can only address
classes its own frames can carry as a LABEL. Packet size is not a label — it is the behaviour
itself — so the Aegis `>1 KB` failure mode is structurally outside what carrier OAM can express.

**Y.1731 Appendix VII** concedes that ETH-LM *"requires frame ordering preservation"*, that counted
frames *"may be forwarded onto different aggregated links ... even if they are all transmitted in
the same VID and at the same priority"*, and recommends flow-aware hashing *"(i.e., all traffic in a
given flow is placed on the same aggregated link)"*. **The standard tells you to pin flows so that
its own mechanism works, and a sprayed fabric is defined by not doing that.**

## The claim, reduced to what survives

> Carrier and transport OAM already measure frame loss per class of service, and can do so on a
> link-scoped maintenance entity (Y.1731 §8.1, §6.2 Table 6-1; RFC 6374 §2.9.1-2.9.2, §3.1). What
> none of them does is make that pair an object of control: G.8021 collapses per-priority counters
> into a single per-ME degraded-signal defect over one configured priority, G.8031 switches the
> whole VID-identified connection and says other entities are "for further study", and G.8032 has
> no degraded state at all. The behavioural sublink is therefore not a new measurement. It is the
> claim that the same (directed link x behaviour) key indexing the loss witness also indexes the
> mitigation, so one class can be quarantined on one directed link while other classes keep using
> it. Two properties place it outside the standardised construction: the class is computed in the
> switch from packet properties INCLUDING SIZE rather than read from a label, which carrier OAM
> structurally cannot express; and we operate under per-packet spraying, the regime Y.1731's own
> Appendix VII concedes its measurement cannot attribute.

## Counterattacks to pre-empt in the paper

1. *"Deploy one VLAN per CoS and G.8031 protects per class."* True as a deployment trick. It makes
   the class part of the forwarding identity, multiplies control state per class per path, still
   cannot express packet size, and still does not survive spraying because Appendix VII's
   attribution problem is independent of VID. Say it before a reviewer does.
2. *"Per-class rerouting is ancient (DiffServ-aware MPLS-TE)."* Also true. **Do not claim per-class
   routing.** Claim the coupling: per-class routing decides where a class goes by POLICY; we decide
   where a class goes because that class's evidence ON THAT DIRECTED LINK says so.

## Also verified

**NetBouncer (NSDI'19) §4.1** models one scalar success probability per link — no packet class,
size or DSCP anywhere. This is the cleanest citation for "prior work treats a link as one resource".

## Evidence quality

Primary PDFs opened and read: G.8013/Y.1731 (06/2023), G.8021/Y.1341 (10/2010, plus the 2022 Amd. 1
and Amd. 2 republications), G.8031/Y.1342 (06/2011, 01/2015 in force, Amd. 1 03/2018), G.8032/Y.1344
(03/2020), MEF 35.1, RFC 6374, NetBouncer. RFC 6374's three load-bearing quotes were re-verified by
the PI independently. Not exhaustively ruled out: G.8031 Annex A state tables and appendices, and
G.8032 clauses 10-11 — a per-class trigger appearing only there, and in neither the scope, the
objectives, the conditions list nor the trigger list, is not a plausible failure mode.
Still secondary-only and not citable without a further pass: deTector, Deepview, proof-of-transit.
