# Comparison with prior work — Related Work positioning for the MCP measurement paper (2026-09-03)

Structured positioning of MCP against the full prior-art landscape, built on the primary sources
already read and cited in the repo's novelty gates (`NOVELTY-GATE.md`, `-2`, `-3`, `-4`, `-DSHARK`,
`-HEALING-2026-09-02`, `-IDENTIFIABILITY-2026-09-02`), the contribution-framing memo
(`CONTRIBUTION-FRAMING-2026-09-02.md`), and the two empirical head-to-heads
(`artifacts/BASELINE-COMPARISON-2026-09-02.md`, `artifacts/LOCALIZATION-COMPARISON-2026-09-02.md`).
This is synthesis for the Related Work section, not a novelty claim. Every cell is populated from the
cited primary source; axes a system does not target are marked **not addressed**, not invented.

**Adversarial reading rule (self-imposed):** the mechanism/primitive MCP uses — a per-directed-link
(tx, rx) witness — is **conceded prior art** (NetSeer, LinkGuardian, LossRadar, UEC LLR, RFC 6374,
dShark's ingress-vs-egress query). The gates retire it in writing. What MCP contributes is a
**measured detection+localization characterization** on a sprayed fabric at the low-loss regime where
the passive state of the art collapses, at a measured 2 B/packet cost. Any sentence here that reads
as "new primitive" is a desk-reject per `CONTRIBUTION-FRAMING-2026-09-02.md` and must be cut.

---

## 1. Comparison table

The nine axes that matter for this paper are split across two sub-tables sharing an identical row
order (one table with nine data columns is unreadable). Table 1 covers the detection/identifiability
axes; Table 2 covers the cost/action axes. Rows are grouped by family (see §2). "DL" = directed link.

### Table 1 — mechanism, vantage, and behaviour under spraying / at low loss

| System (venue, year) | Mechanism / primitive | In-network vs host | Active-probe vs passive | Per-DL granularity | Support under per-packet spraying / multipath | Low-loss detect (1e-3–1e-4) + cost scaling |
|---|---|---|---|---|---|---|
| **MCP (this paper)** | Per-DL (tx, rx) witness stamp + frozen e-BH localizer | **In-fabric** (Tofino) | Passive-observe of a **stamped** stream (witness is in-band, not a probe) | **Yes — exact DL** | **Yes** — witness rides each sprayed packet; holds each DL's own tx | **Detects 100 %/FP-0 at 1e-3 and 1e-4**; median ~22 M pkts **flat across 4 orders** — **Θ(1)** [BASELINE-COMPARISON] |
| NetSeer (SIGCOMM'20) | 4 B egress per-DL sequence number; downstream ingress sees the gap | In-fabric (Tofino) | Passive (in-band seq) | **Yes — exact DL** | Not addressed (fixed-routing DC telemetry; **not evaluated on a sprayed fabric at this regime**) | Loss revealed at next surviving packet → Θ(1) in principle; **not measured at 1e-3–1e-4 under spraying** |
| LinkGuardian (SIGCOMM'23) | 3 B per-port seqNo + era bit + self-replenishing dummy packet | In-fabric (Tofino) | Passive (in-band seq) | **Yes — exact DL (per port)** | Not addressed (per-link recovery; not a spray-localization study) | Gap detected at next packet → Θ(1); not characterized at this regime under spraying |
| LossRadar (CoNEXT'16) | Up/down meters per DL; per-packet 120-bit IBF signature; difference set | In-fabric (switch meters) | Passive (in-band digest) | **Yes — exact DL** | Not addressed (fixed routing) | IBF decodes individual losses only **below ~0.1 % (§3.3)**; above that degrades to a per-port count — a **provisioning** bound, not impossibility |
| UEC LLR (UEC 1.0.2 §5.1) | Per-link seq in MAC preamble; NACK on next frame; per-port counters | In-fabric (MAC) | Passive (in-band seq) | **Yes — exact DL** | Standardized into the sprayed-fabric MAC, but no published spray-regime localization measurement | Next-frame NACK → Θ(1); not independently measured at 1e-3–1e-4 |
| RFC 6374 counter pair | TX/RX loss counters, per-link or per-class ME (`T`-bit) | In-fabric (counters) | Passive | **Yes if ME = DL** | Appendix-VII-class attribution problem: Y.1731 concedes LM cannot attribute when frames are sprayed | `TX>0 & RX==0` sees a dark context; **epoch-boundary skew** (packets in flight) fabricates/hides at low counts — Θ(1) but skew-limited |
| **SprayCheck (arXiv:2605.03702)** | Passive per-(src-leaf, spine) RX counts; one-sided deficit test; cross-leaf intersection | In-fabric counts, **central monitor** decides | **Passive** | Via cross-leaf intersection only | **Yes — designed for spraying** (decomposes a flow into k per-spine tests) | **Detects at 1e-3 (78 %, CI[0.65,0.87]); collapses at 1e-4 (0.00)**; median 24 M→114 M pkts, action rate 100 %→78 %→0 % — **~Θ(1/p)** [BASELINE-COMPARISON] |
| **FlowPulse (HotNets'25)** | Passive learned "temporal-symmetry" RX-load model per port; deviation test | In-fabric counts + learned model | **Passive** | Per-port, via its all/one-sender rule | Yes for detection; uplink signal **diluted ~1/senders** under multi-sender sprayed ports | **Fails at 1e-3 and below (0.00)**; partial at 0.5 % (0.38); 1 % threshold floor — degrades **faster than SprayCheck** [BASELINE-COMPARISON] |
| dShark (NSDI'19) | Host-side analysis over **mirrored per-hop traces**; group-by user keys; TTL path recovery | **Host-based** (commodity collectors) | Passive **post-hoc** (mirrors live traffic) | Hop, via recovered path (`ipv4[:].ttl`) | Group keys are user-defined; not a spray-attribution study; blackhole query needs a TCP retransmit | Detects/localizes silent blackholes; not a low-loss-under-spray cost study; **capture drops bury real drops** |
| NetBouncer (NSDI'19) | Active end-host probes; per-link **scalar** success probability | Host-based probing | **Active** | Per-link (one scalar/link) | Header-based path selection; **per-packet spraying breaks path pinning** | Probing-cost model; treats a link as one resource (no size/class) |
| Boolean network tomography (Bartolini, ToN'20) | Identifiability bound from the routing/monitoring scheme; monitor-placement design | Theory (path measurements) | Passive/path | Identifiability limit, not a per-DL reading | Owns the "identifiability = routing structure" framing; spraying reduces to fractional/Boolean cases | Bound, not a detector — no loss-rate cost curve |
| OmniPath Ping (SIGCOMM'26) | In-network per-hop telemetry cache to resolve spray path ambiguity; service tracing | In-fabric cache | Active (ping/trace) | Per-hop | **Yes — explicitly "first diagnostic primitive under packet spraying"** (concurrent, one cycle ahead) | Tracing primitive; not a low-loss detection-cost study |
| CorrOpt (SIGCOMM'17) | Corruption rate per link → disable → repair-ticket → re-enable & watch | Host/controller + link counters | Passive rate + active re-enable | Per-link (scalar corruption rate) | Fixed-routing DC; link is end-to-end addressable | Detects corruption; **not** a sprayed-fabric low-loss localizer |
| Aegis (NSDI'25) | Production AI-cluster diagnosis; enhanced Pingmesh (varied probe sizes) | Host-based probing | **Active** | Path/probe-level | Minimizes core/agg probe traffic → **cannot audit spray-hidden inter-switch links** | 64 B probes missed a >1 KB-only fault (coverage, not low-loss cost) |
| REPS (arXiv:2407.21625) | UEC spray load-balancer; reroute-away <100 µs; cache good paths; re-explore | In-fabric LB | Reactive reroute | Not a localizer | **Yes — native to sprayed UEC fabrics**, but for *avoidance*, not attribution | No loss-localization primitive; reroutes on failure signal |

### Table 2 — localization under spraying, overhead, and restoration

| System (venue, year) | Localization granularity under spraying | Overhead (added wire bytes / switch state) | Restoration / healing |
|---|---|---|---|
| **MCP (this paper)** | **Exact DL, measured 1.00 (CI[0.93,1.00], set size 1.00) at every rate & both fault families** [LOCALIZATION-COMPARISON] | **2 B/packet** (width-reduced witness; 4 B in the full-width C1 ledger) ≈0.14–0.28 % load; **6 B/DL**, all 1024 DLs **continuously**; 11 ingress / 5 egress stages | **Not claimed as a result** — healing lifecycle is `NARROW` and its frontier may be vacuous (`GATE2-AUDIT-BUDGET.md`); out of this paper's claim |
| NetSeer (SIGCOMM'20) | Exact DL (by construction) — **not measured under spraying at this regime** | ~4 B/packet (per-port seq); per-port switch state; MMU-drop redirect for TM losses | No (telemetry only) |
| LinkGuardian (SIGCOMM'23) | Exact DL — not a spray-localization measurement | 3 B/packet; per-port state + buffered packets for retransmit | **Yes (packet-level)** — selective retransmission recovers the lost packet |
| LossRadar (CoNEXT'16) | Exact DL below ~0.1 % loss; **degrades to per-port count above it** | Per-packet 120-bit signature into IBF meters at every port; upload scales with **losses** (2.9 Mbps @0.1 %) | No |
| UEC LLR (UEC 1.0.2 §5.1) | Exact DL — no published spray-regime localization number | Seq in MAC preamble (in-standard); per-port counters | **Yes** — link-layer retransmission on NACK |
| RFC 6374 counter pair | Per-link or per-class if ME configured; spray attribution not supported | 0 added wire bytes (counters); per-(link/class) counter state; **skew-limited** | No |
| **SprayCheck (arXiv:2605.03702)** | **Exact DL by cross-leaf intersection at 1.0–1.5 % (ties MCP, honest null); ambiguous {uplink,downlink} 2-set at ≤0.5 %, collapses to the 2-set at 1e-3** [LOCALIZATION-COMPARISON] | **0 B/packet** (fully passive); <2 KB switch state **for one flow at a time**, round-robin (~1 min reset) | No |
| **FlowPulse (HotNets'25)** | **Ambiguous port-set or miss below 1.5 % for downlinks; misses uplink faults entirely under multi-sender spraying** [LOCALIZATION-COMPARISON] | **0 B/packet** (fully passive); switch SRAM not stated in the HotNets PDF | No |
| dShark (NSDI'19) | Hop on the recovered path — from **mirrored traces**, blackhole query needs a retransmit | **Mirrors full traffic to collectors** (3.33 Mpps/core target); no in-switch witness state | No (diagnoses; produces no handle to act on) |
| NetBouncer (NSDI'19) | Per-link scalar; no directed-link-under-spray resolution | Active probe traffic; end-host probing infrastructure | No (diagnosis) |
| Boolean network tomography (Bartolini, ToN'20) | Identifiability bound; monitor-placement design (not a per-DL reading) | n/a (analysis) | No |
| OmniPath Ping (SIGCOMM'26) | Per-hop, resolves spray ambiguity (concurrent) | In-network cache state + ping probes | No (tracing) |
| CorrOpt (SIGCOMM'17) | Not a sprayed-fabric DL localizer | Re-enable/observe loop in production traffic (**unpriced**, §5.2) | **Yes** — disable **both directions** → repair → re-enable & watch → relapse re-disable |
| Aegis (NSDI'25) | Path/probe-level; cannot reach spray-hidden inter-switch links | Generated audit workload from hosts (not switch-capped) | **Yes** — quarantine → generated-workload audit → certified return |
| REPS (arXiv:2407.21625) | Not a localizer | In-fabric LB state; reroute cost | **Yes** — reroute-away + later re-explore (no priced audit, no `INCONCLUSIVE`) |

Provenance for every cited fact is in §4. Bold cells are the axes on which MCP's measured advantage
(or its honest ties/nulls) lives.

---

## 2. Positioning narrative — four families, and where MCP honestly sits

**Family A — in-network / in-fabric loss witnesses (NetSeer, LinkGuardian, LossRadar, UEC LLR,
RFC 6374 counter pair).** These own the **primitive** MCP uses. NetSeer's four-byte egress
per-directed-link sequence number checked at the downstream ingress is, verbatim (`NOVELTY-GATE.md`
gate 2), the M2 witness; MCP's 4 B candidate is NetSeer's exact encoding and its 2 B candidate is a
width reduction. LinkGuardian's era bit and self-replenishing dummy packet are the published answers
to MCP's wrap and idle-tail work items. LossRadar already places up/down meters on **both directions
of every link** and takes a set difference. UEC standardizes the same per-link sequence into the MAC.
RFC 6374 already exposes a per-link (and per-class) TX/RX counter pair. **MCP claims none of this as
novel.** What this family does *not* do is report, on a **packet-sprayed** fabric, what a per-directed-link
witness buys and costs **at the 1e-3–1e-4 low-loss regime** — NetSeer/LinkGuardian/UEC were never
evaluated there under spraying, and LossRadar's own §3.3 says its per-packet decode degrades to a
per-port count two orders of magnitude *above* a fully-dark context. That measurement is MCP's slot.

**Family B — passive sprayed-fabric detectors (SprayCheck, FlowPulse).** These are the two directly
comparable systems and the primary external threat — same target regime, same author group
(Krebs/Amir/Landau Feibish/Silberstein), 0-byte fully passive. They are the honest yardstick, and MCP
does **not** dominate them on their own currency (added load): they pay 0 B/packet, MCP pays 2 B.
Where MCP's measured advantage is real is (i) **detection cost-scaling** — MCP's packets-to-detect is
flat (~22 M) across four orders while SprayCheck's grows ~Θ(1/p) (24 M→114 M, action rate 100 %→78 %→0 %)
and FlowPulse fails below ~0.5–1 %; and (ii) **localization** — SprayCheck's cross-leaf intersection
ties MCP at 1.0–1.5 % (reported as an honest null) but degrades to the exact {uplink, downlink} 2-set
both papers concede a single passive vantage cannot resolve at ≤0.5 %, and FlowPulse cannot localize
uplink faults at all under multi-sender spraying. Both gaps are **information-structure consequences**
(MCP holds each directed link's own transmit count; they do not), not inference advances — and MCP's
own localization artifact says so in writing. The contribution is quantifying that property's **price
and payoff on silicon against faithful baselines**, not a cleverer inference.

**Family C — active probing and tomography (dShark, NetBouncer, Aegis's Pingmesh, OmniPath Ping,
Boolean network tomography).** dShark already **localizes silent black holes** from mirrored per-hop
traces (Table 2, "Silent black hole localizer"), and its ingress-vs-egress-existence query is the same
*idea* as TX-vs-RX — so MCP claims no capability novelty over it, only **cost and actionability**
(two 8-bit registers per sublink in-switch vs a mirroring fleet, and a rerouteable resource vs a
diagnosis with no handle). NetBouncer models a link as one scalar success probability and pins paths
by header — which per-packet spraying breaks. Bartolini (ToN'20) owns the "identifiability is bounded
by the routing/monitoring scheme" framing, and OmniPath Ping (SIGCOMM'26, concurrent) owns the
"spraying causes path ambiguity; in-network per-hop telemetry resolves it" problem statement in the
target venue. Because C is occupied on both the framing and the primitive, MCP **cannot** be pitched
as a new identifiability bound or a new spray-diagnosis primitive (`NOVELTY-GATE-IDENTIFIABILITY`:
FAIL). It is pitched as a measurement.

**Family D — repair / restoration systems (CorrOpt, Aegis, REPS).** These close the loop but assume
the faulty resource is end-to-end addressable: CorrOpt disables **both directions** and re-admits with
real traffic; Aegis audits with **host-generated** workload that, by its own account, minimizes core/agg
traffic and so structurally **cannot reach a spray-hidden inter-switch link**; REPS reroutes away and
later re-explores with real data. **None can place congruent evidence on a directed link that spraying
has emptied.** That gap is the *healing* survivor (`NOVELTY-GATE-HEALING`, NARROW) — but its result is
unproven and possibly vacuous, so **this paper does not claim restoration**; family D is cited to bound
what MCP's detection/localization enables, not as an MCP result.

**Where MCP sits, stated honestly.** MCP is **not** a new witness primitive (Family A owns it), **not**
a new spray-diagnosis primitive or identifiability bound (Family C owns those), and **not** a
restoration system (Family D, and MCP's own healing result is gated). MCP is the **first faithful,
primary-source-grounded head-to-head** of the two newest passive sprayed-fabric detectors against an
in-fabric per-directed-link witness, on the regime all three target, **quantifying on real Tofino
silicon** what a 2 B/packet witness buys — flat 100 %/FP-0 detection and exact single-directed-link
localization across four orders of magnitude where the passive state of the art's cost grows ~Θ(1/p)
and its localization collapses to the {uplink, downlink} 2-set — and what it costs (~0.14 % load, a
12-stage ingress footprint with no headroom). The disambiguating power is an information-structure
property, not an inference advance; the contribution is measuring that property's price and payoff.
This is a **ToN/IMC-tier characterization**, and overclaiming it as a primitive is a desk-reject
(`CONTRIBUTION-FRAMING-2026-09-02.md`).

---

## 3. The 3–4 closest systems — the single distinguishing axis for each

- **SprayCheck (arXiv:2605.03702) — passive; collapses below ~1e-3 and aliases the directed link.**
  The one axis: SprayCheck detects at 1e-3 (78 %) but its packets-to-detect grows ~Θ(1/p) and its
  action rate hits 0.00 at 1e-4, and its cross-leaf intersection degrades to the exact {uplink,
  downlink} 2-set at ≤0.5 %, where MCP stays flat and exact — at the cost of the 2 B/packet SprayCheck
  does not pay. (Detection + localization measured, honest 1.0–1.5 % tie reported.)

- **FlowPulse (HotNets'25) — passive; a 1 % threshold floor and uplink dilution under multi-sender
  spraying.** The one axis: FlowPulse's learned temporal-symmetry test fails at 1e-3 and below and
  **cannot localize (or even detect) an uplink fault** once a single sender's loss is diluted ~1/senders
  below its 1 % floor — a property of the sprayed fabric MCP targets, reproduced faithfully, not a
  handicap imposed on the baseline.

- **NetSeer (SIGCOMM'20) — same primitive, never measured on a sprayed fabric at this regime.** The
  one axis: NetSeer *is* MCP's witness encoding, so MCP concedes the mechanism entirely; the
  distinction is purely the **measured characterization** — NetSeer reports no packets-to-detect-vs-loss-rate
  curve and no localization accuracy under per-packet spraying at 1e-3–1e-4, which is exactly the gap
  MCP fills.

- **dShark (NSDI'19) — post-hoc host-side trace analysis, not an in-fabric live witness.** The one
  axis: dShark localizes the same silent-blackhole class (so MCP claims no capability novelty), but
  does it by **mirroring full traffic to commodity collectors** (3.33 Mpps/core, capture drops can
  bury real drops) and produces no handle to act on; MCP does it with two 8-bit registers per sublink
  **in the switch**, mirroring nothing, on a resource the data plane can reroute.

(Family-D repair note, for the one-liner a reviewer will want: **CorrOpt (SIGCOMM'17) / Aegis
(NSDI'25)** are repair systems whose re-admission re-runs real or host-generated traffic and therefore
**cannot reach a directed link that per-packet spraying has starved of traffic** — the gap MCP's
per-directed-link vantage exposes but this paper does not attempt to close.)

---

## 4. Provenance (title, venue, year — primary sources)

All read/verified in the cited gates unless marked "verified this session (2026-09-03)".

- **NetSeer** — Zhou et al., *Flow Event Telemetry on Programmable Data Plane*, ACM SIGCOMM 2020,
  doi:10.1145/3387514.3406214. (§3.3 verbatim in `NOVELTY-GATE.md` gate 2.)
- **LinkGuardian** — *LinkGuardian* (per-port seqNo + era bit + dummy packet), ACM SIGCOMM 2023,
  doi:10.1145/3603269.3604853. (`NOVELTY-GATE.md` gate 2.)
- **LossRadar** — Li, Miao, Kim, Yu, *LossRadar: Fast Detection of Lost Packets in Data Center
  Networks*, ACM CoNEXT 2016, pp. 481–495. Full cite verified this session. (§3.3, §4.1 in
  `NOVELTY-GATE-4.md`.)
- **UEC LLR** — Ultra Ethernet Consortium Specification 1.0.2, §5.1 Link Layer Retry.
  (`NOVELTY-GATE.md` gate 2.)
- **RFC 6374** — Frost & Bryant, *Packet Loss and Delay Measurement for MPLS Networks*, IETF, 2011
  (§2.9.1–2.9.2, §3.1 `T`-bit). (`NOVELTY-GATE-3.md`, `-4.md`.)
- **SprayCheck** — Krebs, Amir, Landau Feibish, Silberstein, arXiv:2605.03702 (§3.6 uplink/downlink
  ambiguity + cross-leaf intersection; §4.2 per-(src-leaf, spine) counts). (`NOVELTY-GATE-IDENTIFIABILITY`,
  `BASELINE-COMPARISON`, `LOCALIZATION-COMPARISON`.)
- **FlowPulse** — Krebs, Gavrilenko, Amir, Landau Feibish, Silberstein, *FlowPulse: Catching Network
  Failures in ML Clusters*, ACM HotNets 2025 (§5.3 per-sender all/one rule; learned temporal-symmetry).
  Authorship/venue verified this session. (`LOCALIZATION-COMPARISON`, `BASELINE-COMPARISON`.)
- **dShark** — Yu et al., *dShark: A General, Easy to Program and Scalable Framework for Analyzing
  In-network Packet Traces*, USENIX NSDI 2019, pp. 207–220 (Table 2 blackhole localizer; ingress/egress
  existence query). (`NOVELTY-GATE-DSHARK.md`, primary PDF read.)
- **NetBouncer** — Tan et al., *NetBouncer: Active Device and Link Failure Localization in Data Center
  Networks*, USENIX NSDI 2019 (§4.1 scalar per-link success probability). (`NOVELTY-GATE-3.md`, `.md` 1b.)
- **Boolean network tomography** — Bartolini, He, Arrigoni, Massini, *On Fundamental Bounds of Failure
  Identifiability by Boolean Network Tomography*, IEEE/ACM ToN 2020, arXiv:1903.10636.
  (`NOVELTY-GATE.md` 1b, `-IDENTIFIABILITY`.)
- **OmniPath Ping** — Yang et al., ACM SIGCOMM 2026, doi:10.1145/3789240.3829105 (in-network per-hop
  cache to resolve spray path ambiguity). (`NOVELTY-GATE-IDENTIFIABILITY`, abstract verified.)
- **CorrOpt** — Zhuo et al., *Understanding and Mitigating Packet Corruption in Data Center Networks*,
  ACM SIGCOMM 2017, doi:10.1145/3098822.3098849 (§5.2 disable-both-directions / re-enable loop).
  (`NOVELTY-GATE-HEALING-2026-09-02.md`.)
- **Aegis** — Dong et al., *Evolution of Aegis: Fault Diagnosis for AI Model Training Service in
  Production*, USENIX NSDI 2025 (§4.2 >1 KB-only fault, 64 B Pingmesh miss, enhanced probe sizes).
  (`NOVELTY-GATE-2.md`, `-HEALING`; USENIX PDF verified by PI.)
- **REPS** — *REPS* (Ultra Ethernet spray load balancing; reroute-away <100 µs, cache/re-explore),
  arXiv:2407.21625, 2025. (`NOVELTY-GATE-HEALING-2026-09-02.md`.)
- **US 9,161,259 B2** — Cisco, granted 2015 (per-class MTR link removal on a class-specific watermark;
  Family-D adjacency, cited to forestall the "MTR already does per-class quarantine" attack).
  (`NOVELTY-GATE-4.md` §2.)

Empirical numbers are from `artifacts/BASELINE-COMPARISON-2026-09-02.md` (detection, 50 seeds/rate,
Wilson CIs) and `artifacts/LOCALIZATION-COMPARISON-2026-09-02.md` (localization, 50 seeds, McNemar).
MCP overhead numbers are hardware-compiled (`artifacts/LEDGER-COMPILE-GATE.md`), not estimated.
