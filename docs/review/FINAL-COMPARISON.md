# Final Comparison: Sealed Behavioral-Sublink Evidence

Date: 2026-08-31
Status: paper-ready comparison; implementation and silicon evidence verified, direct reimplementations
of external systems not claimed

## Result and claim boundary

The contribution is **not** a new observability primitive, the first silent-blackhole detector, the
first TX/RX comparison, or the first programmable-switch gray-failure detector. Those capabilities
are occupied by prior work. The defensible contribution is the following systems composition:

> A sealed behavioral-sublink evidence ledger turns exact post-TM departures and downstream arrivals
> into typed, fail-closed epoch records. A positive-departure/zero-arrival record is an immediate
> operational blackhole observation; nonzero gray loss is handled separately by an anytime-valid
> controller e-process. The record carries the same sublink identifier used by mitigation, but the
> remaining automatic restoration/controller lifecycle is not claimed complete.

The data plane contributes evidence, not physical root-cause discrimination. A valid loss record
means non-delivery between the two frontiers; it does not by itself distinguish a bad link from every
other cause in that interval.

## Comparison with the closest published systems

| System | Evidence and deployment | Reported capability | Timing / validity contract | Difference from this implementation |
|---|---|---|---|---|
| [NetSight (NSDI 2014)](https://www.usenix.org/conference/nsdi14/technical-sessions/presentation/handigol) | Per-packet postcards reconstructed as packet histories on servers | General path and switch-state diagnosis | History analysis after records are collected | A broader forensic substrate. The ledger keeps aggregate sublink counts and sends no per-packet postcard stream; it is not a replacement for NetSight's packet-level explanations. |
| [FlowRadar (NSDI 2016)](https://www.usenix.org/conference/nsdi16/technical-sessions/presentation/li-yuliang) | Compact in-switch encoding of all-flow counters, decoded at a remote collector | All-flow monitoring and collector-side applications | Periodic decoding; no sealed-evidence contract claimed on the paper page | Occupies compact presence/counter monitoring. The distinction is the directed behavioral-sublink key, exact frozen epochs, invalidity/censor types, and a decision tied to that key—not compact counting itself. |
| [Alternate Marking (RFC 9341)](https://datatracker.ietf.org/doc/html/rfc9341) and [Clustered Alternate Marking (RFC 9342)](https://datatracker.ietf.org/doc/html/rfc9342) | Packets are divided into alternately marked color blocks; counters at measurement points are compared for loss. RFC 9342 extends the method to multipoint/ECMP-style paths and clusters | Hybrid and end-to-end loss measurement over marked batches | Explicit marking periods and timing assumptions separate the block being counted from the block being read | The direct ancestor of bank/color epochs and count comparison. Neither banking nor counter differencing is claimed as new. Our narrower addition is a behavioral-sublink key, exact post-TM/downstream frontiers, typed receipt/censor provenance, and an anytime-valid decision over valid blocks. |
| [LossRadar (CoNEXT 2016)](https://www.cs.yale.edu/homes/yu-minlan/writeup/conext16.pdf) | Upstream and downstream directed-link meters encode packet identifiers into invertible-Bloom digests | Detects and identifies lost packets; covers both directions of every link under full deployment | Batch IDs plus a downstream timeout handle packets in flight and reordering | The closest TX/RX antecedent. Our counters do not recover packet identities. They instead use fixed 1 KiB state, post-TM committed-departure semantics, a bank stamped into each packet, a guard, and fail-closed epoch validation. |
| [Speedlight (SIGCOMM 2018)](https://www.vincen.tl/files/speedlight-sigcomm18.pdf) | Coordinated P4/control-plane protocol for causally consistent, approximately synchronous network-wide snapshots | Coherent snapshots of arbitrary data-plane state across switches | Explicit distributed snapshot protocol; reported microsecond synchronization | Stronger than our prototype for a distributed multi-switch cut. Our exact bank travels with packets and was proved on a single-chip loopback fabric; extending the seal across independent switches remains future work. |
| [dShark (NSDI 2019)](https://www.usenix.org/system/files/nsdi19-yu.pdf) | Queries over mirrored, distributed packet captures on commodity-server collectors | Its implemented query set includes an ingress/egress existence query and a silent-blackhole localizer | Handles capture noise in its multi-packet analysis; the paper reports more than 10 Mpps analysis throughput | Directly occupies blackhole localization and departure/arrival comparison as capabilities. Our difference is acquisition and record semantics: in-switch aggregate state rather than a capture fleet, plus an action-indexed, fail-closed epoch certificate. |
| [NetSeer (SIGCOMM 2020)](https://rmiao.github.io/assets/pdf/netseer-sigcomm20.pdf) | Flow-event detection, compression, batching, and reporting inside the programmable data plane | Detects flow events including packet drops, congestion, path changes, and pauses | Event-driven telemetry; reports 0.01% of original traffic to storage after in-switch reduction | Occupies programmable data-plane drop telemetry and link sequence evidence. Our C-W4 witness is therefore treated as prior art; the final mechanism's additional object is the sealed count ledger and its statistical decision, not a new sequence witness. |
| [FANcY (SIGCOMM 2022)](https://discovery.ucl.ac.uk/id/eprint/10158039/) | In-network gray-failure detector for ISP networks, implemented on Intel Tofino | Detects and localizes tiny affected traffic fractions in seconds and demonstrates fine-grained fast rerouting | Fast in-network detection; no claim here about its internal validity rules beyond the primary-source abstract | Directly occupies programmable-switch gray-failure detection and mitigation. Our narrower distinction is per-behavioral-sublink frozen evidence, explicit censor/repair semantics, and a controller-side anytime-valid test in a sprayed-fabric emulation. |
| [dDrops (Computer Networks 2022)](https://www.sciencedirect.com/science/article/abs/pii/S1389128622002742) | Adjacent programmable switches use packet IDs, recent packet-feature buffers, notifications, and dynamic memory allocation; implemented on Tofino and BMv2 | Detects and locates silent drops with packet details; reports detection within 5 ms | Packet-level recovery is bounded by available buffer during long continuous loss | Directly occupies fine-grained P4 silent-drop detection. Our ledger deliberately gives up packet identity for fixed aggregate state, auditable epoch closure, and a calibrated gray-loss decision. |
| [LinkGuardian (SIGCOMM 2023)](https://ayushmishra.net/pdfs/sigcomm23-linkguardian.pdf) | Link-local sequence numbers, switch buffering, retransmission requests, and dummy packets expose and recover corruption losses; implemented on Intel Tofino | Sub-RTT link-local packet-loss recovery while preserving packet order; dummy packets expose tail gaps without a retransmission timeout | Per-packet sequence/liveness protocol coupled directly to recovery | Occupies link-local sequence/liveness handling and recovery, so the C-W4 witness is not novel. Our ledger does not retransmit or preserve order; it instead certifies aggregate behavioral-sublink health, separates total from gray loss, and fails closed on invalid epochs. |
| [NetBouncer (NSDI 2019)](https://www.usenix.org/system/files/nsdi19spring_tan_prepub.pdf) | End hosts actively probe selected IP-in-IP paths; a central inference stage separates device failures and estimates link failures | Production-oriented device/link localization, including gray failures missed by device-local monitoring | Probe epochs and a planned subset of paths trade probe cost against identifiability | The closest operational active-probing family. Our mechanism is passive with respect to measured application packets and names a behavioral sublink directly, but it lacks NetBouncer's network-wide device-versus-link inference. |
| [SprayCheck (2026 preprint)](https://arxiv.org/abs/2605.03702) | Passive inference from adaptive-routing/load-balancing statistics plus flow information | Reports 1.5% single-link loss in one Llama-3-70B iteration and 0.5% in five iterations on a 64-spine topology | Iteration-level passive evidence in a large adaptive-routing model | The closest topology/workload comparator. No superiority claim is made: this repo has not reimplemented SprayCheck under the exact same traffic, topology, and budget. The present result proves sealed CLF evidence and the decision rule on Tofino. |
| [Safe anytime-valid inference](https://arxiv.org/abs/2210.01948) and [predictive-recursion e-processes](https://academic.oup.com/biomet/article/112/2/asae066/7914010) | General sequential statistical foundations | Optional-stopping-safe evidence and mixture-style e-process constructions | Type-I error control uniformly over stopping times under the stated null | Occupies the statistical primitive. The contribution is applying a fixed mixture to sealed network epochs with censor restarts and geometric alpha spending, not inventing e-values or e-processes. |

The published systems are not experimental straw men. Alternate Marking, LinkGuardian, NetBouncer,
FANcY, dDrops, dShark, NetSeer, LossRadar, and SprayCheck each solve a broader, faster, or more
detailed problem along at least one axis. The comparison identifies a different joint point: fixed
aggregate state, behavioral-sublink granularity, exact epoch provenance, fail-closed invalidity,
immediate full-blackhole action, and an anytime-valid gray-loss rule.

## Comparison with the implementations actually run in this repository

These are the only quantitative head-to-head arms. External systems above were reviewed as prior
art but were not reimplemented, so this table does not imply experimental superiority over them.

| Implemented arm | Total blackhole | Broad gray-loss band | Invalid epoch behavior | Fresh measured result |
|---|---|---|---|---|
| C-W4 sequence witness | No signal while the blackhole persists; a later survivor reveals the gap retroactively | Sequence-gap evidence is corroboration, not an exact loss-rate certificate | No typed epoch ledger | Silicon sequence `201 -> 201 -> 45`: unchanged during the outage, then changed on the first survivor after repair |
| One-bit presence frontier | Acts when `TX > 0` and `RX = 0` | Misses whenever at least one packet arrives | Earlier implementation could be masked by a stray arrival | In simulation: 100% at zero survival, 0% at 50%, 75%, 90%, 95%, and 97% survival |
| One-epoch fixed ratio (`RX/TX <= 1/8`) | One-epoch action | Covers near-total starvation but misses moderate/low gray loss | A valid exact count is required, but there is no sequential accumulation | In simulation: 100% at survival <=15%, 97.6% at 25%, and 0% at 50% through 100% |
| Sealed sequential ledger | Immediate `BLACKHOLE` for valid `TX > 0, RX = 0` | Fixed six-alternative mixture accumulates exact count evidence | Stale, missing, raced, incomplete, reset, saturated, impossible, or receipt-invalid epochs become `INCONCLUSIVE`; censored sequences restart with spent alpha | Simulation: 100% detection at 95% survival (median 4 epochs), 99.5% at 97% (median 12); 0.4% statistical action at the 0.99 null and 0% under perfect delivery |

## Final-source Tofino evidence

One source build and one gate-agent runtime produced the final matched triad:

```text
program=mcp_fabric_clf_eg
build=158d63f370a84264157a4a7d0c87036a86b224f148ae582357153b1a631c85d9
setup=022f95f0d34cd2d3398aba55f225c6c8b2538a3730c03c4b7abfb9ac86d838b4
runtime=1ba36ada91bdd44fdc4fe525dcea46fa868d9ebd6ecc35fd8619c055b8e8441b
switchd_pid=168913
```

| Scenario | Exact silicon result |
|---|---|
| 95% survival, sublink 6 | Epochs 2500–2503 were sealed at `TX=40, RX=38, drops=2`; six-point-mixture e-values `1.13899`, `4.05357`, `15.0464`, `57.6701`; `GRAYHOLE` on epoch 4 at threshold 40 |
| Healthy control, sublink 6 | Epochs 2600–2603 were sealed at `TX=40, RX=40`; all `MONITOR`; e-value decayed from `0.0773583` to `0.00636353` |
| Total blackhole, sublink 6 | Epochs 3000–3002 were sealed at `TX=40, RX=0, drops=40`; `BLACKHOLE` on the first and every subsequent epoch |

The two 512-entry banked `bit<8>` frontier arrays occupy 1 KiB total. The CLF bank uses an existing
dead shim byte, so the frontier adds zero wire bytes. The exact source identified above compiled
with 0 errors and 5 warnings to 11 ingress and 5 egress stages and 42 allocated tables; hashes and
the complete `table_summary.log` are preserved in
[`FINAL-COMPILE-EVIDENCE.txt`](artifacts/FINAL-COMPILE-EVIDENCE.txt). After the campaign, the gate
reported zero active injections, repeated the exact identity above, and Vision had no surviving
trial process. The full command record, including censored attempts, is in
[`SEQUENTIAL-EVIDENCE-SWEEP.md`](artifacts/SEQUENTIAL-EVIDENCE-SWEEP.md).

## What may and may not appear in the paper

**May claim:** this implementation joins exact behavioral-sublink counts, sealed provenance,
typed censoring, declared receipts, immediate zero-arrival action, and anytime-valid gray-loss
accumulation; the final source/build/runtime reproduced healthy, 95%-survival, and total-blackhole
outcomes on Tofino.

**Must not claim:** first silent-blackhole detector; first ingress/egress comparison; first in-switch
gray-failure detector; first action on a localized bad link; first synchronized snapshot; first
sequential/e-process test; physical root-cause identification; a production-ready threshold; a
distributed multi-switch epoch seal; or superiority over an external system without a matched
reimplementation.
