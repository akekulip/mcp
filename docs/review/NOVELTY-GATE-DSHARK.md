# Novelty gate: dShark (NSDI'19) — retrieved and read

**Date:** 2026-08-30. Paper: Yu, Zhu, Arzani, Fonseca, Zhang, Deng, Yuan, *"dShark: A General,
Easy to Program and Scalable Framework for Analyzing In-network Packet Traces"*, NSDI '19,
pp. 207–220. DBLP `conf/nsdi/YuZAFZDY19`. PDF `https://www.usenix.org/system/files/nsdi19-yu.pdf`.

`HURDLES.md` and the earlier novelty gates carried dShark as the one **unretrieved FATAL vector**.
It has now been read. **Verdict: it does not kill the project, but it does kill one framing of it.**

## What dShark actually does

dShark is a **host-side analysis framework over mirrored, per-hop packet captures** — not a
data-plane mechanism. Its stated deployment model:

> "packets can be mirrored from the switches and forwarded to trace collectors. These collectors
> are usually commodity servers, connected via 10Gbps or 40Gbps links."

Its performance goal is set by that model:

> "with a common CPU on a commodity server, dShark must be able to analyze at least 3.33 Mpps"

and the headline result is analysis throughput, not switch cost:

> "on a set of commodity servers, with four cores per server, dShark can execute typical analyses
> in real time, even if all servers are capturing 1500B packets at 40Gbps line rate."

## The direct hit — dShark localizes silent black holes

Table 2 of the paper lists 18 implemented diagnosis applications. Two are squarely in our
territory:

| application | dShark's grouping | dShark's query |
|---|---|---|
| **Silent black hole localizer** [43, 69] | packets with **duplicate** TCP(`ipid`, `seq`) | get dropped hop in the recovered path(`ipv4[:].ttl`) — *"Localize switches that drop all packets"* |
| Silent packet drop localizer [69] | packets with **duplicate** TCP(`ipid`, `seq`) | *"Localize random packet drops"* |
| Packet drops on middleboxes | same packet pre/post middlebox | **"exist ingress and egress trace"** |

**We must stop claiming that detecting or localizing silent black holes is itself novel.** It is
published, implemented, and deployed at a major cloud provider. Any sentence in the paper that
implies otherwise has to go.

## Where the difference actually is — and where it is NOT

**Not a capability difference.** The third row above, *"exist ingress and egress trace"*, is a
direct analogue of comparing a source-side departure record against a receiver-side arrival
record. Given captures at both ends of a link, dShark can see a blackhole while it is happening.
Our TX/RX frontier comparison is the same *idea* implemented differently.

**The retransmission dependency applies only to dShark's own blackhole query.** That query groups
on *duplicate* `(ipid, seq)` — i.e. it keys on a TCP retransmission, so the loss is revealed by a
later surviving copy. That is the same structural dependency C-W4 has, and it is retroactive in
the same way (measured for C-W4 in `artifacts/HW-CLF-VS-CW4.md`). But it would be wrong to
generalise this to dShark as a whole, because the ingress/egress-existence query has no such
dependency.

**The real differences are mechanism, cost and actionability:**

1. **Evidence acquisition.** dShark requires mirroring the traffic off the switch to collectors.
   CLF requires two 8-bit registers per sublink in the switch and mirrors nothing. Our measured
   cost is 11 ingress / 5 egress MAU stages for the whole program with the frontier included.
2. **Capture noise is dShark's own stated problem**, and it is a problem we do not have:
   > "Mirrored packets can get dropped on their way to collectors or dropped by the collectors.
   > If one just counts the packet occurrence on each hop, the real packet drops may be buried in
   > mirrored packet drops and remain unidentified."
   A register increment in the data plane cannot be lost in transit to a collector.
3. **Actionability.** dShark diagnoses; it produces no handle to act on. A behavioural sublink is
   an *addressable resource* the data plane can reroute (the P2 health gate), so detection and
   mitigation name the same object.
4. **Grouping is declared, not queried.** dShark groups at analysis time by packet identity
   (`ipid`, `seq`, 5-tuple). A sublink is a pre-declared aggregate — (directed link × behaviour
   class) — that exists in the pipeline and can be counted, compared and acted on without
   reconstructing packet identity.

## Consequences for the paper

* **Drop** any claim of being first to detect or localize silent black holes.
* **Drop** any claim that this class of failure is invisible to prior work.
* **Cite dShark prominently** in related work and state the ingress/egress-existence query
  explicitly, rather than letting a reviewer find it.
* The defensible claim is **not capability but cost and actionability**: the same class of
  failure, found with in-switch state instead of a mirroring fleet, on an object that mitigation
  can address. That is a systems contribution, and it is weaker than "a new observability
  primitive" — the framing has to change accordingly.
* This also reframes gate 4's advice to drop the O(L) vs O(LK) argument. Against dShark the cost
  comparison is not counter-scaling at all; it is **registers versus packet capture**, which is a
  far larger and more defensible gap. That comparison has not yet been measured against a real
  mirroring baseline on our testbed, and until it is, the cost claim remains unquantified.

## Status

dShark is no longer an unretrieved FATAL vector. It is a **live positioning constraint** with a
concrete required action list above. The remaining unretrieved comparators named in earlier gates
(dDrops, Speedlight) are still outstanding.
