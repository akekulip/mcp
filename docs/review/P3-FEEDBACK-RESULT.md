# P3 — Feedback is not free, and the data-plane fast path earns its place (conditionally)

Every capacity number before this one assumed the mitigation lands the instant the evidence exists.
It does not: the witness raises the gap **downstream**, the spray choice is made **upstream**, and
production keeps flowing onto the faulty sublink until the event gets back. This measures what that
costs, using **our own silicon numbers** rather than estimates:

* controller path, `tau_slow` = **96.2–116.6 ms** (`p4/reports/slow-loop-silicon.md`: bfrt register
  read 48.5 ms + counter sync 29.8 ms + write 9.6 ms)
* data-plane path, `tau_fast` = **97.4 µs** (`docs/DESIGN-ALTERNATIVES.md`, H7 measured on silicon)

25 G link, 1500 B packets (2.08 M pkt/s), affected context carrying 25 % of them.

| fault rate | detection time | unsafe pkts, instant | unsafe pkts, controller | unsafe pkts, fast path | fast path removes |
|---|---|---|---|---|---|
| 1e-2 | 0.27 ms | 1.4 | **556.6** | 1.9 | **99.7 %** |
| 1e-3 | 1.92 ms | 1.0 | 56.5 | 1.1 | 98.1 % |
| 1e-4 | 19.2 ms | 1.0 | 6.6 | 1.0 | 84.7 % |
| 1e-5 | 192 ms | 1.0 | 1.6 | 1.0 | 35.7 % |

## The finding

**Feedback latency only matters when it is comparable to detection time, and detection time scales
as 1/p.** At a 1e-2 fault the witness has its evidence in 0.27 ms, so 107 ms of controller round
trip *is* the exposure — 99.7 % of it — and the fast path removes 555 packets. At 1e-5 detection
itself takes 192 ms, the feedback is a third of the total, and the fast path saves 0.6 packets.

So the plan's rule — a data-plane fast path is allowed "only if it materially improves unsafe
exposure" — resolves to **yes for fast faults, no for slow ones**, with the crossover where
detection time meets `tau_slow`, i.e. around p ≈ 1e-4 on a 25 G link.

Note also the floor: the "instantaneous" column never reaches zero. About one packet is lost
gathering the evidence that a fault exists at all, and no feedback mechanism can remove it. That is
the irreducible cost of learning, and it is what the earlier capacity numbers were implicitly
reporting.

## Flapping is the second, independent argument

A control loop slower than the flap period acts on a world that has already changed, and quarantines
a context that is healthy by the time the entry lands:

| flap period | controller false quarantines | data-plane false quarantines |
|---|---|---|
| 20 ms | **95** | 0 |
| 50 ms | 7 | 0 |
| 200 ms | 5 | 0 |
| 1000 ms | 0 | 0 |

This is a *correctness* argument, not an efficiency one, and it bites precisely where the exposure
argument is weakest — a link that flaps fast is not necessarily one that loses many packets. Stale
events must be dropped by epoch, which is why the mechanism carries a sequence epoch rather than a
bare "this link is bad" notification.

## Honest limits of this model

* `detect_time` uses the sequential-test approximation (a gap is worth ~ln(1/p) nats, so ~h/ln(1/p)
  gaps are needed); it is the same test the rest of the project uses, expressed in time rather than
  epochs, but it is an approximation and not a simulation of the CUSUM.
* The flapping model is a deterministic square wave, so the counts are a sensitivity, not a rate.
* Exposure is counted in packets lost to the fault. It does not price retransmission, collective
  stalls, or the capacity stranded while a context is quarantined — those need P4's trace-driven run.
* Ingress has **2 stages** left after the health gate (10/12 used), so "build the fast path" is
  constrained by that budget and must be designed against it rather than assumed.
