# CLF detection rates — item 2 — 2026-08-30

Repeated trials with the guard-interval discipline the epoch-race finding requires
(quiesce -> zero -> quiesce -> generate -> settle -> read), paired fault/control arms interleaved in
time on the same fabric.

## Results

| arm | n | detected | Wilson 95% CI |
|---|---:|---|---|
| fault (blackhole armed) | 100 | **91 (0.910)** | [0.838, 0.952] |
| control (nothing armed) | 100 | 0 (0.000) | [0.000, 0.037] |

Across four separate runs the fault-arm rate was **0.92, 0.80, 0.96 and 0.91** — a spread that is
itself evidence something environmental is uncontrolled.

| PREREG rule | verdict |
|---|---|
| **1 — >=95% detection on fault, 0% on control** | **FAILS.** 0.910 point estimate, not a CI technicality. The control half passes outright: 0/100. |
| **5 — IMPOSSIBLE == 0 under a guard interval** | **PASSES.** 0 across 200 trials. |

Rule 5 passing matters more than it looks. `NOVELTY-GATE-4.md` concluded that CLF's only real
advantage over standardised per-class counters is that **a presence bit is monotone within an
epoch**, so packets in flight at an epoch boundary cannot fabricate a blackhole. Zero IMPOSSIBLE
states across 200 guarded trials is a direct measurement of that property holding.

## The unexplained residual — recorded, not explained away

Every miss reads `verdict=HEALTHY` with the target sublink observed, i.e. **TX=1 and RX=1 on a
sublink carrying a full-range drop**. Injector ground truth on a miss:

    I 2 0 65535 26        (entry on sublink 2, seq [0..65535], 26 packets destroyed)

So the fault fired. The benign explanation — "the probe delivered nothing, TX=0, correctly IDLE" —
is ruled out.

**A hypothesis was tested and REFUTED.** I proposed a race between arming the injector and starting
the probe: the gate write takes ~2 ms, so early packets might cross before the entry lands. Adding a
1 s settle after arming made detection **worse**, 23/25 -> 20/25, and introduced an IMPOSSIBLE
state. The knob remains (`--arm-settle`) defaulting to the original behaviour; the hypothesis is
recorded as wrong rather than quietly dropped.

What is NOT yet distinguished, and needs per-packet instrumentation rather than more trials:

- whether a small number of ctx-2 packets traverse vlink 0 without matching the injector entry;
- whether RX is being set by traffic other than the probe (background from the second host, or
  packets in flight from the previous trial despite the guard);
- whether the drop-versus-mark ordering inside egress lets a dropped packet still mark RX
  downstream. The compiled order is `tbl_rx_frontier` (stage 2), `tbl_wit_link` (3),
  `tbl_eg_fail` (3), `tbl_tx_frontier` (4); a deparser drop does not stop MAU execution, so this
  ordering deserves direct verification rather than reasoning.

## Consequence

**No CLF detection rate may be published as a property of the mechanism until this is resolved.**
The number is currently a property of the mechanism *and* an uncontrolled residual, and there is no
principled way to separate them from the outside. The blackhole-detection result in
`HW-CLF-BLACKHOLE.md` stands as an existence proof — the difference mask isolated exactly the
injected sublink — but 0.910 is not the detection rate of CLF.
