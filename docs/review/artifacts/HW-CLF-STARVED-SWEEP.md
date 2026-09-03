# Is RX a faithful estimator of survival? — and what that says about STARVED_RATIO

**Date:** 2026-08-30. Sublink 2 (vlink 0, ctx 2), first directed link, 60 packets per point.
`STARVED_RATIO = 8` was chosen, not measured. This sweep asks the question that has to be
answered before any threshold is defensible: **does RX/TX actually track the survival rate?**

## Method

`K <sublink> lo hi` drops packets whose per-sublink witness sequence falls inside the range.
Arming `[seq + k .. 65535]` spares the first `k` sequence values and destroys everything after,
so `k` sets the survivor count.

## A prerequisite that had to be measured first

The witness sequence does **not** advance once per packet. Measured directly:

```
reg_wit_seq before=13859 after=13959   delta=100 for 50 packets sent
-> 2.0 sequence values consumed per packet
```

It is stamped on each fabric pass that carries the witness, so **one packet consumes two
sequence values**. Sparing `k` sequence values therefore spares `k/2` packets. Without this the
sweep reads as a factor-of-two measurement error rather than as a correct parameterisation.

Two consequences beyond this sweep:

* Any sequence-range fault injection covers half as many packets as its width suggests.
* The 16-bit sequence space wraps every **32768 packets per sublink**, not 65536. The `wrap`
  scenario in `sim/clf/PREREG.md` should use that figure.

## Result

| k (seq values spared) | expected survivors (k/2) | TX | RX | RX/TX |
|---:|---:|---:|---:|---:|
| 0 | 0 | 60 | 0 | 0.000 |
| 1 | 0.5 | 60 | 1 | 0.017 |
| 2 | 1 | 60 | 1 | 0.017 |
| 5 | 2.5 | 62 | 3 | 0.048 |
| 8 | 4 | 60 | 4 | 0.067 |
| 15 | 7.5 | 60 | 8 | 0.133 |
| 30 | 15 | 60 | 15 | 0.250 |
| 45 | 22.5 | 60 | 21 | 0.350 |
| 60 | 30 | 60 | 30 | 0.500 |

RX tracks `k/2` across the whole range, monotonically and without a knee. **RX/TX is a faithful
linear estimator of the survival fraction**, which is the property a ratio threshold needs.

## What this settles about the threshold, and what it does not

**Settles:** `STARVED_RATIO = 8` is not an arbitrary register constant. Because RX/TX estimates
survival faithfully, the constant states a policy — *"at most one arrival per eight departures"*,
i.e. **survival at or below 12.5% while RX is unsaturated** — and that is a statement about link
behaviour rather than about the encoding.

**Does not settle:** where the boundary belongs. The sweep shows the classification is genuinely
marginal near it: at `k = 15` the measured ratio is **0.133** against a threshold of **0.125** —
6% apart, a difference of roughly one packet in sixty. A threshold this close to a real operating
point needs either a margin, hysteresis, or evidence accumulated over several epochs before it
drives any action. It is still not in `sim/clf/PREREG.md` and remains provisional.

**Also unmeasured:** the noise floor. TX read 62 rather than 60 at one point, from background
traffic on the same sublink, so the estimator carries an error of a packet or two that has not
been characterised over repeated runs at a fixed k.
