# Selective detection of a conditional fault, on silicon — 2026-08-29

> Historical component record. The end-to-end latency limitation stated below was closed for
> partial loss on 2026-08-30; see `HW-CLOSED-LOOP.md`. The five-packet detection result here is
> otherwise retained unchanged.

A fault injected into ONE behavioural sublink is detected on that sublink and on no other. This is
the detection half of the thesis, on a Tofino 1.

## Method

17 behavioural sublinks were carrying traffic (see `HW-SUBLINK-PRIMITIVE.md`). The egress injector
`tbl_eg_fail` — added for this campaign because the program had no post-stamp fault path at all
(H39a) — was armed on exactly one:

    key: md.sublink = 2  (vlink 0, ctx 2 = the >=1024 B size class)
         hdr.witness.seq range [149, 153]      -> 5 packets
    action: Egress.eg_fail_drop, DirectCounter eg_fail_ctr

The table sits immediately after `tbl_wit_stamp` in egress, so a dropped packet has ALREADY consumed
a sequence number and its loss is visible to the downstream witness. 120 packets of 1400 B payload
were then sent from Vision.

## Result

**Ground truth, from the injector's own DirectCounter:**

    sublink=2  seq=[149..153]  ->  DROPPED 5 packets

**Detection, from the witness registers, read `from_hw`:**

| sublink | vlink | ctx | stamped | clean run | discontinuity? |
|---:|---:|---:|---:|---:|---|
| 0 | 0 | 0 | 958 | 958 | no |
| 1 | 0 | 1 | 2097 | 2097 | no |
| **2** | **0** | **2** | **206** | **51** | **YES** |
| 16 | 1 | 0 | 24 | 24 | no |
| 17 | 1 | 1 | 47 | 47 | no |
| 18 | 1 | 2 | 84 | 84 | no |
| 33 | 2 | 1 | 16 | 16 | no |
| 34 | 2 | 2 | 1 | 1 | no |
| 129 | 8 | 1 | 71 | 71 | no |
| 130 | 8 | 2 | 1 | 1 | no |
| 160 | 10 | 0 | 26 | 26 | no |
| 161 | 10 | 1 | 26 | 26 | no |
| 162 | 10 | 2 | 81 | 81 | no |
| 193 | 12 | 1 | 23 | 23 | no |
| 224 | 14 | 0 | 24 | 24 | no |
| 225 | 14 | 1 | 24 | 24 | no |
| 226 | 14 | 2 | 84 | 84 | no |

**Sublinks reporting a discontinuity: 1 of 17.**

Note that sublinks 18, 162 and 226 are the SAME size class (ctx 2) on other directed links, and
sublinks 0 and 1 are other size classes on the SAME directed link. Neither the class alone nor the
link alone triggers — only the pair does. That is the point of the abstraction.

## The count is exact, not approximate

`reg_wit_observed` is not a cumulative arrival counter. Its SALU is `rv = v; if (gap != 0) v = 0;
else v = v |+| 1`, so it counts consecutive CLEAN arrivals and resets on any discontinuity — the
reset IS the detection signal.

`reg_wit_seq` is read-then-increment, so a value of 206 means sequences 0..205 were assigned.
After the last dropped packet (153), arrivals are 154..205 = 52. The survivor at 154 is the one
that exposes the gap and resets the run, so it is not counted in the new run: 155..205 = **51**.
Measured: **51**. The whole packet ledger is accounted for.

## What this establishes

Conditional loss confined to one traffic class on one directed link is detected at that exact
granularity, in the data plane, at line rate, with a per-pair sequence witness and zero added wire
bytes. Aggregate link monitoring cannot express this fault; a per-link witness would attribute it
to the link and quarantine three healthy classes with it.

## What it does not establish

- No control-plane loop. The gap has not been carried to a collector as an event, no decision was
  taken, and `tbl_health_gate` was not written. Mirror sessions exist (1/2 at 128 B, 3 at 64 B, to
  dp9) but no gap event has yet been captured.
- No latency claim. The end-to-end feedback path remains unmeasured.
- `tbl_wit_verdict` still fails to allocate at load (H42), so its `wit_ctr` gap count is
  unavailable; the evidence above comes from the injector counter and the arrival-run reset.
- One fault, one sublink, one run. No false-positive rate, no confidence interval.
