# PREREG H7 on silicon — fast-loop reaction latency under fault F1 (loss)

Fifth hardware session. Date 2026-08-27, switch `decps@10.10.54.81` (UfiSpace Tofino 1,
SDE 9.13.2), `bf_switchd` PID 26316, build `mcp_fabric.p4 sha256 f0b667937ebdf5e8…`.
**`bf_switchd` was not restarted and nothing was rebooted.** No `coarse_time` messages.
Chip left idle: no shapers, `reg_attn` seeded 4096 in both pipes, counters zeroed,
`tbl_fail` empty.

This closes the gap that blocked F1: the NIC-side **evidence producer** now exists
(`nic/evidence_probe.py`, see `nic/README.md`). Estimators follow **PREREG amendment
v1.4**: τ_fast is the ramp back-extrapolation, τ_slow is the full-sweep epoch, the
sid-3 first-drop timestamp is reported alongside as an independent check, and the
minimal 1-slot τ_slow is secondary.

---

## Verdict

| PREREG H7 criterion | F6 (congestion) | **F1 (loss)** |
|---|---|---|
| median τ_fast ≤ 100 µs | 97.4 µs — met | **10.115 ms — FAILS by ~100×** |
| BCa 95 % CI of τ_slow/τ_fast entirely > 100 | 452 – 1143 — met | **8.6 – 9.1 — FAILS** |
| gate fires on the faulty path, not on ≥ 90 % of healthy paths | 0 % — met | **0 % — met** |

**H7 fails for F1**, and the reason is structural rather than a defect: for F1 the
"fast loop" is not in the switch at all. Loss is invisible to the data plane — a
dropped packet leaves no evidence at the next hop — so it has to be *measured on a
host over a time window* and reported back. τ_fast for F1 is therefore a host software
parameter, and it lands in the same millisecond regime as a slow-loop epoch. The
switch's own contribution to it is negligible: once the evidence packet arrives, the
register moves in one pipeline pass.

That distinction is worth stating plainly in the paper: **MCP's fast loop is genuinely
fast for faults the data plane can see itself (queue depth, F6) and is host-bound for
faults it cannot (loss, F1).**

---

## The producer, and the one thing that had to be measured

`nic/evidence_probe.py` sends sequenced probes into the hairpinned fabric, measures
per-path loss/RTT/reorder from the returning copies, quantises to `evid_h`, and emits
evidence to UDP 58853. It needs no controller and no bfrt connection.

A delivered frame carries **no fabric shim** — the destination leaf strips it — so the
probe cannot read the spray index off the wire and must recompute the switch's own
decision. `mcp_fabric.p4`'s `CRCPolynomial(0x04C11DB7, reversed, init=xor=0xFFFFFFFF)`
+ `Hash<bit<16>>` is exactly the standard reflected CRC-32 truncated to its low 16
bits, so with two spines:

```python
spray   = zlib.crc32(src_ip_be + dst_ip_be + sport_be) & 1
path_id = leaf(dst_ip) * 2 + spray
```

**Validated against silicon before the file was trusted**, by capturing mirrored copies
(which carry both `mirror_h.path_id` and the inner UDP source port):

| destination | leaf | source ports checked | mismatches |
|---|---|---|---|
| 10.0.1.2 | 1 | 2994 | **0** |
| 10.0.1.3 | 2 | 1989 | **0** |

4983 of 4983. The mapping is a property of the compiled binary, not the protocol.

### Validation (1) — loss appears on the faulty path only

22 s run at 10 000 pps, `fail 0 1 drop` (1 % on the uplink of path 2) armed for ~8 s:

| | path 2 (faulty) | path 3 (healthy) |
|---|---|---|
| windows with `loss_q > 0` | **894 / 2200** (peak `loss_q` 48) | **0 / 2200** |
| `reg_attn` before | 4096 / 4096 | 4096 / 4096 |
| `reg_attn` during fault | **65535 / 65535** (both pipes) | 4083 / 4083 (decay only) |
| `reg_attn` after `fail-clear` | 65529, decaying | 4071, decaying |

End-to-end 414 probes lost of 220 000 sent, against 400 predicted from the injection
rate and the fault window. `sock_drops = 0`. Evidence reaches **both pipes**, confirming
the `tbl_evid_fwd` path added after the v1 session.

One operational note that matters for reps: with `n_clean = 4096` and ~10 k passes/s,
attention decays at ~2.4 units/s, so a saturated slot needs **hours** to return to
baseline. Every rep re-seeds; a rep that relies on self-clearing is measuring the
previous rep.

---

## H7-F1 — 12 reps

Probe at 10 000 pps to `10.0.1.2` (both spines), 10 ms windows, 5 ms grace,
`W = 1000`. `fail 0 1 drop` (1 %, uplink vlink 0 = path 2) armed 4 s in, held 4 s.
Faulty path 2; healthy path 3. All timestamps are `mirror_h.tstamp` (switch clock).

| rep | copies | drop copies | attn@react | bumps before | ns/bump (ms) | **τ_fast v1.4 (ms)** | τ_fast sid-3 (ms) | healthy raised |
|---|---|---|---|---|---|---|---|---|
| 1 | 82 420 | 211 | 5116 | 0.996 | 10.167 | **10.127** | 14.378 | 0/1 |
| 2 | 82 499 | 207 | 5116 | 0.996 | 10.154 | **10.114** | 10.667 | 0/2 |
| 3 | 82 559 | 204 | 5116 | 0.996 | 10.179 | **10.139** | 8.861 | 0/1 |
| 4 | 82 597 | 197 | 5116 | 0.996 | 10.152 | **10.112** | 10.281 | 0/1 |
| 5 | 82 539 | 168 | 5116 | 0.996 | 10.141 | **10.101** | 8.962 | 0/1 |
| 6 | 82 299 | 179 | 5116 | 0.996 | 10.169 | **10.130** | 14.180 | 0/1 |
| 7 | 81 757 | 198 | 5116 | 0.996 | 10.155 | **10.115** | 15.100 | 0/2 |
| 8 | 82 361 | 218 | 5116 | 0.996 | 10.167 | **10.128** | 7.641 | 0/1 |
| 9 | 82 338 | 210 | 5116 | 0.996 | 10.160 | **10.120** | 13.528 | 0/1 |
| 10 | 82 490 | 185 | 5116 | 0.996 | 10.135 | **10.096** | 14.035 | 0/2 |
| 11 | 82 391 | 201 | 5116 | 0.996 | 10.151 | **10.112** | 8.857 | 0/1 |
| 12 | 82 689 | 196 | 5116 | 0.996 | 10.138 | **10.098** | 8.189 | 0/1 |

**τ_fast (v1.4 ramp): median 10.115 ms, BCa 95 % CI 10.101 – 10.127 ms.**
**τ_fast (sid-3 first drop, check): median 10.474 ms, BCa 95 % CI 8.857 – 14.035 ms.**

The two independent estimators agree to **3.4 %** on the median. That is the strongest
available evidence that the v1.4 ramp estimator is sound: the sid-3 timestamp is the
switch's own record of the first dropped packet and shares no machinery with the ramp
fit. The v1.4 interval is far tighter because the estimator is nearly deterministic
here — `attn@react = 5116` and `bumps_before = 0.996` in **all 12 reps**, i.e. the
first gated copy always catches exactly the first bump — whereas the sid-3 figure
carries the U(0, window) phase jitter of the emission boundary.

`t_sat − t_evid`: median **609.6 ms** (606.3 – 614.3). Attention ramps to saturation
over ~60 evidence packets at one per 10 ms window.

### Paired ratio (τ_slow from the F6 session, 12 reps, paired by index)

| τ_slow basis | median ratio | BCa 95 % CI | entirely > 100? | sign test |
|---|---|---|---|---|
| **full-sweep epoch, 88.8 ms (v1.4 primary)** | **8.8** | **8.6 – 9.1** | **no** | 0/12, p = 1.000 |
| minimal 1-slot, 2.20 ms (secondary) | 0.2 | 0.2 – 0.2 | no | 0/12, p = 1.000 |

Against the minimal controller path the "fast" loop is **five times slower** than the
slow one. For F1 the ordering the hypothesis assumes does not hold at all.

### Specificity — met, decisively

**0 of 15 healthy path-instances** showed any copy with `attn > 4096` across the 12
reps. Path 3 stayed at `attn_max = 4096` with `raised = 0` in every rep while path 2
saturated. Evidence is addressed by `path_id`, so a lossy spine cannot raise a
sibling path's gate.

---

## Where the 10 ms goes, and how far it can be pushed

τ_fast for F1 decomposes exactly into producer parameters:

```
τ_fast ≈ grace_ms  +  U(0, window_ms)  +  (switch terms, negligible)
       ≈ 5 ms      +  U(0, 10 ms)                  = 5 – 15 ms, mean 10 ms
```

Observed sid-3 range 7.641 – 15.100 ms, median 10.474 ms. The model predicts the
distribution, not just the mean.

`grace` is the interval after which an unacknowledged probe is declared lost. It cannot
be shrunk below the probe RTT tail without manufacturing loss out of packets that are
merely late — and that is not hypothetical:

**A first sensitivity attempt at `window = 1 ms, grace = 1 ms` was discarded as
invalid.** In all six reps `attn` was already saturated (65535) when the first real
drop occurred, because in-flight probes were being retired as lost. Measured RTT over
the validation run: mean 214 µs, but per-window **max 1.36 ms median, 1.61 ms p95,
1.80 ms maximum**. A 1 ms grace sits inside that tail.

Re-run above the tail, `window = 2 ms, grace = 3 ms`, 6 reps:

| | value |
|---|---|
| `attn` at first drop copy | **4092 in all 6** — no false loss before the fault |
| τ_fast v1.4 | median **2.028 ms** |
| τ_fast sid-3 | median **5.017 ms** (model: 3 + U(0,2) = 3 – 5 ms ✓) |
| ratio vs full-sweep epoch | **43.8** |
| healthy paths raised | **1 / 6** |

Tightening the window buys a 5× improvement in τ_fast and takes the ratio from 8.8 to
43.8 — still short of 100 — **and it starts to cost specificity**: one of six reps
raised a healthy path, against 0 of 15 at the default setting. That is the same
false-loss mechanism, now intermittent rather than dominant.

So for the NIC evidence loop there is a floor, and it is set by the RTT tail of the
measurement path rather than by anything in the switch. On this testbed
(Python producer, ~1.8 ms RTT tail) the floor is roughly `grace + window/2 ≈ 2.5 ms`,
which caps the achievable ratio near ~35. Reaching a ratio of 100 would need the RTT
tail down to a few hundred microseconds — a kernel-bypass or hardware-timestamped
producer, not a tuning change.

---

## New defect found: evidence-packet mirror copies are mislabelled

A mirrored copy **of an evidence packet** carries `mirror_h.path_id = 0`,
`vlink = 0`, `next_hop = 0` regardless of the path the evidence was about. Evidence
packets are handled by `tbl_evid_fwd` instead of `tbl_final`, so `hdr.fabric` is never
made valid, and the deparser emits `hdr.fabric.path_id` — which reads as zero.

Confirmed by inspection: every "path 0" copy had inner UDP dport **58853** and inner
sport 20002/20003, i.e. they are the probe's own evidence packets, gated at ~100 %
because the gate correctly read the *saturated path-2* register.

**The attention update itself is correct** — only the label on the copy is wrong. But a
naive collector-side analysis attributes 1594 saturated copies per rep to a path that
carries no data traffic, which looks exactly like a specificity failure. The analysis
here excludes them by inner UDP dport (19 395 excluded across the 12 reps).

Fix in the P4: emit `md.attn_idx` rather than `hdr.fabric.path_id` in the mirror header
(it is the value the gate actually indexed, and it is valid on every path), or suppress
mirroring of evidence packets entirely.

---

## Anomalies and operational notes

- `sock_drops = 0` in every reported run; 0 kernel capture drops in all 12 reps.
  ~82 500 copies and ~9.2 MB of pcap per rep.
- The probe's **reorder counter is a host artefact**, not a fabric measurement: ~500
  source ports per path spreads a path's probes across NIC receive queues, so a
  zero-loss run still reports ~17 500 out-of-order arrivals. The switch ignores
  `flags` anyway.
- Measured RTT (~214 µs mean) is dominated by the Python send/receive path, not the
  fabric; it is reported for completeness and is inert at the switch, since
  `tbl_exceed_evid` is installed as `loss_q >= 1 OR rtt_q >= 255`.
- With `--emit-on any` (the default), `rtt_q` is always non-zero, so evidence is
  emitted every window regardless of loss — 2200 packets per 11 s run. Only
  `loss_q >= 1` bumps attention. Use `--emit-on loss` to emit only on loss.

## Reproduction

```bash
# on Vision, as root
./nic/evidence_probe.py --dry-run                       # path map + quantisers
sudo ./nic/evidence_probe.py --pps 10000 --duration 11 --csv run.csv
# on the switch, mid-run
python3 setup_skeleton.py fail 0 1 drop ; sleep 4 ; python3 setup_skeleton.py fail-clear
# collector capture on Vision
tcpdump -i enp59s0f0np0 -Q in -s 96 -w f1.pcap ether dst a5:a5:a5:a5:a5:a5
```

Harness scripts used for the reps (`h7f1_rep.sh`, `h7f1_vision.sh`, `h7f1_analyse.py`)
follow the F6 pattern: seed and zero **before** the capture starts, one persistent bfrt
connection to arm the fault (1.9 ms write), analysis from the raw pcap.

Nothing was committed.
