# PREREG H7 on silicon — fast-loop reaction latency under fault F6 (congestion)

Fourth hardware session on `mcp_fabric`. Date 2026-08-27, switch `decps@10.10.54.81`
(UfiSpace Tofino 1, SDE 9.13.2), `bf_switchd` PID 26316 started 23:23 on build
`p4/mcp_fabric.p4 sha256 f0b667937ebdf5e8…`. **`bf_switchd` was not restarted and
nothing was rebooted.** No `coarse_time` messages (`grep -c` = 0). The chip is left
idle: no shapers armed, `reg_attn` seeded 4096 in both pipes, counters zeroed,
`tbl_fail` empty.

**12 reps of F6, 12 reps of τ_slow.** All fast-loop timestamps are
`mirror_h.tstamp` = `ig_intr_md.ingress_mac_tstamp`, the switch's own ASIC clock, so
no host-clock cross-calibration is involved and PREREG's "residual ≤ 1 µs" clause is
not on the critical path.

## Fault coverage

**F6 (congestion) was measured. F1 (loss) was NOT run**, because it needs a NIC-side
evidence *producer* that does not exist. Only the switch-side consumer exists
(`tbl_exceed_evid` + the `evid_h` header), and it has been exercised synthetically —
`mcp_evid.py` hand-builds evidence packets, and the v2 session confirmed the bump is
exact (+1024 per packet, both pipes). But nothing on Hulk or Vision measures real loss
and emits `evid_h`, so there is no F1 fault to react *to*. PREREG H7 asks for
"≥ 10 reps × 2 faults"; this report delivers **one fault**. H7 cannot be closed until
the evidence producer exists.

---

## Headline result, and a definitional problem that must be fixed in PREREG

**The fast loop reacts, on the faulty path only, and it is ~900× faster than a slow-loop
epoch. But τ_fast as PREREG defines it is not measurable on this implementation,
because it is ≤ 0 by construction.**

PREREG defines τ_fast as the time from the first evidence to the first gated sample.
In `mcp_fabric.p4` the ingress apply order is

```p4
tbl_exceed_csig.apply();   // is this packet evidence?      -> md.exceed
tbl_attn.apply();          // bump or decay                 -> md.attn (POST-update)
tbl_gate.apply();          // sample with P = md.attn/65536
```

so the packet that *carries* the evidence is itself gated under the attention its own
evidence just raised. Evidence and reaction are the **same packet**. There is no
interval to measure: the fast loop's reaction latency is **zero packets**, bounded
above by one pipeline traversal.

Measured, over 12 reps: `t_react − t_evid` was **≤ 0 in 12/12 reps** and **exactly 0
in 7/12** (the same mirrored copy is both the first copy reporting
`csig.worst_qdepth ≥ 4096` and the first copy with `attn > 4096`). Median **0 ns**.
The negative values (−403 to −806 µs) are a sampling artefact: with P = 1/16 at
baseline, a *non-evidence* packet on the faulty path is often sampled under
already-raised attention before an *evidence-carrying* packet happens to be sampled.

Corroborating evidence that the two are the same packet: on the first copy that
reports `worst_qdepth ≥ 4096`, the attention field already reads **5075 to 17363**
(4096 + k·1024, k = 1…13), never 4096. The gate had already moved before that copy
was emitted.

### The estimator actually used

Because `attn` rises by exactly `k_up = 1024` per exceeding packet and saturates at
65535, the `attn` field in the copies is a **counter of exceeding packets**, and the
ramp is a staircase whose slope gives the time per exceeding packet. That lets the
first exceeding packet be located by back-extrapolation:

```
bumps_before_react = (attn_at_react − 4096) / 1024
ns_per_bump        = (t_sat − t_react) / ((65535 − attn_at_react) / 1024)
τ_fast_est         = bumps_before_react × ns_per_bump
```

τ_fast_est is the time from the **first packet that crossed the threshold** to the
**first copy the collector actually saw under raised attention**. It is an upper
bound on the loop's own latency and is dominated by the sampling interval, not by the
switch. It is the quantity reported below, and it is the honest one to compare
against τ_slow: both are "time until the mechanism's effect is observable".

---

## Per-rep results

Fault: 50 Mb/s max-rate shaper on **vlink 1** (uplink leaf0→spine1, dp164 qid 1),
armed ~4.5 s into an 11 s blast of 150 000 pps (121 Mb/s) from Vision to `10.0.1.2`,
held 3 s, then released. The hash spray puts ~75 kpps on the shaped spine, so the
uplink is offered ~60 Mb/s against a 50 Mb/s cap. Faulty path = **path 3**
(leaf0→spine1); healthy path with traffic = **path 2** (leaf0→spine0).

| rep | copies | τ_fast as defined (ns) | attn at react | τ_fast_est (µs) | t_sat − t_evid (ms) | kernel drops | iface drops | pcap (MB) |
|---|---|---|---|---|---|---|---|---|
| 1 | 714 848 | 0 | 8147 | 85.3 | 1.209 | 0 | 1071 | 80.1 |
| 2 | 714 848 | −402 878 | 6099 | 54.3 | 1.209 | 0 | 1049 | 80.1 |
| 3 | 714 848 | 0 | 8147 | 113.8 | 1.612 | 0 | 1593 | 80.1 |
| 4 | 714 848 | −537 049 | 17363 | 406.8 | 0.940 | 0 | 1271 | 80.1 |
| 5 | 714 848 | 0 | 8147 | 85.3 | 1.209 | 0 | 1221 | 80.1 |
| 6 | 713 424 | −805 757 | 7123 | 97.4 | 1.074 | 0 | 1605 | 79.9 |
| 7 | 714 848 | 0 | 17363 | 332.8 | 1.209 | 0 | 1441 | 80.1 |
| 8 | 714 848 | −671 552 | 6099 | 67.9 | 1.343 | 0 | 1425 | 80.1 |
| 9 | 714 848 | −805 617 | 7123 | 97.4 | 1.075 | 0 | 1502 | 80.1 |
| 10 | 713 424 | 0 | 5075 | 21.8 | 1.343 | 0 | 1499 | 79.9 |
| 11 | 714 848 | 0 | 17363 | 369.8 | 1.343 | 0 | 1438 | 80.1 |
| 12 | 714 848 | 0 | 10195 | 133.2 | 1.209 | 0 | 1314 | 80.1 |

**τ_fast (as defined):** median **0 ns**, ≤ 0 in 12/12.

**τ_fast_est:** median **97.4 µs**, range 21.8 – 406.8 µs,
BCa 95 % CI of the median **67.9 – 215.1 µs**.

**Ramp to saturation (t_sat − t_evid):** median **1.209 ms**, range 0.940 – 1.612 ms.
That is ~57 exceeding packets at ~21 µs each — the attention word goes from baseline
to fully saturated in about a millisecond of congested traffic.

---

## τ_slow — one emulated slow-loop epoch, 12 reps

Timed with `time.perf_counter()` on the switch's own CPU, over one persistent bfrt
connection: observe → decide → install.

| phase | operation | median |
|---|---|---|
| observe | full `reg_attn` read, 256 slots, `from_hw=True`, both pipes | **48.5 ms** |
| observe | `SyncCounters` + read of `tbl_vlink` (64 rows) and `tbl_fail` (0 rows) | **29.8 ms** |
| decide | pick the max-attention path (trivial; the I/O is what is being characterised) | 0.14 ms |
| install | full 256-slot `reg_attn` write | **9.6 ms** |
| **total** | | **88.8 ms** |

**τ_slow median 88.8 ms**, range 84.7 – 97.1 ms, BCa 95 % CI **86.4 – 92.1 ms**.

**Minimal path** (read 1 slot + write 1 slot): median **2.20 ms**
(read 1.37 ms, write 0.84 ms).

---

## Paired ratio τ_slow / τ_fast

Paired by rep index (the two are independent measurement sets of equal size, not
simultaneous; stated plainly rather than implied).

| ratio basis | median | BCa 95 % CI | entirely > 100? |
|---|---|---|---|
| **full epoch** τ_slow (88.8 ms) | **907** | **452 – 1143** | **yes** |
| minimal path τ_slow (2.20 ms) | 22 | 6 – 27 | **no** |

Per-rep full-epoch ratios: 1001, 1762, 767, 223, 1027, 869, 270, 1285, 945, 4463,
254, 649.

**Sign test** on log₁₀(ratio) > 2: **12/12 successes, one-sided p = 2.44 × 10⁻⁴.**

The minimal-path row is the honest counterweight and belongs in the paper: if a future
controller reads and writes only the one register slot it cares about, the separation
drops to ~22×, and the H7 threshold of 100 would **not** be met. The 900× figure is a
property of a controller that sweeps all 256 slots and both counter tables every
epoch. Whichever is claimed, the epoch's *scope* has to be stated with it.

---

## Specificity (H7 clause 3)

Over the same windows, **0 of 13 healthy path-instances showed any copy with
`attn > 4096`** — 0.0 %, against a target of < 90 %. The healthy path's attention
never moved off its seed:

```
rep 1  path 2 (healthy): 96 241 copies, attn_max = 4096, raised = 0
       path 3 (faulty) : 618 607 copies, attn_max = 65535, raised = 559 394
```

Every rep looks like this. The gate is raised on the faulty path and on nothing else.
The mechanism for the clean separation is worth stating: attention is indexed by
`path_id`, and the CSIG tag that triggers the bump names the path it travelled, so a
congested spine cannot raise a sibling path's gate.

## Controller-frozen sanity check

Between arm and release the only bfrt writes issued were the two TM shaper writes
(`tf1.tm.queue.sched_shaping` / `sched_cfg`) that arm and release the fault itself.
Neither touches `reg_attn`, `tbl_gate`, `tbl_exceed_csig`, or any RegisterParam. The
rep driver holds one bfrt connection and issues nothing else in the window, and the
seed/zero happens **before** the capture starts. The gate's response is therefore
entirely data-plane; PREREG's failure branch ("no gated sample within T when the
controller is frozen") does not apply — samples arrived throughout.

## Verdict against PREREG H7

| criterion | result |
|---|---|
| median τ_fast ≤ 100 µs across ≥ 10 reps | **met** — 0 ns as defined; 97.4 µs by the back-extrapolated estimator (CI 67.9 – 215.1 µs, so the median is close to the threshold and the upper CI exceeds it) |
| 95 % BCa CI of τ_slow/τ_fast entirely above 100 | **met for a full-sweep epoch** (452 – 1143); **not met** for a single-slot controller (6 – 27) |
| gate fires on the faulty path, not on ≥ 90 % of healthy paths | **met, decisively** — 0 % of healthy paths raised |
| ≥ 10 reps × **2** faults | **not met** — F6 only; F1 needs the NIC evidence producer |

**H7 is supported for F6 on this build, subject to two caveats that must be carried
into the paper**: the τ_slow scope (full sweep vs single slot), and the fact that
τ_fast as currently defined is degenerate.

## Recommended PREREG amendment

Redefine τ_fast so it measures something the implementation can exhibit. The current
definition assumes evidence and reaction are different packets; in this data plane
they are the same one. Three workable options:

1. **Declare it zero and say why** — τ_fast = 0 packets because `tbl_gate` reads the
   post-update attention; report the *ramp* (median 1.209 ms to saturation) as the
   fast loop's characteristic time instead. This is the most defensible.
2. **Define τ_fast as onset → first observable reaction** and accept that it is
   dominated by the sampling rate (median 97.4 µs here) — then it must be reported
   *with* the baseline gate probability, since it scales as 1/P.
3. **Define it against the fault, not the evidence**: time from the shaper landing to
   the first raised copy. This is dominated by queue-fill time (~77 ms in these runs,
   from the observed `worst_qdepth` trajectory) and characterises the *fault*, not the
   loop.

## Anomalies and operational notes

- **Capture loss:** 0 kernel drops in all 12 reps. 1049 – 1605 frames per rep were
  dropped **by the interface** out of ~715 000 copies, i.e. **0.15 – 0.22 %**. Too
  small to move any median here, but it is a real ceiling: at saturation the faulty
  path alone emits ~2 copies per packet and the collector is a single 25 G port
  shared with the delivered traffic. A study needing every copy must either lower the
  gate or move the collector off dp9.
- **Capture volume:** 80 MB per rep at `-s 96`, 960 MB across 12 reps, 8 575 328 copies
  analysed. The analyser is a raw `struct` pcap reader; scapy is far too slow at this
  volume.
- **Unit trap in the `shape` command.** `setup_skeleton.py shape <vlink> <gbps>` takes
  **Gb/s**. The literal instruction `setup_skeleton.py shape 1 50` would set
  50 Gb/s — i.e. no shaping at all on a 25 G port, and the fault would silently never
  happen. The runs used `shape 1 0.05`. Worth adding an explicit unit suffix to the
  CLI before someone loses an afternoon to it.
- **Rep ordering matters.** The seed must happen *before* the capture starts. An early
  version seeded after the blast began, so the first ~2 s of every capture carried the
  *previous* rep's saturated attention and `t_react` collapsed onto the first frame,
  giving τ_fast ≈ −4.3 s. Those runs were discarded and the harness reordered; the 12
  reps reported here all seed first.

## Harness

- `h7_rep.py setup|arm` (on the switch) — one bfrt connection; `setup` seeds and
  zeroes, `arm` waits, writes the shaper, waits, releases. Arm write **3.9 ms**,
  release write 3.9 ms, so the fault edge is sharp relative to every measured interval.
- `h7_slow.py <n>` (on the switch) — the τ_slow epoch.
- `mcp_blast3.py <pps> <s> <dst>` (on Vision) — paced AF_PACKET blaster, holds
  149 998 pps against a 150 000 pps target.
- `h7_analyse.py <pcap> <faulty_path>` (on Vision) — raw pcap reader emitting the H7
  quantities as JSON.
- `h7_vision.sh`, `h7_rep.sh` — per-rep orchestration; SSH ControlMaster sockets keep
  per-command latency off the critical path.

Nothing was committed.
