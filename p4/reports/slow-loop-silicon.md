# The slow loop on silicon — `controller/epoch_loop.py` first hardware run

Sixth hardware session. Date 2026-08-27, switch `decps@10.10.54.81` (UfiSpace Tofino 1,
SDE 9.13.2), `bf_switchd` PID 30702 on build `mcp_fabric.p4 sha256 5d16721b…`.
**`bf_switchd` was not restarted by this work and nothing was rebooted.** No
`coarse_time` messages. Chip left idle: all 256 `reg_attn` slots at 4096 in both pipes,
no shapers, `tbl_fail` empty, counters zeroed.

Traffic is 10 000 pps from Vision to `10.0.1.2` (both spines), generated with
`mcp_blast3.py` — the paced AF_PACKET blaster, not `mcp_send.py`, because scapy cannot
hold 10 kpps.

**Headline: the bfrt path ran against silicon first try. No API errors.** The three
changes made were two performance fixes and one instrumentation column, all measured;
they are described below and are now in HEAD.

---

## 1. Unit tests on the switch — PASS

```
cd /home/decps/mcp && python3 -m unittest discover -s controller/tests
```

| package state | python | result |
|---|---|---|
| at hand-off | 3.8.10 | **Ran 32 tests — OK** |
| current (after the `infer` fix landed mid-session) | 3.8.10 | **Ran 35 tests — OK** |

No failures, no errors, no 3.9+ syntax problems. `conf/` must be copied alongside
`controller/`: `infer.FROZEN_CONFIG_PATH` resolves to `<repo>/conf/infer/frozen.yaml`
and the module verifies its own source hash against it. Verified consistent for the
version run: `module_hash() = 7896b02dfb07c9b9` matches `frozen.yaml`.

---

## 2. Observe-only run against the live switch — PASS on every check

```
python3 -m controller.epoch_loop --epoch-ms 100 --epochs 100 --freeze-controller \
        --pcap /tmp/copies.pcap --iface enp59s0f0np0 --out /tmp/loop_frozen.csv
```

### The loop had to be split across two hosts, and here is exactly how

The loop needs a live copy source *and* bfrt. The copies arrive at **Vision** (dp9 is
the mirror collector); bfrt only exists on the **switch** (`GRPC_ADDR` is hard-coded to
`localhost:50052`, and the `bfrt_grpc` package ships with the SDE, which is not
installed on Vision). `LiveSource` therefore cannot run where `BfrtAdapter` runs.

As the task anticipated: **copies were captured on Vision to a pcap and replayed with
`--pcap` on the switch, while the counter and register reads ran live.** Concretely,
15 s of copies were captured under 10 kpps steady state, then the loop replayed them on
the switch while a second, statistically identical 10 kpps blast kept the live counters
moving. Consequences to keep in mind:

- The counter deltas and the copies come from **different windows of the same
  steady-state condition**, not the same instants. Under a constant offered load this
  is sound for rate checks, and it is what the numbers below are.
- It would **not** be sound for anything requiring per-epoch correspondence between a
  copy and the counter delta that produced it, and it cannot show the policy's own
  effect on the sampling rate (§3).
- The clean fix is to run the loop on the collector host with a bfrt endpoint reachable
  over the network (make `GRPC_ADDR` a flag, install `bfrt_grpc` on Vision or tunnel
  50052), or to move the mirror collector to a port on the switch host.

### Verification

| check | expected | measured |
|---|---|---|
| copies per epoch | ≈125 (6.25 % × 2 passes × 10 kpps × 0.1 s) | **median 117** (min 93, max 153) |
| `tbl_vlink` delta, uplink pair v0+v1 | ≈1000 pkt/epoch | **exactly 1000** (500 + 500) |
| `tbl_vlink` delta, downlink pair v9+v13 | ≈1000 pkt/epoch | **exactly 1000** (500 + 500) |
| `reg_attn` snapshot | matches `setup_attention.py attn` | **yes** (see below) |
| writes while frozen | 0 | **0 over 100 epochs**, `frozen=1` |
| samples per epoch | 16 vlink + 2 path | **18**, `coverage_paths = 2` |
| counter reads per epoch | 2 tables + 256 slots | **258** |

The 117 vs 125 gap is not error: attention decays slightly below 4096 under load, so
`attn[15:8]` is 15 rather than 16 and the gate probability is 15/256 = 5.86 %, giving
2 × 10 000 × 0.0586 × 0.1 = **117**. The independently captured copy stream agrees
(17 319 copies in 15 s = 1155/s ≈ 1170 predicted).

`reg_attn` cross-check: the loop logged `attn_p0_mean` 4095.98 → 4095.89 over the run
(the mean across all 256 slots, most of which carry no traffic and do not decay), while
`setup_attention.py attn` read immediately afterwards gave `path 2: attn=[4081, 4081]`
and `path 3: attn=[4080, 4080]` — the two slots that *do* carry traffic, decaying as
expected. Consistent, and both pipes agree.

Only 4 of the 16 virtual links carry traffic (v0, v1 uplinks; v9, v13 downlinks), which
is correct for a single source leaf and a single destination leaf; v8 and v12 picked up
2–3 background frames across the whole run.

---

## 3. Policy run — PASS

```
python3 -m controller.epoch_loop --epoch-ms 100 --epochs 30 --policy uniform \
        --budget 4 --a-hi 65535 --a-lo 256 --pcap /tmp/fault.pcap --out /tmp/loop_policy.csv
```
with `setup_skeleton.py fail 0 1 drop` armed throughout (vlink 0 = the uplink of path 2).

**Exactly 4 slots at high attention per epoch, and the set rotates.** `reg_writes = 256`
every epoch (the policy writes the full vector). `chosen` is `0;1;2;3` at epoch 1,
`4;5;6;7` at epoch 2, `8;9;10;11` at epoch 3 … `116;117;118;119` at epoch 30 — a clean
round-robin, 4 × 29 = 116. `attn_hi_slots` (read from the snapshot at the *start* of
each epoch, so it reflects the previous epoch's write) is 0 at epoch 1 and **4 for
every subsequent epoch**.

Independent readback straight from bfrt after the run, not from the loop's own log:

```
slots at 65535: [116, 117, 118, 119]
slots at a_lo=256: 252     other: []
```

Exactly 4 high, 252 low, nothing in between — the write lands as specified.

Fault injection accounting for the capture window: `fail_ctr inj_drop = 713` against
75 000 packets on vlink 0 = 0.95 % (injected 0.999 %), and vlink 9 carried
74 287 = 75 000 − 713 exactly.

### Localization of the injected fault

The suspects do name the faulty path's links, after a warm-up:

```
ep1-17   anomaly=0   (warm-up: statistics still 0)
ep18     anomaly=1   vlink:9=5.503 ; vlink:0=5.416 ; vlink:12=0
ep24     anomaly=1   vlink:9=19.36 ; vlink:0=19.10
ep30     anomaly=1   vlink:9=41.44 ; vlink:0=40.92
```

`vlink:0` — the actually faulty uplink — is in the top-3 suspect list in **18 of 30
epochs**, from epoch 18 onward. `vlink:9` appears in all 30.

**The uplink and the downlink of the faulty path are statistically indistinguishable
here, and that is expected, not a defect.** All the loss evidence is path-level
(`path:2` loss from sid-3 copies), and `infer` de-aggregates a path sample uniformly
over the path's links, which for path 2 are exactly `{vlink:0, vlink:9}`. Both receive
half the loss, so their statistics track each other to within 1 % (41.44 vs 40.92) with
`vlink:9` consistently a hair ahead. Separating them needs a second path that crosses
one link but not the other — i.e. traffic from a second source leaf, which this
single-host testbed cannot generate. Worth stating as a **topology identifiability
limit of the current testbed**, not an inference bug.

Warm-up: the anomaly bit first sets at epoch 18 of 30, consistent with the known
"~10 observations of an element" behaviour. It did fire within 30 epochs here.

---

## 4. A real defect found, and its fix confirmed

**In the first observe-only run — with no fault injected at all — the localizer raised
the anomaly bit in 90 of 100 epochs.** The top-ranked suspect was always a near-idle
virtual link, and it outranked everything else by two orders of magnitude:

```
top-ranked suspect histogram: {vlink:8: 77, vlink:12: 13, vlink:10: 10}
epoch 50 ranked: vlink:8=4893 ; vlink:10=0 ; vlink:11=0
```

`vlink:8` carried **3 packets in the entire 100-epoch run** (2 epochs out of 100); v12
carried 2. Every virtual link gets a `Sample` every epoch, so links with no traffic
were contributing zero-count samples that nevertheless moved the posterior and the
CUSUM. In the first policy run this buried the real signal: `vlink:8 = 2626` against
`vlink:0 = 33.98` for the genuinely faulty link.

This was reported and **fixed in `controller/infer.py` (commit af5e858, "zero-count
probes carry no information … ranking excludes unobserved elements")** while the
session was running. Re-running both experiments against the fixed module:

| | before fix | after fix |
|---|---|---|
| observe-only, no fault: anomaly epochs | **90 / 100** | **0 / 100** |
| policy run with fault: top suspect | `vlink:8` (spurious, stat 2626) | **`vlink:9` / `vlink:0`** (the faulty path's links) |
| policy run: spurious element in top-3 | every anomaly epoch | none |

The false-alarm rate on an idle fabric went from 90 % to 0 %, and the faulty link went
from rank 3 behind a spurious element to rank 1–2. The numbers in §2 and §3 above are
all from the **post-fix** runs.

---

## 5. Changes made to the controller (all measured, all now in HEAD)

**No API errors were found.** `BfrtAdapter` connected, read counters, read and wrote
`reg_attn`, and honoured `--freeze-controller` on the first attempt. The idioms it
copied from `setup_attention.py` and `setup_skeleton.py` were all correct, including
the `(Data, Key)` tuple order, the per-client `bind_pipeline_config`, `client_id 4`,
`pipe_id 0xFFFF`, and `SyncCounters` before every counter read.

Three changes, two of them performance fixes prompted by `tau_slow` overrunning the
epoch:

1. **`hw_adapter.read_attn`: keyless full-table get instead of 256 explicit keys.**
   Measured on silicon, 6 paired repetitions: **47.5 ms keyless vs 54.7 ms with 256
   keys**, identical content, and the keyless result still carries `$REGISTER_INDEX` in
   the key so the indexing logic is unchanged. Saves ~7 ms/epoch.
2. **`hw_adapter.write_attn`: cache the 256 key objects.** They are identical every
   epoch; only the data changes. `t_write` fell from 23.6 ms to 20.5 ms. Less than
   hoped — the residual is `make_data` plus the RPC itself, not `make_key`.
3. **`epoch_loop`: new `vlink_deltas` CSV column.** Per-vlink packet deltas for the
   epoch, taken from the counter samples already in the Observation. This is what makes
   the "1000 per uplink pair" check in §2 verifiable from the log rather than by
   inference; it is a diagnostic column, not a behaviour change.

---

## 6. Measured per-phase timings, and the one thing that does not fit

100 ms epoch, medians over the run:

| phase | observe-only (frozen) | policy run (writes) |
|---|---|---|
| `t_read` (copies) | 0.7 ms | 0.7 ms |
| `t_sync` (counters + `reg_attn` read) | **94.7 ms** | **93.6 ms** |
| `t_infer` | 0.4 ms | 0.4 ms |
| `t_write` (256 slots) | 0.0 ms | **20.5 ms** |
| **`tau_slow`** | **96.2 ms** | **116.6 ms** |
| epochs exceeding the 100 ms epoch | 20 / 100 | **30 / 30** |

**The loop cannot hold a 100 ms epoch when it writes.** Observe-only just fits
(20 % of epochs overrun); with the full 256-slot write every epoch, all 30 overran. The
loop detects this itself and logs the warning, and `run()` then skips the sleep, so the
epoch cadence silently becomes ~117 ms rather than 100 ms. That is worth deciding
explicitly: either raise `--epoch-ms` to ~150, shrink the observe phase, or write only
the slots that changed.

Consistency with the H7 session's `tau_slow` of **88.8 ms**: that figure was raw bfrt
calls (register read 48.5 ms + counter sync/read 29.8 ms + register write 9.6 ms). The
loop's observe phase is 94.7 ms against 78.3 ms for the equivalent raw reads. The
~16 ms difference is the adapter's own Python decoding (`to_dict()` on 64 counter rows
and 256 register rows, plus dict building), **not** switch load: re-measuring the raw
sequence under 10 kpps of traffic gave 87.6 ms against 88.8 ms idle, i.e. no load
sensitivity at all. Likewise `t_write` of 20.5 ms against 9.6 ms raw is Python-side
`make_data` construction for 256 slots.

So the slow loop's cost is dominated by **bfrt read I/O (~78 ms) plus Python object
decoding (~16 ms)**, and the inference itself is negligible at 0.4 ms.

---

## 7. Reproduction

```bash
# on the switch
cd /home/decps/mcp && python3 -m unittest discover -s controller/tests
export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib; P=$SDE_INSTALL/lib/python3.8/site-packages
export PYTHONPATH=$P/tofino:$P/tofino/bfrt_grpc:$P
python3 -m controller.epoch_loop --epoch-ms 100 --epochs 100 --freeze-controller \
        --pcap /tmp/copies.pcap --out /tmp/loop_frozen.csv

# on Vision, concurrently
sudo python3 /home/decps/mcp_blast3.py 10000 25 10.0.1.2
sudo tcpdump -i enp59s0f0np0 -Q in -s 160 -w /tmp/copies.pcap ether dst a5:a5:a5:a5:a5:a5
```

`controller/` and `conf/` were copied to `/home/decps/mcp/` on the switch. Nothing was
committed by this work; the three controller changes were picked up and committed by
the coordinator during the session.
