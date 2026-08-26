# Steps 5–7 on silicon — attention, gating, mirrors and the CSIG tag

Second hardware session on `mcp_fabric`. Date 2026-08-27, switch `decps@10.10.54.81`
(UfiSpace Tofino 1, SDE 9.13.2), `bf_switchd` PID 15392 started 22:40:37 on the final
build `p4/mcp_fabric.p4 sha256 232b7355fe58c67c…` (all 8 steps: 12-byte `fabric_h`,
attention register + PREREG §7.4 rule, TCAM measurement gate, mirror sessions, CSIG
tag). **`bf_switchd` was not restarted and nothing was rebooted by this work.**

Traffic host: Vision `enp59s0f0np0` (dp9, front panel 15/1). Probes are raw L2 frames,
source MAC `02:00:00:00:00:0a`, destination MAC Vision's own, `10.0.1.1 → 10.0.1.2`
(leaf 1), UDP `sport 10000+i`, `dport 5000`, 35-byte payload carrying a sequence
number. Capture is `tcpdump -Q in` on the same interface. Control-plane numbers come
from `setup_skeleton.py counters` (which calls `SyncCounters` first) and
`setup_attention.py attn <path>`.

The path under test is **path_id 2** = leaf 0 → spine 0 → leaf 1, and **path_id 3** =
leaf 0 → spine 1 → leaf 1, read from the `to_loop` action data (`path_id = dst_leaf *
N_SPINE + spray`), identical at hops 0 and 1.

---

## Summary

| item | verdict |
|---|---|
| (a) regression with the natural encoding | **PASS** — the alias fix broke nothing |
| (b) gated sample volume and seed response | **PASS** on counts, **FAIL** on the `measured` flag and on `worst_vlink` |
| (c) fault mirrors | **PASS** on count (±0, both directions), **FAIL** on the `dropped` flag and ethertype |
| (d) attention update from NIC evidence | **PASS**, exact |
| (e) clean decay | **PASS**, exact, but 3 register updates per packet, not 2 |
| (f) CSIG compare-and-replace | **PASS** under congestion; degenerate on an idle fabric |

Four defects were found. Two were control-plane bugs and are **fixed** in
`setup_attention.py`; two are in `mcp_fabric.p4` and are left for its owner.

---

## Defects fixed in this session (control plane)

### D1 — `tbl_eg_vlink` used a different virtual-link encoding from the ingress

`setup_attention.py` computed `vlink_dn(spine, leaf) = 8 + leaf*N_SPINE + spine`
while `setup_skeleton.py` — which is authoritative, because `tbl_vlink` writes
`md.vlink_id` and `tbl_fail` keys on it — uses `8 + spine*N_LEAF + leaf`. Six of the
eight downlinks disagreed (only dp172/q0 = 8 and dp175/q1 = 15 coincided), so
`csig.worst_vlink` named the wrong virtual link exactly when a downlink was the worst
hop. Fixed to match, with the reason recorded at the function.

### D2 — `eg_intr_md.egress_qid` is the PORT-GROUP queue, not the per-port qid

`tbl_eg_vlink` was keyed on the raw qid the ingress wrote into `ig_tm_md.qid`. On
Tofino 1 the egress sees the port-group queue number instead:

```
pg_queue = (port_in_pipe % 4) * 8 + qid          # a port group is 4 ports x 8 queues
```

So only ports sitting in slot 0 of their port group — dp164 and dp172 — ever matched.
**12 of the 16 rows could never match**, and those lookups took the const default
`set_eg_vlink(0)`, stamping `csig.worst_vlink = 0`.

Measured before the fix: `tbl_eg_vlink` TBL_MISS incremented by exactly **1 per
packet** in pipe 1 (two csig-carrying fabric egress events per packet, one hit at
dp164 and one miss at dp173). Deleting the dp164 rows took it to 2 per packet, which
identified dp173 as the miss. After the fix, **0 misses per packet**.

The same arithmetic is what `setup_skeleton.tm_coords()` already used for the TM
shapers, so the two files now agree.

The clinching evidence came from sentinel rows: installing `(dp9, qid q) → 90+q` for
every `q` in 0..31 made all 599 mirrored copies report `worst_vlink = 98`, i.e. the
collector's copies egress at **pg-queue 8** — dp9 is `port_in_pipe 9`, slot 1, so
`1*8 + 0 = 8`. Rows for qid 0..7 alone did nothing, which is why the first sentinel
attempt looked like a null result.

---

## Defects found in `mcp_fabric.p4` (NOT fixed here — owner's call)

### D3 — `Mirror.emit()` copies the packet as it ARRIVED, without that pass's header edits

This is the single most consequential finding, and it invalidates the `flags`-based
acceptance criteria as written.

Evidence, three independent measurements:

1. **Fault mirror on an uplink (a hop-0 event).** `fail 0 50 drop`, 1000 packets:
   `fail_ctr inj_drop = 256`, and Vision received **256 plain `0x0800` frames of
   length 64** — no fabric header at all — even though `act_enter` ran in that same
   pass and would have added a 12-byte shim and a 14-byte tag. The count matches
   `inj_drop` exactly.
2. **Fault mirror on a downlink (a hop-1 event).** `fail 9 50 drop`, 1000 packets:
   `inj_drop = 238`, and Vision received **238 `0x88F0` frames of length 64** carrying
   `fabric.hop = 1` — the value the *previous* pass wrote — where `act_transit` in the
   mirroring pass would have written 2.
3. **The `measured` flag scales with the gate probability of the PREVIOUS pass.** At
   `attn = 4096` (P = 4096/65536 = 1/16) only **37 of 508** copies (7.3 %) had
   `flags` bit0 set; at `attn = 65535` (P ≈ 99.6 %) it was **1976 of 1989** (99.3 %).
   If the copy carried its own pass's edits it would be 100 % in both cases.

Consequences:

- `flags` bit0 (`measured`) never marks the copy that was actually sampled; it marks
  the copy taken on the *next* pass. `flags` bit1 (`dropped`) is never set on a fault
  mirror at all — **0 copies with bit1 in either fault run**.
- A gated sample at **hop 0** arrives at the collector as a plain, untruncated IPv4
  frame indistinguishable from a real delivery. At `attn = 4096`, 4000 packets
  produced 273 such duplicates; at 65535, 1000 packets produced 992. Any
  delivered-count measured at the host is inflated by exactly this.
- A gated sample at **hop 2** still carries the shim (the copy predates
  `act_deliver`'s `setInvalid`), so tagged copies come from passes 1 and 2, not 0 and 1.

The fix belongs in the P4: either stamp the flags into the shim *before* the mirror is
armed (i.e. write `hdr.fabric.flags` from the same action that sets `mirror_type`
rather than in `tbl_final`), or carry the flags in a mirror header field list rather
than relying on the packet body.

### D4 — the CSIG tag on a mirrored copy is overwritten by the COLLECTOR's egress

`Egress` applies `tbl_eg_vlink` + compare-and-replace to **any** packet with a valid
`csig`, including a mirrored copy on its way out of the collector port. The replace
predicate is `diff == 0` where `diff = worst_qdepth |-| this_q` (saturating), i.e. it
fires whenever `this_q >= worst_qdepth` — **including when both are 0**.

On an idle fabric every queue is ~0, so the collector always wins the tie and every
copy arrives stamped `worst_vlink = 0`, `worst_hop = fabric.hop`, `worst_qdepth =` the
collector port's own depth. Measured on an idle fabric: `worst_vlink = 0` in
**508/508**, **1989/1989**, **234/234** copies across three runs, with
`worst_qdepth ∈ {2, 4}`.

Under real congestion the recorded worst is larger than the collector's queue, the
predicate is false, and the true tag survives — see (f). So this is a "ties go to the
last writer" artifact, not a total loss, but it destroys the telemetry in exactly the
regime where the fabric is healthy and the tag should read "nothing interesting here"
rather than a fabricated one.

Fix in the P4: gate the CSIG compare-and-replace on the egress port being a fabric
loop port. Making `tbl_eg_vlink`'s default action a no-op that leaves `md.diff`
non-zero would do it, since a miss already identifies a non-fabric port. A control-
plane workaround is not available: the default action is `const`, and installing a row
for the collector only relabels the corruption.

### D5 (architectural, worth stating) — `reg_attn` is per pipe, and the two evidence sources land in different pipes

`setup_attention.py attn <p>` prints one value per pipe, e.g.
`path 2: attn=[4096, 4096]`. dp9 is in pipe 0; the loop ports are in pipe 1. Therefore:

- **NIC evidence** (§6 D1) arrives on dp9 and updates **pipe 0 only**. Measured in (d):
  `attn=[14336, 4096]` after 10 evidence packets — pipe 1 untouched.
- **CSIG exceedance** is detected at hops 1 and 2, which ingress on loop ports, so it
  updates **pipe 1 only**. Measured in (f): `path 3: attn=[4090, 65535]`.
- Hop 0 cannot see a CSIG tag at all — the tag is inserted by `act_enter` later in the
  same pass — so the source leaf's gate can never learn about downstream congestion
  from CSIG, only from NIC evidence.

Net effect: the source-leaf sampling decision and the in-fabric sampling decision are
driven by disjoint evidence and never converge. This is not a bug in the code as
written, but it is a property the design should state explicitly, and it is invisible
in a single-pipe simulator.

### D6 (minor) — the evidence UDP port in decimal

`UDP_PORT_EVIDENCE = 0xE5E5` is **58853**, not 59877. The tests used 58853.

---

## Acceptance results

### (a) Regression with the natural encoding (`SHIM_MD_ALIAS = False`) — PASS

`setup_attention.py seed 0` first, so the measurement gate cannot fire and the
forwarding path is measured on its own. 1000 packets to `10.0.1.2`:

```
frames from generator MAC : 1000
  plain_0x0800_len77         1000
distinct sequence numbers : 1000   (duplicate deliveries: 0)

vlink  0  up   L0->S0  dp164 qid=0   pkts=500   bytes=40500
vlink  1  up   L0->S1  dp164 qid=1   pkts=500   bytes=40500
vlink  9  down S0->L1  dp173 qid=0   pkts=500   bytes=53500
vlink 13  down S1->L1  dp173 qid=1   pkts=500   bytes=53500
```

1000 of 1000 returned as plain `0x0800`, both shims stripped, hash spray exactly
500/500, and the expected uplinks and downlinks only. **The alias fix broke nothing.**

The byte counters independently confirm the new wire format: 40500/500 = 81 B at hop 0
(77 B frame + 4 B FCS) and 53500/500 = 107 B at hop 1, a difference of exactly **26 B
= 12 B `fabric_h` + 14 B `csig_h`**.

`setup_skeleton.py up` also negotiated the new action arity by itself, reporting
`to_loop written as vlink_id, loop_port, qid, next_vsw, path_id, …` and
`act_enter written as next_hop, epoch` — the mechanism added after the step-4 session
picked up both new arguments without an edit.

### (b) Gated samples — PASS on counts, FAIL on the flag and on `worst_vlink`

`attn = 4096` → `attn[15:8] = 16` → gate row L=16 → P = 4096/65536 = 6.25 % per pass.
4000 packets:

| quantity | measured | expected |
|---|---|---|
| `0x88F0` mirrored copies | **508** | ~500 (2 taggable passes × 4000 × 1/16); accept 400–600 |
| plain duplicate deliveries (hop-0 copies, D3) | 273 | ~250 |
| `csig.path_id == fabric.path_id` | **508/508** | all |
| copies on path 2 / path 3 | 250 / 258 | ~even |
| **`flags` bit0 set** | **37/508 (7.3 %)** | all — **FAIL**, see D3 |
| **`worst_vlink` ∈ {0,1,9,13}** | **0 in 508/508** | uplink or downlink id — **FAIL**, see D4 |

Seed sweep:

| seed | tagged copies | plain duplicates | `flags` bit0 |
|---|---|---|---|
| `seed 0` | **0** | 0 | — |
| `seed 4096` (1000 pkts) | 132 | 63 | 9/132 |
| `seed 65535` (1000 pkts) | **1989** (≈2/packet) | **992** (≈1/packet) | 1976/1989 (99.3 %) |

`seed 0` gives exactly zero copies and 1000/1000 clean deliveries; `seed 65535` gives
two tagged copies plus one plain duplicate per packet, i.e. all three passes sampling.
Re-seeded to 4096 afterwards.

### (c) Fault mirrors — PASS on count (±0), FAIL on flag and ethertype

| run | `fail_ctr inj_drop` | 64-byte mirror copies | match |
|---|---|---|---|
| `fail 0 50 drop` (uplink, hop 0) | **256** | **256** plain `0x0800` | **exact** |
| `fail 9 50 drop` (downlink, hop 1) | **238** | **238** `0x88F0`, `hop=1` | **exact** |

Both are ±0 against `fail_ctr`, and the 64-byte length confirms mirror session 3
(`$max_pkt_len = 64`) is the one that fired. The forwarding arithmetic also closes:
in the uplink run, delivered distinct sequence numbers were **744 = 1000 − 256**, and
downlink `vlink 9` carried **244 = 500 − 256**.

What fails is the *form* of the evidence, per D3: no copy has `flags` bit1 set, and a
hop-0 fault produces a plain IPv4 copy with no fabric header. `fail-clear` was run
after each.

One accounting subtlety worth recording: in the downlink run the delivered distinct
count was 777 rather than the naive 762 = 1000 − 238. The 15 extra are hop-0 gated
mirror copies (full 77-byte plain frames) belonging to packets that were later dropped
at hop 1 — expected count `1000 × 1/16 × (238/500) ≈ 15`. They are D3 duplicates
masquerading as deliveries.

### (d) Attention update from NIC evidence — PASS, exact

Evidence packets: IPv4/UDP `dport 0xE5E5` (58853), payload
`magic=0xE5, path_id=2, rtt_q=0, loss_q=5, ecn_q=0, flags=0, seq16`.

```
before                       path 2: attn=[4096,  4096] clean=[ 0, 0]
after 10 pkts, loss_q = 5    path 2: attn=[14336, 4096] clean=[ 0, 0]
after 10 pkts, loss_q = 0    path 2: attn=[14336, 4096] clean=[10, 0]
```

- 4096 + 10 × 1024 = **14336**, exact, and `clean` reset to 0 ✓
- `loss_q = 0` does **not** bump ✓ (threshold is `loss_q >= 1`). It does take the clean
  branch, so `clean` advances by 10 — correct per the rule, worth knowing.
- Evidence packets never reach `tbl_vlink`: the only virtual-link traffic during the
  test was 1 packet each on vlinks 0/1/8/12, which is Vision's own background traffic
  to `dst_leaf 0`, not the 20 evidence packets ✓
- Pipe 1 is untouched — see D5.

### (e) Clean decay — PASS, exact, and it is 3 updates per packet

Re-seeded to 4096, counters zeroed, 10000 packets to `10.0.1.2`:

```
packets on path 2 (uplink vlink 0, dst=1) : 5000
packets on path 3 (uplink vlink 1, dst=1) : 5000

path 2: attn=[4095, 4094] clean=[904, 1808]
path 3: attn=[4095, 4094] clean=[904, 1808]
```

Reconciliation, with `n_clean = 4096`:

- **pipe 0** sees the packet **once** (hop 0, ingress dp9): 5000 clean events =
  1×4096 + 904 → one decrement, `attn = 4095`, `clean = 904`. Exact.
- **pipe 1** sees it **twice** (hop 1 on dp172 and hop 2 on dp165): 10000 clean events
  = 2×4096 + 1808 → two decrements, `attn = 4094`, `clean = 1808`. Exact.

So the register is updated **three times per packet**, not twice: `tbl_attn.apply()`
is outside the `md.hop != LAST_HOP` guard, so the delivery pass updates it too, and at
that pass `md.attn_idx` comes from the parser (`hdr.fabric.path_id`), which is the same
path id. Combined with D5 (per-pipe registers) the correct rule is
`decrements = floor(passes_in_that_pipe / n_clean)`, with 1 pass per packet in the
ingress pipe of the host and 2 in the pipe that owns the loop ports.

### (f) CSIG compare-and-replace — PASS under congestion, degenerate when idle

**Idle fabric.** `worst_qdepth ∈ {2, 4}` and `worst_vlink = 0` in every copy, because
the collector wins the tie (D4). `worst_hop` always equals the copy's own
`fabric.hop`, which is the same artifact.

**Under congestion.** A 50 Mb/s max-rate shaper was installed on **vlink 1** (uplink
L0→S1, dp164 qid 1, pipe 1, pg_id 9, pg_queue 1) and 20000 frames were blasted from
Vision with a raw AF_PACKET sender at **298 651 pps = 241 Mb/s**, comfortably above the
shaper. Vlink 1 was chosen over vlink 0 deliberately: virtual-link id 0 is
indistinguishable from the `set_eg_vlink(0)` miss default, so a test on vlink 0 cannot
tell a correct stamp from a corrupted one.

```
mirrored copies                         16840
(worst_vlink, worst_hop) = (1, 1)       15577   <- the shaped uplink, 92.5 %
(worst_vlink, worst_hop) = (0, 1)         616   <- unshaped path, collector tie
(worst_vlink, worst_hop) = (0, 2)         647   <- unshaped path, collector tie
worst_qdepth  max 11306 cells, median 5968, >= 4096 in 11341 copies
copies on path 3 (shaped) / path 2      15690 / 1150
```

`worst_vlink` is the shaped link in 92.5 % of copies and `worst_qdepth` is three orders
of magnitude above idle, so the compare-and-replace works and the tag survives both the
downstream hop and the collector once there is a real worst hop to report.

The run also demonstrates the whole loop end to end, which is the point of steps 5–7:

```
path 3: attn=[4090, 65535]        (shaped path)
path 2: attn=[4090, 4084]         (unshaped path)
```

Congestion on the uplink → CSIG tag records 5968 cells median → at the next hop's
ingress `tbl_exceed_csig` (threshold 4096 cells) fires → `attn |+| 1024` saturates at
**65535** in pipe 1 → the gate moves from 6.25 % to ~100 % on that path, which is why
15690 of 16840 copies are path 3. The unshaped path decayed normally. Pipe 0's copy of
path 3 stayed at 4090 because hop 0 never sees a CSIG tag (D5).

The shaper was disarmed afterwards with the new `setup_skeleton.py unshape 1`, and a
final 1000-packet run returned 1000 of 1000 with the counters back at 500/500 and
500/500.

---

## Changes made to the control plane

`p4/control/setup_attention.py`
- `vlink_dn` corrected to the ingress encoding (D1).
- new `eg_qid()`; `plan_eg_vlink` now keys on the port-group queue (D2).
- `install_eg_vlink` sweeps stale rows left by the previous encoding (12 removed on
  first run).

`p4/control/setup_skeleton.py`
- new `unshape <vlink>` command: disarms `max_rate_enable` and restores 25 Gb/s. A
  shaper left armed is a silent packet sink, so `shape` now has an inverse.
- `shape` accepts a fractional Gb/s so a rate low enough to queue a software generator
  is expressible.

Neither file was committed.

## Things left as they are

- Mirror sessions stay at sid 1 (128 B) and sid 3 (64 B) → dp9. `setup_skeleton.py`'s
  own `install_mirrors` is still the documented no-op; `setup_attention.py` owns the
  sessions now, and the two do not conflict.
- `tbl_exceed_evid`'s second row is `(any loss, rtt_q >= 255)`, i.e. the RTT trigger is
  effectively off, as `up` intends.
- Table debug counters are left armed `TBL_MISS` on `tbl_eg_vlink` in both pipes and on
  `tbl_vlink`/`tbl_final` from the previous session. They are read-only diagnostics with
  no forwarding effect and they are what localised D2.
- No `coarse_time` messages in the switchd log (`grep -c` = 0).
- Final state: `up` on both control planes, `reg_attn` seeded 4096, counters zeroed, no
  shapers armed, `tbl_fail` empty, `tbl_eg_vlink` exactly 16 rows.

## Harness

Scripts staged on Vision at `/home/decps/`:

- `mcp_send.py <n> <dst_ip> [inter]` — scapy probe generator (from the step-4 session).
- `mcp_blast.py <n> <dst_ip> [sport]` — raw AF_PACKET blaster, ~300 kpps / 241 Mb/s,
  needed to build a queue behind a TM shaper; scapy cannot.
- `mcp_evid.py <n> <path_id> <loss_q> [rtt_q]` — NIC evidence packets (§6 D1).
- `mcp_decode.py <pcap> [--json]` — decodes the 12 B `fabric_h` + 14 B `csig_h` wire
  format, separates deliveries from mirrored copies, and cross-checks
  `csig.path_id` against `fabric.path_id`.

Capture is always `tcpdump -i enp59s0f0np0 -Q in -s 300 -w … ether src
02:00:00:00:00:0a`, stopped by saved PID (never `pkill -f`, which also matches the
enclosing `sudo bash -c` and kills the session).
