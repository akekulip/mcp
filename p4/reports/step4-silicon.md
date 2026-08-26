# Step 4 on silicon — the 4x2 fabric forwards, and one real P4 defect

First hardware run of `mcp_fabric.p4`. Everything before this report was compiled
but never executed on a chip. Date: 2026-08-26. Switch `decps@10.10.54.81`
(ufispace, Tofino 1, SDE 9.13.2). `bf_switchd` (PID 4419, started 21:22:28) is
running the **step-4** build of `mcp_fabric.p4`, `sha256 c40dbfbe85e4…`, which was
git HEAD when this work started. `p4/mcp_fabric.p4` was neither edited nor
reloaded here. **While this testing was in progress the other engineer committed
steps 5–8 and replaced the switch's `mcp_fabric.p4`, `mcp_fabric.bfrt.json` and
`tofino.bin` on disk (22:27–22:28) without restarting `bf_switchd`** — see §2.5,
because it has real consequences for the control plane. Everything measured below
was executed by the step-4 dataplane.

Traffic host: **Vision** `enp59s0f0np0` (MAC `3c:fd:fe:cc:5d:c0`) on front panel
15/1 = `dev_port 9`. Hulk is not cabled to the switch and played no part.

---

## 1. What was programmed

`p4/control/setup_skeleton.py` was rewritten from the obsolete 2-leaf x 4-spine /
`dp68`+`dp8`+`dp65` assumptions to the real wiring and the decided shape.

**Topology as verified from `bfshell -> ucli -> show`** (the `D_P` column is
authoritative):

| role | front panel | dev_port | speed |
|---|---|---|---|
| Vision, leaf 0's host | 15/1 | 9 | 25G RS-FEC, UP |
| loop pair 0 | 5/0 ↔ 6/0 | 164 ↔ 172 | 25G RS-FEC, UP |
| loop pair 1 | 5/1 ↔ 6/1 | 165 ↔ 173 | 25G RS-FEC, UP |
| loop pair 2 | 5/2 ↔ 6/2 | 166 ↔ 174 | 25G RS-FEC, UP |
| loop pair 3 | 5/3 ↔ 6/3 | 167 ↔ 175 | 25G RS-FEC, UP |

All nine ports were already added and UP, so `bring_up_ports()` only reports and
verifies them; it adds a port only if one is missing. Re-adding a live port
bounces the link, and a bounced DAC in the middle of a fabric is a silent sink.

**Virtual-link encoding** (16 links, one real TM queue each):

```
uplink   leaf l -> spine s :  id = l*2 + s        (0..7)   queue = (5/l, qid=s)
downlink spine s -> leaf l :  id = 8 + s*4 + l    (8..15)  queue = (6/l, qid=s)
```

Bit 3 of the id is the direction, and the spine index is the real TM qid in both
directions. The two directions sit on different physical ports (cage 5 up, cage 6
down), so `qid = s` is unambiguous and the "qid 2+s downstream" variant offered in
the task is not needed: 8 ports x 2 qids already gives 16 distinct queues.
Direction lives in the id, so one-direction asymmetric failure is free.

**The three passes**, and why each is identifiable on the wire:

```
hop 0   ingress dp9     role HOST, src_leaf 0   -> uplink   out 5/l  qid s
hop 1   ingress 6/l     role LOOP, src_leaf l   -> downlink out 6/d  qid s
hop 2   ingress 5/d     role LOOP, src_leaf d   -> deliver  out dp9
```

Both halves of loop pair `l` carry `src_leaf = l`. A cage-6 port only ever sees
hop-1 traffic and a cage-5 port only ever sees hop-2 traffic, so a port frame
counter is a direct check on each pass — which is exactly how the defect below was
localised.

**Hosts.** `10.0.1.1 -> leaf 0` (Vision). Leaves 1, 2, 3 have no host, so
`10.0.1.2/3/4` map to leaves 1/2/3 and their delivery port is also `dp9`: the
packet traverses leaf0 -> spine s -> leaf d and is then **hairpinned back to
Vision**. That is deliberate — it is what lets a single-host testbed exercise all
four leaves and both spines.

**Rows installed by `up`:** `tbl_port_role` 9, `tbl_dst_leaf` 4, `tbl_vlink` 64
(32 hop-0 + 32 hop-1, over 16 distinct vlink ids), `tbl_final` 12,
`tbl_spray_mode` 1 (`spray_from_hash`, mask = 1), `reg_spray_rr` 64 slots seeded.

**Not installed:** queue shapers (available as `shape <vlink> <gbps>`, kept out of
`up` — an inert or mis-sized shaper is a silent packet sink and steps 1–4 do not
need finite link capacity to be correct), and mirror sessions (`install_mirrors`
is a documented no-op: `dp65`/33-1 has no module, the Agilio leg is gone, and
33/2–33/3 belong to another rig).

---

## 2. The defect: parser-lifted metadata is byte-aliased

**Symptom.** Hop 0 worked immediately — `dp164` transmitted, `dp172` received the
same count — but *nothing* came back to Vision and no hop-1 counter ever moved.

**Localisation.** The per-pipe table debug counters (`tbl_dbg_counter`, armed
`TBL_MISS`) split the pipeline cleanly. `dp9` is in pipe 0, the loop ports are in
pipe 1. Over one 100-packet run, pipe 1 showed:

| table | key source | result |
|---|---|---|
| `tbl_port_role` | `ig_intr_md.ingress_port` | **HIT** +101 |
| `tbl_dst_leaf` | `hdr.ipv4.dst_addr` | **HIT** +100 |
| `tbl_spray_mode` | `md.role`, `md.hop` | hit 0 |
| `tbl_vlink` | `md.*` | **MISS** +101 |
| `tbl_final` | `md.role`, `md.hop`, `md.dst_leaf` | **MISS** +101 |

The two tables that hit key on intrinsic metadata and header fields; the two that
miss key on `md` fields. `tbl_dst_leaf` hitting on `10.0.1.2` proves the 6-byte
shim *was* parsed (IPv4 was read at the correct offset). Capturing the shimmed
frame directly — by temporarily pointing the uplink at `dp9` — showed the wire
bytes were perfect:

```
88f0 | 11 01 01 00 00 00     vsw_id=17 hop=1 spray=1 loops=0 flags=0 nxt=0
88f0 | 10 01 00 00 00 00     vsw_id=16 hop=1 spray=0 ...
```

So the shim was right and the lookups still missed. Because `if (md.hop == 0)`
was false and `if (md.hop != LAST_HOP)` was true while no `hop == 1` row matched,
`md.hop` had to be some third value. Sweeping candidate key values into
`tbl_vlink` and watching which per-row `DirectCounter` moved gave the answer, and
a second sweep confirmed the complementary case — 60 of 60 packets accounted for:

```
HIT role=2 hop=0x1001 src=0 dst=1 spray=0x0100  pkts=28   (the 28 spine-0 packets)
HIT role=2 hop=0x1101 src=0 dst=1 spray=0x0101  pkts=32   (the 32 spine-1 packets)
```

**Measured rule.** The parser's

```p4
md.hop       = (bit<16>)hdr.fabric.hop;
md.spray_idx = (bit<16>)hdr.fabric.spray;
```

do **not** zero-extend on this binary. bf-p4c gave each 16-bit metadata field the
parser's 16-bit extraction container, so the high byte holds the **preceding shim
byte**:

```
md.hop       == (fabric.vsw_id << 8) | fabric.hop
md.spray_idx == (fabric.hop    << 8) | fabric.spray
```

The fresh-from-host pass is unaffected: at hop 0 there is no shim, `md.hop` comes
from the parser start state (a constant assign) and `md.spray_idx` from the spray
action, so both are clean. Only the looped passes are corrupted — which is why
this could not be caught by anything short of running the program.

**Workaround, entirely in the control plane.** The high byte of `md.hop` is
whatever the previous pass wrote into `fabric_h.vsw_id`, and that value is pure
control-plane data (`next_vsw` in `to_loop`). Writing `next_vsw = 0` on every row
makes `md.hop` exactly the hop number again, which restores both gates and every
`tbl_final` key. `md.spray_idx` cannot be repaired the same way — its high byte is
the hop number, which must be 1 and 2 — so the looped-pass `tbl_vlink` rows carry
the aliased spray key `hop << 8 | spine` instead (`0x0100` / `0x0101`).

This is controlled by `SHIM_MD_ALIAS = True` in `setup_skeleton.py`. The offline
`self_check()` asserts the three invariants that make the workaround sound:
the source pass must still read as hop 0, the transit pass must not read as
`LAST_HOP`, and — the sharp one — the **delivery pass must read exactly as
`LAST_HOP`**, or `tbl_vlink` and `tbl_fail` would run on it and black-hole every
delivered packet. It also asserts that `md.hop` does not depend on the spine,
because `tbl_final` has no spray key and could not express it.

**Cost.** `fabric_h.vsw_id` is 0 on the wire instead of naming the virtual switch
of each pass. Nothing in steps 1–4 keys on it (`md.vsw_id` is parsed and never
used) and the spine is still recoverable from `fabric_h.spray`, which is the field
§4 makes load-bearing. It is a wire annotation lost, not a mechanism.

**The real fix belongs in `mcp_fabric.p4`**, which this task must not edit. Any of:
stop lifting these bytes in the parser and set them from a MAU action; declare the
metadata fields `bit<8>`; or pair the shim bytes into `bit<16>` header fields so
the widths line up. When that lands, set `SHIM_MD_ALIAS = False` and re-run `up` —
every key reverts to the natural encoding and `vsw_id` goes back to naming the
virtual switch. **Nothing else in the control plane changes.**

---

## 2.5 Hazard: the served bfrt schema can describe a program the chip is not running

`bf_switchd` reads its bfrt schema from the JSON path named in its conf file and
serves that to gRPC clients. Replacing that file under a **running** switchd
therefore changes what the control plane is *told* about the program while the
chip keeps executing the binary loaded at startup. That is exactly what happened
at 22:27–22:28: `mcp_fabric.bfrt.json` on the switch became the step-8 schema
while the chip stayed on the step-4 binary from 21:22.

The two differ in action arity:

| action | step 4 (loaded on the chip) | step 5+ (served schema) |
|---|---|---|
| `Ingress.to_loop` | `vlink_id, loop_port, qid, next_vsw` | `+ path_id` |
| `Ingress.act_enter` | `next_hop` | `+ epoch` |

The first `up` run after the swap trusted the schema, sent `path_id`, had every
`tbl_vlink` write rejected, and — because `install_vlinks` cleared the table
*before* installing — left `tbl_vlink` **empty**. Forwarding went to zero
(0 of 1000 packets returned). Two changes were made so this cannot recur:

1. **Arity is negotiated, not assumed.** `install_vlinks` and `install_final`
   propose the schema-implied form first and fall back through the alternatives,
   keeping the first form the switch actually accepts and reporting it:
   `tbl_vlink: to_loop written as vlink_id, loop_port, qid, next_vsw, …` and
   `tbl_final: act_enter written as next_hop`. `TO_LOOP_PATH_ID` and
   `OPTIONAL_ACTION_ARGS` allow forcing either way.
2. **Write first, sweep second.** Stale rows are now removed only *after* every
   planned row is in place, and only rows outside the planned key set are removed.
   A failed install can no longer empty a table.

Both were verified: `up` correctly selected the 4-argument `to_loop` and the
1-argument `act_enter` against the step-4 chip, and a following 1000-packet run
returned 1000 of 1000 with the counters back to 500/500 on the uplinks and
500/500 on the downlinks.

A separate bug was fixed in the same place: the schema probe used
`info.data_dict_allname[action]`, which is not keyed by action name and raises
`KeyError`, so the detection silently reported "no such field" every time. The
correct call is `info.data_field_name_list_get(action)`.

**Recommended next step for whoever owns the deployment:** restart `bf_switchd`
so the chip runs the step-8 binary that is now on disk, then re-run
`setup_skeleton.py up` and re-check the aliasing. The step-8 parser still contains
the same construct that produced the defect —

```p4
md.hop       = (bit<16>)hdr.fabric.hop;      // mcp_fabric.p4:260
md.vsw_id    = (bit<16>)hdr.fabric.vsw_id;   // :261
md.spray_idx = (bit<16>)hdr.fabric.spray;    // :267
```

— so the aliasing is very likely still present, but that is a property of the
compiled binary and must be **re-measured**, not assumed. The new
`bit<16> path_id` field in `fabric_h` is lifted at matching width
(`md.attn_idx = hdr.fabric.path_id`) and should be unaffected. The sweep that
measured it is cheap to repeat: install `tbl_vlink` probe rows across candidate
`(md.hop, md.spray_idx)` values and read which per-row `DirectCounter` moves.

---

## 3. Acceptance results

All counts are from `setup_skeleton.py counters` (which calls `SyncCounters`
first) and from a `tcpdump -Q in` capture on Vision's own `enp59s0f0np0`, filtered
on the generator MAC `02:00:00:00:00:0a`. Probes are IPv4/UDP,
`10.0.1.1 -> 10.0.1.2`, `sport 10000+i`, `dport 5000`, 35-byte payload carrying a
sequence number.

### (a) Per-virtual-link counters — PASS

1000 packets to `10.0.1.2` (leaf 1), clean fabric:

```
vlink  0  up   L0->S0  dp164 qid=0   pkts=501   (500 test + 1 background)
vlink  1  up   L0->S1  dp164 qid=1   pkts=500
vlink  9  down S0->L1  dp173 qid=0   pkts=500
vlink 13  down S1->L1  dp173 qid=1   pkts=500
```

Exactly the two expected uplinks (leaf0 -> spine0/1) and the two expected
downlinks (spine0/1 -> leaf1), and the hash spray split them **500 / 500**.
Port counters agree: `dp165` RX 1000 (the hop-2 ingress at leaf 1's cage-5 port),
`dp173` TX 1000 (the downlink egress).

A later clean run also confirmed the pass structure arithmetically: `tbl_fail`'s
default `inj_none` counter read **2000** for 1000 packets — two fabric passes each,
with the delivery pass correctly skipping `tbl_fail`.

Leaves 2 and 3, 200 packets each:

```
vlink 10 down S0->L2  pkts=100     vlink 14 down S1->L2  pkts=100
vlink 11 down S0->L3  pkts=100     vlink 15 down S1->L3  pkts=100
```

200/200 returned in both cases. Twelve of the sixteen virtual links have now
carried real traffic; uplinks 2–7 (leaves 1–3 towards the spines) are unreachable
because only leaf 0 has a host.

### (b) Shim stripped on delivery — PASS

1000 of 1000 frames returned with `ether_type 0x0800`, 1000 distinct sequence
numbers 0..999, no duplicates, no malformed frames. The returned bytes are the
original frame:

```
3cfd fecc 5dc0 0200 0000 000a 0800 4500 003f 0001 0000 4011 64ab
0a00 0101 0a00 0102 2710 1388 002b 8129 4d43 5030 3030 3030 30…
```

`ipv4.total_len` is 0x003f = 63 as sent (the shim is an L2 shim between Ethernet
and IPv4, so no length or checksum is ever touched), the UDP ports and checksum
are unchanged, and the payload `MCP000000` is intact.

### (c) `fail 0 50 drop` — PASS

`fail 0 50 drop` installs one `tbl_fail` row: `vlink 0`, `rnd_fail in [0,32767]`,
= 50.000%. 1000 packets:

| quantity | value |
|---|---|
| uplink vlink 0 (spine 0) offered | 500 |
| uplink vlink 1 (spine 1) offered | 500 |
| downlink vlink 9 (S0->L1) delivered | **242** |
| downlink vlink 13 (S1->L1) delivered | 500 |
| `tbl_fail` vlink 0 `inj_drop` | **259** |
| frames captured at Vision | **742** |

The affected virtual link's delivered count is halved (242 of 500 = 48.4%,
259 of 500 = 51.8% dropped — both within noise of 50% at n=500), the unaffected
spine is untouched at 500, and end-to-end delivery is 742 = 500 + 242, matching
the capture exactly.

`fail_ctr` reads 259 where the flow-level arithmetic says 258. The extra one is
explained and is worth recording as a **design wart**: `md.vlink_id` initialises
to 0, and `tbl_vlink`'s default action `black_hole` does not set it, so a packet
that resolves *no* virtual link arrives at `tbl_fail` carrying `vlink_id = 0` and
can match a failure row installed for real vlink 0. One background frame from
Vision did exactly that. Suggested fix when `mcp_fabric.p4` is next touched:
initialise `md.vlink_id` to `0xFFFF` in the parser start state, or reserve id 0.

### (d) `fail-clear` — PASS

After `fail-clear`, 1000 packets: **1000 of 1000** returned. Counters back to
500/500 on the uplinks and 500/500 on the downlinks, `black_hole` default counter
0, `inj_none` default counter 2000. A final confirmation run after everything else
also returned 1000/1000, so the chip is left in a working state.

### Extra: `blackhole 0 1 0` — PASS

Deleting the `(leaf 0 -> leaf 1, spine 0)` row and sending 400 packets: 200
returned (the spine-1 half), `vlink 1` carried 200, and the counted default action
recorded **202** black-holed packets (200 test + 2 background). The design claim
that black-holing gives exact ground truth holds.

---

## 4. Deviations, and things left as they are

- **`SHIM_MD_ALIAS` workaround** — section 2. This is the one substantive
  deviation from the intended design: `fabric_h.vsw_id` is 0 on the wire.
- **`qid = spine` in both directions**, rather than `2+s` downstream. Documented in
  the encoding block; the directions are on different ports so the queues are
  already distinct.
- **Leaves 1–3 deliver to `dp9`** (hairpin), because no host is cabled to them.
  `LEAF_HOST_DP` is a one-line change per leaf when that changes.
- **Shapers not installed by `up`, and `shape` was NOT exercised on silicon.** It is
  available as `shape <vlink> <gbps>`; the TM target is computed per-port
  (`pipe = dev_port >> 7`), so the loop ports correctly use pipe 1, not pipe 0 —
  but that path is unverified, and the `pg_queue` arithmetic assumes the default
  8-queues-per-port carving. Verify both before relying on it.
- **Only the `hash` spray mode was exercised.** `random`, `rr` and `sel` are
  installed by the same one-row table but were not run; `sel` additionally needs
  ActionProfile members and a selector group, which nothing here installs.
- **Mirror sessions: none.** No collector exists on this testbed.
- **`reg_spray_rr` is per pipe.** All host traffic enters on `dp9` (pipe 0) today,
  so the round-robin counter is effectively single-copy; a host in another pipe
  would make it per-pipe. `set_spray("rr")` prints this warning.
- **Table debug counters left armed** at `TBL_MISS` on `tbl_vlink` and `tbl_final`
  in both pipes. They are a read-only diagnostic with no forwarding effect and
  they are the instrument that found the defect; leaving them armed is deliberate.
- **`bf_switchd` log noise.** `up` logs `Table Add failed … Already exists` for
  every row that already exists — a consequence of `_upsert` trying `entry_add`
  before `entry_mod`. Benign. **No `coarse_time` messages at all** (`grep -c` = 0).
- **Default-entry counters** (`black_hole`, `inj_none`) are cumulative since
  program load and are not reset by re-installing rows; `zero` now resets them
  explicitly, which succeeded on this SDE.
- **The on-disk program files on the switch no longer match the running binary**
  (§2.5). The chip runs step 4; `/home/decps/mcp/p4/` holds step 8. This must be
  resolved by a `bf_switchd` restart before any step-5+ testing, and the results
  in this report re-validated against the new binary.
- Nothing was rebooted. `bf_switchd` was never restarted by this work.

## 5. Control-plane API notes worth keeping

- `entry_get` yields **`(Data, Key)`**, not `(Key, Data)`. The previous skeleton
  had this backwards, which would have silently read the wrong fields.
- A table's `const default_action` counter is the **default entry** and is
  invisible to a plain `entry_get`; it needs `default_entry_get`. Without it,
  "black-holed" and "forwarded" ground truth simply does not appear.
- `entry_del(target)` with no key list bulk-deletes, and it works where deleting
  range-match keys read back from `entry_get` does not.
- `tbl_dbg_counter` accepts `TBL_HIT` and `TBL_MISS` but **not** `TBL_HIT_MISS`
  (`INVALID_ARGUMENT`), and its target must be a specific pipe.
- P4 tables are symmetric: write with `pipe_id = 0xffff`. TM tables are
  pipe-specific and must use the port's own pipe.
- `$COUNTER_SPEC_PKTS` / `$COUNTER_SPEC_BYTES` can be written on `entry_add`, which
  is how `up` and `zero` reset the per-row counters.
- Action-data field names come from `info.data_field_name_list_get(action)`.
  `info.data_dict_allname` exists but is **not** keyed by action name, so indexing
  it by one raises `KeyError` — inside a bare `try/except` that becomes a feature
  that silently never fires.
- `tbl_dbg_counter` values are cumulative and per pipe, and reading them does not
  clear them, so take a before/after snapshot and diff.

## 6. Exact commands

On the switch (`ssh decps@10.10.54.81`):

```bash
export SDE=/home/decps/Downloads/bf-sde-9.13.2
export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib
P=$SDE_INSTALL/lib/python3.8/site-packages
cd /home/decps/mcp/p4/control
PYTHONPATH=$P/tofino:$P/tofino/bfrt_grpc:$P python3 setup_skeleton.py up
PYTHONPATH=$P/tofino:$P/tofino/bfrt_grpc:$P python3 setup_skeleton.py zero
PYTHONPATH=$P/tofino:$P/tofino/bfrt_grpc:$P python3 setup_skeleton.py fail 0 50 drop
PYTHONPATH=$P/tofino:$P/tofino/bfrt_grpc:$P python3 setup_skeleton.py fail-clear
PYTHONPATH=$P/tofino:$P/tofino/bfrt_grpc:$P python3 setup_skeleton.py counters
PYTHONPATH=$P/tofino:$P/tofino/bfrt_grpc:$P python3 setup_skeleton.py ports
```

Port state (`show` lands directly in the `pm` context, and `bfshell` only flushes
its output when it exits):

```bash
( sleep 4; printf "ucli\n"; sleep 4; printf "show\n"; sleep 6; printf "exit\nexit\n"; sleep 2 ) \
  | timeout 150 $SDE_INSTALL/bin/bfshell | tr -d "\r"
```

On Vision, as root (scripts staged at `/home/decps/mcp_send.py` and
`/home/decps/mcp_analyse.py`; no IP address was added to the interface — the probe
is raw L2 and does not need one):

```bash
tcpdump -i enp59s0f0np0 -Q in -s 200 -w /tmp/mcp.pcap ether src 02:00:00:00:00:0a &
TD=$!
sleep 3
python3 /home/decps/mcp_send.py 1000 10.0.1.2 0.001
sleep 4
kill $TD
python3 /home/decps/mcp_analyse.py /tmp/mcp.pcap
```

`mcp_send.py` sends `Ether(dst=<Vision MAC>, src=02:00:00:00:00:0a)/IP(10.0.1.1 ->
dst)/UDP(sport=10000+i, dport=5000)/payload`. The source MAC is locally
administered rather than Vision's own so the returning frame cannot be discarded
by a self-MAC receive filter, and the destination MAC is Vision's own so the
hairpinned copy is accepted without relying on promiscuous mode.

**Do not use `pkill -f "tcpdump -i enp59s0f0np0"`** to stop the capture: the
pattern also matches the enclosing `sudo bash -c` command line and kills the whole
session. Save the PID.
