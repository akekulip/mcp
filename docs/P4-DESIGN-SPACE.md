# P4-DESIGN-SPACE — Emulating a packet-sprayed leaf-spine fabric with an in-data-plane measurement-attention loop on one Tofino 1

**Status:** design-only. No P4 written, no switch access (Tofino at `decps@10.10.54.81` is down as of
2026-08-25). Every claim below is either (a) read out of a named local file this session, (b) measured
on this workstation this session, or (c) explicitly flagged `VERIFY`.

**Scope.** One Tofino 1 (TNA, bf-p4c, SDE 9.13.2 on the switch / 9.13.1 locally) hosting:
a *virtual* 2-level leaf-spine fabric whose virtual links are real TM queues on real loopback/recirc
ports; per-packet spraying at the source leaf; per-path measurement state and an "attention weight"
that the pipeline reads to steer mirroring, tag insertion, and trimming; in-band reflection of
NIC-side evidence; and runtime-settable failure injection. This is the Tier-2 hardware artifact of
`~/.claude/plans/we-have-to-do-spicy-patterson.md` (M3), and it closes hurdles H1–H5, H10–H12, H14 in
`/home/philip/Projects/mcp/HURDLES.md`.

**Companion documents.** `/home/philip/Projects/mcp/HURDLES.md` (risk register),
`/home/philip/Projects/mcp/WORKING_NOTES.md` (session state),
`~/.claude/skills/tofino-p4/references/constraints.md` (the eight bf-p4c constraint classes; this
document adds two more, §8.4).

---

## 0. How to read this document

Each of §2–§7 answers one requirement, and each follows the same shape:

1. **What has to happen** — one paragraph, no jargon.
2. **Alternatives** — at least two, each with its Tofino-1 constraint analysis and a cost estimate in
   MAU stages / SRAM-TCAM / PHV bytes.
3. **Recommendation** — one option, with the reason stated in one sentence.

§8 is the consolidated budget. §9 is the offline compile plan (with this session's measurements).
§10 is the switch-up validation checklist. §11 is the honest cut list: things that were asked for or
that look natural and that **cannot be built** on this target, with the reason.

Cost estimates are *estimates*. Nothing here has been through bf-p4c. The single most valuable next
action is §9's skeleton compile, which converts most of §8 from estimate to measurement.

---

## 1. The system in one page

```
  Vision / Hulk (25 G, dp9)                        Agilio CX on Vision (10 G, dp65)
        |  host traffic, UDP sport = per-packet entropy      |  NIC evidence packets in
        |                                                    |  truncated mirrors out (collector)
        v                                                    v
  +--------------------------------------------------------------------------+
  |                        Tofino 1, pipe 0, ingress                          |
  |                                                                           |
  |  parse: eth -> [fabric shim 0x88F0] -> [csig tag] -> ipv4 -> udp -> ...    |
  |                                                                           |
  |  S0 role/hop classify   S1 draws + dst-leaf   S2 spray select              |
  |  S3 vlink resolve (-> qid, loop port)         S4 failure injection         |
  |  S5 per-path counters   S6 attention read/write   S7 gate + mirror arm     |
  |  S8 forward + shim rewrite                                                 |
  +--------------------------------------------------------------------------+
        |                       |                                |
        | ucast_egress_port     | mirror_type=1                  | ucast_egress_port
        v  = dp68, qid = vlink  v  sid 1..3, $max_pkt_len         v  = dp9 (deliver)
   +---------------+      truncated copy -> dp65 collector
   | dp68 recirc   |  <-- 8 REAL TM queues = 8 virtual links, each with its own shaper
   | dp8 MAC-near  |  <-- 8 more REAL TM queues = 8 more virtual links
   +---------------+
        |
        v  (egress, on every pass)
  +--------------------------------------------------------------------------+
  |  E0 role   E1 read deq_qdepth / deq_timedelta, compare-and-replace csig    |
  |  E2 insert csig on first hop / strip on last hop                           |
  +--------------------------------------------------------------------------+
```

A packet entering from a host takes **three pipeline passes** for a 2-level fabric:

| pass | role | virtual element | leaves on |
|---|---|---|---|
| 1 | source leaf: classify, spray, pick spine | leaf → spine uplink | loop port, `qid = vlink_up` |
| 2 | spine: forward toward destination leaf | spine → leaf downlink | loop port, `qid = vlink_dn` |
| 3 | destination leaf: strip shim, deliver | — | host port `dp9` |

Two loop traversals per packet. Every virtual link is a distinct TM queue, so `deq_qdepth` read in
egress is genuinely per-virtual-link, and a per-queue shaper gives each virtual link a real,
runtime-settable capacity. This is the load-bearing idea of the whole design and it is what makes
the emulation more than a relabelling exercise.

---

## 2. Ground truth: what is verified, what must be checked before the first hardware run

### 2.1 Verified this session (workstation-local measurements)

| Fact | Evidence |
|---|---|
| A complete, built SDE 9.13.1 exists locally at `/home/philip/bf-sde-9.13.1` (7.5 GB) | `du -sh` |
| `bf-p4c` runs: `p4c 9.13.1 (SHA: e558d01)` | `$SDE_INSTALL/bin/bf-p4c --version` |
| A minimal TNA program compiles clean locally | wrote `smoke.p4`, `bf-p4c --target tofino --arch tna` → `0 errors, 3 warnings`, emitted `bfrt.json`, `manifest.json`, `pipe/`, `smoke.conf` |
| `tofino-model`, `p4i`, and the `ptf` python package are all installed | `install/bin/tofino-model`, `install/bin/p4i`, `install/lib/python3.8/site-packages/ptf` |
| `/opt` contains **no** bf-sde | `ls /opt` |
| The Docker daemon is not reachable by this user | `docker images` → `permission denied ... /var/run/docker.sock` |
| System `p4c` is open-source p4lang-p4c 1.2.4.2 at `/usr/bin/p4c` (no Tofino backend) | `dpkg -l | grep p4lang` |

### 2.2 Recorded elsewhere, load-bearing, and **must be re-verified against `$PORT` at S-UP**

| Item | Record | Where recorded | Why it matters |
|---|---|---|---|
| `dp9` = front-panel 15/1, 25 G, host leg | `Tooling/tofino_25g_connectivity_map.md` §0 (verified 2026-08-12) says the host on dp9 is **Vision** at `192.168.10.1` | map §0 | which host generates traffic |
| …but `WORKING_NOTES.md` (2026-08-25) says **Hulk**'s `enp59s0f0np0` is the interface "→switch" | `mcp/WORKING_NOTES.md` | **direct conflict — resolve first** |
| `dp8` = 15/0, 25 G, MAC-near loopback | map §0; `case_a_defense3_fixed_ack_delay_setup.py:607-622` | second loop port |
| `dp64` = 33/0, 1 G, DNP3 relay leg (in use by another project) | map §0 | not available to us |
| `dp65` = 33/1, 10 G, Netronome Agilio leg on Vision (`10.0.1.10`) | agent memory `vision-netronome-smartnic` (2026-07-17); **not** in the connectivity map | our NIC vantage point and proposed collector |
| `dp66`/`dp67` = 33/2–3, **internal CPU KR links — do not touch** | same memory note | removes two candidate loop ports |
| `dp68` = internal pipe-0 recirc port, no cable, no `$PORT` entry needed | `GridCloak/p4/gridcloak_c.p4:64` (`WANSEG_PORT = 9w68`), `gc_switch_setup_c.py:107-111` | primary loop port |
| The chip currently runs `defense4_caseA`; `gc-switchd.service` will seize it with `gridcloak` if `bf_switchd` dies | map §0; `~/.claude/skills/tofino-p4/references/testbed.md` | H12 — shared-chip protocol |

### 2.3 Unknown and design-relevant — measure these first

| Unknown | Why it matters | How to settle it |
|---|---|---|
| **Line rate of `dp68` recirculation** | The entire bandwidth budget (§2.5) is a function of it. Neither local program measures it: GridCloak deliberately *caps* dp68 at 100 kpps with a queue shaper (`gc_switch_setup_c.py:47,163-177`) for churn control | pktgen ramp on dp68, find the drop knee (§10.4) |
| Number of TM queues carved per port | Both local programs address queues as `pg_queue = pg_port_nr*8 + qid` (`gc_switch_setup_c.py:172`), i.e. **8 per port**. Tofino-1's TM can carve more, but nothing local does | read `tf1.tm.port.sched_cfg` / queue-mapping profile |
| Whether `dp69`–`dp71` are usable recirc ports in pipe 0 | Would add loop capacity | try `tf1.pktgen.port_cfg` `recirculation_enable` on each |
| Pipe count on this chip | Registers are **per-pipe**; a virtual link in pipe 1 would hold separate counters | `bf_switchd` startup log / `$PORT` enumeration |

The generated `.conf` for GridCloak lists `pipe_scope: [0,1,2,3]`
(`GridCloak/p4/gridcloak.tofino/gridcloak.conf`), but that is the **bf-p4c default for the tofino
target**, not evidence about the silicon. Do not treat it as a pipe count.

**Design consequence, and it is decisive:** every wired port on this box (`dp8`, `dp9`, `dp64`,
`dp65`) has `dev_port < 128`, i.e. all of them are in **pipe 0**. Since Tofino registers are
instantiated per pipe, keeping every virtual link in pipe 0 is the only way the per-path counters
mean one thing. **The recommended design uses pipe 0 exclusively and does not depend on pipe 1
existing.**

### 2.4 Loop capacity available in pipe 0

| Loop port | Kind | Speed | Queues (default carving) | Status |
|---|---|---|---|---|
| `dp68` | internal recirculation | `VERIFY` (nominally pipe rate) | 8 (`pg_id=17, pg_port_nr=0`) | HW-proven as a recirc port by GridCloak |
| `dp8` | front-panel 15/0 in `BF_LPBK_MAC_NEAR` | 25 G | 8 | HW-proven as a hold ring by defense4 |
| `dp69`–`dp71` | possible recirc | unknown | 8 each | `VERIFY` — do not design-depend |

**16 real TM queues** across dp68 + dp8 is the budget to design against. That is exactly a 2-leaf ×
4-spine fabric (8 uplinks + 8 downlinks), or a 4-leaf × 2-spine fabric (8 + 8). Design for **16
virtual links**; treat anything beyond as requiring a queue-carving change plus the `dp69`–`dp71`
probe.

### 2.5 Bandwidth budget for H hops

Let `L` = host-offered load into the fabric (Gb/s on the wire), `P` = loop traversals per packet,
`S` = mean frame size (bytes), `ov` = per-pass on-the-wire overhead the emulation adds. With the
recommended headers (§3) `ov = 6 B` fabric shim `+ 12 B` CSIG tag `= 18 B`.

```
loop_demand(Gb/s) = L × P × (S + ov) / S            must be ≤ C_loop
=> L_max = C_loop × S / (P × (S + 18))
```

`P = 2` for a 2-level fabric (leaf→spine, spine→leaf). `P = 4` for a 3-level fabric.

| S (B) | overhead factor | `L_max`, P=2, C=100 G | `L_max`, P=2, C=25 G | `L_max`, P=4, C=100 G |
|---|---|---|---|---|
| 1500 | 1.012 | **49.4 G** | 12.3 G | 24.7 G |
| 512 | 1.035 | **48.3 G** | 12.1 G | 24.2 G |
| 256 | 1.070 | **46.7 G** | 11.7 G | 23.4 G |
| 64 | 1.281 | **39.0 G** | 9.8 G | 19.5 G |

Host ingress physically available is `dp9` 25 G + `dp65` 10 G = **35 G**.

- If `dp68` runs at ~100 G, a **2-level fabric at full host rate fits for every frame size**, and a
  3-level fabric fits for a single 25 G host at moderate sizes. This is the good case.
- If `dp68` is effectively 25 G, host load must be capped at **≈10 Gb/s** for a 2-level fabric.
  That is still a usable experiment (it is a *measurement* study, not a throughput study), but it
  must be stated in the paper and it changes the traffic-generation plan.
- Splitting the two passes across two loop ports (uplinks on `dp68`, downlinks on `dp8`) does **not**
  raise the ceiling: the 25 G `dp8` leg then carries the full `L` and becomes the binding link.
  The split is worth doing anyway, for queue isolation, not for bandwidth.

**Packets per second is not the binding constraint.** A Tofino-1 pipe processes on the order of one
packet per clock (~1.2 Gpps); 100 G of 64 B frames is ~149 Mpps, and our loop demand is a small
multiple of the host rate. The loop port's *byte* rate binds first. `VERIFY` the pipe clock and the
recirc port speed at S-UP before quoting either number in the paper.

**Recommendation:** budget for **P = 2 (2-level fabric), 16 virtual links, `L ≤ 20 Gb/s` from hosts**
until `C_loop` is measured, and use Tofino pktgen on `dp68` (GridCloak's `tf1.pktgen.app_cfg`
recipe) for any line-rate stress so the result does not depend on host NIC behaviour.

---

## 3. (a) Virtual-switch identity and hop counter across passes

### What has to happen

A packet that leaves the pipeline toward a loop port and comes back must be recognisable as
"already in the fabric", must say which virtual switch should handle it next, and must carry a hop
counter so the pipeline knows when to strip the emulation and deliver.

### The one hard fact that eliminates an option

**TNA bridged metadata does not survive recirculation.** Bridged metadata is an ingress→egress
carriage within a single pass; a recirculated packet is re-parsed from its own bytes at the loop
port's ingress. Both local programs state and rely on this: GridCloak carries its pass state in the
`gc_obf_h.seq` field *on the wire* (`gridcloak_c.p4:116-125`, state machine at `:420-454`), and
defense4 carries the pass budget in `ibspg_h.seq` and decrements it per pass
(`defense4_rrc_bor_unified12.p4:810`, `dec_loop` at `:2799`). So the alternatives reduce to *which
bytes on the wire*.

Bridged metadata is still useful and is still used here — just **within** a pass, to hand the
ingress-side vlink decision to egress so egress can do the CSIG work (§5).

### Alternative A1 — 802.1Q VLAN tag

`vsw_id` in the 12-bit VID, `hop` in the 3-bit PCP. Precedent: SprayCheck put 16 virtual switches on
one Tofino-1 this way.

- **Pros:** 4 B on the wire, standard, visible to `tcpdump` on the host, no custom parser state
  beyond a select on TPID `0x8100`.
- **Cons:** only 3 bits of hop; PCP is also the natural QoS field and we want it free; a VLAN tag
  interacts with host NIC offloads and NetworkManager on Vision (which already flushed manually
  added IPs once — memory note `vision-netronome-smartnic`); and 12+3 bits is the wrong shape for
  the six fields this design actually needs (§3, recommendation).
- **Cost:** 4 B PHV, 1 parser state, 1 deparser emit.

### Alternative A2 — private ethertype + custom shim header  ★ RECOMMENDED

Rewrite `eth.etype` to a private value on entry into the fabric, and carry a fixed shim immediately
after the Ethernet header. Precedent is strong and local:

- GridCloak: `ETHERTYPE_GC_OBF = 0x88B5` (`gridcloak_c.p4:55`), parser select at `:219-226`, decap
  restores the saved `original_ethertype` at `:447`.
- defense4: `ETHERTYPE_IBSPG_TOKEN = 0x88C1` (`:189`), matched at `:1306`, and the parse state
  `parse_token` (`:1330-1337`) **forces the role** — with the explicit security note at `:1328-1329`
  that because the ethertype is internal-only, no injected frame can talk its way onto a host port.
  We want exactly that property.
- defense4's synthetic-event build additionally shows the pattern of *distinct* ethertypes
  (`0x88C6/0x88C7/0x88C8`, `:296-306`) used to re-establish identity after a loopback pass has
  stripped everything else — with the honest caveat recorded at `:291-294` that a stamped frame is
  no longer byte-preserved.

Proposed layout (6 bytes, deliberately 16-bit aligned — see §8.3 for why not 8-bit):

```p4
const bit<16> ETYPE_MCP_FABRIC = 0x88F0;   // private, internal only

header fabric_h {
    bit<8>  vsw_id;   // which virtual switch handles this pass
    bit<8>  hop;      // 0 = fresh from host; incremented per pass
    bit<8>  spray;    // spray index chosen at the source leaf (recorded, see §4)
    bit<8>  loops;    // remaining extra latency loops (§7.4)
    bit<8>  flags;    // bit0 measured, bit1 mirrored, bit2 fault-injected
    bit<8>  rsvd;     // keeps the header 6 B and 16-bit-container friendly
}   // 6 bytes
```

The original ethertype is **not** carried. Every packet in this fabric is IPv4 (the traffic
generator's contract), so the last hop restores `0x0800` from a constant. That saves 2 B and one
field; if mixed ethertypes are ever needed, widen the shim to 8 B and store it, as GridCloak does.

- **Pros:** exact field widths; 8-bit hop (up to 255 passes, so the latency-inflation loops of §7.4
  come for free); the ethertype select is a parser transition we already pay for; forced-role
  parsing gives the same injection resistance defense4 documents; no VLAN/QoS collision.
- **Cons:** invisible to host tooling without a dissector; 6 B rather than 4 B.
- **Cost:** 6 B PHV (3 × 16-bit containers), 1 parser state, 1 deparser emit, 1 action to set/clear.

### Alternative A3 — bridged metadata

**Infeasible for this purpose** (see above). Listed so the design record shows it was considered.

### Recommendation

**A2**, private ethertype `0x88F0` plus a 6-byte `fabric_h` shim, because it is the only option that
gives the six fields at the widths this design needs while reusing a parse transition we already pay
for — and it is the pattern with two independent hardware-verified precedents on this exact chip.

Two carriage details worth fixing now:

1. **Put the shim (and the CSIG tag, §5) between Ethernet and the original L3 header, as L2 shims.**
   Then no IPv4 `total_len` and no IPv4/UDP checksum ever needs updating. This single choice
   eliminates constraint Class 6 (the silent bf-p4c ICE on end-around-carry checksum updates) from
   the entire program. It is worth stating in the source as a load-bearing comment, per
   constraints.md operational caveat B.
2. **Distinguish fresh from looped by ingress port, not only by the shim.** defense4's live build
   does exactly this (`state from_loopback` at `:1196-1197` keys off the parser's port-derived entry
   state). Belt and braces: a fresh packet arriving on `dp9` with a `0x88F0` ethertype is a spoof
   and must be dropped — the same repair defense4 made at `:34-35, 729, 2305`.

### Mapping virtual links to physical loop ports and real queues

| Option | Mechanism | Ceiling | Verdict |
|---|---|---|---|
| **M1** one physical loop port per virtual link | `ucast_egress_port = dp68 / dp8 / dp69…` | 2 verified, maybe 5 | **Rejected** — `dp64`/`dp65` are wired to other things, `dp66`/`dp67` are internal CPU KR links that must not be touched, and `dp69`–`dp71` are unverified. Does not reach 16. |
| **M2** one TM queue per virtual link on a shared loop port ★ | `ucast_egress_port = loop`, `ig_tm_md.qid = vlink_id & 7` | 8 per loop port → **16** | **Recommended** |
| **M3** multicast replication per link | `mcast_grp_a` + RID interpretation | n/a | **Rejected** — replication makes copies, it does not make a path. The RRC work already established that the mirror/PRE route is the wrong mechanism for anything that is not fan-out. |

**M2 in detail.** `vlink_id ∈ [0,15]`. Bit 3 selects the loop port (`0 → dp68`, `1 → dp8`), bits
[2:0] are the `qid`. `ig_tm_md.qid` is a single scalar per packet, which is fine because each pass
traverses exactly one virtual link. Both local programs write exactly these two TM fields and
nothing else (`gridcloak_c.p4` writes only `ucast_egress_port` and `qid`).

**This is what makes each virtual link *real*:**

- a per-queue max-rate shaper gives the virtual link a finite, runtime-settable capacity
  (`tf1.tm.queue.sched_shaping` with `unit`, `provisioning="UPPER"`, `max_rate`, `max_burst_size`,
  plus `tf1.tm.queue.sched_cfg` with `max_rate_enable=True` — **the shaper is inert without the
  second call**, `gc_switch_setup_c.py:163-177`);
- congestion on that virtual link therefore produces genuine queueing, and `eg_intr_md.deq_qdepth`
  read in egress is genuinely that link's depth (§5);
- **TM tables require `pipe_id=0`, not `0xffff`** — this is the single most-likely-to-bite
  control-plane detail in the whole design, and it is called out in the source at
  `gc_switch_setup_c.py:163`.

Two shaper cautions carried forward from GridCloak's notes: a `PPS`-unit shaper is a *cap*, not a
pacer — at low rates it clumps, and GridCloak measured a TM PPS shaper starving a queue entirely at
100–200 pps with depth pinned and zero dequeue, only draining correctly above ~1200 pps. For link
capacity emulation use **`BPS` units at realistic rates** (1–25 Gb/s), not PPS, and never shape below
about 1 Gb/s without re-measuring.

---

## 4. (b) Per-packet spraying, and making it replayable

### What has to happen

At the source-leaf hop, choose one of `k` spines per packet (not per flow), and be able to reproduce
the same choice sequence in a later run so an experiment can be replayed.

### Alternative B1 — `Random<>`

```p4
Random<bit<8>>() rng_spray;
// ... md.spray_rand = rng_spray.get();
```

Two idioms are both HW-proven locally and they differ:

- `sdnp_exp.p4:83` calls `rng.get()` **directly in the apply body**, unconditionally, once.
- `~/labs/09-simple_l3_lag_ecmp/solution/p4src/random_hash.p4:23-40` wraps it in a keyless 1-entry
  table whose `default_action` calls the extern (`control calc_rng`), and instantiates one such
  control per 32 bits of hash needed.

Prefer the `sdnp_exp.p4` form (simpler, one fewer logical table — and per §8.4/N10 a bare action call
becomes its own logical table on Tofino-1).

- **Pros:** cheapest option; genuinely per-packet; no hash unit consumed.
- **Cons — and this is decisive:** **there is no control-plane seed for `Random<>` on Tofino 1.** Two
  runs will differ. Random mode cannot be replayed, only characterised.
- **Cost:** 1 Random unit; folds into an existing stage.

### Alternative B2 — hash of host-written UDP source-port entropy  ★ RECOMMENDED default

```p4
CRCPolynomial<bit<32>>(coeff=32w0x04C11DB7, reversed=true, msb=false, extended=false,
                       init=32w0xFFFFFFFF, xor=32w0xFFFFFFFF) poly_spray;
Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_spray) h_spray;
// md.spray_hash = h_spray.get({ hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.udp.src_port });
```

- **Pros:** fully deterministic given the input trace, so a run replays exactly; and it is the
  *right model* — RoCEv2/UEC NICs spray by varying the UDP source port per packet, so the switch
  hashing sport is what real sprayed fabrics do. It also puts the entropy under the experiment's
  control (the generator writes the sport sequence), which is exactly what a pre-registered
  evaluation needs.
- **Cons:** consumes a hash unit; the spray quality is only as good as the generator's sport
  sequence; **constraint Class 7** — a `Hash` instance is bound to the field list of its first
  `.get()`, so a second tuple shape needs a second instance. `~/labs/09` shows both declaration
  styles (polynomial as a control constructor parameter, `ipv4_ipv6_hash.p4:31-53`; or built inside
  from a `bit<32>` coeff, `:102-130`).
- **Cost:** 1 hash unit, 1 stage (co-locatable with the Random draw and the destination-leaf lookup,
  which are all independent).

### Alternative B3 — `ActionSelector` + `ActionProfile`

The lab-09 pattern: `ActionProfile(size=2048) lag_ecmp; Hash<bit<HASH_WIDTH>>(IDENTITY) final_hash;
ActionSelector(action_profile=…, hash=…, mode=FAIR|RESILIENT, max_group_size=120,
num_groups=1024) lag_ecmp_sel;` with `hash : selector` as a table key
(`simple_l3_lag_ecmp.p4:474-496`).

- **Pros:** idiomatic ECMP; the control plane manages group membership; `RESILIENT` mode means
  removing a member (= a spine going down) reshuffles only that member's flows — which is a genuinely
  useful *black-hole-with-reroute* failure mode (§7.5).
- **Cons:** heaviest of the three (profile + selector + a wider hash — note lab-09's width
  arithmetic: `BASE_HASH_WIDTH` 14 for FAIR / 51 for RESILIENT, plus subgroup bits, rounded up to a
  32-bit multiple at `:119`); the selection is still hash-driven so it buys no determinism B2 does
  not already have; and it adds a stage we are trying to save.
- **Cost:** ~1–2 stages, an action profile, a selector, one hash.

### Alternative B4 — control-plane-seeded round-robin via a SALU counter

The lab-09 `round_robin_hash.p4:51-61` pattern: `Register<bit<32>, bit<16>>(1, 0) packet_num;` with a
`RegisterAction` that returns the pre-state and increments; `spray_idx = counter & (k-1)`.

- **Pros:** perfectly deterministic *and* perfectly balanced — the ideal "uniform spray" baseline
  the evaluation needs, and it is replayable because the control plane seeds the counter.
- **Cons:** one register for all source leaves means multi-group distribution can skew (stated as a
  known limitation at `round_robin_hash.p4:18-20`); fix by indexing the register by source leaf.
  Bursty aliasing against periodic traffic is a real risk and should be checked, not assumed.
- **Cost:** 1 register + 1 SALU, 1 stage.

### Recommendation

**Ship all three of B1, B2, B4 in one binary, selected at runtime**, with **B2 as the default**.
Reason: the evaluation needs uniform-random, hash-of-entropy, and perfect round-robin as *baselines
against each other*, and a runtime switch removes three recompiles and three chances for the
pipelines to differ in some other way.

Implementation shape that avoids branching hazards:

- **Stage 1:** compute all three candidates unconditionally — `rng_spray.get()`, `h_spray.get({…})`,
  `rr_next.execute(src_leaf)`. They are independent, cheap, and co-locatable.
- **Stage 2:** a small table `tbl_spray_mode` (key: a control-plane-written `spray_mode` plus the
  role) selects which candidate lands in `md.spray_idx`.

This costs one extra stage versus branching, and it is far easier to debug on hardware — which is
the tie-breaker.

**Determinism, stated honestly:** modes B2 and B4 replay exactly. Mode B1 does not and cannot,
because Tofino-1's `Random<>` has no control-plane seed. To keep B1 runs *analysable* even though
they are not replayable, **the chosen spray index is written into `fabric_h.spray` on the wire**, so
a capture at the collector reconstructs the path taken by every packet regardless of mode. That is
the substitute for a seed, and it should be said plainly in the paper.

---

## 5. (c) Measurement state, attention weights, and what they gate

### 5.1 Per-path counters

`path_id = (dst_leaf << 2) | spine`, 8 bits, ≤ 64 paths. Computed once at the source-leaf hop and
carried in metadata for that pass (the shim's `vsw_id`/`spray` fields let a later pass recompute it
if needed).

```p4
Register<bit<32>, bit<8>>(64, 0) reg_path_count;
RegisterAction<bit<32>, bit<8>, bit<32>>(reg_path_count) path_inc = {
    void apply(inout bit<32> v, out bit<32> rv) { v = v + 1; rv = v; }
};
```

Cost: 1 register (64 × 32 b = 256 B of SRAM, negligible), 1 SALU, 1 stage.

### 5.2 Variance / Z-score — the honest answer

**A true per-path variance or Z-score cannot be computed in a Tofino-1 SALU.** There is no divide,
and the SALU cannot compare two runtime variables against each other. `sdnp_exp.p4:69-72` says it in
the source: *"Comparing two variables in an if is illegal on Tofino, so the comparison lives in the
TCAM range key."*

Three ways to live with that:

**C1 — sum and sum-of-squares on chip, statistics in the control plane.** Two 32-bit registers per
path; the control plane reads both each epoch and computes mean, variance, and Z off-chip.
*Problem:* a 32-bit sum-of-squares of packet counts overflows quickly, and the fast loop still cannot
act on the result within an epoch. Adds a register and a stage for little gain.

**C2 — EWMA deviation in the SALU.** `v = v - (v >> k) + md.delta` with `md.delta = x >> k`
precomputed in an earlier stage. *Problem:* three operands in one SALU op is exactly constraint
Class 5 territory, and defense4's experience says the failure modes here are silent, not loud (see
§8.4/N9: a `bit<8>` `v < 0` test compiles with no error and no warning to an unsigned compare that is
never true). High risk, low reward.

**C3 — count on chip, price off chip, compare against a control-plane-written threshold ★.** The
data plane keeps counts (and optionally a per-path max queue depth). The control plane reads the
register array each epoch, computes mean/variance/Z in Python where those operations are free, and
writes back (i) a per-path threshold and (ii) a per-path attention weight. The data plane's only
statistical act is `count ≥ threshold`, where `threshold` arrives as a PHV operand from an earlier
register read — which the SALU **can** do (register value vs. one PHV input).

**Recommendation: C3.** It is the design the two-timescale thesis already asserts — fast loop counts
and gates, slow loop computes statistics and re-prices — and it is the only one of the three that is
both feasible and simple. Say plainly in the paper that the on-chip "deviation detector" is a
threshold comparison, not a Z-score, and that the Z-score lives in the epoch controller.

Two SALU rules that must be obeyed while doing this (§8.4):

- **N8, PHV operand budget:** a register gets at most **2 PHV inputs**, shared across all of its
  RegisterActions. defense4 hit both rejection messages verbatim (`:1586-1601`): a separate byte gave
  *"not allocated in a valid region on the input xbar to be a source of an ALU operation"*, and a
  packed 16-bit pair gave *"requires more than 2 PHV inputs"*. The fix there was to make a new value
  ride on an operand the register already had. Plan the operands per register up front.
- **N9, never compare SALU state against a large constant.** defense4 lost a silicon run to this
  (`:491-524`): with `TAG_INACTIVE = 0xFF` the predicate `v == TAG_INACTIVE` did not fire on
  hardware, the conditional write never committed, and one fault produced 64 pktgen drops. The
  constant was moved to `0x00`. Compare against **zero or a PHV field**. K=2 is proven working, K=255
  proven broken, nothing between tested.

### 5.3 The attention-weight register

```p4
Register<bit<8>, bit<8>>(64, 0) reg_attn;      // 8-bit weight, 0..255, per path
```

Read in the fast path into `md.attn`; written by the control plane each epoch; **also** written by
the NIC-evidence path (§6). Two RegisterActions on one register — well inside the hard cap of 4
(§8.4/N7), but note the cap, because it is the constraint that will bite when a fourth consumer
appears.

**Gating rule — probabilistic, one 8-bit compare:**

```p4
if (md.rnd_attn < md.attn) { md.do_measure = 16w1; }   // rnd_attn from Random<bit<8>>
```

An 8-bit vs 8-bit magnitude compare consumes ~16 bits of the 44-bit gateway budget (Class 1), so it
is safe **as the only predicate in its gateway**. Do not fuse it with anything else; defense4 records
that a compound two-field test *"tipped ingress to 13 stages"* and had to be precomputed into a
single field (`:941-943, 2209-2217`). Precompute, then test one field.

Semantics: attention `a` means "measure this path with probability `a/256`". That is exactly a
steerable measurement budget, it is one register write per path per epoch, and it degrades
gracefully (`a=0` → off, `a=255` → always).

**Alternative gating — deterministic 1-in-N** via a per-path counter (`if ((cnt & mask) == 0)`).
Replayable and exact, but bursty and prone to aliasing with periodic collective traffic — which is
precisely the traffic this fabric will carry. Offer it as a runtime mode for the replay experiments;
default to probabilistic.

**Seed every register from the control plane at startup** (constraint Class 8) — `reg_attn`,
`reg_thresh`, `reg_path_count`, `reg_spray_rr`. Never rely on an in-SALU `v == 0` sentinel.

### 5.4 (i) Truncated mirror to a collector

Ingress mirroring, three sessions plus a spare:

| sid | purpose | `$max_pkt_len` | destination |
|---|---|---|---|
| 1 | high-attention sample, headers + payload prefix | 128 | `dp65` (Agilio/Vision) |
| 2 | high-attention sample, headers only | 64 | `dp65` |
| 3 | fault evidence (every injected drop/corrupt) | 64 | `dp65` |
| 4 | spare / full-capture debug | 16384 | `dp65` |

P4 side (all three local precedents agree on the shape):

```p4
// in ingress MAU
ig_dprsr_md.mirror_type = 3w1;          // MIRROR_TYPE_CLONE
md.mirror_sid = <session id>;           // MUST be metadata, not a literal

// in the ingress deparser
Mirror() mcp_mirror;                    // no-arg constructor
if (ig_dprsr_md.mirror_type == 3w1) { mcp_mirror.emit(md.mirror_sid); }
```

Four API facts, each from a named line, that will otherwise cost a compile cycle each:

1. **The session id must live in metadata.** `defense4_rrc_bor_unified12.p4:429-430`: *"never passed
   to mirror.emit as a literal — bf-p4c rejects a constant session selector."*
2. **Use the no-arg `Mirror()` constructor.** `:3302`: the typed constructor errors *"Inconsistent
   mirror selectors"* on Tofino-1.
3. **`Mirror().emit` appends the original packet after whatever header you give it.**
   `~/labs/11-simple_l3_mirror/solution/p4src/simple_l3_mirror.p4:526-528`. The single-argument form
   (`gridcloak_c.p4:526-528`) therefore yields a byte-identical copy of the post-ingress-modification
   frame — which is what we want, since our shim and CSIG tag are already on it.
4. **`$mirror.cfg` is action-based and the action name is mandatory.**
   `case_a_defense3_fixed_ack_delay_setup.py:909-916`: *"make_data REQUIRES the action name or it
   fails INVALID_ARGUMENT"*; the action is `"$normal"`, fields are `$direction="INGRESS"`,
   `$ucast_egress_port`, `$ucast_egress_port_valid`, `$session_enable`, `$max_pkt_len`.
   `$max_pkt_len` is runtime-settable per session — that is the knob the epoch controller turns.

**Truncation arithmetic gotcha:** `$max_pkt_len` is applied by the TM and *includes* any mirror header
that egress later strips (`~/labs/11-simple_l3_mirror/solution/ptf-tests/test.py:473-504`). We emit
no mirror header, so the arithmetic is simple here — but note it, because adding one later silently
changes the truncation point. Tofino-2's 4-byte-boundary truncation restriction does **not** apply to
Tofino-1.

**Mirror bandwidth budget.** Collector is `dp65` at 10 G.

```
mirror_bps = (a/256) × pps × trunc_len × 8      must be ≤ 10 Gb/s
```

| host load | S | pps | trunc | max attention `a` before saturating dp65 |
|---|---|---|---|---|
| 25 G | 256 B | 12.2 M | 64 B | 255 (uses 6.2 G at a=255) — **never saturates** |
| 25 G | 256 B | 12.2 M | 128 B | 205 |
| 25 G | 64 B | 37.2 M | 64 B | **134** |
| 20 G | 1500 B | 1.67 M | 128 B | 255 — never saturates |

The 64 B / line-rate corner is the only one where the collector binds. The epoch controller must
enforce the budget in its own units (bytes/s of mirror), which is exactly the shadow-price mechanism
the controller already implements. Add a data-plane backstop: a `Meter` on the mirror-arm table, so
the budget cannot be violated even if the controller is wedged.

### 5.5 (ii) The fixed CSIG-style tag, compare-and-replace across hops

12 bytes, inserted at the source leaf's egress, updated at every hop's egress, stripped at the last
hop:

```p4
header csig_h {
    bit<8>  worst_hop;    // which hop owns the reported depth
    bit<8>  worst_vlink;  // which virtual link
    bit<16> worst_qdepth; // eg_intr_md.deq_qdepth[18:3]  (8-cell granularity)
    bit<32> worst_tdelta; // eg_intr_md.deq_timedelta (ns)
    bit<16> path_id;      // echoed for the collector
    bit<16> epoch;        // control-plane epoch parity, for staleness detection
}   // 12 bytes
```

**Compare-and-replace, in EGRESS:**

```p4
if (md.this_qdepth > hdr.csig.worst_qdepth) {
    hdr.csig.worst_qdepth = md.this_qdepth;
    hdr.csig.worst_hop    = md.hop;
    hdr.csig.worst_vlink  = md.vlink_id;
    hdr.csig.worst_tdelta = eg_intr_md.deq_timedelta;
}
```

Design points, each load-bearing:

- **Fixed size, not a growing INT stack.** A per-hop INT stack grows the packet per hop, needs per-hop
  length fixup, and — the killer on TNA — the deparser cannot emit a header after the unparsed
  residual, so appending is structurally awkward. A fixed "worst hop so far" tag is the CSIG/UEC
  semantic anyway, costs the same 12 B at hop 1 and hop 8, and is a single compare.
- **Egress placement is nearly free.** The ingress pipeline is where the stage pressure is; egress on
  this program is otherwise almost empty. Prior work on this chip measured the egress size axis as
  costing **zero ingress stages** because the placements are independent. Put every CSIG operation in
  egress.
- **Slice `deq_qdepth` to 16 bits.** `eg_intr_md.deq_qdepth` is 19 bits. A 19-bit vs 19-bit gateway
  compare is 38 bits — under the 44-bit budget, but only barely, and only if it is the sole
  predicate. Slicing to `[18:3]` gives a 16-bit compare (32 bits of gateway input), keeps a
  comfortable margin, and 8-cell granularity is far finer than any decision we make with it.
- **L2 shim placement means no length or checksum fixup.** Same reason as §3: the tag sits between
  Ethernet and the original ethertype, so IPv4 `total_len` and both checksums are untouched, and
  constraint Class 6 never comes into play.
- **Insert once, strip once.** `hdr.csig.setValid()` in the source leaf's egress; `setInvalid()` in
  the destination leaf's egress, at which point the shim is also stripped and `eth.etype` restored.
  Both are `setValid`/`setInvalid` in table actions keyed on the role — cheap, and per the parser
  lesson in §8.4/N11, decode the role from a table action rather than from a chain of runtime bit
  tests.

Egress needs to know `vlink_id` and `hop`, which ingress computed. Carry them in **bridged metadata**
— this is the one place bridged metadata is the right tool, because it is an intra-pass hand-off.
`simple_l3_mirror.p4:114-136, 301-309` shows the idiom: build the bridge header in the parser, fill
the rest in the MAU, demultiplex in the egress parser with `pkt.lookahead<inthdr_h>()` and a
two-field `select` on `(header_type, header_info)`.

Cost: 12 B egress PHV, ~2 egress stages, 1 bridged-metadata header (~4 B).

### 5.6 (iii) Deflect-on-drop trimming — downgrade to mirror-on-drop

The NDP-style behaviour ("when you would drop, send the header on anyway") is attractive because it
gives loss evidence with zero added latency. On Tofino-1 it needs `ig_tm_md.deflect_on_drop` plus a
truncation step, and **there is no local precedent for it at all** — no program in any of the
surveyed repos sets `deflect_on_drop`.

**Recommendation: do not build DoD trimming for the first version.** Get the same evidence the cheap
way: when the failure-injection table (§7) decides to drop, arm mirror session 3 (64 B truncation) on
the same packet before dropping it. The collector then receives a trimmed header for every dropped
packet, which is the observable the evaluation actually needs. `simple_l3_mirror.p4:456` shows the
exact composition — `action acl_drop_and_mirror(sid) { acl_mirror(sid); drop(); }` — and confirms the
mirror still fires when the packet is dropped, because the mirror is taken in the ingress deparser.

Keep DoD trimming on the stretch list, gated behind a measurement of what Tofino-1's DoD path
actually delivers on this box.

### 5.7 How the control plane seeds and re-prices attention each epoch

Read side, per epoch:

```python
tgt = gc.Target(device_id=0, pipe_id=0xffff)          # P4 tables/registers: all pipes
reg = bfrt.table_get("pipe.Ingress.reg_path_count")
counts = {k.to_dict()["$REGISTER_INDEX"]: d.to_dict()["Ingress.reg_path_count.f1"][0]
          for k, d in reg.entry_get(tgt, flags={"from_hw": True})}
```

For the direct counters on the failure-injection table, **`SyncCounters` is mandatory before the
read** (`sdnp_setup.py:107-115`):

```python
t.operations_execute(tgt, "SyncCounters")
for k, d in t.entry_get(tgt, flags={"from_hw": True}):
    pkts  = d.to_dict()["$COUNTER_SPEC_PKTS"]
    bytes = d.to_dict()["$COUNTER_SPEC_BYTES"]
```

Note the tuple-order asymmetry in the bfrt client, which is a real source of bugs: a **keyless**
`entry_get` yields `(key, data)`, while `next()` on a **single-key** `entry_get` yields
`(data, key)`. `sdnp_setup.py` demonstrates both (`:100` vs `:112`).

Write side, per epoch: register writes to `reg_attn` and `reg_thresh` (64 entries each), plus
occasional `$mirror.cfg` `$max_pkt_len` changes and queue-shaper updates. Two operational notes:

- Full-array seeds take a few seconds; budget for it in per-trial reset paths
  (`~/.claude/skills/tofino-p4/references/build-deploy.md`).
- Use distinct `client_id`s so the epoch controller, the setup script, and any probe can coexist
  against one `bf_switchd` — GridCloak uses 2 and 6, `sdnp_setup.py` uses 0. Only `client_id=0`
  should call `bind_pipeline_config`.

Epoch cadence: the plan's sweep is 10 ms–10 s. A 64-entry register read plus a 64-entry write is two
gRPC round trips; at 10 ms epochs that is the thing to measure first (§10.4), not assume.

---

## 6. (d) In-band reflection of NIC-side evidence

### What has to happen

The NIC (Vision's Agilio via XDP, or a host-side XDP program) observes per-path RTT, ECN marks, and
PSN gaps that the switch cannot see, and must get that evidence into the switch's attention register
fast enough to matter.

### Alternative D1 — dedicated evidence packets  ★ RECOMMENDED

The NIC emits a small UDP packet to a reserved destination port carrying quantized per-path evidence.

```p4
const bit<16> UDP_PORT_EVIDENCE = 0xE5E5;

header evid_h {
    bit<8>  magic;    // 0xE5, sanity
    bit<8>  path_id;  // (dst_leaf << 2) | spine
    bit<8>  rtt_q;    // quantized RTT
    bit<8>  loss_q;   // quantized PSN-gap / NAK count
    bit<8>  ecn_q;    // quantized CE marks
    bit<8>  flags;    // direction, epoch parity
    bit<16> seq;      // epoch sequence, for staleness detection
}   // 8 bytes
```

- **Parser cost:** reached only from `select(hdr.udp.dst_port) { UDP_PORT_EVIDENCE : parse_evid; }`
  — one extra parser state and one extra select arm on a field already extracted. Note that the PHV
  is allocated program-wide regardless of how rarely the header is valid, so the honest cost is
  **8 B of PHV always**, not "8 B on evidence packets".
- **MAU cost:** one stage, sharing the `reg_attn` SALU with the fast-path read (two RegisterActions
  on one register — they *must* be in the same stage, which is fine because we want them there).
- **Data-path cost: zero.** Evidence packets are recognised at ingress, applied to `reg_attn`, then
  dropped (or forwarded to CPU for logging). They never enter the fabric, never get sprayed, never
  recirculate — assert this in a PTF test (§10.3/T11).
- **Cons:** extra packets on the wire (tiny), and one NIC→switch latency of staleness.

**Quantization must happen on the NIC.** The switch cannot divide and cannot compute a Z-score, so
the NIC ships 8-bit buckets and the switch does a min/max/add. This is not a limitation to hide; it
is the natural division of labour and should be stated as such.

### Alternative D2 — piggyback on reverse-direction data packets

The NIC writes an 8-byte shim (or reuses RoCEv2 BTH reserved bits) on every reverse packet.

- **Pros:** no extra packets; the tightest possible loop.
- **Cons:** every reverse packet pays the parse and PHV cost; touching the BTH invalidates ICRC
  unless it is recomputed, which XDP cannot do cheaply; IPv4 options break NIC offloads and add
  parser TCAM pressure. High cost, marginal latency gain over D1.

### Alternative D3 — echo the CSIG tag

The receiving NIC copies the received `csig_h` back into the reverse direction's tag, and the switch
reads it on the reverse pass.

- **Pros:** one header format serves both directions; conceptually elegant; no new parser state.
- **Cons:** needs symmetric traffic; requires the NIC to store per-flow state; and it conflates
  switch-observed evidence with NIC-observed evidence in one field.

### Recommendation

**D1 now, D3 as a refinement.** D1 is the only one whose parse cost is bounded and whose failure mode
is benign (a lost evidence packet just means a stale weight). D3 becomes attractive once the fast
loop is proven, because it removes the extra packets — implement it as a second value of
`evid_h.flags` rather than a second header.

**Fail-safe:** every evidence-driven update to `reg_attn` must be bounded (clamp to `[0,255]`) and
must carry `seq`, so the control plane can detect a NIC that has stopped reporting and fall back to
its own pricing. A silent stale attention weight is the worst failure mode this design has.

---

## 7. (e) Failure injection, all runtime-settable

Every mechanism below is keyed on `vlink_id`, which already encodes **direction** (uplink `L→S` and
downlink `S→L` are distinct ids). That one choice makes one-direction asymmetry free — §7.3.

### 7.1 Per-virtual-link random drop  ★ fork `sdnp_exp.p4` verbatim

This is a solved problem locally. `sdnp_exp.p4` is silicon-verified (2026-06-27) and does exactly
this:

```p4
Random<bit<16>>() rng_fail;                                   // sdnp_exp.p4:54
DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) fail_ctr;

table tbl_fail {
    key = { md.vlink_id : exact;        // which virtual link
            md.rnd_fail : range; }      // 16-bit RNG draw
    actions = { inj_drop; inj_corrupt; inj_none; }
    counters = fail_ctr;
    size = 64;
    const default_action = inj_none();
}
```

Control plane (`sdnp_setup.py:75-89`): the range key format is
`gc.KeyTuple("md.rnd_fail", low=0, high=hi)`, inclusive on both ends, `hi = int(65535 * pct / 100.0)`.
Drop probability is `hi/65536` and is retuned at runtime by rewriting the bounds — **no recompile**.

Clearing entries has a landmine that `sdnp_setup.py:62-72` documents and works around: on this bfrt
version, **range-match keys returned by `entry_get` do not round-trip into `entry_del`**, and there is
no `table.clear()`. The working idiom is `table.entry_del(tgt)` with **no key list** (bulk delete),
followed by a re-read that verifies the table is actually empty. Reuse that function verbatim.

**Why a range table and not a gateway compare:** comparing `md.rnd_fail < reg_dropprob[vlink]` is two
runtime 16-bit operands. That is legal *alone* but immediately overflows the 44-bit gateway budget
when combined with anything else (Class 1), and it costs an extra register read stage. The range table
costs TCAM we have plenty of and is directly control-plane-settable. `sdnp_exp.p4:69-72` states the
rationale in source; `gridcloak_c.p4:373` uses the same trick for a completely different purpose.

Constraint Class 2 check: a 16-bit range key consumes 4 of the 5 available range nibbles. In budget,
but **do not add a second range field to this table** — put it in a second table if ever needed.

Cost: 1 TCAM stage, 1 stats ALU (the DirectCounter), 1 Random unit.

### 7.2 Payload corruption (ICRC invalidation)

Two options, both a second action on the same `tbl_fail`:

**F1 — wrong UDP checksum ★ RECOMMENDED.** RoCEv2 traffic normally carries UDP checksum 0 (ignored).
Writing a wrong non-zero value forces the receiving NIC to drop the frame — the same observable as a
corrupted ICRC, at the cost of a single 16-bit constant write:

```p4
action inj_corrupt() { hdr.udp.checksum = 16w0xBAD1; fail_ctr.count(); }
```

Zero extra parsing, zero extra PHV, one action. Crucially it is a **constant write**, not carry
arithmetic, so it stays clear of constraint Class 6 (the silent ICE).

**F2 — true ICRC invalidation via the BTH.** Parse the 12-byte RoCEv2 Base Transport Header (after
UDP port 4791) and flip a bit in its reserved field or PSN. More faithful, and the BTH's PSN is
independently useful for loss detection — but it costs 12 B of PHV and a parser state on every
packet.

**Recommendation: F1 by default, F2 only if the evaluation needs BTH/PSN for another reason.** If
BTH is parsed anyway, switch to F2 for fidelity at no marginal cost.

### 7.3 One-direction asymmetry

Free. Uplink and downlink are distinct `vlink_id`s, so installing a `tbl_fail` row for the uplink id
only produces a perfectly asymmetric link. No P4 change, no extra resource — this falls out of the
§3 mapping decision.

### 7.4 Latency inflation

**L1 — extra recirculation loops.** `fabric_h.loops` (already in the shim, §3) is set by a table
`tbl_delay` keyed on `vlink_id`. On each pass, if `loops > 0`, decrement it and recirculate to the
*same* queue without advancing `hop`.

- Granularity ≈ one pipeline traversal plus queueing ≈ 1 µs; range 0–255 loops ≈ 0–255 µs.
- **Costs loop bandwidth.** `n` extra loops on a traffic fraction `f` multiply loop demand by
  `(1 + f·n)`. At `f=1, n=8` that is a 9× blow-up — it will hit the §2.5 ceiling immediately. Cap it
  and account for it explicitly in the budget.
- Precedent: defense4's `dec_loop` (`:2799`) decrements a wire-carried pass budget exactly this way,
  and its `hdr.ib.seq == 32w0` exhaustion test (`:2911`) is the pattern to copy — including its
  warning that such a field must only be read inside the branch that owns it.

**L2 — per-queue rate shaper ★ RECOMMENDED as the primary mechanism.** Shape the virtual link's queue
to `X` Gb/s (`tf1.tm.queue.sched_shaping` + `sched_cfg`, §3) and the delay emerges from real
queueing. Zero pipeline cost, zero extra loop bandwidth, and it is the *same* mechanism that makes
`deq_qdepth` meaningful — so a "slow link" and a "congested link" are the same thing, as they are in
a real fabric.

**Recommendation: L2 for load-dependent delay (the realistic case), L1 for a fixed
propagation-like delay independent of load.** Ship both; they answer different questions.

### 7.5 Black hole

Delete the `tbl_vlink` entry for the affected virtual link; the table's default action drops. Instant,
runtime, zero data-plane cost, and the default-action counter gives an exact count of black-holed
packets.

A richer variant, if spray mode B3 (`ActionSelector`) is enabled: remove the spine from the selector
group. In `RESILIENT` mode only that member's share reshuffles, which emulates *link-down plus
reroute* rather than a silent sink — a genuinely different fault class, and worth having.

### 7.6 Ground truth

Every injection mechanism must be counted, or the evaluation has no ground truth to score detection
against:

- `tbl_fail` carries a `DirectCounter` (packets and bytes) per row — so injected drops and
  corruptions are counted exactly, per virtual link.
- `tbl_vlink`'s default action carries its own counter — black-holed packets counted exactly.
- Mirror session 3 delivers a trimmed header for every injected drop (§5.6) — so the *identity* of
  each lost packet is recoverable, not just the count.

This is the single most important thing to get right, because the paper's time-to-detect metric is
measured against it.

---

## 8. (f) Consolidated budget

### 8.1 Ingress stage plan — target ≤ 9 of 12

| Stage | Purpose | Tables / externs | Notes |
|---|---|---|---|
| S0 | role, hop, is-loop classify | `tbl_port_role` (exact, ≤16 entries) | **Lever:** classify `ingress_port` in the **parser** instead and this stage disappears — a measured saving on this chip. defense4 does it (`:1196-1234`) |
| S1 | independent draws + destination-leaf lookup | `rng_spray`, `rng_fail`, `rng_attn` (Random), `h_spray` (Hash), `tbl_dst_leaf` (exact, 1 K) | all mutually independent → co-locatable |
| S2 | spray select | `tbl_spray_mode` (exact), `reg_spray_rr` + 1 SALU | |
| S3 | vlink resolve | `tbl_vlink` (exact on role/hop/src_leaf/spray, 64 entries) → sets `vlink_id`, `qid`, loop port | black-hole = delete entry |
| S4 | failure injection | `tbl_fail` (exact + 16-bit range, 64) + DirectCounter | TCAM + stats ALU |
| S5 | per-path counters | `reg_path_count` (64×32 b) + `reg_thresh` read | two independent register reads share a stage |
| S6 | attention read **and** NIC-evidence write | `reg_attn` (64×8 b), **2 RegisterActions, same stage** | both actions on one register must co-locate |
| S7 | gate + mirror arm | `tbl_gate` (exact) → `mirror_type`, `mirror_sid` | one-field gateway only (§5.3) |
| S8 | final forward, shim write / strip, hop++ | `tbl_final` (exact on role/hop) | |

**Estimate: 9 stages, 8 with the parser-classify lever.** Slack: 3–4 stages against the 12 available,
which is the headroom the requirement asked for.

Two placement risks to watch in the first compile:

- **Logical table IDs, not stages, may bind.** Tofino-1 allows 16 logical table IDs per stage, and
  defense4 measured stages 6/7/8 saturated at 16/16 with 19 bare action tables — because **a bare
  action call becomes its own logical table** (`:2164-2197`). Mitigation, taken from that source: use
  textual macros (`#define MCP_TO_LOOP() { … }`) for repeated small effects instead of named actions.
  Read the LTID column of the resource report, not just the stage count.
- **`reg_attn`'s two RegisterActions force S6's contents.** If a third consumer appears, check the
  hard cap of 4 first (§8.4/N7).

### 8.2 Egress stage plan — ≤ 4 of 12

| Stage | Purpose |
|---|---|
| E0 | role from bridged metadata / egress port |
| E1 | read `deq_qdepth[18:3]` and `deq_timedelta`; compare-and-replace into `csig_h` |
| E2 | `csig` setValid on first hop / setInvalid + ethertype restore on last hop |

Egress is otherwise empty, and egress placement is independent of ingress placement on this chip — so
the CSIG work costs **zero ingress stages**. This is why every measurement-tag operation belongs in
egress.

### 8.3 PHV estimate

| Group | Contents | Bytes |
|---|---|---|
| Ingress, matched ("hot") | `fabric_h` 6 B, `md` (vlink_id, path_id, spray_idx, attn, rnd_fail, rnd_attn, role, do_measure as `bit<16>` each = 16 B; `thresh` 4 B), `ipv4.dst` 4 B, `udp.src_port` 2 B | **≈ 32 B** |
| Ingress, tagalong (never matched) | `eth.dst/src` 12 B, `ipv4` remainder 16 B, `udp` remainder 6 B, `evid_h` 8 B | ≈ 42 B |
| Egress, matched | `csig_h` 12 B, `deq_qdepth` + `deq_timedelta` 8 B, bridged metadata 4 B | **≈ 24 B** |

Comfortable. Two rules that matter more than the totals:

- **Never use sub-byte fields** next to 32-bit register outputs — constraint Class 3, `invalid
  SuperCluster`. Every flag is at least `bit<8>`.
- **…but prefer `bit<16>` for new metadata.** This refines Class 3 with defense4's measurement
  (`:897-914`): its `phv_allocation_summary_0.log` showed MAU group **B0-15 at 16/16 containers**
  while overall PHV was only 16.5 % used. The 8-bit MAU group saturates long before the chip does.
  defense4 therefore made `shape_enable`, `payload49`, `do_shape` and `outcome` all `bit<16>` *purely
  for placement*. Do the same here: `bit<8>` is the floor, `bit<16>` is the default for anything new.
  This is why `fabric_h` in §3 is laid out as three 16-bit-friendly pairs.

### 8.4 Constraint classes touched

Classes 1–8 are `~/.claude/skills/tofino-p4/references/constraints.md`. N7–N11 are additions this
design depends on, each with a named source line; they are numbered from 7 to avoid renumbering the
canonical eight.

| Class | Where it bites in this design | Mitigation already in the design |
|---|---|---|
| **1** 44-bit gateway | attention gate (8 v 8), CSIG qdepth compare (16 v 16), drop probability | one predicate per gateway; drop probability moved to a range table; precompute compound tests into one field |
| **2** range key ≤ 20 bits | `tbl_fail` 16-bit RNG range = 4 of 5 nibbles | no second range field in that table |
| **3** byte-aligned PHV | all flags | every flag ≥ `bit<8>`; new metadata `bit<16>` (see N12) |
| **4** learn digest ≤ 48 B | **not used** — evidence goes out by mirror, not digest | n/a; keep it that way |
| **5** single-stage arithmetic | `path_id = (dst_leaf<<2) | spine` | fold the shift into `tbl_dst_leaf`'s action data; OR in the next stage |
| **6** silent ICE on end-around carry | **avoided by construction** | shim and CSIG tag are L2 shims → no IPv4/UDP length or checksum update anywhere in the program |
| **7** one `Hash` per tuple shape | `h_spray` (5-tuple) | a second hash needs a second `CRCPolynomial`+`Hash` instance; watch for the warning *"Expected single call to get for hash instance"* as the canary |
| **8** SALU `v==0` sentinel | `reg_attn`, `reg_thresh`, `reg_path_count`, `reg_spray_rr` | control plane seeds every slot at startup |
| **N7** ≤ 4 RegisterActions per Register | `reg_attn` has 2 | hard error, quoted verbatim at `defense4_rrc_bor_unified12.p4:1625-1639`: *"too many RegisterActions attached to the Register… limits the number … to 4"*. Budget them per register up front |
| **N8** ≤ 2 PHV inputs per Register | `reg_attn` (fast-path index + evidence value) | `:1586-1601`. If a third operand is needed, make it ride on an operand the register already has |
| **N9** SALU large-constant compare / signed compare | any threshold sentinel | `:491-524` — compare against **zero or a PHV field**, never a large constant. `:1641-1647` — `v < 8w0` on a `bit<8>` register compiles silently to an unsigned compare that is never true; cast to `(int<8>)v < 8s0` |
| **N10** a bare action call is its own logical table (16 LTIDs/stage) | S7/S8 small effects | `:2164-2197` — use textual macros for repeated small effects |
| **N11** N runtime bit-tests serialize into N stages | shim/CSIG setValid decisions | fold the decode into per-value table actions rather than a chain of `if (x & mask)` tests |
| **N12** the 8-bit MAU PHV group saturates first | all new metadata | `:897-914` — default new metadata to `bit<16>` |

### 8.5 Mirror sessions and other fixed resources

| Resource | Used | Available (Tofino 1) |
|---|---|---|
| Mirror sessions | 4 (sids 1–4, all `INGRESS`, all → `dp65`) | ~1 K; bandwidth binds long before count |
| `Random` units | 3 (`rng_spray`, `rng_fail`, `rng_attn`) | plentiful |
| `Hash` instances | 1 (`h_spray`) — plus 1 more if a second tuple shape appears | per-stage hash units |
| Registers | 5 (`path_count`, `thresh`, `attn`, `spray_rr`, optional `qmax`) | SRAM is not close to binding: 64 × 32 b = 256 B each |
| DirectCounters | 2 (`tbl_fail`, `tbl_vlink` default) | stats ALUs, 1 per stage that uses one |
| TM queues | 16 (8 on `dp68`, 8 on `dp8`) | 8/port under the current carving — **the real ceiling** |
| Parser states added | 4 (`parse_fabric`, `parse_csig`, `parse_evid`, `from_loop`) | parser TCAM; small |

---

## 9. (g) Offline compile plan while the switch is down

### 9.1 Is an SDE available on this workstation? — **Yes. Verified this session.**

| Question | Answer | Evidence |
|---|---|---|
| SDE under `/home/philip`? | **Yes** — `/home/philip/bf-sde-9.13.1`, 7.5 GB, fully built | `du -sh`, `ls` |
| Does `bf-p4c` run? | **Yes** — `p4c 9.13.1 (SHA: e558d01)` | `$SDE_INSTALL/bin/bf-p4c --version` |
| Does a TNA program actually compile? | **Yes** — a minimal ingress/egress TNA program compiled with `0 errors, 3 warnings` and emitted `bfrt.json`, `manifest.json`, `pipe/`, `smoke.conf` | smoke test written and run this session |
| SDE under `/opt`? | **No** | `ls /opt` — only `containerd, google, mininet, teamviewer, vagrant, zeek` |
| SDE under `~/src`? | **No** | `find /home/philip -maxdepth 2 -iname '*bf-sde*'` returns only `bf-sde-9.13.1` |
| A container with an SDE? | **Unknown — could not check.** The Docker daemon refuses this user: `permission denied … /var/run/docker.sock` | `docker images`, `docker ps -a` |
| Open-source `p4c` as a fallback? | Present (`/usr/bin/p4c`, `p4lang-p4c 1.2.4.2`) but it has **no Tofino/TNA backend** | `dpkg -l | grep p4lang` |

Additional offline assets in the same tree, all present:

- `install/bin/tofino-model` — the software ASIC model
- `install/bin/p4i` — the resource visualizer
- `install/lib/python3.8/site-packages/ptf` and `bf_pktpy/ptf` — the PTF framework
- `$SDE/run_tofino_model.sh`, `run_switchd.sh`, `run_p4_tests.sh`, `run_bfshell.sh`

**Conclusion: the full offline loop — compile, resource report, model-mode `bf_switchd`, bfrt control
plane, and PTF functional tests — is available on this workstation today.** The switch being down
blocks silicon measurements (§10.4) and nothing else.

### 9.2 The plan

**Build command.** Skip the p4studio cmake flow; it exists to `make install` into `$SDE_INSTALL` for
`bf_switchd`, which offline iteration does not need. Use the direct invocation that `sdnp_exp.p4`
itself documents at lines 10–11:

```bash
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH

$SDE_INSTALL/bin/bf-p4c --target tofino --arch tna \
    -o mcp_fabric.tofino --bf-rt-schema mcp_fabric.bfrt.json \
    mcp_fabric.p4
```

**Read the resource report, not the summary line.** After a successful build the artefacts that
matter are under `mcp_fabric.tofino/pipe/logs/`: `mau.resources.log` (stages, logical table IDs,
SRAM/TCAM per stage), `phv_allocation_summary_*.log` (per-MAU-group container occupancy — this is
where the B0-15 saturation of N12 shows up), and `context.json`. Prior experience on this chip: the
compiler's *initial* stage estimate can differ from the settled placement, so read `context.json`
rather than trusting the first summary.

**Sequence — smallest thing that can fail, first.**

1. **Skeleton compile.** Headers, parser, deparser, and empty controls. Confirms the shim/CSIG/evid
   header layout parses and deparses, and gives a baseline PHV report. Half a day.
2. **Forwarding + vlink resolve.** `tbl_port_role`, `tbl_dst_leaf`, `tbl_vlink`, `tbl_final`, plus the
   `qid` and loop-port writes. First real stage number.
3. **Spray.** All three modes plus `tbl_spray_mode`. Watch for the Class 7 hash canary warning.
4. **Failure injection.** Fork `sdnp_exp.p4`'s `Random` + range + DirectCounter block essentially
   verbatim.
5. **Measurement + attention.** The registers and their RegisterActions — this is where N7/N8/N9 bite.
   Compile after *each* register, not after all of them.
6. **Mirror.** Deparser `Mirror()`, metadata session id.
7. **Egress CSIG.** Bridged metadata, compare-and-replace.
8. **Evidence header.** Parser arm plus the second RegisterAction on `reg_attn`.

Compile at every step. A stage-count jump between two adjacent steps localises the cost immediately;
a jump discovered after eight changes costs a bisection session.

**Version drift is the one real risk.** Local is 9.13.1; the switch runs 9.13.2, and the `tofino-p4`
skill is explicit that mixing versions is a silent source of "works on my machine" drift. Policy:

- iterate locally on 9.13.1 for speed;
- **re-compile on the switch's 9.13.2 before any hardware run**, and diff the resource report;
- treat any change in stage count, LTID occupancy, or PHV group saturation between the two as a
  blocker to investigate, not a rounding difference.

**Offline PTF.** `run_tofino_model.sh` + `run_switchd.sh` + `run_p4_tests.sh`, with the ADTD harness
as the template (§10.3). One caveat carried forward and worth writing into the test README: **the
software model accepts some control-plane writes that the ASIC rejects** — symmetric-table writes in
particular behave differently between `pipe_id=0` and `pipe_id=0xffff` on hardware. A model PASS is
necessary, not sufficient.

**If the switch's SDE host becomes reachable before the ASIC does** (`decps@10.10.54.81` may answer
SSH even with the chip down), compile there too and diff — that closes the version-drift risk
without needing the silicon.

---

## 10. (h) S-UP validation checklist

### 10.1 Before touching anything — shared-chip protocol

1. `ssh decps@10.10.54.81` reachable.
2. Identify what owns the chip. Expect `defense4_caseA`. **Do not restart `bf_switchd` without
   Philip's explicit approval** — it is shared infrastructure and a restart drops whatever sibling
   pipeline is loaded.
3. Before loading a different program: `sudo systemctl stop gc-switchd && sudo systemctl mask
   gc-switchd && pkill -f launch_switchd.sh`. `gc-switchd` auto-loads `gridcloak` and seizes the
   Tofino whenever another project's `bf_switchd` dies; the symptom is `Failed to find BfRtInfo for
   program <yours>` plus `coarse_time write failed` floods. `systemctl unmask gc-switchd` hands it
   back.
4. `bf_switchd` needs `LD_LIBRARY_PATH` from the SDE env and **stdin kept open** — run it under tmux,
   not a bare `nohup` that closes stdin (H11).

### 10.2 bfrt sanity, in order

| # | Step | Pass criterion |
|---|---|---|
| 1 | Resolve the §2.2 conflict: which host is on `dp9`? | `$PORT` shows `dp9` UP at 25 G, and a ping from the named host arrives |
| 2 | `$PORT` for `dp9` (25 G, `BF_FEC_TYP_RS`, `PM_AN_DEFAULT`) and `dp65` (10 G, `FEC=NONE`, `PM_AN_FORCE_DISABLE`) | `$PORT_UP == True`, `$SPEED` as configured |
| 3 | `dp8` MAC-near loopback — **DELETE then add** | entry readback shows `$LOOPBACK_MODE == "BF_LPBK_MAC_NEAR"` and `$PORT_UP == True` |
| 4 | `dp68` recirculation: `tf1.pktgen.port_cfg` with `pktgen_enable=True, recirculation_enable=True`; **no `$PORT` entry** | a packet sent to `ucast_egress_port=68` reappears at ingress |
| 5 | Probe `dp69`–`dp71` for recirculation capability | note the result in `HURDLES.md`; do not depend on it |
| 6 | TM queue shapers on all 16 vlink queues (`tf1.tm.queue.sched_shaping` **and** `sched_cfg` with `max_rate_enable=True`), **`pipe_id=0`** | readback matches; a shaped queue actually limits throughput |
| 7 | Seed every register slot (`reg_attn`, `reg_thresh`, `reg_path_count`, `reg_spray_rr`) | read-back equals written values on all 64 entries |
| 8 | Install all 16 `tbl_vlink` entries; verify `qid` mapping | per-queue counters increment on the expected queue |
| 9 | `$mirror.cfg` sids 1–4 with the `"$normal"` action | readback shows the right `$ucast_egress_port` and `$max_pkt_len` |
| 10 | Confirm the pipe count and that all traffic stays in pipe 0 | per-pipe register reads agree with the all-pipe read |

**Step 3 in full, because the failure is silent** — `case_a_defense3_fixed_ack_delay_setup.py:607-622`
carries the comment *"dp8 MAC-near loopback: DELETE then re-add. A live entry rejects a loopback-mode
change, and the failure is silent."*

```python
lk = [port_tbl.make_key([gc.KeyTuple("$DEV_PORT", PORT_L)])]
try:    port_tbl.entry_del(tgt, lk)       # idempotent on a cold load
except Exception: pass
port_tbl.entry_add(tgt, lk, [port_tbl.make_data([
    gc.DataTuple("$SPEED",            str_val="BF_SPEED_25G"),
    gc.DataTuple("$FEC",              str_val="BF_FEC_TYP_NONE"),
    gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_FORCE_DISABLE"),
    gc.DataTuple("$LOOPBACK_MODE",    str_val="BF_LPBK_MAC_NEAR"),
    gc.DataTuple("$PORT_ENABLE",      bool_val=True)])])
```

Also worth copying from that file: it **gates the whole run on port speed** (`:550-576`), raising
`SpeedError` unless both `$PORT.$SPEED` and `tm.scheduling_speed` are the expected value, because
every timing number is speed-conditional. Our §2.5 bandwidth budget has exactly the same property —
add the same gate.

### 10.3 PTF tests to write **now**, against the offline model

Template: `/home/philip/Projects/ADTD/p4/tofino/ptf/test_decoy.py` — a real `BfRuntimeTest` suite
(`import ptf.testutils as testutils`, `from bfruntime_client_base_tests import BfRuntimeTest`,
`class DecoyTest(BfRuntimeTest)` with `setUp` calling `BfRuntimeTest.setUp(self, client_id=0,
p4_name=…)`, `send_packet` / `verify_packet` / `testutils.dp_poll`) that its own docstring says runs
on the offline `tofino-model` with no physical switch. Its "make the oracle deterministic by
programming constant table contents" trick is directly reusable for our spray tests.

Note that the neighbouring `b5*.py` files in the same directory are bfrt hardware drivers, not PTF
tests — `test_decoy.py` and `test_checksum_unit.py` are the PTF patterns to copy.

| ID | Test | Pass criterion |
|---|---|---|
| T1 | Shim survives a loop | packet in on host port → out on host port, payload byte-identical, shim and CSIG **stripped**, `eth.etype == 0x0800` |
| T2 | Hop accounting | `reg_path_count[p]` increments exactly `P` times per packet for the configured `P` |
| T3 | Spray determinism (hash mode) | two identical 1000-packet runs produce **byte-identical** spray histograms |
| T4 | Spray determinism (round-robin) | spray sequence is exactly `0,1,2,3,0,1,2,3,…` from a seeded counter |
| T5 | Spray balance (random mode) | 10 000 packets, each of 4 spines within a 3σ binomial band of 2500 |
| T6 | Drop injection accuracy | `p = 25 %` on vlink 3, 10 000 packets → `fail_ctr` drop count in [2300, 2700]; delivered `== sent − dropped` exactly |
| T7 | One-direction asymmetry | drop row on the uplink id only → reverse direction loss-free (0 drops) |
| T8 | Black hole | delete the `tbl_vlink` entry → 0 delivered, default-action counter `== sent` |
| T9 | Corruption | `inj_corrupt` fires → egress frame has `udp.checksum == 0xBAD1`, everything else unchanged |
| T10 | Attention gating | `attn=0` → 0 mirrors; `attn=255` → every packet mirrored; `attn=64` → 25 % within 3σ |
| T11 | Mirror truncation | `$max_pkt_len=64` → mirrored frames are exactly 64 B |
| T12 | CSIG compare-and-replace | shape one vlink to force depth → emerging tag names **that** hop id and reports a depth strictly greater than the other hop's |
| T13 | Evidence packet | inject `evid` with `path_id=5, rtt_q=200` → `reg_attn[5]` changes per the update rule, **and** the evidence packet does not recirculate (loop counter unchanged) and does not egress to a host port |
| T14 | Evidence spoofing | an `evid` packet arriving on a *loop* port is dropped, not applied |
| T15 | Fabric-ethertype spoofing | a frame with `etype=0x88F0` arriving fresh on a host port is dropped (the defense4 `:34-35` repair) |
| T16 | Latency inflation | `loops=8` on vlink 2 → end-to-end delta increases monotonically and by ≈ 8 × pipeline latency |
| T17 | Register seeding | after `setUp`, every one of the 64 slots of every register reads back its seeded value (Class 8) |
| T18 | Clean-run false alarms | 60 s of fault-free traffic → 0 paths cross threshold, mirror rate stays at the configured baseline |

Determinism rule for the whole suite, borrowed from `test_decoy.py`: where a data-plane value is
genuinely unpredictable (an RNG draw, a hash index), **program a constant-valued table or register so
the oracle is deterministic anyway**, and test the *mechanism* rather than the draw.

### 10.4 Hardware-only measurements, in priority order

1. **`dp68` recirculation line rate.** pktgen ramp on `dp68`, find the drop knee. Everything in §2.5
   is parameterised on this number, so it is the first measurement and it gates the traffic plan.
2. **Compiler resource report on 9.13.2**, diffed against the local 9.13.1 report.
3. **Loop-bandwidth ceiling end to end.** Ramp host load with `P=2` and confirm the predicted `L_max`
   from §2.5 within measurement error; report the discrepancy honestly if there is one.
4. **Control-loop latency**: bfrt register write → observed change on the wire. The
   `ADTD/p4/tofino/ptf/b5c_latency.py` register-update method applies directly, including its
   clock-sync caveat (run the write and the capture on the same host, or use PTP).
5. **Epoch cost**: wall-clock time for a 64-entry register read plus a 64-entry write, over 100
   epochs, p50/p99. This sets the floor on the epoch sweep in `paper/PREREG.md`.
6. **Budget respect**: mirror bytes/s ≤ configured budget across 10 epochs with attention varying.
7. **Calibration distributions** (probe RTT, counter-read latency) fed into htsim, with the KS
   distance reported (H9).

---

## 11. Cut list — asked for, or natural, and not feasible on this target

Being explicit here is cheaper than rediscovering each of these mid-build.

| # | Item | Why not | What we do instead |
|---|---|---|---|
| 1 | Carry virtual-switch identity in **bridged metadata** across recirculation | Bridged metadata is intra-pass only; a recirculated packet is re-parsed from its own bytes | Carry it on the wire in `fabric_h` (§3). Bridged metadata is still used, but only ingress→egress within a pass |
| 2 | True per-path **variance / Z-score in the SALU** | No divide; the SALU cannot compare two runtime variables | Count on chip, compute statistics in the epoch controller, compare against a control-plane-written threshold (§5.2 C3). Say so in the paper |
| 3 | **One physical loop port per virtual link** | `dp64`/`dp65` are wired to other things, `dp66`/`dp67` are internal CPU KR links that must not be touched, `dp69`–`dp71` unverified | One TM **queue** per virtual link on `dp68` + `dp8` → 16 links (§3, M2) |
| 4 | A **growing INT stack** across hops | Grows the packet per hop, needs per-hop length fixup, and TNA cannot emit a header after the unparsed residual | Fixed 12 B compare-and-replace CSIG tag (§5.5) |
| 5 | **Deflect-on-drop trimming** | No local precedent on this chip; DoD plus truncation is unvalidated here | Mirror a 64 B trimmed copy at the drop decision instead (§5.6). DoD stays on the stretch list |
| 6 | **Seeded `Random<>`** for replayable random spray | Tofino-1's `Random<>` has no control-plane seed | Replay uses hash or round-robin mode; the chosen index is recorded in `fabric_h.spray` so random runs stay analysable (§4) |
| 7 | Virtual links spanning **two pipes** | Registers are instantiated per pipe, so per-path counters would split; and every wired port on this box is in pipe 0 anyway | Pipe 0 only (§2.3) |
| 8 | 25 G + 10 G host ingress at **3 or more virtual hops** if `dp68` turns out to be 25 G-equivalent | §2.5 arithmetic | Cap host load, or drive line rate from pktgen on `dp68` |
| 9 | **Learn digests** for evidence export | 48 B/quantum cap (Class 4) plus digest-name-resolution pitfalls, and mirrors already carry the full evidence | Truncated mirror to `dp65` (§5.4) |
| 10 | More than **16 virtual links** without further work | 8 queues/port under the current TM carving | Either re-carve the queue mapping or find more recirc ports — both are `VERIFY` items, not assumptions |

---

## 12. Open questions that need Philip

1. **Which host is on `dp9`?** `Tooling/tofino_25g_connectivity_map.md` §0 (verified 2026-08-12) says
   Vision; `mcp/WORKING_NOTES.md` (2026-08-25) says Hulk's `enp59s0f0np0` goes to the switch. The
   traffic-generation plan differs, and Vision is also where the Agilio lives.
2. **Is `dp65` still the Agilio leg at 10 G?** It is recorded only in agent memory (2026-07-17), not
   in the connectivity map, and the memory note says the Agilio setup was explicitly *temporary* and
   should not be written into the map. If `dp65` is gone, the collector moves and §5.4's bandwidth
   table changes.
3. **`bf_switchd` restart approval and a scheduling window** — the chip currently runs
   `defense4_caseA` (H12).
4. **Docker group membership** — checked 2026-08-26: `decps` is not in `docker` on the switch (needs `sudo usermod -aG docker decps`), so the container SDE question in §9.1 can actually be answered rather
   than left unknown.
5. **Confirm the fabric shape** — DECIDED 2026-08-26 by Philip: **4 leaves × 2 spines**. Was: 2 leaves × 4 spines or 4 leaves × 2 spines? Both fit 16 virtual links;
   the first gives more spray fan-out (better for the spraying claims), the second more leaf
   diversity (better for the traffic-matrix claims).

---

## 13. Provenance

Files read or measured this session, by path:

- `~/.claude/skills/tofino-p4/SKILL.md`, `references/constraints.md`, `references/build-deploy.md`,
  `references/testbed.md`
- `/home/philip/Projects/Tooling/tofino_25g_connectivity_map.md`
- `/home/philip/Projects/mcp/README.md`, `HURDLES.md`, `WORKING_NOTES.md`
- `~/.claude/plans/we-have-to-do-spicy-patterson.md`
- `/home/philip/Projects/dnp3-research/research/synthesis/validation/tofino/sdnp_exp.p4` (113 lines)
  and `sdnp_setup.py` (137 lines)
- `/home/philip/Projects/GridCloak/p4/gridcloak_c.p4` (592 lines), `gc_switch_setup_c.py` (182),
  `gc_pktgen_test.py` (240, **stale** relative to `gridcloak_c.p4` — its table and counter names
  belong to an older `gridcloak.p4`; use it only for the pktgen one-shot idiom),
  `gridcloak.tofino/gridcloak.conf`
- `/home/philip/Projects/DNP3/defense4/timing/implementation/exact_experiment_source/defense4_rrc_bor_unified12.p4`
  (3509 lines)
- `/home/philip/Projects/DNP3/defense4/timing/implementation/control/case_a_defense3_fixed_ack_delay_setup.py`
  (1563 lines) — **note the path**: this file is *not* under `exact_experiment_source/control/`, and
  the line ranges are `:607-622` for the loopback DELETE-then-add and `:902-931` for `$mirror.cfg` /
  `$max_pkt_len`, not the ranges quoted in the task brief
- `~/labs/09-simple_l3_lag_ecmp/solution/p4src/` (6 files, 1089 lines)
- `~/labs/11-simple_l3_mirror/solution/p4src/simple_l3_mirror.p4` (924 lines),
  `solution/bfrt_python/setup.py`, `solution/ptf-tests/test.py`
- `/home/philip/Projects/NetImmune/netimmune.p4` (798 lines)
- `/home/philip/Projects/ADTD/p4/tofino/ptf/` (`test_decoy.py`, `test_checksum_unit.py`, `b5*.py`)
- `/home/philip/bf-sde-9.13.1/` — `bf-p4c --version`, a smoke compile, and a binary/asset inventory

One correction to the local knowledge base, already applied to the skill: the switch is
`decps@10.10.54.81`, not `10.10.54.15` (H14).

---

## Errata from the compile sequence (2026-08-26, steps 5–7 on SDE 9.13.1 and 9.13.2)

Three claims above did not survive bf-p4c; the shipped program does it differently. Kept here so
nobody "restores" the original text.

1. **§5.3 gating compare.** `if (md.rnd_attn < md.attn)` is rejected regardless of width: a gateway
   magnitude compare needs a constant operand ("one operand … must be constant"). The gate is a
   256-row TCAM table on `attn[15:8]` (exact) × `rnd_attn` (range) — 1/256 resolution, no gateway.
2. **§5.5 compare-and-replace.** Same rule: `this_qdepth > worst_qdepth` cannot be a gateway
   predicate. Shipped: `diff = worst |-| this` (saturating) and `if (diff == 0)`.
   Also `deq_qdepth[18:3]` does not allocate in egress (mid-word slice of intrinsic metadata);
   the tag carries `deq_qdepth[15:0]` (1-cell granularity). `deq_timedelta` is 18 bits.
3. **§5.5 bridged metadata / egress insertion.** Not used. The tag is inserted and zeroed by
   ingress `act_enter` (source leaf); egress only updates `worst_*` from the shim's `hop`, the
   (port, qid) → vlink table and the intrinsic metadata. Reason: egress header writes may fill a
   packed container from one source only (casts and constants count), and the `(path_id|epoch)`
   pair could not be written in egress in any arrangement tried. `fabric_h` carries `path_id` (8 B).
4. **§7.4 register constants.** A register's actions share 4 parameter slots: `a_max` is implicit
   (`bump_cap + k_up − 1`); a stateful action with a computed index cannot be a default action.

5. **§5.4 mirror content.** Ingress `Mirror.emit()` copies the packet *as it arrived*, not as this
   pass modified it (measured: the copy's flags tracked the previous pass). The copy therefore
   carries a 24-byte `mirror_h` (fake Ethernet dst `A5:A5:A5:A5:A5:A5`, ethertype `0x88F1`, then
   hop/vlink/path_id/attn/flags of the mirroring pass) in front of the unmodified frame; the
   egress parser recognises the `0xA5A5` prefix and does not run CSIG on copies. The field list
   may contain no literals, and parser-written key metadata in it breaks stage-1 RNG placement.
6. **§5.3/§5.7 registers are per pipe.** `reg_attn` is one instance per pipe; the host port (dp9)
   and the loop ports are in different pipes, so NIC evidence and CSIG exceedance would land in
   different registers. Evidence packets update the host pipe's register, are forwarded to loop
   port 5/0 (`tbl_evid_fwd`), update the loop pipe's register on the second pass and are dropped.
   The controller must read/seed all pipes (`pipe_id=0xffff` writes; reads return one value per pipe).
8. **§5.5/§7.4 CSIG exceedance is single-pipe by construction.** The tag is inserted at the source
   leaf's own pass, so the first ingress that can see a tag is a loop port (the loop pipe); the host
   pipe's `reg_attn` reacts only to NIC evidence and controller re-pricing. Measured
   `attn = [4094, 65535]` on the congested path. The epoch controller reads both pipes.
9. **Mirror header `next_hop`.** The emitted `hdr.fabric.hop` is already incremented by the mirroring
   pass; the inner frame's ethertype discriminates source-leaf (0x0800) from spine (0x88F0) copies.
7. **§5.3 update cadence.** Attention is updated on the two fabric passes of a data packet (hops 0
   and 1) and by evidence packets; the delivery pass is not a sample.

Stage budget after all eight steps: ingress 8 of 12, egress 3 (the 16-bit shim removed a stage).

