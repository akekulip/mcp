#!/usr/bin/env python3
"""setup_skeleton.py — bfrt control plane for mcp_fabric (steps 1-4).

Programs a **4 leaves x 2 spines** virtual fabric on the real testbed wiring, using
the cage-5 <-> cage-6 DAC as eight physical loop links.  Port roles, destination-leaf
lookup, 16 virtual links over 16 real TM queues, the spray-mode switch and the
per-virtual-link failure injection are all control-plane data; nothing in
mcp_fabric.p4 hard-codes the shape.

===========================================================================
STATUS — RUN ON SILICON 2026-08-26.  Full numbers: p4/reports/step4-silicon.md.
---------------------------------------------------------------------------
Against the LIVE switch (decps@10.10.54.81, SDE 9.13.2, bf_switchd running the
STEP-4 build of mcp_fabric.p4 = git HEAD, sha256 c40dbfbe...), traffic from
Vision enp59s0f0np0 on dp9:

  --dry-run self-check                    PASS
  `up`, every table write accepted        PASS  (9 + 4 + 64 + 12 + 1 rows)
  3-pass forwarding, 1000 pkts to leaf 1  PASS  1000/1000 returned
  shim stripped on delivery               PASS  ether_type 0x0800, IPv4/UDP intact
  hash spray over 2 spines                PASS  uplink 0: 500, uplink 1: 500
  correct up/down links only              PASS  vlinks 0,1 up and 9,13 down
  leaves 2 and 3 (hairpin)                PASS  200/200 each, 100/100 per spine
  `fail 0 50 drop`                        PASS  742/1000 delivered, 258 dropped
  `fail-clear`                            PASS  1000/1000 restored
  `blackhole 0 1 0`                       PASS  200/400 delivered, 202 counted

TWO REAL DEFECTS FOUND:
 1. The ingress parser's 8-bit-to-16-bit metadata lifts are byte-aliased on this
    binary, so every looped pass missed tbl_vlink and tbl_final until the control
    plane compensated.  Measurement and compensation: SHIM_MD_ALIAS, below.  The
    proper fix is a P4 change and belongs to whoever owns mcp_fabric.p4.
 2. bf_switchd serves its bfrt schema from the JSON file named in its conf, so
    replacing that file under a RUNNING switchd makes the schema describe a
    program the chip is not executing.  That happened mid-session and briefly
    emptied tbl_vlink.  install_vlinks/install_final now NEGOTIATE action arity
    and always write before sweeping stale rows: see TO_LOOP_PATH_ID and
    OPTIONAL_ACTION_ARGS.
===========================================================================

Usage (on the switch, with the SDE env set):
    export SDE=/home/decps/Downloads/bf-sde-9.13.2
    export SDE_INSTALL=$SDE/install
    export LD_LIBRARY_PATH=$SDE_INSTALL/lib
    P=$SDE_INSTALL/lib/python3.8/site-packages
    PYTHONPATH=$P/tofino:$P/tofino/bfrt_grpc:$P python3 setup_skeleton.py <cmd>

    python3 setup_skeleton.py --dry-run            # print the entry plan, no writes
    python3 setup_skeleton.py up                   # ports + roles + fabric + spray + seeds
    python3 setup_skeleton.py spray hash|random|rr|sel
    python3 setup_skeleton.py fail <vlink> <pct> [drop|corrupt]
    python3 setup_skeleton.py fail-clear
    python3 setup_skeleton.py shape <vlink> <gbps> # optional, NOT part of `up`
    python3 setup_skeleton.py blackhole <src_leaf> <dst_leaf> <spray>
    python3 setup_skeleton.py counters [--json]
    python3 setup_skeleton.py zero                 # reset vlink counters, clear tbl_fail
    python3 setup_skeleton.py ports                # $PORT link state + frame counters
"""
import json
import sys

DEV = 0
PROG = "mcp_fabric"
GRPC_ADDR = "localhost:50052"

# Only client_id 0 may call bind_pipeline_config.  The epoch controller must use a
# DIFFERENT client_id and must not bind (design doc §5.7).
CLIENT_ID = 0

# ===========================================================================
# TOPOLOGY — verified against `bfshell -> ucli -> show` on 2026-08-26.
# The D_P column of `show` is authoritative; front-panel names are for humans.
# ===========================================================================
#
#   Vision enp59s0f0np0  <-->  15/1  = dev_port 9   (25G RS-FEC, AN, UP)
#       the ONLY host on this switch.  Hulk enp59s0f0np0 is NOT cabled to the
#       switch (physical fix pending), so Hulk plays no part in forwarding.
#
#   cage 5 <-> cage 6 are joined lane-for-lane by one 4-lane DAC at 25G RS:
#       5/k  = dev_port 164+k      6/k = dev_port 172+k       k = 0..3
#   A frame sent out 5/k arrives on 6/k and vice-versa.  That gives FOUR
#   physical loop links, one per leaf.
#
#   dp65 (33/1) is gone and there is no Agilio collector; 33/2 and 33/3 belong to
#   another rig and are NEVER touched here.
#
HOST_DP = 9                                  # 15/1 — Vision, leaf 0's host
LEAF_A = [164, 165, 166, 167]                # 5/l — "leaf side" of loop pair l
LEAF_B = [172, 173, 174, 175]                # 6/l — "spine side" of loop pair l
PEER = dict([(LEAF_A[i], LEAF_B[i]) for i in range(4)] +
            [(LEAF_B[i], LEAF_A[i]) for i in range(4)])

# P4 constants — keep in sync with mcp_fabric.p4
ROLE_OTHER, ROLE_HOST, ROLE_LOOP, ROLE_NIC = 0, 1, 2, 3
LAST_HOP = 2

N_LEAF = 4
N_SPINE = 2
SPRAY_MASK = N_SPINE - 1          # action data for the spray-mode actions (= k-1 = 1)

# Virtual-switch ids carried in fabric_h.vsw_id: leaves 0..N_LEAF-1, spines 16+s.
VSW_SPINE_BASE = 16

# ===========================================================================
# MEASURED SILICON QUIRK — parser-lifted metadata is byte-aliased (2026-08-26)
# ---------------------------------------------------------------------------
# mcp_fabric.p4's ingress parser lifts three 8-bit shim bytes into 16-bit
# metadata fields:
#       md.hop       = (bit<16>)hdr.fabric.hop;
#       md.vsw_id    = (bit<16>)hdr.fabric.vsw_id;
#       md.spray_idx = (bit<16>)hdr.fabric.spray;
# On the loaded step-4 binary these do NOT zero-extend.  bf-p4c gave each 16-bit
# metadata field the parser's 16-bit extraction container, so the HIGH byte holds
# the PRECEDING shim byte.  Measured on hardware by sweeping candidate key values
# and watching which tbl_vlink DirectCounter moved (60/60 packets accounted for):
#
#       md.hop       == (fabric.vsw_id << 8) | fabric.hop      e.g. 0x1001
#       md.spray_idx == (fabric.hop    << 8) | fabric.spray    e.g. 0x0100
#
# Consequences, and why this file compensates the way it does:
#
#  * The fresh-from-host pass is UNAFFECTED: at hop 0 there is no shim, md.hop
#    comes from the parser start state (a constant assign) and md.spray_idx from
#    the spray action, so both are clean.  Only the looped passes are aliased.
#  * The high byte of md.hop is whatever the PREVIOUS pass wrote into
#    fabric_h.vsw_id, and that value is pure control-plane data (`next_vsw` in
#    to_loop).  Writing next_vsw = 0 on EVERY row therefore makes md.hop exactly
#    equal to the hop number again — which restores both `if (md.hop == 0)` and
#    `if (md.hop != LAST_HOP)` and every tbl_final key.  That is the whole fix.
#  * md.spray_idx cannot be repaired the same way, because its high byte is the
#    hop number and the hop number has to be 1 and 2.  So the tbl_vlink rows for
#    the looped passes carry the ALIASED spray key (hop << 8 | spine) instead.
#
# Cost of the workaround: fabric_h.vsw_id is 0 on the wire instead of naming the
# virtual switch of each pass.  Nothing in steps 1-4 keys on it (md.vsw_id is
# parsed and never used), and the spine is still recoverable from fabric_h.spray,
# which is the field §4 makes load-bearing.  It is a wire annotation we lose, not
# a mechanism.
#
# THE REAL FIX belongs in mcp_fabric.p4 (owned by another engineer): stop lifting
# these bytes in the parser, or declare them so the widths line up — e.g. make
# the metadata fields bit<8>, or pair the shim bytes into bit<16> header fields,
# or set md.hop/md.spray_idx from a MAU action instead of the parser.  When that
# lands, set SHIM_MD_ALIAS = False below and re-run `up`; every key reverts to
# the natural encoding and vsw_id goes back to naming the virtual switch.
SHIM_MD_ALIAS = False   # P4 fixed 2026-08-27: fabric_h fields are 16-bit, parser copies are same-width


def wire_vsw(pass_idx, spine, dst_leaf):
    """The value written into fabric_h.vsw_id by the pass with this index — i.e.
    to_loop's `next_vsw` action data on the row that pass matched."""
    if SHIM_MD_ALIAS:
        return 0                      # forced to 0, see the block above
    return VSW_SPINE_BASE + spine if pass_idx == 0 else dst_leaf


def md_hop(pass_idx, spine, dst_leaf):
    """md.hop as the MAU actually sees it on the pass with this index."""
    if pass_idx == 0:
        return 0                      # no shim: parser start-state constant
    if not SHIM_MD_ALIAS:
        return pass_idx
    return (wire_vsw(pass_idx - 1, spine, dst_leaf) << 8) | pass_idx


def md_spray(pass_idx, spine):
    """md.spray_idx as the MAU actually sees it on the pass with this index.
    On a looped pass the high byte is the hop number the previous pass wrote,
    which is exactly pass_idx."""
    if pass_idx == 0 or not SHIM_MD_ALIAS:
        return spine
    return (pass_idx << 8) | spine


# ===========================================================================
# VIRTUAL-LINK ENCODING  (16 ids, one real TM queue each)
# ---------------------------------------------------------------------------
#   uplink   leaf l -> spine s :  id = l*N_SPINE + s          =  0..7
#                                 queue = (LEAF_A[l], qid=s)
#   downlink spine s -> leaf l :  id = 8 + s*N_LEAF + l       =  8..15
#                                 queue = (LEAF_B[l], qid=s)
#
# So bit 3 of the id is the direction, and the spine index is ALWAYS the real TM
# qid in both directions.  The two directions live on different physical ports
# (cage 5 for up, cage 6 for down), so qid=s is unambiguous and there is no need
# for the "qid 2+s downstream" variant the task offered: 8 ports x 2 qids = the
# 16 distinct queues we need.  Direction is in the id, so §7.3's one-direction
# asymmetric failure is free (install tbl_fail for the uplink id only).
#
# THREE PASSES, and how the wiring makes each one identifiable:
#   hop 0  ingress dp9      role HOST, src_leaf 0  -> uplink   out 5/l  (qid s)
#   hop 1  ingress 6/l      role LOOP, src_leaf l  -> downlink out 6/d  (qid s)
#   hop 2  ingress 5/d      role LOOP, src_leaf d  -> deliver  out dp9
# The hop counter in the shim is what actually separates the passes; the port
# roles just supply src_leaf.  A cage-6 port only ever sees hop-1 traffic and a
# cage-5 port only ever sees hop-2 traffic, which makes a port frame counter a
# direct check on each pass.
# ===========================================================================

# Host IP -> leaf.  Leaf 0's host is Vision on dp9.  Leaves 1..3 have NO host
# today, so their delivery port is dp9 as well: a packet addressed to
# 10.0.1.2/3/4 traverses leaf0 -> spine s -> leaf 1/2/3 and is then HAIRPINNED
# back to Vision.  That is deliberate — it is what makes a single-host testbed
# exercise all four leaves and both spines.  Replace LEAF_HOST_DP[l] with the
# real port the day leaf l gets a host.
HOST_IPS = {
    "10.0.1.1": 0,
    "10.0.1.2": 1,
    "10.0.1.3": 2,
    "10.0.1.4": 3,
}
LEAF_HOST_DP = [HOST_DP, HOST_DP, HOST_DP, HOST_DP]

# Default virtual-link capacity for the OPTIONAL `shape` command.  Use BPS at
# realistic rates, NEVER PPS — a PPS shaper is a cap, not a pacer, and it was
# measured starving a queue entirely below ~1200 pps.  Shapers are deliberately
# NOT part of `up`: an inert or mis-sized shaper is a silent packet sink, and
# steps 1-4 do not need finite link capacity to be correct.
DEFAULT_VLINK_GBPS = 10

SPRAY_ACTIONS = {
    "random": "Ingress.spray_from_random",   # B1 — per-packet, NOT replayable
    "hash":   "Ingress.spray_from_hash",     # B2 — default, replayable
    "rr":     "Ingress.spray_from_rr",       # B4 — perfectly balanced, replayable
    "sel":    "Ingress.spray_from_sel",      # B3 — ActionSelector, group-managed
}
DEFAULT_SPRAY = "hash"


# ===========================================================================
# The entry plan.  Pure functions, no bfrt — reviewable and self-checkable
# offline, and the same functions drive both --dry-run and the real writes.
# ===========================================================================

def vlink_up(leaf, spine):
    """Uplink leaf->spine.  ids 0..7."""
    return leaf * N_SPINE + spine


def vlink_dn(spine, leaf):
    """Downlink spine->leaf.  ids 8..15."""
    return 8 + spine * N_LEAF + leaf


def vlink_placement(vlink_id):
    """id -> (real dev_port, real TM qid).  See the encoding block above."""
    if vlink_id < 8:
        return LEAF_A[vlink_id // N_SPINE], vlink_id % N_SPINE
    v = vlink_id - 8
    return LEAF_B[v % N_LEAF], v // N_LEAF


def vlink_name(vlink_id):
    if vlink_id < 8:
        return "up   L%d->S%d" % (vlink_id // N_SPINE, vlink_id % N_SPINE)
    v = vlink_id - 8
    return "down S%d->L%d" % (v // N_LEAF, v % N_LEAF)


def plan_roles():
    """(dev_port, role, src_leaf).

    Both halves of loop pair l carry src_leaf = l: on a cage-6 port that is the
    leaf the uplink came FROM (which is what hop 1 keys on), on a cage-5 port it
    is the leaf the packet is being delivered BY (unused at hop 2, since
    tbl_vlink is not applied there).  One uniform rule, no special cases."""
    rows = [(HOST_DP, ROLE_HOST, 0)]
    for l in range(N_LEAF):
        rows.append((LEAF_A[l], ROLE_LOOP, l))
        rows.append((LEAF_B[l], ROLE_LOOP, l))
    return rows


def plan_dst_leaf():
    # path_base = leaf * N_SPINE, precomputed here so the data plane never
    # shifts (design Class 5).  path_id = path_base | spray_idx names one of the
    # N_LEAF*N_SPINE end-to-end paths; steps 1-4 only carry it.
    return [(ip, leaf, leaf * N_SPINE) for ip, leaf in sorted(HOST_IPS.items())]


def plan_vlink():
    """(role, hop, src_leaf, dst_leaf, spray) -> (vlink_id, port, qid, next_vsw).

    The KEY values here are what the MAU actually sees, which on the looped
    passes is the byte-aliased form (see SHIM_MD_ALIAS above), not the logical
    hop/spine numbers.  The DATA values are plain.

    Rows are enumerated over every (src_leaf, dst_leaf, spine) even though only
    src_leaf 0 is reachable today: the extra rows cost nothing (64 of 256) and
    they mean adding a host to leaf 1 is a one-line HOST_IPS/role edit.
    Because src_leaf is part of the key, one vlink_id is spread over several
    rows; `counters` aggregates by vlink_id as well as printing the raw rows."""
    rows = []
    # hop 0 — source leaf picks a spine and takes the uplink out of cage 5.
    for leaf in range(N_LEAF):
        for dst in range(N_LEAF):
            for spine in range(N_SPINE):
                v = vlink_up(leaf, spine)
                port, qid = vlink_placement(v)
                rows.append(((ROLE_HOST, md_hop(0, spine, dst), leaf, dst,
                              md_spray(0, spine)),
                             (v, port, qid, wire_vsw(0, spine, dst))))
    # hop 1 — the spine takes the downlink toward the destination leaf, out of
    # cage 6.  spray_idx (= the spine) came off the wire, src_leaf off the port.
    for leaf in range(N_LEAF):
        for dst in range(N_LEAF):
            for spine in range(N_SPINE):
                v = vlink_dn(spine, dst)
                port, qid = vlink_placement(v)
                rows.append(((ROLE_LOOP, md_hop(1, spine, dst), leaf, dst,
                              md_spray(1, spine)),
                             (v, port, qid, wire_vsw(1, spine, dst))))
    return rows


def plan_final():
    """tbl_final rows.  The hop key is the MAU-visible md.hop.

    With SHIM_MD_ALIAS the workaround forces fabric_h.vsw_id to 0, so md.hop is
    the plain hop number again and this table needs no per-spine duplication —
    which is fortunate, because tbl_final has no spray key and could not express
    one."""
    rows = []
    for dst in range(N_LEAF):
        rows.append(((ROLE_HOST, md_hop(0, 0, dst), dst),
                     ("Ingress.act_enter", {"next_hop": 1})))
    for dst in range(N_LEAF):
        rows.append(((ROLE_LOOP, md_hop(1, 0, dst), dst),
                     ("Ingress.act_transit", {"next_hop": 2})))
    for dst in range(N_LEAF):
        rows.append(((ROLE_LOOP, md_hop(LAST_HOP, 0, dst), dst),
                     ("Ingress.act_deliver", {"port": LEAF_HOST_DP[dst]})))
    return rows


def plan_spray(mode):
    # One row: spraying happens only on a host port at hop 0.  k lives in the
    # action data (mask = k-1), so 4x2 vs 2x4 is a control-plane edit.
    return [((ROLE_HOST, 0), SPRAY_ACTIONS[mode], SPRAY_MASK)]


def plan_shapers(gbps=DEFAULT_VLINK_GBPS):
    rows = []
    for v in range(N_LEAF * N_SPINE * 2):
        port, qid = vlink_placement(v)
        pipe, pg_id, pg_queue = tm_coords(port, qid)
        rows.append((v, port, qid, pipe, pg_id, pg_queue, gbps))
    return rows


def tm_coords(dev_port, qid):
    """(pipe, pg_id, pg_queue) for a TM queue.

    Tofino 1: dev_port = pipe*128 + port_in_pipe; a port group is 4 ports and the
    default carving is 8 queues per port.  dp9 is pipe 0, the loop ports
    (164-175) are pipe 1 — TM tables are PIPE-SPECIFIC, so the target must be the
    port's own pipe, never 0xffff."""
    pipe = dev_port >> 7
    pip = dev_port & 0x7F
    return pipe, pip // 4, (pip % 4) * 8 + qid


# ---------------------------------------------------------------------------
# self-check: a miniature emulator of the loaded pipeline over the plan.  It
# catches an encoding slip (a wrong peer, a wrong qid, a missing tbl_final row)
# offline, before it becomes an hour of packet chasing on silicon.
# ---------------------------------------------------------------------------

def _role_map():
    return dict((dp, (role, leaf)) for dp, role, leaf in plan_roles())


def simulate(dst_ip, spine, ingress_dp=HOST_DP, max_pass=6):
    """Walk the plan the way the chip walks the tables, INCLUDING the two gates
    (`if (md.hop == 0)` and `if (md.hop != LAST_HOP)`) and the measured metadata
    aliasing.  Returns a trace of
    (pass, ingress_dp, role, md.hop, vlink_id, egress_dp, qid, action)."""
    roles = _role_map()
    vlink = dict(plan_vlink())
    final = dict(plan_final())
    dst_leaf = HOST_IPS[dst_ip]
    trace = []
    dp = ingress_dp
    for p in range(max_pass):
        if dp not in roles:
            trace.append((p, dp, None, None, None, None, None, "no-role/drop"))
            return trace
        role, src_leaf = roles[dp]
        mhop = md_hop(p, spine, dst_leaf)
        mspray = md_spray(p, spine)
        v = port = qid = None
        if mhop != LAST_HOP:                      # the P4 gate, on the ALIASED value
            key = (role, mhop, src_leaf, dst_leaf, mspray)
            if key not in vlink:
                trace.append((p, dp, role, mhop, None, None, None,
                              "tbl_vlink miss -> black_hole"))
                return trace
            v, port, qid, _vsw = vlink[key]
        fkey = (role, mhop, dst_leaf)
        if fkey not in final:
            trace.append((p, dp, role, mhop, v, port, qid,
                          "tbl_final miss -> act_drop"))
            return trace
        act, args = final[fkey]
        trace.append((p, dp, role, mhop, v, port, qid, act))
        if act == "Ingress.act_deliver":
            trace.append((p + 1, args["port"], None, None, None, None, None, "HOST"))
            return trace
        if port is None:
            trace.append((p, dp, role, mhop, v, port, qid, "no egress port"))
            return trace
        dp = PEER[port]
    trace.append((max_pass, dp, None, None, None, None, None, "LOOPS FOREVER"))
    return trace


def self_check():
    n = N_LEAF * N_SPINE * 2
    vs = sorted(set(d[0] for _, d in plan_vlink()))
    assert vs == list(range(n)), "vlink ids must span 0..%d, got %s" % (n - 1, vs)

    # one queue per virtual link, and one virtual link per queue
    q_of_v, v_of_q = {}, {}
    for _, (v, port, qid, _vsw) in plan_vlink():
        assert (port, qid) == vlink_placement(v), \
            "row for vlink %d disagrees with vlink_placement" % v
        q_of_v.setdefault(v, set()).add((port, qid))
        v_of_q.setdefault((port, qid), set()).add(v)
    for v, qs in q_of_v.items():
        assert len(qs) == 1, "vlink %d on %d queues: %s" % (v, len(qs), qs)
    for q, links in v_of_q.items():
        assert len(links) == 1, "queue dp%d/qid%d shared by vlinks %s" % (q[0], q[1], links)
    assert len(v_of_q) == n, "expected %d distinct (port, qid) pairs, got %d" % (n, len(v_of_q))
    assert len(set(p for p, _ in v_of_q)) == 2 * N_LEAF, "expected %d loop ports" % (2 * N_LEAF)
    for v in range(n):
        _p, qid = vlink_placement(v)
        assert 0 <= qid < 8, "qid %d outside the default 8-queues-per-port carving" % qid

    # every loop port has a role, and its DAC peer has one too
    roles = _role_map()
    for dp in LEAF_A + LEAF_B:
        assert roles[dp][0] == ROLE_LOOP, "dp%d must be ROLE_LOOP" % dp
        assert PEER[dp] in roles, "dp%d has no peer role" % dp
    assert roles[HOST_DP][0] == ROLE_HOST

    # uplinks leave cage 5, downlinks leave cage 6 — so hop 1 always ingresses on
    # a cage-6 port and hop 2 always ingresses on a cage-5 port
    for v in range(n):
        port, _q = vlink_placement(v)
        assert (port in LEAF_A) == (v < 8), "vlink %d on the wrong cage" % v

    # the two P4 gates must still mean what they say once aliasing is applied:
    # the source pass must look like hop 0, the transit pass must not look like
    # LAST_HOP, and the delivery pass MUST look exactly like LAST_HOP (otherwise
    # tbl_vlink and tbl_fail run on the delivery pass and black-hole it)
    for sp in range(N_SPINE):
        for d in range(N_LEAF):
            assert md_hop(0, sp, d) == 0, "source pass no longer reads as hop 0"
            assert md_hop(1, sp, d) != LAST_HOP, "transit pass reads as LAST_HOP"
            assert md_hop(1, sp, d) != 0, "transit pass reads as hop 0 (would re-spray)"
            assert md_hop(LAST_HOP, sp, d) == LAST_HOP, \
                ("delivery pass reads as md.hop=0x%04x, not LAST_HOP: tbl_vlink would "
                 "run on it.  With SHIM_MD_ALIAS this REQUIRES wire_vsw()==0."
                 % md_hop(LAST_HOP, sp, d))
    # tbl_final has no spray key, so its hop key must not depend on the spine
    for d in range(N_LEAF):
        for p in (0, 1, LAST_HOP):
            assert len(set(md_hop(p, sp, d) for sp in range(N_SPINE))) == 1, \
                "md.hop on pass %d depends on the spine — tbl_final cannot key that" % p

    # end to end: every (dst leaf, spine) path must deliver in exactly 3 passes
    paths = 0
    for ip in sorted(HOST_IPS):
        for s in range(N_SPINE):
            tr = simulate(ip, s)
            acts = [t[7] for t in tr]
            assert acts == ["Ingress.act_enter", "Ingress.act_transit",
                            "Ingress.act_deliver", "HOST"], \
                "path %s spine %d does not deliver: %s" % (ip, s, acts)
            assert tr[0][4] == vlink_up(0, s), "hop 0 took the wrong uplink"
            assert tr[1][4] == vlink_dn(s, HOST_IPS[ip]), "hop 1 took the wrong downlink"
            assert tr[2][1] in LEAF_A, "hop 2 must ingress on a cage-5 port"
            assert tr[3][1] == LEAF_HOST_DP[HOST_IPS[ip]], "delivered to the wrong host port"
            paths += 1

    assert SPRAY_MASK == N_SPINE - 1
    print("plan self-check OK: %d leaves x %d spines, %d virtual links on %d distinct "
          "TM queues over %d loop ports, %d end-to-end paths deliver in 3 passes"
          % (N_LEAF, N_SPINE, n, len(v_of_q), 2 * N_LEAF, paths))
    print("  SHIM_MD_ALIAS = %s%s" % (SHIM_MD_ALIAS,
          " (fabric_h.vsw_id forced to 0; looped-pass spray keys are hop<<8|spine)"
          if SHIM_MD_ALIAS else ""))


def print_plan():
    print("=== port roles (tbl_port_role), %d rows ===" % len(plan_roles()))
    for dp, role, leaf in plan_roles():
        tag = {ROLE_HOST: "HOST", ROLE_LOOP: "LOOP"}[role]
        fp = "15/1" if dp == HOST_DP else ("5/%d" % LEAF_A.index(dp) if dp in LEAF_A
                                           else "6/%d" % LEAF_B.index(dp))
        print("  dp%-4d %-5s role=%s src_leaf=%d" % (dp, fp, tag, leaf))

    print("=== destination leaf (tbl_dst_leaf), %d rows ===" % len(plan_dst_leaf()))
    for ip, leaf, base in plan_dst_leaf():
        print("  %-10s -> leaf %d, path_base %2d, delivered on dp%d"
              % (ip, leaf, base, LEAF_HOST_DP[leaf]))

    print("=== spray mode (tbl_spray_mode), default '%s' ===" % DEFAULT_SPRAY)
    for key, act, mask in plan_spray(DEFAULT_SPRAY):
        print("  role=%d hop=%d -> %s(mask=%d)" % (key[0], key[1], act, mask))

    print("=== virtual links: id -> real queue ===")
    for v in range(N_LEAF * N_SPINE * 2):
        port, qid = vlink_placement(v)
        print("  vlink %2d  %-12s  dp%-4d qid=%d   (peer dp%d)"
              % (v, vlink_name(v), port, qid, PEER[port]))

    rows = plan_vlink()
    print("=== tbl_vlink, %d rows (keys are MAU-visible, see SHIM_MD_ALIAS) ===" % len(rows))
    for key, data in rows:
        print("  role=%d hop=0x%04x src_leaf=%d dst_leaf=%d spray=0x%04x"
              "  ->  vlink=%2d dp%-4d qid=%d next_vsw=%d"
              % (key[0], key[1], key[2], key[3], key[4],
                 data[0], data[1], data[2], data[3]))

    print("=== tbl_final, %d rows ===" % len(plan_final()))
    for key, (act, args) in plan_final():
        print("  role=%d hop=0x%04x dst_leaf=%d -> %s %s"
              % (key[0], key[1], key[2], act, args))

    print("=== queue shapers (OPTIONAL, not installed by `up`) ===")
    for v, port, qid, pipe, pg_id, pg_queue, gbps in plan_shapers():
        print("  vlink %2d -> dp%-4d qid=%d  pipe=%d pg_id=%d pg_queue=%-2d  max_rate=%d Gb/s"
              % (v, port, qid, pipe, pg_id, pg_queue, gbps))

    print("=== mirror sessions ===")
    print("  none — dp65/33-1 is gone and there is no Agilio collector on this")
    print("  testbed today.  install_mirrors() is a documented no-op (TODO step 6).")

    print("=== example forwarding traces ===")
    for ip in sorted(HOST_IPS):
        for s in range(N_SPINE):
            tr = simulate(ip, s)
            print("  %s spine %d:" % (ip, s))
            for (i, dp, role, hop, v, eport, qid, act) in tr:
                if act == "HOST":
                    print("      pass %d: delivered to host on dp%d" % (i, dp))
                else:
                    print("      pass %d: in dp%-4d role=%s hop=%s vlink=%s -> out dp%s qid=%s  %s"
                          % (i, dp, role, hop, v, eport, qid, act))


# ===========================================================================
# bfrt side.  Imported lazily so --dry-run works without the SDE.
# ===========================================================================

def connect():
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(GRPC_ADDR, client_id=CLIENT_ID, device_id=DEV)
    iface.bind_pipeline_config(PROG)          # client_id 0 ONLY
    bfrt = iface.bfrt_info_get(PROG)
    # P4 tables/registers are symmetric: write with pipe_id 0xffff.  Targeting
    # pipe 0 on a symmetric table returns INVALID_ARGUMENT on this SDE.
    tgt = gc.Target(device_id=DEV, pipe_id=0xffff)
    return gc, iface, bfrt, tgt


def _upsert(table, tgt, key, data):
    try:
        table.entry_add(tgt, [key], [data])
    except Exception:
        table.entry_mod(tgt, [key], [data])


def _clear(t, tgt, name):
    """Delete every entry.  Needed because the KEY SHAPE of tbl_vlink/tbl_final
    changes with SHIM_MD_ALIAS and with the fabric shape, so plain upserts would
    leave stale unreachable rows behind that pollute the counters."""
    n = len(list(t.entry_get(tgt, flags={"from_hw": False})))
    if n:
        t.entry_del(tgt)
        left = len(list(t.entry_get(tgt, flags={"from_hw": False})))
        if left:
            raise RuntimeError("%s not empty after clear: %d remain" % (name, left))
    return n


def _clear_except(t, tgt, rows, gc):
    """Delete entries whose key is not in `rows`.  Used instead of a blanket
    clear-then-install so that a failed install can never leave the table empty:
    the planned rows are written first, and only then is the leftover swept."""
    want = set((k[0], k[1], k[2], k[3], k[4]) for k, _ in rows)
    n = 0
    for _data, key in list(t.entry_get(tgt, flags={"from_hw": False})):
        kd = key.to_dict()
        cur = (kd["md.role"]["value"], kd["md.hop"]["value"], kd["md.src_leaf"]["value"],
               kd["md.dst_leaf"]["value"], kd["md.spray_idx"]["value"])
        if cur not in want:
            t.entry_del(tgt, [t.make_key([
                gc.KeyTuple("md.role", cur[0]), gc.KeyTuple("md.hop", cur[1]),
                gc.KeyTuple("md.src_leaf", cur[2]), gc.KeyTuple("md.dst_leaf", cur[3]),
                gc.KeyTuple("md.spray_idx", cur[4])])])
            n += 1
    return n


def _action_fields(bfrt_table, action):
    """Names of the action-data fields of `action`, from the LIVE bfrt info.

    Use data_field_name_list_get(action).  `info.data_dict_allname` exists but is
    NOT keyed by action name — indexing it by one raises KeyError, which a bare
    try/except turns into a silent "no fields", i.e. a feature that never fires."""
    try:
        return set(bfrt_table.info.data_field_name_list_get(action))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# ports
# ---------------------------------------------------------------------------

REQUIRED_PORTS = [(HOST_DP, "BF_SPEED_25G")] + \
                 [(dp, "BF_SPEED_25G") for dp in LEAF_A + LEAF_B]


def bring_up_ports(gc, bfrt, tgt):
    """Idempotent, and deliberately conservative.

    Every port this program needs is a REAL cabled port that is already added and
    UP (dp9 to Vision, and the eight cage-5/cage-6 DAC lanes).  Re-adding a port
    bounces the link, so an existing port is only reported, never reconfigured;
    a MISSING port is added at 25G RS-FEC.  If a required port is down we say so
    loudly rather than silently programming a fabric that cannot forward."""
    port = bfrt.table_get("$PORT")
    have = {}
    for data, key in port.entry_get(tgt, flags={"from_hw": False}):
        kd, dd = key.to_dict(), data.to_dict()
        have[kd["$DEV_PORT"]["value"]] = dd
    down = []
    for dp, speed in REQUIRED_PORTS:
        if dp in have:
            dd = have[dp]
            up = dd.get("$PORT_UP", False)
            print("  dp%-4d present: %s %s enable=%s up=%s"
                  % (dp, dd.get("$SPEED"), dd.get("$FEC"),
                     dd.get("$PORT_ENABLE"), up))
            if not dd.get("$PORT_ENABLE", False):
                port.entry_mod(tgt,
                               [port.make_key([gc.KeyTuple("$DEV_PORT", dp)])],
                               [port.make_data([gc.DataTuple("$PORT_ENABLE",
                                                             bool_val=True)])])
                print("    -> enabled")
            if not up:
                down.append(dp)
        else:
            key = port.make_key([gc.KeyTuple("$DEV_PORT", dp)])
            data = port.make_data([
                gc.DataTuple("$SPEED", str_val=speed),
                gc.DataTuple("$FEC", str_val="BF_FEC_TYP_REED_SOLOMON"),
                gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_DEFAULT"),
                gc.DataTuple("$LOOPBACK_MODE", str_val="BF_LPBK_NONE"),
                gc.DataTuple("$PORT_ENABLE", bool_val=True)])
            port.entry_add(tgt, [key], [data])
            print("  dp%-4d ADDED %s RS-FEC, enabled" % (dp, speed))
    if down:
        print("  WARNING: required ports DOWN: %s — the fabric will black-hole"
              % ", ".join("dp%d" % d for d in down))
    return down


def show_ports(bfrt, tgt):
    port = bfrt.table_get("$PORT")
    stat = bfrt.table_get("$PORT_STAT")
    want = set(dp for dp, _ in REQUIRED_PORTS)
    st = {}
    for data, key in stat.entry_get(tgt, flags={"from_hw": True}):
        dp = key.to_dict()["$DEV_PORT"]["value"]
        if dp in want:
            st[dp] = data.to_dict()
    print("  %-6s %-8s %-6s %-6s %14s %14s" % ("dp", "speed", "enab", "up",
                                               "frames_rx", "frames_tx"))
    for data, key in port.entry_get(tgt, flags={"from_hw": False}):
        kd, dd = key.to_dict(), data.to_dict()
        dp = kd["$DEV_PORT"]["value"]
        if dp not in want:
            continue
        s = st.get(dp, {})
        print("  dp%-4d %-8s %-6s %-6s %14s %14s"
              % (dp, dd.get("$SPEED"), dd.get("$PORT_ENABLE"), dd.get("$PORT_UP"),
                 s.get("$FramesReceivedOK"), s.get("$FramesTransmittedOK")))


# ---------------------------------------------------------------------------
# P4 tables
# ---------------------------------------------------------------------------

def install_roles(gc, bfrt, tgt):
    t = bfrt.table_get("pipe.Ingress.tbl_port_role")
    for dp, role, leaf in plan_roles():
        _upsert(t, tgt,
                t.make_key([gc.KeyTuple("ig_intr_md.ingress_port", dp)]),
                t.make_data([gc.DataTuple("role", role),
                             gc.DataTuple("src_leaf", leaf)], "Ingress.set_role"))
    print("  tbl_port_role: %d rows" % len(plan_roles()))


def install_dst_leaf(gc, bfrt, tgt):
    import socket
    import struct
    t = bfrt.table_get("pipe.Ingress.tbl_dst_leaf")
    for ip, leaf, base in plan_dst_leaf():
        v = struct.unpack("!I", socket.inet_aton(ip))[0]
        _upsert(t, tgt,
                t.make_key([gc.KeyTuple("hdr.ipv4.dst_addr", v)]),
                t.make_data([gc.DataTuple("dst_leaf", leaf),
                             gc.DataTuple("path_base", base)], "Ingress.set_dst"))
    print("  tbl_dst_leaf: %d rows" % len(plan_dst_leaf()))


# The loaded step-4 binary's to_loop takes 4 action arguments; the step-5+ program
# adds a 5th, `path_id`.  Which one is live cannot be decided from the served bfrt
# schema alone: bf_switchd serves the schema from the JSON path in its conf file,
# so replacing that file under a RUNNING switchd (which happened on 2026-08-26 at
# 22:27, while the chip kept executing the 21:22 binary) makes the schema describe
# a program the chip is not running.  Writing the wrong arity then fails every row
# and leaves tbl_vlink EMPTY, i.e. a total black hole.  So: propose variants in
# order and keep the first one the switch actually accepts.
#   None  = auto-detect (schema hint first, then fall back)
#   True  = always send path_id;  False = never send it
TO_LOOP_PATH_ID = None


def _to_loop_variants(gc, t, v, port, qid, vsw, dst_leaf, spray, zero_ctr):
    """Candidate action-data lists, most-preferred first."""
    base = [gc.DataTuple("vlink_id", v),
            gc.DataTuple("loop_port", port),
            gc.DataTuple("qid", qid),
            gc.DataTuple("next_vsw", vsw)]
    pid = [gc.DataTuple("path_id", dst_leaf * N_SPINE + spray)]
    ctr = [gc.DataTuple("$COUNTER_SPEC_PKTS", 0),
           gc.DataTuple("$COUNTER_SPEC_BYTES", 0)] if zero_ctr else []

    if TO_LOOP_PATH_ID is True:
        order = [base + pid + ctr, base + pid]
    elif TO_LOOP_PATH_ID is False:
        order = [base + ctr, base]
    else:
        fields = _action_fields(t, "Ingress.to_loop")
        want_pid = bool(fields and "path_id" in fields)
        first = (base + pid) if want_pid else base
        second = base if want_pid else (base + pid)
        order = [first + ctr, first, second + ctr, second]
    return [(a, t.make_data(a, "Ingress.to_loop")) for a in order]


def install_vlinks(gc, bfrt, tgt, zero_ctr=True):
    t = bfrt.table_get("pipe.Ingress.tbl_vlink")
    rows = plan_vlink()
    chosen = None
    installed = 0
    stale = None
    for (role, hop, src, dst, spray), (v, port, qid, vsw) in rows:
        key = t.make_key([gc.KeyTuple("md.role", role),
                          gc.KeyTuple("md.hop", hop),
                          gc.KeyTuple("md.src_leaf", src),
                          gc.KeyTuple("md.dst_leaf", dst),
                          gc.KeyTuple("md.spray_idx", spray)])
        variants = _to_loop_variants(gc, t, v, port, qid, vsw, dst, spray, zero_ctr)
        if chosen is not None:
            variants = [variants[chosen]]
        last = None
        for i, (args, data) in enumerate(variants):
            try:
                _upsert(t, tgt, key, data)
            except Exception as e:
                last = e
                continue
            if chosen is None:
                chosen = i
                names = [a.name for a in args]
                # Only clear stale rows AFTER a write shape is known to work, so a
                # wrong guess can never leave the table empty.
                stale = _clear_except(t, tgt, rows, gc)
                print("  tbl_vlink: to_loop written as %s" % ", ".join(names))
            installed += 1
            break
        else:
            raise RuntimeError("tbl_vlink row %s rejected in every form: %s"
                               % ((role, hop, src, dst, spray), last))
    print("  tbl_vlink: %d rows installed, %s stale rows removed%s"
          % (installed, stale if stale is not None else 0,
             " (counters zeroed)" if zero_ctr else ""))


# Action arguments that exist in the step-5+ program but not in the step-4 build,
# with the value to use when they ARE present.  Same hazard as to_loop's path_id:
# the served schema may describe a program the chip is not running, so every one of
# these is proposed and then dropped if the switch rejects it.
#   act_enter.epoch — the measurement epoch id; 0 until an epoch controller owns it.
OPTIONAL_ACTION_ARGS = {"Ingress.act_enter": {"epoch": 0}}


def install_final(gc, bfrt, tgt):
    t = bfrt.table_get("pipe.Ingress.tbl_final")
    rows = plan_final()
    installed, stale, noted = 0, None, set()
    for (role, hop, dst), (act, args) in rows:
        key = t.make_key([gc.KeyTuple("md.role", role),
                          gc.KeyTuple("md.hop", hop),
                          gc.KeyTuple("md.dst_leaf", dst)])
        base = [gc.DataTuple(k, v) for k, v in sorted(args.items())]
        extra = [gc.DataTuple(k, v)
                 for k, v in sorted(OPTIONAL_ACTION_ARGS.get(act, {}).items())]
        fields = _action_fields(t, act)
        want = bool(extra) and bool(fields) and all(
            e.name in fields for e in extra)
        order = ([base + extra, base] if want else
                 ([base, base + extra] if extra else [base]))
        last = None
        for arglist in order:
            try:
                _upsert(t, tgt, key, t.make_data(arglist, act))
            except Exception as e:
                last = e
                continue
            if act not in noted:
                noted.add(act)
                print("  tbl_final: %s written as %s"
                      % (act.split(".")[-1], ", ".join(a.name for a in arglist)))
            installed += 1
            break
        else:
            raise RuntimeError("tbl_final row %s/%s rejected in every form: %s"
                               % ((role, hop, dst), act, last))
    # sweep only after every planned row is in place — never clear first
    want_keys = set((k[0], k[1], k[2]) for k, _ in rows)
    stale = 0
    for _data, key in list(t.entry_get(tgt, flags={"from_hw": False})):
        kd = key.to_dict()
        cur = (kd["md.role"]["value"], kd["md.hop"]["value"], kd["md.dst_leaf"]["value"])
        if cur not in want_keys:
            t.entry_del(tgt, [t.make_key([gc.KeyTuple("md.role", cur[0]),
                                          gc.KeyTuple("md.hop", cur[1]),
                                          gc.KeyTuple("md.dst_leaf", cur[2])])])
            stale += 1
    print("  tbl_final: %d rows installed, %d stale rows removed" % (installed, stale))


def set_spray(gc, bfrt, tgt, mode):
    if mode not in SPRAY_ACTIONS:
        raise SystemExit("spray mode must be one of %s" % sorted(SPRAY_ACTIONS))
    t = bfrt.table_get("pipe.Ingress.tbl_spray_mode")
    for (role, hop), act, mask in plan_spray(mode):
        _upsert(t, tgt,
                t.make_key([gc.KeyTuple("md.role", role), gc.KeyTuple("md.hop", hop)]),
                t.make_data([gc.DataTuple("mask", mask)], act))
    print("  spray mode = %s (mask=%d, %d spines)" % (mode, SPRAY_MASK, N_SPINE))
    if mode == "random":
        print("  NOTE: Random<> has no control-plane seed on Tofino 1 — this run is "
              "characterisable but NOT replayable.  The chosen index is written into "
              "fabric_h.spray on the wire so a capture still reconstructs every path.")
    if mode == "rr":
        print("  NOTE: reg_spray_rr is PER PIPE.  All host traffic enters on dp9 "
              "(pipe 0) today, so the counter is effectively single-copy; add a "
              "host in another pipe and the round-robin becomes per-pipe.")
    if mode == "sel":
        print("  NOTE: 'sel' also needs ActionProfile members and a selector group "
              "installed in pipe.Ingress.spray_prof / spray_sel_impl — not done here.")


def seed_registers(gc, bfrt, tgt):
    """Seed every slot so nothing depends on an in-SALU `v == 0` sentinel."""
    r = bfrt.table_get("pipe.Ingress.reg_spray_rr")
    for i in range(64):
        r.entry_add(tgt,
                    [r.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])],
                    [r.make_data([gc.DataTuple("Ingress.reg_spray_rr.f1", 0)])])
    print("  reg_spray_rr: 64 slots seeded to 0")


def install_mirrors(gc, bfrt, tgt):
    """NO-OP by design.

    TODO(step 6): there is no mirror collector on this testbed.  dp65 (33/1) has
    no module and the Agilio leg is gone; 33/2 and 33/3 belong to another rig and
    must not be used.  When a collector is cabled, restore the $mirror.cfg block
    (remember: $mirror.cfg is ACTION-BASED — make_data without the "$normal"
    action name fails INVALID_ARGUMENT)."""
    print("  mirror sessions: none (no collector on this testbed) — TODO step 6")


# ---------------------------------------------------------------------------
# failure injection
# ---------------------------------------------------------------------------

def clear_fail(bfrt, tgt):
    """Delete every tbl_fail entry.

    LANDMINE: on this bfrt version range match keys returned by entry_get do NOT
    round-trip into entry_del, and there is no table.clear().  entry_del(target)
    with no key list bulk-deletes, which does work.  Always re-read afterwards."""
    t = bfrt.table_get("pipe.Ingress.tbl_fail")
    before = len(list(t.entry_get(tgt)))
    if before:
        t.entry_del(tgt)
    remaining = len(list(t.entry_get(tgt)))
    if remaining:
        raise RuntimeError("tbl_fail not empty after clear: %d entries remain" % remaining)
    print("  tbl_fail: cleared %d entries" % before)
    return before


def set_fail(gc, bfrt, tgt, vlink, pct, mode="drop"):
    """Install one failure row for one virtual link.

    Probability = (high - low + 1)/65536, retunable at runtime by rewriting the
    bounds.  vlink_id encodes DIRECTION, so installing the uplink id only gives a
    perfectly asymmetric link for free."""
    t = bfrt.table_get("pipe.Ingress.tbl_fail")
    action = {"drop": "Ingress.inj_drop", "corrupt": "Ingress.inj_corrupt"}[mode]
    if pct <= 0:
        print("  vlink %d: no failure row installed (pct=%s)" % (vlink, pct))
        return
    hi = int(round(65536 * pct / 100.0)) - 1
    hi = max(0, min(65535, hi))
    _upsert(t, tgt,
            t.make_key([gc.KeyTuple("md.vlink_id", vlink),
                        gc.KeyTuple("md.rnd_fail", low=0, high=hi),
                        gc.KeyTuple("$MATCH_PRIORITY", 1)]),
            t.make_data([], action))
    print("  vlink %2d (%s): %s for rnd_fail in [0,%d] = %.3f%%"
          % (vlink, vlink_name(vlink), mode, hi, (hi + 1) / 65536.0 * 100))


def set_shaper(gc, bfrt, tgt, vlink, gbps):
    """A per-queue max-rate shaper gives a virtual link a finite capacity.

    THE SHAPER IS INERT WITHOUT THE SECOND CALL: sched_shaping sets the rate,
    sched_cfg's max_rate_enable arms it.  TM tables are PIPE-SPECIFIC: the target
    must be the port's own pipe, which for the loop ports is pipe 1, NOT 0."""
    import bfrt_grpc.client as gc_mod
    port, qid = vlink_placement(vlink)
    pipe, pg_id, pg_queue = tm_coords(port, qid)
    tgt_tm = gc_mod.Target(device_id=DEV, pipe_id=pipe)
    q_shape = bfrt.table_get("tf1.tm.queue.sched_shaping")
    q_cfg = bfrt.table_get("tf1.tm.queue.sched_cfg")
    q_shape.entry_mod(
        tgt_tm,
        [q_shape.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pg_queue)])],
        [q_shape.make_data([gc.DataTuple("unit", str_val="BPS"),
                            gc.DataTuple("provisioning", str_val="UPPER"),
                            gc.DataTuple("max_rate", val=gbps * 1000 * 1000),  # kb/s
                            gc.DataTuple("max_burst_size", val=16384)])])
    q_cfg.entry_mod(
        tgt_tm,
        [q_cfg.make_key([gc.KeyTuple("pg_id", pg_id), gc.KeyTuple("pg_queue", pg_queue)])],
        [q_cfg.make_data([gc.DataTuple("scheduling_enable", bool_val=True),
                          gc.DataTuple("max_rate_enable", bool_val=True)])])
    print("  vlink %2d (%s) dp%d qid%d, pipe=%d pg_id=%d pg_queue=%d: max_rate %d Gb/s"
          % (vlink, vlink_name(vlink), port, qid, pipe, pg_id, pg_queue, gbps))


# ---------------------------------------------------------------------------
# counters
# ---------------------------------------------------------------------------

def _rows(t, tgt):
    """entry_get yields (Data, Key) — NOT (Key, Data).  Getting this backwards is
    a silent wrong-field read, so it is asserted here once."""
    out = []
    for data, key in t.entry_get(tgt, flags={"from_hw": True}):
        out.append((key.to_dict(), data.to_dict()))
    return out


def _val(d, name):
    v = d.get(name)
    if isinstance(v, dict):
        return v.get("value", v)
    return v


def collect_counters(bfrt, tgt):
    res = {"vlink_rows": [], "vlink_totals": {}, "fail_rows": [], "fail_totals": {}}
    t = bfrt.table_get("pipe.Ingress.tbl_vlink")
    t.operations_execute(tgt, "SyncCounters")
    for k, d in _rows(t, tgt):
        if d.get("action_name", "").endswith("to_loop"):
            v = _val(d, "vlink_id")
        else:
            v = None
        row = {"role": _val(k, "md.role"), "hop": _val(k, "md.hop"),
               "src_leaf": _val(k, "md.src_leaf"), "dst_leaf": _val(k, "md.dst_leaf"),
               "spray": _val(k, "md.spray_idx"), "vlink": v,
               "pkts": _val(d, "$COUNTER_SPEC_PKTS"),
               "bytes": _val(d, "$COUNTER_SPEC_BYTES")}
        res["vlink_rows"].append(row)
        if v is not None and row["pkts"]:
            tot = res["vlink_totals"].setdefault(v, {"pkts": 0, "bytes": 0})
            tot["pkts"] += row["pkts"]
            tot["bytes"] += row["bytes"]

    # tbl_vlink's const default action is black_hole, and it counts too: that is
    # the exact ground truth for §7.5 black-holed packets.  It is the DEFAULT
    # ENTRY, invisible to a plain entry_get.
    try:
        for data, _key in t.default_entry_get(tgt, flags={"from_hw": True}):
            dd = data.to_dict()
            res["vlink_default"] = {"action": dd.get("action_name"),
                                    "pkts": _val(dd, "$COUNTER_SPEC_PKTS"),
                                    "bytes": _val(dd, "$COUNTER_SPEC_BYTES")}
    except Exception as e:
        res["vlink_default"] = {"error": str(e)}

    t = bfrt.table_get("pipe.Ingress.tbl_fail")
    t.operations_execute(tgt, "SyncCounters")
    for k, d in _rows(t, tgt):
        row = {"vlink": _val(k, "md.vlink_id"),
               "rnd_low": _val(k, "md.rnd_fail") if "md.rnd_fail" in k else None,
               "action": d.get("action_name"),
               "pkts": _val(d, "$COUNTER_SPEC_PKTS"),
               "bytes": _val(d, "$COUNTER_SPEC_BYTES")}
        rk = k.get("md.rnd_fail")
        if isinstance(rk, dict):
            row["rnd_low"], row["rnd_high"] = rk.get("low"), rk.get("high")
        res["fail_rows"].append(row)
        if row["vlink"] is not None:
            tot = res["fail_totals"].setdefault(row["vlink"], {})
            a = (row["action"] or "").split(".")[-1]
            tot[a] = tot.get(a, 0) + (row["pkts"] or 0)
    # tbl_fail's const default action (inj_none) also counts.  It is the table's
    # DEFAULT ENTRY, which a plain entry_get does not return, so read it
    # separately — without it "forwarded" ground truth is invisible.
    try:
        for data, _key in t.default_entry_get(tgt, flags={"from_hw": True}):
            dd = data.to_dict()
            res["fail_default"] = {"action": dd.get("action_name"),
                                   "pkts": _val(dd, "$COUNTER_SPEC_PKTS"),
                                   "bytes": _val(dd, "$COUNTER_SPEC_BYTES")}
    except Exception as e:
        res["fail_default"] = {"error": str(e)}
    return res


def show_counters(bfrt, tgt, as_json=False):
    res = collect_counters(bfrt, tgt)
    if as_json:
        print(json.dumps(res, indent=1, sort_keys=True))
        return
    print("  --- tbl_vlink, per virtual link (rows summed over src_leaf/dst_leaf) ---")
    if not res["vlink_totals"]:
        print("      (all zero)")
    for v in sorted(res["vlink_totals"]):
        t = res["vlink_totals"][v]
        port, qid = vlink_placement(v)
        print("      vlink %2d  %-12s dp%-4d qid=%d   pkts=%-10d bytes=%d"
              % (v, vlink_name(v), port, qid, t["pkts"], t["bytes"]))
    print("  --- tbl_vlink, non-zero rows ---")
    for r in res["vlink_rows"]:
        if r["pkts"]:
            print("      role=%s hop=%s src=%s dst=%s spray=%s vlink=%s pkts=%s bytes=%s"
                  % (r["role"], r["hop"], r["src_leaf"], r["dst_leaf"], r["spray"],
                     r["vlink"], r["pkts"], r["bytes"]))
    vd = res.get("vlink_default")
    if vd:
        print("      default entry (%s, no virtual link resolved): pkts=%s bytes=%s%s"
              % ((vd.get("action") or "").split(".")[-1], vd.get("pkts"),
                 vd.get("bytes"), (" err=" + vd["error"]) if "error" in vd else ""))
    print("  --- tbl_fail ---")
    for r in res["fail_rows"]:
        print("      vlink=%-3s rnd=[%s,%s] %-18s pkts=%s bytes=%s"
              % (r["vlink"], r.get("rnd_low"), r.get("rnd_high"),
                 (r["action"] or "").split(".")[-1], r["pkts"], r["bytes"]))
    fd = res.get("fail_default")
    if fd:
        print("      default entry (%s, everything NOT failed): pkts=%s bytes=%s%s"
              % ((fd.get("action") or "").split(".")[-1], fd.get("pkts"),
                 fd.get("bytes"), (" err=" + fd["error"]) if "error" in fd else ""))


def zero_default_counters(gc, bfrt, tgt):
    """Reset the DEFAULT-ENTRY counters of tbl_vlink (black_hole) and tbl_fail
    (inj_none).  These are cumulative since program load and are NOT touched by
    re-installing rows, so without this a trial's "black-holed" and "forwarded"
    ground truth is a running total rather than a per-trial number.  Both tables
    have a `const default_action`, so only the counter spec is written."""
    for name, act in (("pipe.Ingress.tbl_vlink", "Ingress.black_hole"),
                      ("pipe.Ingress.tbl_fail", "Ingress.inj_none")):
        t = bfrt.table_get(name)
        try:
            t.default_entry_set(tgt, t.make_data(
                [gc.DataTuple("$COUNTER_SPEC_PKTS", 0),
                 gc.DataTuple("$COUNTER_SPEC_BYTES", 0)], act))
            print("  %s default-entry counter zeroed" % name.split(".")[-1])
        except Exception as e:
            print("  %s default-entry counter NOT zeroed (%s) — it is cumulative "
                  "since program load, so diff it across a trial instead"
                  % (name.split(".")[-1], type(e).__name__))


def blackhole(gc, bfrt, tgt, src_leaf, dst_leaf, spray):
    """Delete the tbl_vlink row.  The counted default action then drops, so the
    number of black-holed packets is exact."""
    t = bfrt.table_get("pipe.Ingress.tbl_vlink")
    t.entry_del(tgt, [t.make_key([gc.KeyTuple("md.role", ROLE_HOST),
                                  gc.KeyTuple("md.hop", 0),
                                  gc.KeyTuple("md.src_leaf", src_leaf),
                                  gc.KeyTuple("md.dst_leaf", dst_leaf),
                                  gc.KeyTuple("md.spray_idx", spray)])])
    print("  black hole: leaf %d -> leaf %d via spine %d removed (uplink vlink %d)"
          % (src_leaf, dst_leaf, spray, vlink_up(src_leaf, spray)))


def main():
    argv = [a for a in sys.argv[1:]]
    as_json = "--json" in argv
    args = [a for a in argv if not a.startswith("--")]
    if "--dry-run" in argv or not args:
        self_check()
        print_plan()
        print("\n[--dry-run] no bfrt calls made.")
        return

    cmd = args[0]
    gc, iface, bfrt, tgt = connect()

    if cmd == "up":
        print("[ports]")
        bring_up_ports(gc, bfrt, tgt)
        print("[p4 tables]")
        install_roles(gc, bfrt, tgt)
        install_dst_leaf(gc, bfrt, tgt)
        install_vlinks(gc, bfrt, tgt)
        install_final(gc, bfrt, tgt)
        set_spray(gc, bfrt, tgt, DEFAULT_SPRAY)
        seed_registers(gc, bfrt, tgt)
        install_mirrors(gc, bfrt, tgt)
        clear_fail(bfrt, tgt)
        print("[done] %d leaves x %d spines up; shapers NOT installed (use `shape`)"
              % (N_LEAF, N_SPINE))
    elif cmd == "spray":
        set_spray(gc, bfrt, tgt, args[1])
    elif cmd == "fail":
        set_fail(gc, bfrt, tgt, int(args[1]), float(args[2]),
                 args[3] if len(args) > 3 else "drop")
    elif cmd == "fail-clear":
        clear_fail(bfrt, tgt)
    elif cmd == "shape":
        set_shaper(gc, bfrt, tgt, int(args[1]), int(args[2]))
    elif cmd == "blackhole":
        blackhole(gc, bfrt, tgt, int(args[1]), int(args[2]), int(args[3]))
    elif cmd == "counters":
        show_counters(bfrt, tgt, as_json)
    elif cmd == "zero":
        install_vlinks(gc, bfrt, tgt, zero_ctr=True)
        clear_fail(bfrt, tgt)
        zero_default_counters(gc, bfrt, tgt)
    elif cmd == "ports":
        show_ports(bfrt, tgt)
    else:
        raise SystemExit("unknown command: %s" % cmd)


if __name__ == "__main__":
    main()
