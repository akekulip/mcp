#!/usr/bin/env python3
"""setup_skeleton.py — bfrt control plane for mcp_fabric (steps 2-4).

Programs the 2 leaves x 4 spines virtual fabric described in
docs/P4-DESIGN-SPACE.md: port roles, destination-leaf lookup, 16 virtual links over
16 real TM queues on two loop ports, the spray-mode selection, and the per-virtual-link
failure injection.  Modelled on
  /home/philip/Projects/dnp3-research/research/synthesis/validation/tofino/sdnp_setup.py
  /home/philip/Projects/GridCloak/p4/gc_switch_setup_c.py

NOTHING HERE HAS BEEN RUN AGAINST A SWITCH OR AGAINST THE tofino-model.  The Tofino at
decps@10.10.54.81 was down when this was written.  The entry PLAN (--dry-run) is pure
Python and is self-checked; every bfrt call is unverified until S-UP.

Usage (on the switch, or against a model-mode bf_switchd, with the SDE env set):
    python3 setup_skeleton.py --dry-run            # print the full entry plan, no writes
    python3 setup_skeleton.py up                   # ports + roles + fabric + spray + seeds
    python3 setup_skeleton.py spray hash|random|rr|sel
    python3 setup_skeleton.py fail <vlink> <pct> [drop|corrupt]
    python3 setup_skeleton.py fail-clear
    python3 setup_skeleton.py shape <vlink> <gbps>
    python3 setup_skeleton.py blackhole <src_leaf> <dst_leaf> <spray>   # delete a vlink row
    python3 setup_skeleton.py counters
"""
import sys

DEV = 0
PROG = "mcp_fabric"
GRPC_ADDR = "localhost:50052"

# Only client_id 0 may call bind_pipeline_config.  The epoch controller must use a
# DIFFERENT client_id and must not bind (§5.7).
CLIENT_ID = 0

# ---------------------------------------------------------------------------
# topology — every one of these must be re-verified against $PORT at S-UP.
# docs/P4-DESIGN-SPACE.md §2.2 records a DIRECT CONFLICT about which host is on dp9
# (the connectivity map says Vision, WORKING_NOTES says Hulk).  Resolve before use.
# ---------------------------------------------------------------------------
HOST0_DP = 9    # 25 G front panel 15/1 — leaf 0's host
HOST1_DP = 65   # 10 G front panel 33/1 — leaf 1's host AND the mirror collector (Agilio)
LOOP_UP_DP = 68  # internal pipe-0 recirculation port, no cable  -> carries the 8 uplinks
LOOP_DN_DP = 8   # front panel 15/0 in BF_LPBK_MAC_NEAR          -> carries the 8 downlinks

# P4 constants — keep in sync with mcp_fabric.p4
ROLE_OTHER, ROLE_HOST, ROLE_LOOP, ROLE_NIC = 0, 1, 2, 3
LAST_HOP = 2

N_LEAF = 2
N_SPINE = 4
SPRAY_MASK = N_SPINE - 1          # action data for the spray-mode actions

# Virtual-switch ids carried in fabric_h.vsw_id: leaves 0..N_LEAF-1, spines 16+s.
VSW_SPINE_BASE = 16

# Host IP -> leaf.  The traffic generator's contract.
HOST_IPS = {
    "10.0.1.1": 0,
    "10.0.1.2": 1,
}

# Default virtual-link capacity.  §3: use BPS at realistic rates, NEVER PPS — a PPS
# shaper is a cap, not a pacer, and GridCloak measured it starving a queue entirely
# below ~1200 pps.  Never shape below about 1 Gb/s without re-measuring.
DEFAULT_VLINK_GBPS = 10

MIRROR_SESSIONS = {          # §5.4
    1: 128,                  # high-attention sample, headers + payload prefix
    2: 64,                   # high-attention sample, headers only
    3: 64,                   # fault evidence (every injected drop/corrupt)
    4: 16384,                # spare / full capture
}

SPRAY_ACTIONS = {
    "random": "Ingress.spray_from_random",   # B1 — per-packet, NOT replayable
    "hash":   "Ingress.spray_from_hash",     # B2 — default, replayable
    "rr":     "Ingress.spray_from_rr",       # B4 — perfectly balanced, replayable
    "sel":    "Ingress.spray_from_sel",      # B3 — ActionSelector, group-managed
}
DEFAULT_SPRAY = "hash"


# ===========================================================================
# The entry plan.  Pure functions, no bfrt — so it can be reviewed and diffed
# offline while the switch is down.
# ===========================================================================

def vlink_up(leaf, spine):
    """Uplink leaf->spine.  ids 0..7."""
    return leaf * N_SPINE + spine


def vlink_dn(spine, leaf):
    """Downlink spine->leaf.  ids 8..15."""
    return 8 + spine * N_LEAF + leaf


def vlink_placement(vlink_id):
    """§3 option M2: bit 3 picks the loop port, bits [2:0] are the real TM qid."""
    port = LOOP_DN_DP if (vlink_id & 0x8) else LOOP_UP_DP
    return port, vlink_id & 0x7


def plan_roles():
    return [
        (HOST0_DP,   ROLE_HOST, 0),
        (HOST1_DP,   ROLE_HOST, 1),
        (LOOP_UP_DP, ROLE_LOOP, 0),
        (LOOP_DN_DP, ROLE_LOOP, 0),
    ]


def plan_dst_leaf():
    # path_base = leaf << 2, precomputed here so the data plane never shifts (Class 5).
    return [(ip, leaf, leaf << 2) for ip, leaf in sorted(HOST_IPS.items())]


def plan_vlink():
    """(role, hop, src_leaf, dst_leaf, spray) -> (vlink_id, loop_port, qid, next_vsw)."""
    rows = []
    # hop 0 — source leaf picks a spine and takes the uplink.
    for leaf in range(N_LEAF):
        for dst in range(N_LEAF):
            for spine in range(N_SPINE):
                v = vlink_up(leaf, spine)
                port, qid = vlink_placement(v)
                rows.append(((ROLE_HOST, 0, leaf, dst, spine),
                             (v, port, qid, VSW_SPINE_BASE + spine)))
    # hop 1 — the spine takes the downlink toward the destination leaf.  src_leaf is 0
    # here because a loop port has no leaf of its own; the spine is identified by the
    # spray index the parser lifted out of the shim.
    for dst in range(N_LEAF):
        for spine in range(N_SPINE):
            v = vlink_dn(spine, dst)
            port, qid = vlink_placement(v)
            rows.append(((ROLE_LOOP, 1, 0, dst, spine), (v, port, qid, dst)))
    return rows


def plan_final():
    rows = []
    for dst in range(N_LEAF):
        rows.append(((ROLE_HOST, 0, dst), ("Ingress.act_enter",   {"next_hop": 1})))
        rows.append(((ROLE_LOOP, 1, dst), ("Ingress.act_transit", {"next_hop": 2})))
    rows.append(((ROLE_LOOP, LAST_HOP, 0), ("Ingress.act_deliver", {"port": HOST0_DP})))
    rows.append(((ROLE_LOOP, LAST_HOP, 1), ("Ingress.act_deliver", {"port": HOST1_DP})))
    return rows


def plan_spray(mode):
    # One row per host role/hop-0.  Both host ports share ROLE_HOST, so one row covers
    # both leaves; k lives in the action data.
    return [((ROLE_HOST, 0), SPRAY_ACTIONS[mode], SPRAY_MASK)]


def plan_shapers(gbps=DEFAULT_VLINK_GBPS):
    """Every virtual link gets a real per-queue max-rate shaper.  This is what makes
    the link a link rather than a label: congestion on it produces genuine queueing
    and eg_intr_md.deq_qdepth is genuinely that link's depth."""
    rows = []
    for v in range(N_LEAF * N_SPINE * 2):
        port, qid = vlink_placement(v)
        pg_id, pg_port_nr = port // 4, port % 4     # dp68 -> 17/0, dp8 -> 2/0
        rows.append((v, port, qid, pg_id, pg_port_nr * 8 + qid, gbps))
    return rows


def print_plan():
    print("=== port roles (tbl_port_role) ===")
    for dp, role, leaf in plan_roles():
        print("  dp=%-3d role=%d src_leaf=%d" % (dp, role, leaf))

    print("=== destination leaf (tbl_dst_leaf) ===")
    for ip, leaf, base in plan_dst_leaf():
        print("  %-10s -> leaf %d, path_base %d" % (ip, leaf, base))

    print("=== spray mode (tbl_spray_mode), default '%s' ===" % DEFAULT_SPRAY)
    for key, act, mask in plan_spray(DEFAULT_SPRAY):
        print("  role=%d hop=%d -> %s(mask=%d)" % (key[0], key[1], act, mask))

    print("=== virtual links (tbl_vlink), %d rows ===" % len(plan_vlink()))
    for key, data in plan_vlink():
        print("  role=%d hop=%d src_leaf=%d dst_leaf=%d spray=%d"
              "  ->  vlink=%2d dp%-3d qid=%d next_vsw=%d"
              % (key[0], key[1], key[2], key[3], key[4],
                 data[0], data[1], data[2], data[3]))

    print("=== final (tbl_final), %d rows ===" % len(plan_final()))
    for key, (act, args) in plan_final():
        print("  role=%d hop=%d dst_leaf=%d -> %s %s" % (key[0], key[1], key[2], act, args))

    print("=== queue shapers, %d rows ===" % len(plan_shapers()))
    for v, port, qid, pg_id, pg_queue, gbps in plan_shapers():
        print("  vlink %2d -> dp%-3d qid=%d  pg_id=%d pg_queue=%-2d  max_rate=%d Gb/s"
              % (v, port, qid, pg_id, pg_queue, gbps))

    print("=== mirror sessions ===")
    for sid, mx in sorted(MIRROR_SESSIONS.items()):
        print("  sid=%d -> dp%d $max_pkt_len=%d" % (sid, HOST1_DP, mx))


def self_check():
    """Cheap invariants on the plan.  Runs offline; catches an encoding slip before it
    becomes an hour of packet chasing."""
    vs = [d[0] for _, d in plan_vlink()]
    assert min(vs) == 0 and max(vs) == 15, "vlink ids must span 0..15"
    seen = {}
    for _, (v, port, qid, _vsw) in plan_vlink():
        seen.setdefault((port, qid), set()).add(v)
    for (port, qid), links in seen.items():
        assert len(links) == 1, "queue dp%d/qid%d shared by vlinks %s" % (port, qid, links)
    assert len(seen) == 16, "expected 16 distinct (loop port, qid) pairs, got %d" % len(seen)
    for v in range(16):
        port, qid = vlink_placement(v)
        assert 0 <= qid <= 7, "qid out of the 8-per-port carving"
    print("plan self-check OK: 16 virtual links on 16 distinct TM queues")


# ===========================================================================
# bfrt side.  Imported lazily so --dry-run works without the SDE.
# ===========================================================================

def connect():
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(GRPC_ADDR, client_id=CLIENT_ID, device_id=DEV)
    iface.bind_pipeline_config(PROG)          # client_id 0 ONLY
    bfrt = iface.bfrt_info_get(PROG)
    tgt = gc.Target(device_id=DEV, pipe_id=0xffff)   # P4 tables/registers: all pipes
    tgt_tm = gc.Target(device_id=DEV, pipe_id=0)     # TM tables are PIPE-SPECIFIC (0, not 0xffff)
    return gc, iface, bfrt, tgt, tgt_tm


def _upsert(table, tgt, key, data):
    try:
        table.entry_add(tgt, [key], [data])
    except Exception:
        table.entry_mod(tgt, [key], [data])


def bring_up_ports(gc, bfrt, tgt):
    port = bfrt.table_get("$PORT")
    cfg = [
        (HOST0_DP, "BF_SPEED_25G", "BF_LPBK_NONE"),
        (HOST1_DP, "BF_SPEED_10G", "BF_LPBK_NONE"),
        (LOOP_DN_DP, "BF_SPEED_25G", "BF_LPBK_MAC_NEAR"),   # the second loop port
    ]
    for dp, speed, lpbk in cfg:
        key = port.make_key([gc.KeyTuple("$DEV_PORT", dp)])
        data = port.make_data([
            gc.DataTuple("$SPEED", str_val=speed),
            gc.DataTuple("$FEC", str_val="BF_FEC_TYP_REED_SOLOMON"),
            gc.DataTuple("$AUTO_NEGOTIATION", str_val="PM_AN_DEFAULT"),
            gc.DataTuple("$LOOPBACK_MODE", str_val=lpbk),
            gc.DataTuple("$PORT_ENABLE", bool_val=True)])
        _upsert(port, tgt, key, data)
        print("  dp%-3d %s %s" % (dp, speed, lpbk))

    # dp68 is an internal recirculation port: no $PORT entry, enable recirc instead.
    pc = bfrt.table_dict["tf1.pktgen.port_cfg"]
    pc.entry_mod(tgt, [pc.make_key([gc.KeyTuple("dev_port", LOOP_UP_DP)])],
                 [pc.make_data([gc.DataTuple("pktgen_enable", bool_val=True),
                                gc.DataTuple("recirculation_enable", bool_val=True)])])
    print("  dp%-3d recirculation + pktgen enabled" % LOOP_UP_DP)


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


def install_vlinks(gc, bfrt, tgt):
    t = bfrt.table_get("pipe.Ingress.tbl_vlink")
    rows = plan_vlink()
    for (role, hop, src, dst, spray), (v, port, qid, vsw) in rows:
        _upsert(t, tgt,
                t.make_key([gc.KeyTuple("md.role", role),
                            gc.KeyTuple("md.hop", hop),
                            gc.KeyTuple("md.src_leaf", src),
                            gc.KeyTuple("md.dst_leaf", dst),
                            gc.KeyTuple("md.spray_idx", spray)]),
                t.make_data([gc.DataTuple("vlink_id", v),
                             gc.DataTuple("loop_port", port),
                             gc.DataTuple("qid", qid),
                             gc.DataTuple("next_vsw", vsw)], "Ingress.to_loop"))
    print("  tbl_vlink: %d rows" % len(rows))


def install_final(gc, bfrt, tgt):
    t = bfrt.table_get("pipe.Ingress.tbl_final")
    rows = plan_final()
    for (role, hop, dst), (act, args) in rows:
        _upsert(t, tgt,
                t.make_key([gc.KeyTuple("md.role", role),
                            gc.KeyTuple("md.hop", hop),
                            gc.KeyTuple("md.dst_leaf", dst)]),
                t.make_data([gc.DataTuple(k, v) for k, v in args.items()], act))
    print("  tbl_final: %d rows" % len(rows))


def set_spray(gc, bfrt, tgt, mode):
    if mode not in SPRAY_ACTIONS:
        raise SystemExit("spray mode must be one of %s" % sorted(SPRAY_ACTIONS))
    t = bfrt.table_get("pipe.Ingress.tbl_spray_mode")
    for (role, hop), act, mask in plan_spray(mode):
        _upsert(t, tgt,
                t.make_key([gc.KeyTuple("md.role", role), gc.KeyTuple("md.hop", hop)]),
                t.make_data([gc.DataTuple("mask", mask)], act))
    print("  spray mode = %s (mask=%d)" % (mode, SPRAY_MASK))
    if mode == "random":
        print("  NOTE: Random<> has no control-plane seed on Tofino 1 — this run is "
              "characterisable but NOT replayable.  The chosen index is written into "
              "fabric_h.spray on the wire so a capture still reconstructs every path.")
    if mode == "sel":
        print("  NOTE: 'sel' also needs ActionProfile members and a selector group "
              "installed in pipe.Ingress.spray_prof / spray_sel_impl — not done here.")


def seed_registers(gc, bfrt, tgt):
    """Constraint Class 8: seed every slot so nothing depends on an in-SALU `v == 0`
    sentinel.  A full-array seed takes a few seconds; budget for it in trial resets."""
    r = bfrt.table_get("pipe.Ingress.reg_spray_rr")
    for i in range(64):
        r.entry_add(tgt,
                    [r.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])],
                    [r.make_data([gc.DataTuple("Ingress.reg_spray_rr.f1", 0)])])
    print("  reg_spray_rr: 64 slots seeded to 0")


def clear_fail(bfrt, tgt):
    """Delete every tbl_fail entry.

    LANDMINE, carried verbatim from sdnp_setup.py:62-72 — on this bfrt version range
    match keys returned by entry_get do NOT round-trip into entry_del, and there is no
    table.clear().  entry_del(target) with no key list bulk-deletes, which does work.
    Always re-read afterwards and verify the table is actually empty.
    """
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

    Probability = (high - low + 1)/65536, retunable at runtime by rewriting the bounds
    (sdnp_setup.py:75-89).  Because vlink_id encodes direction, installing the uplink
    id only gives a perfectly asymmetric link for free (§7.3).
    """
    t = bfrt.table_get("pipe.Ingress.tbl_fail")
    action = {"drop": "Ingress.inj_drop", "corrupt": "Ingress.inj_corrupt"}[mode]
    if pct <= 0:
        print("  vlink %d: no failure row installed (pct=%s)" % (vlink, pct))
        return
    hi = int(65535 * pct / 100.0)
    _upsert(t, tgt,
            t.make_key([gc.KeyTuple("md.vlink_id", vlink),
                        gc.KeyTuple("md.rnd_fail", low=0, high=hi),
                        gc.KeyTuple("$MATCH_PRIORITY", 1)]),
            t.make_data([], action))
    print("  vlink %d: %s for rnd_fail in [0,%d] = %.2f%%"
          % (vlink, mode, hi, hi / 65536.0 * 100))


def set_shaper(gc, bfrt, tgt_tm, vlink, gbps):
    """A per-queue max-rate shaper is what gives a virtual link a finite capacity.

    THE SHAPER IS INERT WITHOUT THE SECOND CALL: sched_shaping sets the rate,
    sched_cfg's max_rate_enable arms it (gc_switch_setup_c.py:163-177).  TM tables need
    pipe_id=0, NOT 0xffff — the single most likely-to-bite control-plane detail here.
    """
    port, qid = vlink_placement(vlink)
    pg_id, pg_queue = port // 4, (port % 4) * 8 + qid
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
    print("  vlink %2d (dp%d qid%d, pg_id=%d pg_queue=%d): max_rate %d Gb/s"
          % (vlink, port, qid, pg_id, pg_queue, gbps))


def install_mirrors(gc, bfrt, tgt):
    """$mirror.cfg is ACTION-BASED and the action name is mandatory — make_data without
    "$normal" fails INVALID_ARGUMENT (case_a_defense3_fixed_ack_delay_setup.py:909-916).
    Sessions are configured now; nothing in steps 1-4 arms them yet (that is step 6)."""
    mir = bfrt.table_get("$mirror.cfg")
    for sid, maxlen in sorted(MIRROR_SESSIONS.items()):
        _upsert(mir, tgt,
                mir.make_key([gc.KeyTuple("$sid", sid)]),
                mir.make_data([gc.DataTuple("$direction", str_val="INGRESS"),
                               gc.DataTuple("$ucast_egress_port", val=HOST1_DP),
                               gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
                               gc.DataTuple("$session_enable", bool_val=True),
                               gc.DataTuple("$max_pkt_len", val=maxlen)], "$normal"))
    print("  mirror sessions %s -> dp%d" % (sorted(MIRROR_SESSIONS), HOST1_DP))


def show_counters(bfrt, tgt):
    """SyncCounters is MANDATORY before reading a DirectCounter (sdnp_setup.py:107-115),
    otherwise the read returns stale or zero values.

    Tuple-order asymmetry in the bfrt client, and it is a real source of bugs: a
    KEYLESS entry_get yields (key, data), while next() on a SINGLE-KEY entry_get yields
    (data, key)."""
    for name in ("pipe.Ingress.tbl_vlink", "pipe.Ingress.tbl_fail"):
        t = bfrt.table_get(name)
        t.operations_execute(tgt, "SyncCounters")
        print("  %s:" % name)
        for k, d in t.entry_get(tgt, flags={"from_hw": True}):
            kd, dd = k.to_dict(), d.to_dict()
            print("    %s -> pkts=%s bytes=%s"
                  % (kd, dd.get("$COUNTER_SPEC_PKTS"), dd.get("$COUNTER_SPEC_BYTES")))


def blackhole(gc, bfrt, tgt, src_leaf, dst_leaf, spray):
    """§7.5: delete the tbl_vlink row.  The counted default action then drops, so the
    number of black-holed packets is exact."""
    t = bfrt.table_get("pipe.Ingress.tbl_vlink")
    t.entry_del(tgt, [t.make_key([gc.KeyTuple("md.role", ROLE_HOST),
                                  gc.KeyTuple("md.hop", 0),
                                  gc.KeyTuple("md.src_leaf", src_leaf),
                                  gc.KeyTuple("md.dst_leaf", dst_leaf),
                                  gc.KeyTuple("md.spray_idx", spray)])])
    print("  black hole: leaf %d -> leaf %d via spine %d removed"
          % (src_leaf, dst_leaf, spray))


def main():
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    if "--dry-run" in sys.argv or not args:
        self_check()
        print_plan()
        print("\n[--dry-run] no bfrt calls made.")
        return

    cmd = args[0]
    gc, iface, bfrt, tgt, tgt_tm = connect()

    if cmd == "up":
        bring_up_ports(gc, bfrt, tgt)
        install_roles(gc, bfrt, tgt)
        install_dst_leaf(gc, bfrt, tgt)
        install_vlinks(gc, bfrt, tgt)
        install_final(gc, bfrt, tgt)
        set_spray(gc, bfrt, tgt, DEFAULT_SPRAY)
        seed_registers(gc, bfrt, tgt)
        install_mirrors(gc, bfrt, tgt)
        for v, _p, _q, _pg, _pq, gbps in plan_shapers():
            set_shaper(gc, bfrt, tgt_tm, v, gbps)
        clear_fail(bfrt, tgt)
    elif cmd == "spray":
        set_spray(gc, bfrt, tgt, args[1])
    elif cmd == "fail":
        set_fail(gc, bfrt, tgt, int(args[1]), float(args[2]),
                 args[3] if len(args) > 3 else "drop")
    elif cmd == "fail-clear":
        clear_fail(bfrt, tgt)
    elif cmd == "shape":
        set_shaper(gc, bfrt, tgt_tm, int(args[1]), int(args[2]))
    elif cmd == "blackhole":
        blackhole(gc, bfrt, tgt, int(args[1]), int(args[2]), int(args[3]))
    elif cmd == "counters":
        show_counters(bfrt, tgt)
    else:
        raise SystemExit("unknown command: %s" % cmd)


if __name__ == "__main__":
    main()
