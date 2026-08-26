#!/usr/bin/env python3
"""setup_attention.py — bfrt control plane for mcp_fabric steps 5-7 (attention register,
§7.4 update-rule constants, measurement gate, exceedance thresholds, CSIG egress vlink map,
mirror sessions).  Companion to setup_skeleton.py (steps 1-4: ports, roles, vlinks, spray,
failure injection), which must have run first and is the ONLY client that binds
(client_id 0).  This script uses client_id 2 and does not bind (§5.7).

Frozen rule (PREREG amendment v1.3):
    exceedance : attn = attn |+| k_up (saturating, a_max = 65535) ; clean = 0
    clean      : if clean >= n_clean-1 and attn > a_min: clean = 0; attn -= 1
                 elif clean >= n_clean-1:                clean = 0
                 else:                                   clean += 1
    gate       : measure iff rnd_attn < attn, as a 256-row TCAM on attn[15:8] x rnd_attn range

Usage (on the switch, SDE env + PYTHONPATH as in setup_skeleton.py):
    python3 setup_attention.py up [--a0 A0] [--k-up K] [--a-min M] [--n-clean N]
    python3 setup_attention.py seed <A0>              # re-seed every reg_attn slot
    python3 setup_attention.py params                 # print the four RegisterParams
    python3 setup_attention.py attn [path_id]         # dump reg_attn (attn, clean) per path
    python3 setup_attention.py thresh evid <loss_q_lo> <rtt_q_lo>   # exceedance if loss_q>=lo OR rtt_q>=lo
    python3 setup_attention.py thresh csig <qdepth_cells_lo>
    python3 setup_attention.py mirror <collector_dp>  # sessions 1 (128 B) and 3 (64 B)
    python3 setup_attention.py mirror-counts          # not available on Tofino 1 mirror cfg; use tcpdump at the collector
    python3 setup_attention.py --dry-run
"""
import argparse
import sys

DEV = 0
PROG = "mcp_fabric"
GRPC_ADDR = "localhost:50052"
CLIENT_ID = 2          # never 0 here: 0 binds and belongs to setup_skeleton.py

N_PATHS = 256          # reg_attn size in the P4
A0_DEFAULT = 4096      # initial attention: measure ~1.6 % of packets (4096/65536)
K_UP_DEFAULT = 1024
A_MIN_DEFAULT = 256
N_CLEAN_DEFAULT = 4096

# Loop ports and the vlink encoding must match setup_skeleton.py (leaf l <-> 5/l <-> 6/l).
LOOP_UP_DP = {0: 164, 1: 165, 2: 166, 3: 167}    # 5/0..5/3  (uplink egress, arrives at spine pass)
LOOP_DN_DP = {0: 172, 1: 173, 2: 174, 3: 175}    # 6/0..6/3  (downlink egress, arrives at dest-leaf pass)
N_SPINE = 2


def vlink_up(leaf, spine):
    return leaf * N_SPINE + spine                 # 0..7


def vlink_dn(spine, leaf):
    return 8 + leaf * N_SPINE + spine             # 8..15


def plan_eg_vlink():
    rows = []
    for leaf in range(4):
        for s in range(N_SPINE):
            rows.append((LOOP_UP_DP[leaf], s, vlink_up(leaf, s)))
            rows.append((LOOP_DN_DP[leaf], s, vlink_dn(s, leaf)))
    return rows


def plan_gate():
    """Row L (1..255): attn[15:8] == L and rnd_attn in [0, (L<<8)-1] -> measure."""
    return [(L, 0, (L << 8) - 1) for L in range(1, 256)]


def print_plan(args):
    print(f"reg_attn seed: {N_PATHS} slots, attn={args.a0}, clean=0")
    print(f"params: k_up={args.k_up} a_min={args.a_min} n_clean_m1={args.n_clean - 1}")
    print(f"tbl_gate: {len(plan_gate())} rows, e.g. {plan_gate()[0]} ... {plan_gate()[-1]}")
    print(f"tbl_eg_vlink: {len(plan_eg_vlink())} rows: {plan_eg_vlink()}")
    print("tbl_exceed_evid: 2 rows (loss_q >= lo, any rtt) and (any loss, rtt_q >= lo)")
    print("tbl_exceed_csig: 1 row (worst_qdepth >= lo cells)")
    print("mirror: sid 1 max_pkt_len 128, sid 3 max_pkt_len 64, INGRESS -> collector dev_port")


# --------------------------------------------------------------------------- bfrt
def connect():
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(GRPC_ADDR, client_id=CLIENT_ID, device_id=DEV)
    bfrt = iface.bfrt_info_get(PROG)
    tgt = gc.Target(device_id=DEV, pipe_id=0xFFFF)
    return gc, iface, bfrt, tgt


def _upsert(gc, table, tgt, keys, data):
    try:
        table.entry_add(tgt, keys, data)
    except gc.BfruntimeRpcException:
        table.entry_mod(tgt, keys, data)


def write_params(gc, bfrt, tgt, k_up, a_min, n_clean):
    for name, val in (("p_k_up", k_up), ("p_a_min", a_min), ("p_n_clean_m1", n_clean - 1)):
        t = bfrt.table_get(f"pipe.Ingress.{name}")
        t.default_entry_set(tgt, t.make_data([gc.DataTuple("value", val)]))
    print(f"params written: k_up={k_up} a_min={a_min} n_clean_m1={n_clean - 1}")


def read_params(gc, bfrt, tgt):
    for name in ("p_k_up", "p_a_min", "p_n_clean_m1"):
        t = bfrt.table_get(f"pipe.Ingress.{name}")
        for d, _ in t.default_entry_get(tgt):
            print(name, d.to_dict()["value"])


def seed_attn(gc, bfrt, tgt, a0):
    t = bfrt.table_get("pipe.Ingress.reg_attn")
    keys, data = [], []
    for i in range(N_PATHS):
        keys.append(t.make_key([gc.KeyTuple("$REGISTER_INDEX", i)]))
        data.append(t.make_data([gc.DataTuple("Ingress.reg_attn.attn", a0),
                                 gc.DataTuple("Ingress.reg_attn.clean", 0)]))
    t.entry_add(tgt, keys, data)      # register writes are idempotent adds
    print(f"reg_attn seeded: {N_PATHS} x (attn={a0}, clean=0)")


def dump_attn(gc, bfrt, tgt, path=None):
    t = bfrt.table_get("pipe.Ingress.reg_attn")
    idx = range(N_PATHS) if path is None else [path]
    for i in idx:
        k = t.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])
        for d, _ in t.entry_get(tgt, [k], {"from_hw": True}):
            dd = d.to_dict()
            attn = dd["Ingress.reg_attn.attn"]
            clean = dd["Ingress.reg_attn.clean"]
            # one value per pipe; the P4 runs in pipe 0 only on this box
            if path is not None or any(attn):
                print(f"path {i:3d}: attn={attn} clean={clean}")


def install_gate(gc, bfrt, tgt):
    t = bfrt.table_get("pipe.Ingress.tbl_gate")
    keys, data = [], []
    for L, lo, hi in plan_gate():
        keys.append(t.make_key([gc.KeyTuple("md.attn[15:8]", L),
                                gc.KeyTuple("md.rnd_attn", low=lo, high=hi),
                                gc.KeyTuple("$MATCH_PRIORITY", 1)]))
        data.append(t.make_data([], "Ingress.set_measure"))
    try:
        t.entry_add(tgt, keys, data)
    except gc.BfruntimeRpcException:
        for k, d in zip(keys, data):
            _upsert(gc, t, tgt, [k], [d])
    print(f"tbl_gate: {len(keys)} rows installed")


def install_eg_vlink(gc, bfrt, tgt):
    t = bfrt.table_get("pipe.Egress.tbl_eg_vlink")
    for port, qid, vl in plan_eg_vlink():
        _upsert(gc, t, tgt,
                [t.make_key([gc.KeyTuple("eg_intr_md.egress_port", port),
                             gc.KeyTuple("eg_intr_md.egress_qid", qid)])],
                [t.make_data([gc.DataTuple("vlink", vl)], "Egress.set_eg_vlink")])
    print(f"tbl_eg_vlink: {len(plan_eg_vlink())} rows installed")


def set_thresh_evid(gc, bfrt, tgt, loss_lo, rtt_lo):
    t = bfrt.table_get("pipe.Ingress.tbl_exceed_evid")
    for k, _ in list(t.entry_get(tgt)):
        t.entry_del(tgt, [k])
    rows = [((loss_lo, 255), (0, 255)), ((0, 255), (rtt_lo, 255))]
    for (l_lo, l_hi), (r_lo, r_hi) in rows:
        t.entry_add(tgt,
                    [t.make_key([gc.KeyTuple("hdr.evid.loss_q", low=l_lo, high=l_hi),
                                 gc.KeyTuple("hdr.evid.rtt_q", low=r_lo, high=r_hi),
                                 gc.KeyTuple("$MATCH_PRIORITY", 1)])],
                    [t.make_data([], "Ingress.evid_exceed")])
    print(f"tbl_exceed_evid: loss_q>={loss_lo} or rtt_q>={rtt_lo}")


def set_thresh_csig(gc, bfrt, tgt, q_lo):
    t = bfrt.table_get("pipe.Ingress.tbl_exceed_csig")
    for k, _ in list(t.entry_get(tgt)):
        t.entry_del(tgt, [k])
    t.entry_add(tgt,
                [t.make_key([gc.KeyTuple("hdr.csig.worst_qdepth", low=q_lo, high=65535),
                             gc.KeyTuple("$MATCH_PRIORITY", 1)])],
                [t.make_data([], "Ingress.set_exceed")])
    print(f"tbl_exceed_csig: worst_qdepth>={q_lo} cells")


def install_mirrors(gc, bfrt, tgt, collector_dp):
    """§5.4: action-based $mirror.cfg; the action name '$normal' is mandatory."""
    t = bfrt.table_get("$mirror.cfg")
    for sid, maxlen in ((1, 128), (3, 64)):
        _upsert(gc, t, tgt,
                [t.make_key([gc.KeyTuple("$sid", sid)])],
                [t.make_data([gc.DataTuple("$direction", str_val="INGRESS"),
                              gc.DataTuple("$ucast_egress_port", collector_dp),
                              gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
                              gc.DataTuple("$session_enable", bool_val=True),
                              gc.DataTuple("$max_pkt_len", maxlen)], "$normal")])
    print(f"mirror sessions 1 (128 B) and 3 (64 B) -> dev_port {collector_dp}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", nargs="?", default="up")
    ap.add_argument("args", nargs="*")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--a0", type=int, default=A0_DEFAULT)
    ap.add_argument("--k-up", type=int, default=K_UP_DEFAULT)
    ap.add_argument("--a-min", type=int, default=A_MIN_DEFAULT)
    ap.add_argument("--n-clean", type=int, default=N_CLEAN_DEFAULT)
    ap.add_argument("--collector", type=int, default=9, help="mirror collector dev_port (dp9 = Vision)")
    a = ap.parse_args()
    if a.dry_run:
        print_plan(a)
        return
    gc, iface, bfrt, tgt = connect()
    try:
        if a.cmd == "up":
            write_params(gc, bfrt, tgt, a.k_up, a.a_min, a.n_clean)
            seed_attn(gc, bfrt, tgt, a.a0)
            install_gate(gc, bfrt, tgt)
            install_eg_vlink(gc, bfrt, tgt)
            set_thresh_evid(gc, bfrt, tgt, 1, 255)      # any reported loss is exceedance; rtt off
            set_thresh_csig(gc, bfrt, tgt, 4096)        # 4096 cells ~ 320 KB queued
            install_mirrors(gc, bfrt, tgt, a.collector)
        elif a.cmd == "seed":
            seed_attn(gc, bfrt, tgt, int(a.args[0]))
        elif a.cmd == "params":
            read_params(gc, bfrt, tgt)
        elif a.cmd == "attn":
            dump_attn(gc, bfrt, tgt, int(a.args[0]) if a.args else None)
        elif a.cmd == "thresh" and a.args[0] == "evid":
            set_thresh_evid(gc, bfrt, tgt, int(a.args[1]), int(a.args[2]))
        elif a.cmd == "thresh" and a.args[0] == "csig":
            set_thresh_csig(gc, bfrt, tgt, int(a.args[1]))
        elif a.cmd == "mirror":
            install_mirrors(gc, bfrt, tgt, int(a.args[0]))
        else:
            sys.exit(f"unknown command {a.cmd}")
    finally:
        iface.tear_down_stream()


if __name__ == "__main__":
    main()
