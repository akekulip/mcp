#!/usr/bin/env python3
"""Switch-side half of the P3 loop: accept a quarantine instruction, write tbl_health_gate.

Runs ON the switch because the bf-rt client libraries live in the SDE and Vision has neither the
SDE nor python grpc.  The controller half (collector + decision) runs on Vision and reaches this
agent over the management network, which is where a controller sits in a real deployment.

Protocol, one line per request, so the wire cost is a single small TCP segment:
    Q <src_leaf> <dst_leaf> <spray> <ctx> <alt_spray>\n   -> install a reroute, reply "OK <us>\n"
    B <src> <dst> <spray> <ctx> <alt> [...]\n             -> batch-install rows, reply
    D <src_leaf> <dst_leaf> <spray> <ctx>\n               -> delete it,         reply "OK <us>\n"
    G <path_id>\n                                            -> read attention state, reply
    T <path_id> <attn> <clean>\n                           -> set attention state, reply "OK <us>\n"
    P\n                                                    -> ping,              reply "OK 0\n"
    V\n                                                    -> report sealed program/build/runtime identity
    V2\n                                                   -> report sealed switch/setup identity too
    R [sublink ...]\n                                      -> dump selected/all witness state
                                                            using census rows tagged "S"
    A <sublink> <ndrop>\n                                  -> contiguous burst injector ranges
    S <sublink> <packet_count> <drop_count> <phase>\n      -> exact dispersed injector ranges
                                                            (command, not R-response row)
    K <sublink> [low high]\n                               -> full or bounded blackhole range
    M [dev_port ...]\n                                      -> read MAC port RX/TX counters

Reads go through this agent too, and that is not incidental: SDE 9.13.2 lets only ONE client bind
the pipeline config ("Client ID N trying to bind but Client ID M already owns this P4"), and an
unbound client cannot read either ("Unable to get bound_program"). A separate reader process
therefore cannot coexist with a writer. One controller process owning the switch connection is the
correct shape, and it is what a real deployment runs.
The reply carries the agent's own bfrt write time in microseconds, so the host-side and
switch-side components of the path can be separated afterwards.
"""
import os, pathlib, socket, sys, time
from gate_agent_core import (
    add_batch_strict,
    clear_entries_strict,
    compute_switch_id,
    format_arm_reply,
    format_blackhole_reply,
    format_port_stats_reply,
    format_spread_reply,
    is_not_found,
    parse_bank_command,
    parse_blackhole_command,
    parse_epoch_command,
    parse_port_stats_command,
    parse_spread_command,
    read_port_stats_rows,
    peer_allowed,
    rewrite_act_enter_field,
    sync_counters_strict,
    verify_loaded_build,
    verify_loaded_setup,
    verify_sha256_manifest,
)
from injector_ranges import modular_drop_ranges, modular_spread_drop_ranges

PROG = os.environ.get("MCP_PROG")
if not PROG:
    raise SystemExit("MCP_PROG is required; refusing an implicit pipeline binding")
RUNTIME_ROOT = os.path.dirname(os.path.abspath(__file__))
RUNTIME_FILES = ("gate_agent.py", "gate_agent_core.py", "injector_ranges.py")
RUNTIME_ID = verify_sha256_manifest(
    RUNTIME_ROOT, PROG + ".runtime-manifest.sha256", expected_files=RUNTIME_FILES)
BUILD_ID = verify_sha256_manifest(RUNTIME_ROOT, PROG + ".build-manifest.sha256")
SETUP_ID = verify_sha256_manifest(RUNTIME_ROOT, PROG + ".setup-manifest.sha256")
SWITCHD_PID = verify_loaded_build(RUNTIME_ROOT, PROG, BUILD_ID)
SWITCH_ID = compute_switch_id(
    pathlib.Path("/etc/machine-id").read_text(), socket.gethostname(), 0,
)
verify_loaded_setup(RUNTIME_ROOT, PROG, SWITCH_ID, SETUP_ID, SWITCHD_PID)

sys.path.append("/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino")
sys.path.append("/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages")
import bfrt_grpc.client as gc

PORT = 47100
ALLOWED_PEERS = frozenset(
    peer.strip() for peer in
    os.environ.get("MCP_GATE_ALLOWED_PEERS", "127.0.0.1,10.10.54.166").split(",")
    if peer.strip())

cli = gc.ClientInterface("localhost:50052", client_id=51, device_id=0)
cli.bind_pipeline_config(PROG)
info = cli.bfrt_info_get(PROG)
tgt = gc.Target(device_id=0, pipe_id=0xFFFF)
gate = info.table_get("pipe.Ingress.tbl_health_gate")
attn_reg = info.table_get("pipe.Ingress.reg_attn")

def key_for(src, dst, spray, ctx):
    return gate.make_key([gc.KeyTuple("md.src_leaf", src), gc.KeyTuple("md.dst_leaf", dst),
                          gc.KeyTuple("md.spray_idx", spray), gc.KeyTuple("md.ctx", ctx)])

def attn_key(path_id):
    return attn_reg.make_key([gc.KeyTuple("$REGISTER_INDEX", path_id)])

def scalar(value):
    return max(value) if isinstance(value, list) and value else (value or 0)

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", PORT)); srv.listen(4)
print("gate_agent listening on %d, bound to %s, build %s, runtime %s, allowed peers %s" %
      (PORT, PROG, BUILD_ID, RUNTIME_ID, ",".join(sorted(ALLOWED_PEERS))), flush=True)

while True:
    conn, peer = srv.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        if not peer_allowed(peer[0], ALLOWED_PEERS):
            conn.sendall(b"ERR unauthorized peer\n")
            print("rejected unauthorized peer %s" % peer[0], flush=True)
            continue
        chunks = []
        total = 0
        while total < 4096:
            chunk = conn.recv(min(1024, 4096 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\n" in chunk:
                break
        buf = b"".join(chunks).decode().strip()
        if not buf:
            conn.sendall(b"ERR empty request\n")
            continue
        for line in buf.splitlines():
            f = line.split()
            if not f:
                continue
            t0 = time.perf_counter_ns()
            try:
                if f[0] == "Q":
                    src, dst, spray, ctx, alt = (int(x) for x in f[1:6])
                    data = gate.make_data([gc.DataTuple("alt_spray", alt)],
                                          "Ingress.sublink_reroute")
                    try:
                        gate.entry_add(tgt, [key_for(src, dst, spray, ctx)], [data])
                    except gc.BfruntimeRpcException:
                        gate.entry_mod(tgt, [key_for(src, dst, spray, ctx)], [data])
                elif f[0] == "B":
                    raw = [int(x) for x in f[1:]]
                    if not raw or len(raw) % 5:
                        raise ValueError("batch requires one or more 5-field gate rows")
                    rows = [tuple(raw[i:i + 5]) for i in range(0, len(raw), 5)]
                    keys = [key_for(src, dst, spray, ctx)
                            for src, dst, spray, ctx, _ in rows]
                    data = [gate.make_data([gc.DataTuple("alt_spray", alt)],
                                           "Ingress.sublink_reroute")
                            for _, _, _, _, alt in rows]
                    # Publication trials require one BFRT batch.  Never turn a failed
                    # batch into a silent row-by-row partial install: return ERR and
                    # leave controller state retryable instead.
                    add_batch_strict(gate, tgt, keys, data)
                elif f[0] == "D":
                    src, dst, spray, ctx = (int(x) for x in f[1:5])
                    try:
                        gate.entry_del(tgt, [key_for(src, dst, spray, ctx)])
                    except gc.BfruntimeRpcException as error:
                        # Reset is idempotent, but only the expected absent-row case
                        # is success.  Schema, binding, and transport errors fail closed.
                        if not is_not_found(error):
                            raise
                elif f[0] == "G":
                    path_id = int(f[1])
                    values = {}
                    for data, _ in attn_reg.entry_get(
                            tgt, [attn_key(path_id)], {"from_hw": True}):
                        values = data.to_dict()
                    attn = scalar(values.get("Ingress.reg_attn.attn", 0))
                    clean = scalar(values.get("Ingress.reg_attn.clean", 0))
                    conn.sendall(("ATTN %d %d %d\n" % (path_id, attn, clean)).encode())
                    continue
                elif f[0] == "T":
                    path_id, attn, clean = (int(x) for x in f[1:4])
                    if not (0 <= path_id < 256 and 0 <= attn <= 0xFFFF and
                            0 <= clean <= 0xFFFF):
                        raise ValueError("attention state out of range")
                    data = attn_reg.make_data([
                        gc.DataTuple("Ingress.reg_attn.attn", attn),
                        gc.DataTuple("Ingress.reg_attn.clean", clean)])
                    attn_reg.entry_add(tgt, [attn_key(path_id)], [data])
                elif f[0] == "A":
                    # Arm the post-stamp injector: A <sublink> <ndrop>
                    # The agent does this because SDE 9.13.2 gives ONE client the pipeline
                    # binding, so a separate arming script cannot coexist with this process.
                    sub, ndrop = int(f[1]), int(f[2])
                    seqt = info.table_get("pipe.Egress.reg_wit_seq")
                    cur = 0
                    for d, k in seqt.entry_get(
                            tgt, [seqt.make_key([gc.KeyTuple("$REGISTER_INDEX", sub)])],
                            {"from_hw": True}):
                        v = d.to_dict()["Egress.reg_wit_seq.f1"]
                        cur = max(v) if isinstance(v, list) else v
                    ranges = modular_drop_ranges(cur, ndrop)
                    ft = info.table_get("pipe.Egress.tbl_eg_fail")
                    keys = [ft.make_key([gc.KeyTuple("md.sublink", sub),
                                         gc.KeyTuple("hdr.witness.seq", low=lo, high=hi),
                                         gc.KeyTuple("$MATCH_PRIORITY", 1)])
                            for lo, hi in ranges]
                    data = [ft.make_data([], "Egress.eg_fail_drop") for _ in keys]
                    ft.entry_add(tgt, keys, data)
                    conn.sendall(format_arm_reply(sub, ranges).encode())
                    print("A %d %d -> armed seq %s" % (sub, ndrop, ranges), flush=True)
                    continue
                elif f[0] == "S":
                    sub, packet_count, drop_count, phase = parse_spread_command(f)
                    seqt = info.table_get("pipe.Egress.reg_wit_seq")
                    cur = 0
                    for d, k in seqt.entry_get(
                            tgt, [seqt.make_key([gc.KeyTuple("$REGISTER_INDEX", sub)])],
                            {"from_hw": True}):
                        v = d.to_dict()["Egress.reg_wit_seq.f1"]
                        cur = max(v) if isinstance(v, list) else v
                    ranges = modular_spread_drop_ranges(
                        cur, packet_count, drop_count, phase)
                    ft = info.table_get("pipe.Egress.tbl_eg_fail")
                    keys = [ft.make_key([gc.KeyTuple("md.sublink", sub),
                                         gc.KeyTuple("hdr.witness.seq", low=lo, high=hi),
                                         gc.KeyTuple("$MATCH_PRIORITY", 1)])
                            for lo, hi in ranges]
                    data = [ft.make_data([], "Egress.eg_fail_drop") for _ in keys]
                    add_batch_strict(ft, tgt, keys, data)
                    conn.sendall(format_spread_reply(
                        sub, packet_count, drop_count, phase, ranges).encode())
                    print("S %d %d %d %d -> armed seq %s" %
                          (sub, packet_count, drop_count, phase, ranges), flush=True)
                    continue
                elif f[0] == "U":
                    # U <udp_dst> <udp_src> <spray>  -- declare ONE audit/probation flow and
                    # pin the sublink it must take.  tbl_audit_steer opens a deliberate
                    # tbl_health_gate bypass at hop 0, which is the only way probation can
                    # reach a sublink the gate has already emptied of production traffic.
                    # Negative spray deletes the declaration, so a probation round can be
                    # closed as explicitly as it was opened.
                    dst_p, src_p, spray = int(f[1]), int(f[2]), int(f[3])
                    at = info.table_get("pipe.Ingress.tbl_audit_steer")
                    ak = at.make_key([gc.KeyTuple("md.audit_src", 1),
                                      gc.KeyTuple("hdr.udp.dst_port", dst_p),
                                      gc.KeyTuple("hdr.udp.src_port", src_p)])
                    if spray < 0:
                        try:
                            at.entry_del(tgt, [ak])
                        except gc.BfruntimeRpcException as error:
                            if not is_not_found(error):
                                raise
                        conn.sendall(("AUDIT-CLEARED %d %d\n" % (dst_p, src_p)).encode())
                    else:
                        ad = at.make_data([gc.DataTuple("spray", spray)],
                                          "Ingress.set_audit_spray")
                        try:
                            at.entry_add(tgt, [ak], [ad])
                        except gc.BfruntimeRpcException:
                            at.entry_mod(tgt, [ak], [ad])
                        conn.sendall(("AUDIT %d %d -> spray %d\n"
                                      % (dst_p, src_p, spray)).encode())
                    continue
                elif f[0] == "K":
                    # K <sublink> -- TOTAL context blackhole ("kill").  NOT "B": that is
                    # already the batch-gate-rows command, and a duplicate branch is dead
                    # code because the first match wins.: drop EVERY packet on this
                    # behavioural sublink by covering the whole 16-bit sequence space.
                    # This is the case C-W4 structurally cannot see: with no survivor there
                    # is never a later packet to expose a discontinuity, so the only
                    # evidence that anything is wrong is the source frontier saying it sent.
                    # K <sublink> [lo hi] -- optional sequence range. The default covers the
                    # whole space (a TOTAL blackhole). A partial range drops only the packets
                    # whose per-sublink sequence falls inside it, which is how a controlled
                    # near-total loss is produced: the survivors are the ones outside it.
                    # Needed because a total blackhole only ever exercises RX == 0, so the
                    # band between "nothing arrived" and "everything arrived" was never tested
                    # on silicon.
                    sub, lo, hi = parse_blackhole_command(f)
                    ft = info.table_get("pipe.Egress.tbl_eg_fail")
                    fk = ft.make_key([gc.KeyTuple("md.sublink", sub),
                                      gc.KeyTuple("hdr.witness.seq", low=lo, high=hi),
                                      gc.KeyTuple("$MATCH_PRIORITY", 1)])
                    fd = ft.make_data([], "Egress.eg_fail_drop")
                    try:
                        ft.entry_add(tgt, [fk], [fd])
                    except gc.BfruntimeRpcException:
                        ft.entry_mod(tgt, [fk], [fd])
                    conn.sendall(format_blackhole_reply(sub, lo, hi).encode())
                    print("K %d -> total blackhole armed" % sub, flush=True)
                    continue
                elif f[0] == "N":
                    # N <bank> -- flip the CLF epoch. Rewrites tbl_final's source-side
                    # act_enter rows so newly entering packets are stamped with the new bank
                    # parity in hdr.fabric.clf_bank.
                    #
                    # This is what makes the frontier readable on a LIVE fabric. A reader
                    # never zeroes: it flips, waits a guard interval for in-flight packets to
                    # land in the new bank, and reads the now-INACTIVE bank, which is
                    # complete and no longer being written. Zeroing the active bank instead
                    # clears TX while packets are in flight, so they arrive and set RX with
                    # no matching TX -- the TX=0/RX=1 state, seen in 50 of 50 trials.
                    bank = parse_bank_command(f)   # hdr.fabric.clf_bank, a dedicated byte
                    t = info.table_get("pipe.Ingress.tbl_final")
                    n = rewrite_act_enter_field(t, tgt, gc.DataTuple, "bank", bank)
                    conn.sendall(("OK %d\n" % n).encode())
                    print("N %d -> %d act_enter rows now stamp bank %d" % (bank, n, bank),
                          flush=True)
                    continue
                elif f[0] == "E":
                    epoch = parse_epoch_command(f)
                    t = info.table_get("pipe.Ingress.tbl_final")
                    n = rewrite_act_enter_field(t, tgt, gc.DataTuple, "epoch", epoch)
                    conn.sendall(("OK %d\n" % n).encode())
                    print("E %d -> %d act_enter rows now stamp epoch %d" %
                          (epoch, n, epoch), flush=True)
                    continue
                elif f[0] == "M":
                    ports = parse_port_stats_command(f)
                    stat = info.table_get("$PORT_STAT")
                    rows = read_port_stats_rows(stat, tgt, ports, gc.KeyTuple)
                    conn.sendall(format_port_stats_reply(rows).encode())
                    continue
                elif f[0] == "I":
                    # I -- injector ground truth: how many packets did tbl_eg_fail actually
                    # destroy, per entry?  "Verify the injected quantity in the DATA, not in
                    # the flags" (repo doctrine).  A miss with a zero counter means the entry
                    # never matched; a miss with a large counter means something else set RX.
                    ft = info.table_get("pipe.Egress.tbl_eg_fail")
                    sync_counters_strict(ft, tgt)
                    out = []
                    for d, k in ft.entry_get(tgt, None, {"from_hw": True}):
                        dd, kk = d.to_dict(), k.to_dict()
                        out.append("I %s %s %s %s" % (
                            kk["md.sublink"]["value"],
                            kk["hdr.witness.seq"]["low"], kk["hdr.witness.seq"]["high"],
                            dd.get("$COUNTER_SPEC_PKTS", 0)))
                    conn.sendall(("".join(x + "\n" for x in out)).encode())
                    conn.sendall(b"OK 0\n"); continue
                elif f[0] == "C":
                    # Clear every injector entry (per-trial reset).
                    ft = info.table_get("pipe.Egress.tbl_eg_fail")
                    keys = [k for _, k in ft.entry_get(tgt, None, {"from_hw": True})]
                    cleared = clear_entries_strict(ft, tgt, keys)
                    conn.sendall(("OK %d\n" % cleared).encode())
                    print("C -> cleared %d injector entries" % len(keys), flush=True)
                    continue
                elif f[0] == "F":
                    # Read both CLF frontiers and pack the per-link 16-bit masks.
                    # The data plane stores a byte per sublink (a per-link mask would need a
                    # one-hot 1 << ctx and the compiler cannot shift a runtime value); packing
                    # here is what preserves the batched per-link record.
                    def rdf(reg, fld):
                        tt = info.table_get(reg); out = {}
                        for d, k in tt.entry_get(tgt, None, {"from_hw": True}):
                            idx = k.to_dict()["$REGISTER_INDEX"]["value"]
                            v = d.to_dict().get(fld, [])
                            v = max(v) if isinstance(v, list) and v else (v or 0)
                            if v: out[idx] = v
                        return out
                    tx = rdf("pipe.Egress.reg_tx_frontier", "Egress.reg_tx_frontier.f1")
                    # RX moved to INGRESS so the receiver's own TM sits outside the link
                    # measurement; the register path moved with it.
                    rx = rdf("pipe.Ingress.reg_rx_frontier", "Ingress.reg_rx_frontier.f1")
                    def pack(d, bank):
                        m = {}
                        for idx in d:
                            if (idx >> 8) != bank:
                                continue
                            sub = idx & 0xFF
                            m[sub >> 4] = m.get(sub >> 4, 0) | (1 << (sub & 0xF))
                        return m
                    lines = []
                    for bank in (0, 1):
                        tm, rm = pack(tx, bank), pack(rx, bank)
                        for vl in sorted(set(tm) | set(rm)):
                            t, r = tm.get(vl, 0), rm.get(vl, 0)
                            lines.append("F %d %d 0x%04X 0x%04X 0x%04X" %
                                         (bank, vl, t, r, t & ~r & 0xFFFF))
                    conn.sendall(("".join(l + "\n" for l in lines)).encode())
                    conn.sendall(b"OK 0\n"); continue
                elif f[0] == "X":
                    # X -- per-sublink frontier COUNTS: "X <bank> <vlink> <ctx> <tx> <rx>".
                    # F packs presence bits and therefore cannot distinguish "one stray
                    # packet arrived" from "the link is carrying full load", which is the
                    # property that made every masking failure silent. Both registers now
                    # hold a saturating count (255 = saturated), so X reports what F throws
                    # away. F is kept: a mask is still the right shape for a blackhole,
                    # which is a count of exactly zero.
                    def rdc(reg, fld):
                        tt = info.table_get(reg); out = {}
                        for d, k in tt.entry_get(tgt, None, {"from_hw": True}):
                            idx = k.to_dict()["$REGISTER_INDEX"]["value"]
                            v = d.to_dict().get(fld, [])
                            v = max(v) if isinstance(v, list) and v else (v or 0)
                            if v: out[idx] = v
                        return out
                    txc = rdc("pipe.Egress.reg_tx_frontier", "Egress.reg_tx_frontier.f1")
                    rxc = rdc("pipe.Ingress.reg_rx_frontier", "Ingress.reg_rx_frontier.f1")
                    rows = []
                    for idx in sorted(set(txc) | set(rxc)):
                        sub = idx & 0xFF
                        rows.append("X %d %d %d %d %d" % (idx >> 8, sub >> 4, sub & 0xF,
                                                          txc.get(idx, 0), rxc.get(idx, 0)))
                    conn.sendall(("".join(r + "\n" for r in rows)).encode())
                    conn.sendall(b"OK 0\n"); continue
                elif f[0] == "Z":
                    # Zero both frontiers (per-epoch or per-trial reset).
                    for reg, fld in (("pipe.Egress.reg_tx_frontier", "Egress.reg_tx_frontier.f1"),
                                     ("pipe.Ingress.reg_rx_frontier", "Ingress.reg_rx_frontier.f1")):
                        tt = info.table_get(reg)
                        tt.entry_del(tgt, None)
                    conn.sendall(b"OK 0\n"); continue
                elif f[0] == "R":
                    requested = [int(x) for x in f[1:]]
                    if any(not 0 <= sublink < 1024 for sublink in requested):
                        raise ValueError("census sublink outside 0..1023")
                    def rd(reg, fld):
                        tt = info.table_get(reg); out = {}
                        keys = ([tt.make_key([gc.KeyTuple("$REGISTER_INDEX", sublink)])
                                 for sublink in requested] if requested else None)
                        for d, k in tt.entry_get(tgt, keys, {"from_hw": True}):
                            idx = k.to_dict()["$REGISTER_INDEX"]["value"]
                            v = d.to_dict().get(fld, [])
                            v = max(v) if isinstance(v, list) and v else (v or 0)
                            if requested or v:
                                out[idx] = v
                        return out
                    seq = rd("pipe.Egress.reg_wit_seq", "Egress.reg_wit_seq.f1")
                    obs = rd("pipe.Ingress.reg_wit_observed", "Ingress.reg_wit_observed.f1")
                    rows = sorted(requested if requested else seq)
                    missing = [i for i in rows if i not in seq or i not in obs]
                    if missing:
                        raise RuntimeError("missing census rows: %s" % missing[:8])
                    payload = "".join("S %d %d %d %d %d\n" % (i, i >> 4, i & 0xF, seq[i],
                                                              obs[i]) for i in rows)
                    conn.sendall(payload.encode())
                    conn.sendall(("OK %d\n" % len(rows)).encode()); continue
                elif f[0] == "V":
                    if len(f) != 1:
                        raise ValueError("V takes no arguments")
                    conn.sendall(("IDENTITY %s %s %s %d\n" %
                                  (PROG, BUILD_ID, RUNTIME_ID, SWITCHD_PID)).encode())
                    continue
                elif f[0] == "V2":
                    if len(f) != 1:
                        raise ValueError("V2 takes no arguments")
                    conn.sendall(("SEALED_IDENTITY %s %s %s %s %s %d\n" %
                                  (PROG, SWITCH_ID, BUILD_ID, SETUP_ID,
                                   RUNTIME_ID, SWITCHD_PID)).encode())
                    continue
                elif f[0] != "P":
                    conn.sendall(b"ERR unknown\n"); continue
                dt = (time.perf_counter_ns() - t0) // 1000
                conn.sendall(("OK %d\n" % dt).encode())
                print("%s -> OK %d us" % (line, dt), flush=True)
            except Exception as e:
                conn.sendall(("ERR %s\n" % str(e)[:80]).encode())
                print("%s -> ERR %s" % (line, str(e)[:80]), flush=True)
    finally:
        conn.close()
