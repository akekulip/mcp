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
    R [sublink ...]\n                                      -> dump selected/all witness state

Reads go through this agent too, and that is not incidental: SDE 9.13.2 lets only ONE client bind
the pipeline config ("Client ID N trying to bind but Client ID M already owns this P4"), and an
unbound client cannot read either ("Unable to get bound_program"). A separate reader process
therefore cannot coexist with a writer. One controller process owning the switch connection is the
correct shape, and it is what a real deployment runs.
The reply carries the agent's own bfrt write time in microseconds, so the host-side and
switch-side components of the path can be separated afterwards.
"""
import os, socket, sys, time
from gate_agent_core import add_batch_strict, clear_entries_strict, is_not_found, peer_allowed
from injector_ranges import modular_drop_ranges
sys.path.append("/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino")
sys.path.append("/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages")
import bfrt_grpc.client as gc

import os
PROG = os.environ.get("MCP_PROG", "mcp_fabric_gate_event")
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
print("gate_agent listening on %d, bound to %s, allowed peers %s" %
      (PORT, PROG, ",".join(sorted(ALLOWED_PEERS))), flush=True)

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
                    encoded = " ".join("%d %d" % bounds for bounds in ranges)
                    conn.sendall(("ARMED %d %s\n" % (sub, encoded)).encode())
                    print("A %d %d -> armed seq %s" % (sub, ndrop, ranges), flush=True)
                    continue
                elif f[0] == "K":
                    # K <sublink> -- TOTAL context blackhole ("kill").  NOT "B": that is
                    # already the batch-gate-rows command, and a duplicate branch is dead
                    # code because the first match wins.: drop EVERY packet on this
                    # behavioural sublink by covering the whole 16-bit sequence space.
                    # This is the case C-W4 structurally cannot see: with no survivor there
                    # is never a later packet to expose a discontinuity, so the only
                    # evidence that anything is wrong is the source frontier saying it sent.
                    sub = int(f[1])
                    ft = info.table_get("pipe.Egress.tbl_eg_fail")
                    fk = ft.make_key([gc.KeyTuple("md.sublink", sub),
                                      gc.KeyTuple("hdr.witness.seq", low=0, high=0xFFFF),
                                      gc.KeyTuple("$MATCH_PRIORITY", 1)])
                    fd = ft.make_data([], "Egress.eg_fail_drop")
                    try:
                        ft.entry_add(tgt, [fk], [fd])
                    except gc.BfruntimeRpcException:
                        ft.entry_mod(tgt, [fk], [fd])
                    conn.sendall(("BLACKHOLED %d [0..65535]\n" % sub).encode())
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
                    bank = 1 if int(f[1]) else 0   # hdr.fabric.clf_bank, a dedicated byte
                    t = info.table_get("pipe.Ingress.tbl_final")
                    n = 0
                    for d, k in t.entry_get(tgt, None, {"from_hw": True}):
                        dd, kk = d.to_dict(), k.to_dict()
                        if dd.get("action_name", "").endswith("act_enter") or "epoch" in dd:
                            fields = [gc.DataTuple("next_hop", dd.get("next_hop", 1))]
                            if "epoch" in dd:
                                fields.append(gc.DataTuple("epoch", dd.get("epoch", 0)))
                            fields.append(gc.DataTuple("bank", bank))
                            try:
                                t.entry_mod(tgt, [k], [t.make_data(fields, "Ingress.act_enter")])
                                n += 1
                            except Exception:
                                pass
                    conn.sendall(("OK %d\n" % n).encode())
                    print("N %d -> %d act_enter rows now stamp bank %d" % (int(f[1]), n, bank),
                          flush=True)
                    continue
                elif f[0] == "I":
                    # I -- injector ground truth: how many packets did tbl_eg_fail actually
                    # destroy, per entry?  "Verify the injected quantity in the DATA, not in
                    # the flags" (repo doctrine).  A miss with a zero counter means the entry
                    # never matched; a miss with a large counter means something else set RX.
                    ft = info.table_get("pipe.Egress.tbl_eg_fail")
                    try:
                        ft.operations_execute(tgt, "SyncCounters")
                    except Exception:
                        pass
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
                    rx = rdf("pipe.Egress.reg_rx_frontier", "Egress.reg_rx_frontier.f1")
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
                elif f[0] == "Z":
                    # Zero both frontiers (per-epoch or per-trial reset).
                    for reg, fld in (("pipe.Egress.reg_tx_frontier", "Egress.reg_tx_frontier.f1"),
                                     ("pipe.Egress.reg_rx_frontier", "Egress.reg_rx_frontier.f1")):
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
                            if v: out[idx] = v
                        return out
                    seq = rd("pipe.Egress.reg_wit_seq", "Egress.reg_wit_seq.f1")
                    obs = rd("pipe.Ingress.reg_wit_observed", "Ingress.reg_wit_observed.f1")
                    payload = "".join("S %d %d %d %d %d\n" % (i, i >> 4, i & 0xF, seq[i],
                                                              obs.get(i, 0)) for i in sorted(seq))
                    conn.sendall(payload.encode()); conn.sendall(b"OK 0\n"); continue
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
