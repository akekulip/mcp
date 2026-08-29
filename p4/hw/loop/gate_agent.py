#!/usr/bin/env python3
"""Switch-side half of the P3 loop: accept a quarantine instruction, write tbl_health_gate.

Runs ON the switch because the bf-rt client libraries live in the SDE and Vision has neither the
SDE nor python grpc.  The controller half (collector + decision) runs on Vision and reaches this
agent over the management network, which is where a controller sits in a real deployment.

Protocol, one line per request, so the wire cost is a single small TCP segment:
    Q <src_leaf> <dst_leaf> <spray> <ctx> <alt_spray>\n   -> install a reroute, reply "OK <us>\n"
    D <src_leaf> <dst_leaf> <spray> <ctx>\n               -> delete it,         reply "OK <us>\n"
    P\n                                                    -> ping,              reply "OK 0\n"
    R\n                                                    -> dump witness state, then "OK 0\n"

Reads go through this agent too, and that is not incidental: SDE 9.13.2 lets only ONE client bind
the pipeline config ("Client ID N trying to bind but Client ID M already owns this P4"), and an
unbound client cannot read either ("Unable to get bound_program"). A separate reader process
therefore cannot coexist with a writer. One controller process owning the switch connection is the
correct shape, and it is what a real deployment runs.
The reply carries the agent's own bfrt write time in microseconds, so the host-side and
switch-side components of the path can be separated afterwards.
"""
import socket, sys, time
sys.path.append("/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino")
sys.path.append("/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages")
import bfrt_grpc.client as gc

PROG = "mcp_fabric_gate_event"
PORT = 47100

cli = gc.ClientInterface("localhost:50052", client_id=51, device_id=0)
cli.bind_pipeline_config(PROG)
info = cli.bfrt_info_get(PROG)
tgt = gc.Target(device_id=0, pipe_id=0xFFFF)
gate = info.table_get("pipe.Ingress.tbl_health_gate")

def key_for(src, dst, spray, ctx):
    return gate.make_key([gc.KeyTuple("md.src_leaf", src), gc.KeyTuple("md.dst_leaf", dst),
                          gc.KeyTuple("md.spray_idx", spray), gc.KeyTuple("md.ctx", ctx)])

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", PORT)); srv.listen(4)
print("gate_agent listening on %d, bound to %s" % (PORT, PROG), flush=True)

while True:
    conn, _ = srv.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        buf = conn.recv(256).decode().strip()
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
                elif f[0] == "D":
                    src, dst, spray, ctx = (int(x) for x in f[1:5])
                    gate.entry_del(tgt, [key_for(src, dst, spray, ctx)])
                elif f[0] == "R":
                    def rd(reg, fld):
                        tt = info.table_get(reg); out = {}
                        for d, k in tt.entry_get(tgt, None, {"from_hw": True}):
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
