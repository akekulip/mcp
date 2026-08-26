"""PTF functional tests for mcp_fabric (steps 1-4).

STATUS: SKELETON. **NOT RUN.** No tofino-model instance was brought up for this — the
workstation has zero veth pairs configured (`ip -o link show type veth` returned 0) and
`veth_setup.sh` needs sudo, and the direct `bf-p4c` build in p4/ is NOT installed into
`$SDE_INSTALL/share/p4/targets/tofino/`, which is where `run_switchd.sh -p mcp_fabric`
looks for `mcp_fabric.conf`. Everything below is therefore unverified: table, key and
action names come from `mcp_fabric.bfrt.json` (grep-verified against the compiled
schema), but no assertion here has ever executed.

To bring it up (all four steps needed, first two want sudo):
    sudo $SDE/install/bin/veth_setup.sh
    # make the artifacts visible to run_switchd: copy p4/mcp_fabric.tofino +
    # p4/mcp_fabric.bfrt.json + a conf into $SDE_INSTALL/share/p4/targets/tofino/,
    # or run bf_switchd directly with --conf-file pointing at
    # p4/mcp_fabric.tofino/mcp_fabric.conf (its paths are relative to p4/).
    $SDE/run_tofino_model.sh -p mcp_fabric --arch tofino -f p4/ptf/ports.json &
    $SDE/run_switchd.sh -p mcp_fabric --arch tofino &
    $SDE/run_p4_tests.sh -p mcp_fabric -t p4/ptf --arch tofino

CAVEAT carried forward from §9.2, and it must stay in this file: **the software model
accepts some control-plane writes that the ASIC rejects** — symmetric-table writes in
particular behave differently between pipe_id=0 and pipe_id=0xffff on hardware. A model
PASS is necessary, not sufficient.

------------------------------------------------------------------------------
Why these tests use veth-backed dev_ports and not dp9/dp68/dp8
------------------------------------------------------------------------------
Port ROLES are table-driven (`tbl_port_role`), so the fabric does not care which
dev_port is the host and which is a loop port. On the model we therefore map:

    dev_port 0 -> leaf 0's host       (dp9  on hardware)
    dev_port 1 -> leaf 1's host       (dp65 on hardware)
    dev_port 2 -> the "uplink" loop   (dp68 on hardware, an internal recirc port)
    dev_port 3 -> the "downlink" loop (dp8  on hardware, MAC-near loopback)

This deliberately breaks the loop open: instead of the packet recirculating invisibly,
each pass leaves on the loop veth where PTF can inspect it, and the test re-injects it
for the next pass. That tests the per-pass logic exactly, and it sidesteps the open
question of whether the model recirculates dev_port 68 the way silicon does — which is
a HARDWARE question anyway (§10.4).
"""
import struct

import ptf.testutils as testutils
from ptf.testutils import send_packet, verify_packet, verify_no_packet_any
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
from scapy.all import Ether, IP, UDP, Raw, bind_layers, Packet
from scapy.fields import ByteField, ShortField, IntField

PROG = "mcp_fabric"

# Model dev_ports (see module docstring). On hardware these become 9 / 65 / 68 / 8.
HOST0_PORT = 0
HOST1_PORT = 1
LOOP_UP_PORT = 2
LOOP_DN_PORT = 3
ENABLE_PORTS = (0, 1, 2, 3)

ETYPE_MCP_FABRIC = 0x88F0
ETYPE_IPV4 = 0x0800
NXT_IPV4, NXT_CSIG = 0, 1

ROLE_OTHER, ROLE_HOST, ROLE_LOOP, ROLE_NIC = 0, 1, 2, 3
LAST_HOP = 2
N_LEAF, N_SPINE = 2, 4
SPRAY_MASK = N_SPINE - 1
VSW_SPINE_BASE = 16

LEAF0_IP = "10.0.1.1"
LEAF1_IP = "10.0.1.2"
HOST_IPS = {LEAF0_IP: 0, LEAF1_IP: 1}

ETH_SRC = "00:00:00:00:00:01"
ETH_DST = "00:00:00:00:00:02"


class FabricShim(Packet):
    """The 6-byte fabric_h from mcp_fabric.p4."""
    name = "FabricShim"
    fields_desc = [
        ByteField("vsw_id", 0),
        ByteField("hop", 0),
        ByteField("spray", 0),
        ByteField("loops", 0),
        ByteField("flags", 0),
        ByteField("nxt", NXT_IPV4),
    ]


bind_layers(Ether, FabricShim, type=ETYPE_MCP_FABRIC)
bind_layers(FabricShim, IP, nxt=NXT_IPV4)


def host_pkt(src_ip=LEAF0_IP, dst_ip=LEAF1_IP, sport=1234, dport=4791, plen=64):
    """A RoCEv2-shaped packet as the NIC would spray it: the per-packet entropy is the
    UDP SOURCE PORT (§4 B2)."""
    return (Ether(dst=ETH_DST, src=ETH_SRC, type=ETYPE_IPV4) /
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=sport, dport=dport, chksum=0) /
            Raw(b"\x00" * plen))


def fabric_pkt(hop, spray, vsw, src_ip=LEAF0_IP, dst_ip=LEAF1_IP, sport=1234):
    """A packet as it looks coming back off a loop port."""
    return (Ether(dst=ETH_DST, src=ETH_SRC, type=ETYPE_MCP_FABRIC) /
            FabricShim(vsw_id=vsw, hop=hop, spray=spray, nxt=NXT_IPV4) /
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=sport, dport=4791, chksum=0) /
            Raw(b"\x00" * 64))


def ip2int(ip):
    return struct.unpack("!I", bytes(int(x) for x in ip.split(".")))[0]


def vlink_up(leaf, spine):
    return leaf * N_SPINE + spine


def vlink_dn(spine, leaf):
    return 8 + spine * N_LEAF + leaf


def vlink_placement(v):
    return (LOOP_DN_PORT if (v & 0x8) else LOOP_UP_PORT), (v & 0x7)


class FabricTest(BfRuntimeTest):
    """Common setup: bring the model's ports up and program the 2x4 fabric.

    This mirrors p4/control/setup_skeleton.py but writes the MODEL port numbers, and
    deliberately does NOT touch the TM queue shapers — those are pipe_id=0 TM tables
    and are one of the things the model is known to treat differently from silicon.
    """

    def setUp(self):
        BfRuntimeTest.setUp(self, 0, PROG)
        self.tgt = gc.Target(device_id=0, pipe_id=0xffff)
        self.bfrt = self.interface.bfrt_info_get(PROG)
        self._enable_ports()
        self._program_fabric()

    def _enable_ports(self):
        port = self.bfrt.table_get("$PORT")
        for dp in ENABLE_PORTS:
            key = port.make_key([gc.KeyTuple("$DEV_PORT", dp)])
            data = port.make_data([gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
                                   gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
                                   gc.DataTuple("$PORT_ENABLE", bool_val=True)])
            try:
                port.entry_add(self.tgt, [key], [data])
            except Exception:
                port.entry_mod(self.tgt, [key], [data])

    def _upsert(self, t, key, data):
        try:
            t.entry_add(self.tgt, [key], [data])
        except Exception:
            t.entry_mod(self.tgt, [key], [data])

    def _program_fabric(self):
        b = self.bfrt

        t = b.table_get("pipe.Ingress.tbl_port_role")
        for dp, role, leaf in [(HOST0_PORT, ROLE_HOST, 0), (HOST1_PORT, ROLE_HOST, 1),
                               (LOOP_UP_PORT, ROLE_LOOP, 0), (LOOP_DN_PORT, ROLE_LOOP, 0)]:
            self._upsert(t,
                         t.make_key([gc.KeyTuple("ig_intr_md.ingress_port", dp)]),
                         t.make_data([gc.DataTuple("role", role),
                                      gc.DataTuple("src_leaf", leaf)], "Ingress.set_role"))

        t = b.table_get("pipe.Ingress.tbl_dst_leaf")
        for ip, leaf in HOST_IPS.items():
            self._upsert(t,
                         t.make_key([gc.KeyTuple("hdr.ipv4.dst_addr", ip2int(ip))]),
                         t.make_data([gc.DataTuple("dst_leaf", leaf),
                                      gc.DataTuple("path_base", leaf << 2)],
                                     "Ingress.set_dst"))

        t = b.table_get("pipe.Ingress.tbl_vlink")
        for leaf in range(N_LEAF):
            for dst in range(N_LEAF):
                for spine in range(N_SPINE):
                    v = vlink_up(leaf, spine)
                    port, qid = vlink_placement(v)
                    self._upsert(t,
                                 t.make_key([gc.KeyTuple("md.role", ROLE_HOST),
                                             gc.KeyTuple("md.hop", 0),
                                             gc.KeyTuple("md.src_leaf", leaf),
                                             gc.KeyTuple("md.dst_leaf", dst),
                                             gc.KeyTuple("md.spray_idx", spine)]),
                                 t.make_data([gc.DataTuple("vlink_id", v),
                                              gc.DataTuple("loop_port", port),
                                              gc.DataTuple("qid", qid),
                                              gc.DataTuple("next_vsw", VSW_SPINE_BASE + spine)],
                                             "Ingress.to_loop"))
        for dst in range(N_LEAF):
            for spine in range(N_SPINE):
                v = vlink_dn(spine, dst)
                port, qid = vlink_placement(v)
                self._upsert(t,
                             t.make_key([gc.KeyTuple("md.role", ROLE_LOOP),
                                         gc.KeyTuple("md.hop", 1),
                                         gc.KeyTuple("md.src_leaf", 0),
                                         gc.KeyTuple("md.dst_leaf", dst),
                                         gc.KeyTuple("md.spray_idx", spine)]),
                             t.make_data([gc.DataTuple("vlink_id", v),
                                          gc.DataTuple("loop_port", port),
                                          gc.DataTuple("qid", qid),
                                          gc.DataTuple("next_vsw", dst)],
                                         "Ingress.to_loop"))

        t = b.table_get("pipe.Ingress.tbl_final")
        for dst in range(N_LEAF):
            self._upsert(t,
                         t.make_key([gc.KeyTuple("md.role", ROLE_HOST),
                                     gc.KeyTuple("md.hop", 0),
                                     gc.KeyTuple("md.dst_leaf", dst)]),
                         t.make_data([gc.DataTuple("next_hop", 1)], "Ingress.act_enter"))
            self._upsert(t,
                         t.make_key([gc.KeyTuple("md.role", ROLE_LOOP),
                                     gc.KeyTuple("md.hop", 1),
                                     gc.KeyTuple("md.dst_leaf", dst)]),
                         t.make_data([gc.DataTuple("next_hop", 2)], "Ingress.act_transit"))
        for dst, port in [(0, HOST0_PORT), (1, HOST1_PORT)]:
            self._upsert(t,
                         t.make_key([gc.KeyTuple("md.role", ROLE_LOOP),
                                     gc.KeyTuple("md.hop", LAST_HOP),
                                     gc.KeyTuple("md.dst_leaf", dst)]),
                         t.make_data([gc.DataTuple("port", port)], "Ingress.act_deliver"))

        self.set_spray("hash")
        self.seed_rr()
        self.clear_fail()

    # ---- runtime knobs, same semantics as control/setup_skeleton.py ----

    def set_spray(self, mode):
        act = {"random": "Ingress.spray_from_random",
               "hash": "Ingress.spray_from_hash",
               "rr": "Ingress.spray_from_rr",
               "sel": "Ingress.spray_from_sel"}[mode]
        t = self.bfrt.table_get("pipe.Ingress.tbl_spray_mode")
        self._upsert(t,
                     t.make_key([gc.KeyTuple("md.role", ROLE_HOST), gc.KeyTuple("md.hop", 0)]),
                     t.make_data([gc.DataTuple("mask", SPRAY_MASK)], act))

    def seed_rr(self, value=0):
        r = self.bfrt.table_get("pipe.Ingress.reg_spray_rr")
        for i in range(64):
            r.entry_add(self.tgt,
                        [r.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])],
                        [r.make_data([gc.DataTuple("Ingress.reg_spray_rr.f1", value)])])

    def clear_fail(self):
        # entry_del with NO key list — range keys from entry_get do not round-trip
        # (sdnp_setup.py:62-72). Always re-read and verify.
        t = self.bfrt.table_get("pipe.Ingress.tbl_fail")
        if len(list(t.entry_get(self.tgt))):
            t.entry_del(self.tgt)
        assert len(list(t.entry_get(self.tgt))) == 0, "tbl_fail not empty after clear"

    def set_fail(self, vlink, pct, mode="drop"):
        t = self.bfrt.table_get("pipe.Ingress.tbl_fail")
        hi = int(65535 * pct / 100.0)
        self._upsert(t,
                     t.make_key([gc.KeyTuple("md.vlink_id", vlink),
                                 gc.KeyTuple("md.rnd_fail", low=0, high=hi),
                                 gc.KeyTuple("$MATCH_PRIORITY", 1)]),
                     t.make_data([], {"drop": "Ingress.inj_drop",
                                      "corrupt": "Ingress.inj_corrupt"}[mode]))

    def counter(self, table_name):
        t = self.bfrt.table_get(table_name)
        t.operations_execute(self.tgt, "SyncCounters")   # MANDATORY before the read
        out = {}
        for k, d in t.entry_get(self.tgt, flags={"from_hw": True}):
            out[str(k.to_dict())] = d.to_dict().get("$COUNTER_SPEC_PKTS")
        return out


class T1_EnterFabric(FabricTest):
    """A fresh host packet gets the shim, hop=1, and leaves on the uplink loop port."""

    def runTest(self):
        pkt = host_pkt()
        send_packet(self, HOST0_PORT, pkt)
        rx = testutils.verify_packet_any_port(self, None, [LOOP_UP_PORT])  # VERIFY: helper name
        # Expectations, to be asserted once the model is live:
        #   rx[Ether].type == ETYPE_MCP_FABRIC
        #   rx[FabricShim].hop == 1
        #   rx[FabricShim].spray in range(N_SPINE)
        #   rx[FabricShim].vsw_id == VSW_SPINE_BASE + rx[FabricShim].spray
        #   the IPv4 header is byte-identical to the one sent (L2 shim -> no checksum fixup)


class T2_SpineTransit(FabricTest):
    """hop 1 on a loop port -> hop 2 on the downlink loop port."""

    def runTest(self):
        for spine in range(N_SPINE):
            pkt = fabric_pkt(hop=1, spray=spine, vsw=VSW_SPINE_BASE + spine)
            send_packet(self, LOOP_UP_PORT, pkt)
            exp = fabric_pkt(hop=2, spray=spine, vsw=HOST_IPS[LEAF1_IP])
            verify_packet(self, exp, LOOP_DN_PORT)


class T3_DeliverAndStrip(FabricTest):
    """hop 2 -> the shim is removed, ethertype is restored, delivered to the dst leaf's
    host port. The delivered frame must be byte-identical to what T1 was given."""

    def runTest(self):
        orig = host_pkt()
        send_packet(self, LOOP_DN_PORT, fabric_pkt(hop=2, spray=0, vsw=1))
        verify_packet(self, orig, HOST1_PORT)


class T4_SpoofGuard(FabricTest):
    """§3 carriage detail 2: the fabric ethertype is internal-only. A frame carrying it
    that arrives on a HOST port is injected, not looped, and must be dropped."""

    def runTest(self):
        send_packet(self, HOST0_PORT, fabric_pkt(hop=1, spray=0, vsw=VSW_SPINE_BASE))
        verify_no_packet_any(self, None, ENABLE_PORTS)


class T5_BlackHole(FabricTest):
    """§7.5: delete the tbl_vlink row and the counted default action drops."""

    def runTest(self):
        t = self.bfrt.table_get("pipe.Ingress.tbl_vlink")
        t.entry_del(self.tgt, [t.make_key([gc.KeyTuple("md.role", ROLE_HOST),
                                           gc.KeyTuple("md.hop", 0),
                                           gc.KeyTuple("md.src_leaf", 0),
                                           gc.KeyTuple("md.dst_leaf", 1),
                                           gc.KeyTuple("md.spray_idx", 0)])])
        self.set_spray("rr")
        self.seed_rr(0)          # so the first packet deterministically picks spine 0
        send_packet(self, HOST0_PORT, host_pkt())
        verify_no_packet_any(self, None, ENABLE_PORTS)
        # and the default-action counter must show exactly 1 packet — that is the
        # ground truth §7.6 requires.


class T6_FailureInjection(FabricTest):
    """§7.1: 100 % drop on one virtual link drops every packet on that link and only
    that link, and fail_ctr counts each one exactly."""

    N = 20

    def runTest(self):
        self.set_spray("rr")
        self.seed_rr(0)
        self.set_fail(vlink_up(0, 0), 100.0, "drop")
        # With round-robin over 4 spines, N packets put N/4 on vlink 0.
        for i in range(self.N):
            send_packet(self, HOST0_PORT, host_pkt(sport=1000 + i))
        # expected: exactly N - N/4 packets out of LOOP_UP_PORT,
        #           tbl_fail's inj_drop row counts N/4.


class T7_CorruptChecksum(FabricTest):
    """§7.2 F1: the corrupt action writes a constant wrong UDP checksum, which the
    receiving NIC drops as if the ICRC were bad. Checks the CONSTANT write, which is
    what keeps this clear of the Class 6 silent ICE."""

    def runTest(self):
        self.set_spray("rr")
        self.seed_rr(0)
        self.set_fail(vlink_up(0, 0), 100.0, "corrupt")
        send_packet(self, HOST0_PORT, host_pkt())
        # expected on LOOP_UP_PORT with UDP.chksum == 0xBAD1 and fabric.flags == 2


class T8_SprayModes(FabricTest):
    """§4: hash mode is deterministic per 5-tuple; round-robin cycles 0,1,2,3."""

    def runTest(self):
        self.set_spray("hash")
        for _ in range(4):
            send_packet(self, HOST0_PORT, host_pkt(sport=4242))
        # expected: the same fabric.spray value on all four

        self.set_spray("rr")
        self.seed_rr(0)
        for i in range(4):
            send_packet(self, HOST0_PORT, host_pkt(sport=5000 + i))
        # expected: fabric.spray == 0, 1, 2, 3 in order — and once per PACKET, not
        # once per pass, which is why the draw is gated on hop == 0


class T9_SprayCarriedOnWire(FabricTest):
    """§4, the honesty clause: even in the unseeded Random mode the chosen index is on
    the wire, so a capture reconstructs the path. Random must still stay in [0, k)."""

    def runTest(self):
        self.set_spray("random")
        for i in range(32):
            send_packet(self, HOST0_PORT, host_pkt(sport=6000 + i))
        # expected: every fabric.spray in range(N_SPINE), and over 32 packets all four
        # values appear at least once
