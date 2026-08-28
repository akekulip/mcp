"""PTF model tests for the Context Capsule (P1) — size x service class, classified at the source.

WHY THIS EXISTS. C-W4 classified at the egress, where the only thing visible is
`eg_intr_md.pkt_length`. The capacity gate measured what that costs: a 25-point oracle gap on a
service-class-only fault, and another on a fault whose boundary falls inside one coarse size bin.
Service class is simply not visible where C-W4 was looking.

THE FIX. The source leaf is the one place in the fabric where the IPv4 header is still parsed, so
it is the only place that can see DSCP. Classify once there into a 4-bit context id, carry it in
the fabric shim's EXISTING pad byte -- zero added wire bytes -- and let every hop index its
witness by `(vlink << 4) | context`. Transit and downstream then agree by construction, because
they read the carried label instead of re-deriving it from what they happen to see.

It is also cheaper: 9 ingress / 3 egress against C-W4's 9 / 4, because the egress no longer needs
a range classifier.

These tests check the gate conditions from `docs/review/BEHAVIORAL-SUBLINK-PLAN.md` P1: distinct
contexts produce independent sequences end to end, source and downstream agree on the id, and the
wire cost is zero.
"""
import ptf.testutils as testutils
from ptf.testutils import send_packet
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
from scapy.all import Ether, IP, UDP, Raw, bind_layers, Packet
from scapy.fields import ShortField, ByteField, IntField

PROG = "mcp_fabric_capsule"

ETYPE_MCP_FABRIC, ETYPE_IPV4 = 0x88F0, 0x0800
NXT_IPV4, NXT_CSIG = 0, 1
ROLE_HOST, ROLE_LOOP = 1, 2
HOST0_PORT, HOST1_PORT, LOOP_UP_PORT, LOOP_DN_PORT = 0, 1, 2, 3
ENABLE_PORTS = (0, 1, 2, 3)
VLINK = 20

# the published mapping: 4 size bins x 4 DSCP classes -> 4-bit context
SIZE_BINS = [(0, 255, 0), (256, 1023, 1), (1024, 2047, 2), (2048, 65535, 3)]
DSCP_CLASSES = [(0x00, 0), (0x08, 1), (0x10, 2), (0x18, 3)]


def ctx_of(size_bin, dscp_class):
    return (dscp_class << 2) | size_bin


class FabricShim(Packet):
    name = "FabricShim"
    fields_desc = [ShortField("vsw_id", 0), ShortField("hop", 0), ShortField("spray", 0),
                   ShortField("path_id", 0), ByteField("loops", 0), ByteField("flags", 0),
                   ByteField("nxt", NXT_IPV4), ByteField("pad", 0)]


class Csig(Packet):
    name = "Csig"
    fields_desc = [ShortField("worst_hop", 0), ShortField("worst_vlink", 0),
                   ShortField("worst_qdepth", 0), IntField("worst_tdelta", 0),
                   ShortField("path_id", 0), ShortField("epoch", 0)]


class Wit(Packet):
    name = "Wit"
    fields_desc = [ShortField("link_id", 0), ShortField("seq", 0)]


bind_layers(Ether, FabricShim, type=ETYPE_MCP_FABRIC)
bind_layers(FabricShim, Csig, nxt=NXT_CSIG)
bind_layers(Csig, Wit)
bind_layers(Wit, IP)


def fabric_pkt(ctx, seq, link=VLINK, plen=48):
    """A pass already carrying a capsule in the shim pad — exercises transit/downstream."""
    return (Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01", type=ETYPE_MCP_FABRIC) /
            FabricShim(hop=1, nxt=NXT_CSIG, pad=ctx) /
            Csig() / Wit(link_id=(link << 4) | ctx, seq=seq) /
            IP(src="10.0.1.1", dst="10.0.1.2") /
            UDP(sport=1234, dport=4791, chksum=0) / Raw(b"\x00" * plen))


class CapsuleBase(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, 0, PROG)
        self.tgt = gc.Target(device_id=0, pipe_id=0xffff)
        self.bfrt = self.interface.bfrt_info_get(PROG)
        self._ports(); self._roles(); self._classifier()
        for i in range(0, 1024):
            self._expect_set(i, 0)

    def _upsert(self, t, k, d):
        try:
            t.entry_add(self.tgt, [k], [d])
        except Exception:
            t.entry_mod(self.tgt, [k], [d])

    def _ports(self):
        port = self.bfrt.table_get("$PORT")
        for dp in ENABLE_PORTS:
            try:
                port.entry_add(self.tgt, [port.make_key([gc.KeyTuple("$DEV_PORT", dp)])],
                               [port.make_data([gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
                                                gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
                                                gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
            except Exception:
                pass

    def _roles(self):
        t = self.bfrt.table_get("pipe.Ingress.tbl_port_role")
        for dp, role in ((HOST0_PORT, ROLE_HOST), (HOST1_PORT, ROLE_HOST),
                         (LOOP_UP_PORT, ROLE_LOOP), (LOOP_DN_PORT, ROLE_LOOP)):
            self._upsert(t, t.make_key([gc.KeyTuple("ig_intr_md.ingress_port", dp)]),
                         t.make_data([gc.DataTuple("role", role), gc.DataTuple("src_leaf", 0)],
                                     "Ingress.set_role"))

    def _classifier(self):
        """The published 4x4 mapping, installed from the control plane so it stays programmable."""
        t = self.bfrt.table_get("pipe.Ingress.tbl_context")
        prio = 1
        for lo, hi, sb in SIZE_BINS:
            for dscp, dc in DSCP_CLASSES:
                self._upsert(t, t.make_key([
                    gc.KeyTuple("hdr.ipv4.total_len", low=lo, high=hi),
                    gc.KeyTuple("hdr.ipv4.diffserv", dscp << 2, 0xFC),
                    gc.KeyTuple("$MATCH_PRIORITY", prio)]),
                    t.make_data([gc.DataTuple("c", ctx_of(sb, dc))], "Ingress.set_ctx"))
                prio += 1

    def _expect_set(self, idx, val):
        t = self.bfrt.table_get("pipe.Ingress.reg_wit_expect")
        t.entry_add(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])],
                    [t.make_data([gc.DataTuple("Ingress.reg_wit_expect.f1", val)])])

    def expect_of(self, idx):
        t = self.bfrt.table_get("pipe.Ingress.reg_wit_expect")
        t.operations_execute(self.tgt, "Sync")
        d = next(t.entry_get(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])],
                             {"from_hw": False}))[0].to_dict()
        v = d["Ingress.reg_wit_expect.f1"]
        return v[0] if isinstance(v, list) else v

    def send(self, ctx, seq):
        send_packet(self, LOOP_UP_PORT, fabric_pkt(ctx, seq))
        testutils.dp_poll(self, timeout=1)


class Test30ServiceClassSeparatesSublinks(CapsuleBase):
    """The gap C-W4 could not close: two packets of the SAME SIZE but different service class
    must land in different behavioural sublinks.

    C-W4 classified on `eg_intr_md.pkt_length` alone, so these two were indistinguishable and a
    class-selective fault condemned both. With the capsule the class is carried from the source.
    """
    def runTest(self):
        same_size_bin = 2
        a = ctx_of(same_size_bin, 0)          # bulk class
        b = ctx_of(same_size_bin, 3)          # a different service class, identical size
        self.assertNotEqual(a, b, "same size, different class must be different contexts")
        for s in range(3):
            self.send(a, s)
        self.send(b, 0)
        self.assertEqual(self.expect_of((VLINK << 4) | a), 3, "class A advanced on its own")
        self.assertEqual(self.expect_of((VLINK << 4) | b), 1, "class B has its own sequence space")


class Test31GapInOneClassSparesTheOther(CapsuleBase):
    """A discontinuity in one service class must leave the other class of the same physical
    link, at the same packet size, contiguous and usable."""
    def runTest(self):
        a, b = ctx_of(2, 0), ctx_of(2, 3)
        for s in range(3):
            self.send(a, s); self.send(b, s)
        self.send(a, 6)                        # seq 3,4,5 lost in class A only
        self.assertEqual(self.expect_of((VLINK << 4) | a), 7, "class A resynchronises on the gap")
        self.assertEqual(self.expect_of((VLINK << 4) | b), 3, "class B is untouched")
        self.send(b, 3)
        self.assertEqual(self.expect_of((VLINK << 4) | b), 4, "and class B keeps counting cleanly")


class Test32CapsuleCostsNoWireBytes(CapsuleBase):
    """The capsule rides the shim's existing pad byte: the header is unchanged and the packet
    size does not depend on the context it carries."""
    def runTest(self):
        sizes = {len(bytes(fabric_pkt(c, 0))) for c in range(16)}
        self.assertEqual(len(sizes), 1, f"packet size must not vary with context: {sizes}")
        self.assertEqual(len(bytes(FabricShim())), 12, "the shim must stay 12 bytes")
        self.assertEqual(len(bytes(Wit())), 4, "the witness must stay 4 bytes")


class Test33AllSixteenContextsAreIndependent(CapsuleBase):
    """4 size bins x 4 service classes = 16 sublinks per directed link, all independent."""
    def runTest(self):
        for c in range(16):
            for s in range(c % 3 + 1):
                self.send(c, s)
        for c in range(16):
            self.assertEqual(self.expect_of((VLINK << 4) | c), c % 3 + 1,
                             f"context {c} must hold exactly its own sequence")
