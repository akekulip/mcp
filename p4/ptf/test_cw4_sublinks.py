"""PTF model tests for C-W4 — behavioural sublinks.

THE ABSTRACTION UNDER TEST. A physical link is not simply healthy or faulty: it can be healthy
for some packet contexts and faulty for others. CorrOpt measured corruption present in both
directions on only 8.2 % of corrupting links yet disabled both, because its hardware could not
express a unidirectional decision. Aegis hit a production fault that dropped only packets larger
than 1 KB while its 64-byte probes saw nothing. So the resource worth tracking is the
BEHAVIOURAL SUBLINK = (directed link x context stratum), not the link.

WHAT C-W4 CHANGES, AND WHAT IT DOES NOT. The wire header is unchanged — `wit_h.link_id` is
already 16 bits and 64 links need 6, so the stratum rides in the low nibble:

    link_id[15:4] = directed vlink        link_id[3:0] = stratum

The downstream check is also unchanged: it already indexes `reg_wit_expect` by the whole 16-bit
field it receives, so it becomes per-sublink the moment the upstream composes the id. Only the
egress gains a classifier on `eg_intr_md.pkt_length`, and the two registers grow 64 -> 1024 cells.
Ingress on Tofino 1 has no packet-length intrinsic, which is exactly why the upstream labels and
the downstream trusts the label — a corrupted label appears as a gap in the WRONG sublink, so it
is detectable rather than silent.

The claim these tests exist to check is the one the whole abstraction rests on: **a discontinuity
in one stratum must leave the other strata of the same physical link certified and usable.**
"""
import ptf.testutils as testutils
from ptf.testutils import send_packet
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
from scapy.all import Ether, IP, UDP, Raw, bind_layers, Packet
from scapy.fields import ShortField, ByteField, IntField

PROG = "mcp_fabric_cw4"

ETYPE_MCP_FABRIC = 0x88F0
NXT_IPV4, NXT_CSIG = 0, 1
ROLE_HOST, ROLE_LOOP = 1, 2
HOST0_PORT, HOST1_PORT, LOOP_UP_PORT, LOOP_DN_PORT = 0, 1, 2, 3
ENABLE_PORTS = (0, 1, 2, 3)
K_UP = 1024
STRATA = 16                      # low nibble of link_id
VLINK = 20                       # the directed link under test


def sublink(vlink, stratum):
    """The composed sequence index: exactly what the upstream stamps."""
    return (vlink << 4) | stratum


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


def wit_pkt(link_id, seq, path_id=0, plen=48):
    return (Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01", type=ETYPE_MCP_FABRIC) /
            FabricShim(hop=1, path_id=path_id, nxt=NXT_CSIG) /
            Csig(path_id=path_id) / Wit(link_id=link_id, seq=seq) /
            IP(src="10.0.1.1", dst="10.0.1.2") /
            UDP(sport=1234, dport=4791, chksum=0) / Raw(b"\x00" * plen))


class CtxBase(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, 0, PROG)
        self.tgt = gc.Target(device_id=0, pipe_id=0xffff)
        self.bfrt = self.interface.bfrt_info_get(PROG)
        self._ports()
        self._roles()
        self.set_k_up(K_UP)
        for i in range(0, 1024):
            self._reg_set("pipe.Ingress.reg_wit_expect", i, 0)

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

    def set_k_up(self, v):
        t = self.bfrt.table_get("pipe.Ingress.p_k_up")
        t.default_entry_set(self.tgt, t.make_data([gc.DataTuple("value", v)]))

    def _reg_set(self, name, idx, val):
        t = self.bfrt.table_get(name)
        field = "Ingress.reg_wit_expect.f1" if "expect" in name else "Egress.reg_wit_seq.f1"
        t.entry_add(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])],
                    [t.make_data([gc.DataTuple(field, val)])])

    def expect_of(self, idx):
        t = self.bfrt.table_get("pipe.Ingress.reg_wit_expect")
        t.operations_execute(self.tgt, "Sync")
        d = next(t.entry_get(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", idx)])],
                             {"from_hw": False}))[0].to_dict()
        v = d["Ingress.reg_wit_expect.f1"]
        return v[0] if isinstance(v, list) else v

    def attn_of(self, path):
        t = self.bfrt.table_get("pipe.Ingress.reg_attn")
        t.operations_execute(self.tgt, "Sync")
        d = next(t.entry_get(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", path)])],
                             {"from_hw": False}))[0].to_dict()
        a = d["Ingress.reg_attn.attn"]
        return a[0] if isinstance(a, list) else a

    def send(self, link_id, seq, path_id=0):
        send_packet(self, LOOP_UP_PORT, wit_pkt(link_id, seq, path_id))
        testutils.dp_poll(self, timeout=1)


class Test20SublinksAreIndependent(CtxBase):
    """Two strata of ONE physical link keep separate sequence spaces."""
    def runTest(self):
        small, large = sublink(VLINK, 0), sublink(VLINK, 3)
        for s in range(4):
            self.send(small, s)
            self.send(large, s)
        self.assertEqual(self.expect_of(small), 4, "small-packet sublink advanced on its own")
        self.assertEqual(self.expect_of(large), 4, "large-packet sublink advanced on its own")
        self.assertNotEqual(small, large, "the two sublinks must not share an index")


class Test21GapInOneStratumSparesTheOthers(CtxBase):
    """THE CLAIM. A discontinuity in the large-packet sublink must leave the small-packet
    sublink of the SAME physical link contiguous, certified and usable.

    This is what makes a behavioural sublink a resource rather than a bigger register: under
    ordinary W4 the gap condemns the whole directed link, and the Aegis fault (only packets
    over 1 KB are dropped) would strand the small-packet traffic that was never affected.
    """
    def runTest(self):
        small, large = sublink(VLINK, 0), sublink(VLINK, 3)
        for s in range(3):                       # both strata running clean
            self.send(small, s)
            self.send(large, s)
        a_before = self.attn_of(0)
        self.send(large, 5)                      # seq 3,4 lost in the LARGE stratum only
        self.assertEqual(self.expect_of(large), 6, "the large sublink resynchronises on the gap")
        self.assertEqual(self.attn_of(0), a_before + K_UP, "and the gap is reported")
        # the small sublink must be untouched and still usable
        self.assertEqual(self.expect_of(small), 3, "the small sublink must not be disturbed")
        a_mid = self.attn_of(0)
        for s in (3, 4, 5):
            self.send(small, s)
        self.assertEqual(self.expect_of(small), 6, "the small sublink keeps counting cleanly")
        self.assertEqual(self.attn_of(0), a_mid,
                         "a healthy stratum of a faulty link raises NO further event")


class Test22StratumIsCarriedWithoutExtraBytes(CtxBase):
    """The stratum rides in the spare bits of the existing 16-bit link_id: no wire cost."""
    def runTest(self):
        # len(pkt[Wit]) counts the payload too; the header itself is what must stay 4 bytes
        self.assertEqual(len(bytes(Wit())), 4, "the witness header must stay 4 bytes")
        a = len(bytes(wit_pkt(sublink(VLINK, 0), 0)))
        b = len(bytes(wit_pkt(sublink(VLINK, 3), 0)))
        self.assertEqual(a, b, "carrying a different stratum must not change the packet size")
        for st in (0, 1, 2, 3):
            idx = sublink(VLINK, st)
            self.assertEqual(idx >> 4, VLINK, "the high half must decode to the directed vlink")
            self.assertEqual(idx & 0xF, st, "the low nibble must decode to the stratum")
            self.send(idx, 0)
            self.assertEqual(self.expect_of(idx), 1, f"stratum {st} has its own sequence space")
