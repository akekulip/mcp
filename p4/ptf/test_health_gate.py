"""Hostile PTF for the behavioural health gate (P2).

WHAT THE GATE IS FOR. Behavioural sublinks are only worth having if the fabric can keep using the
parts of a link that are still proven good. This table does that: when a
(source, destination, spray path, context) sublink is quarantined, the packet's SPRAY CHOICE is
rewritten to a prevalidated backup, and `tbl_vlink` then resolves and counts the path actually
taken.

WHY IT SITS BEFORE `tbl_vlink`. `tbl_vlink` is the counted table. Overriding forwarding downstream
of it would leave the ground-truth counter naming a link the packet never used — corrupting
exactly the evidence the witness exists to provide. Test 43 is the one that would catch that
mistake, by reading the stamped link id off the wire rather than trusting the table.

The gate conditions from `docs/review/BEHAVIORAL-SUBLINK-PLAN.md` P2, one test each: bad-context
reroute, healthy-context continued use of the same physical link, no loops or black holes,
accurate post-reroute counters, and no action on a packet with no entry.
"""
import ptf.testutils as testutils
from ptf.testutils import send_packet
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
from scapy.all import Ether, IP, UDP, Raw, bind_layers, Packet
from scapy.fields import ShortField, ByteField, IntField

PROG = "mcp_fabric_gate"

ETYPE_MCP_FABRIC, ETYPE_IPV4 = 0x88F0, 0x0800
NXT_IPV4, NXT_CSIG = 0, 1
ROLE_HOST, ROLE_LOOP = 1, 2
HOST0_PORT, HOST1_PORT, LOOP_A, LOOP_B = 0, 1, 2, 3
ENABLE_PORTS = (0, 1, 2, 3)
VLINK_A, VLINK_B = 20, 21          # spray 0 -> LOOP_A/vlink 20, spray 1 -> LOOP_B/vlink 21
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


def host_pkt(size, dscp):
    """A plain host packet; the source leaf classifies it into a capsule context."""
    pay = max(size - 34, 0)
    return (Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01", type=ETYPE_IPV4) /
            IP(src="10.0.1.1", dst="10.0.1.2", tos=dscp << 2) /
            UDP(sport=1234, dport=4791, chksum=0) / Raw(b"\x00" * pay))


class GateBase(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, 0, PROG)
        self.tgt = gc.Target(device_id=0, pipe_id=0xffff)
        self.bfrt = self.interface.bfrt_info_get(PROG)
        self._ports(); self._roles(); self._classifier(); self._fabric()
        self._clear_gate()

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
                         (LOOP_A, ROLE_LOOP), (LOOP_B, ROLE_LOOP)):
            self._upsert(t, t.make_key([gc.KeyTuple("ig_intr_md.ingress_port", dp)]),
                         t.make_data([gc.DataTuple("role", role), gc.DataTuple("src_leaf", 0)],
                                     "Ingress.set_role"))

    def _classifier(self):
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

    def _fabric(self):
        b = self.bfrt
        # pin the spray choice: round robin with mask 0 always selects path 0, so any change of
        # egress port in these tests is the GATE's doing and nothing else
        t = b.table_get("pipe.Ingress.tbl_spray_mode")
        self._upsert(t, t.make_key([gc.KeyTuple("md.role", ROLE_HOST), gc.KeyTuple("md.hop", 0)]),
                     t.make_data([gc.DataTuple("mask", 0)], "Ingress.spray_from_rr"))
        t = b.table_get("pipe.Ingress.tbl_dst_leaf")
        self._upsert(t, t.make_key([gc.KeyTuple("hdr.ipv4.dst_addr", 0x0A000102)]),
                     t.make_data([gc.DataTuple("dst_leaf", 0), gc.DataTuple("path_base", 0)],
                                 "Ingress.set_dst"))
        t = b.table_get("pipe.Ingress.tbl_vlink")
        for spray, (vl, port) in enumerate(((VLINK_A, LOOP_A), (VLINK_B, LOOP_B))):
            self._upsert(t, t.make_key([gc.KeyTuple("md.role", ROLE_HOST), gc.KeyTuple("md.hop", 0),
                                        gc.KeyTuple("md.src_leaf", 0), gc.KeyTuple("md.dst_leaf", 0),
                                        gc.KeyTuple("md.spray_idx", spray)]),
                         t.make_data([gc.DataTuple("vlink_id", vl), gc.DataTuple("loop_port", port),
                                      gc.DataTuple("qid", 0), gc.DataTuple("next_vsw", 16),
                                      gc.DataTuple("path_id", vl)], "Ingress.to_loop"))
        t = b.table_get("pipe.Ingress.tbl_final")
        self._upsert(t, t.make_key([gc.KeyTuple("md.role", ROLE_HOST), gc.KeyTuple("md.hop", 0),
                                    gc.KeyTuple("md.dst_leaf", 0)]),
                     t.make_data([gc.DataTuple("next_hop", 1), gc.DataTuple("epoch", 0)],
                                 "Ingress.act_enter"))
        t = b.table_get("pipe.Egress.tbl_eg_vlink")
        for vl, port in ((VLINK_A, LOOP_A), (VLINK_B, LOOP_B)):
            self._upsert(t, t.make_key([gc.KeyTuple("eg_intr_md.egress_port", port),
                                        gc.KeyTuple("eg_intr_md.egress_qid", 0)]),
                         t.make_data([gc.DataTuple("vlink", vl),
                                      gc.DataTuple("vlink_base", vl << 4)], "Egress.set_eg_vlink"))

    def _clear_gate(self):
        t = self.bfrt.table_get("pipe.Ingress.tbl_health_gate")
        try:
            for data, key in t.entry_get(self.tgt, None, {"from_hw": False}):
                if key is not None:
                    t.entry_del(self.tgt, [key])
        except Exception:
            pass

    def quarantine(self, ctx, spray=0, alt=1):
        """Quarantine ONE behavioural sublink: the entry's presence IS the quarantine."""
        t = self.bfrt.table_get("pipe.Ingress.tbl_health_gate")
        self._upsert(t, t.make_key([gc.KeyTuple("md.src_leaf", 0), gc.KeyTuple("md.dst_leaf", 0),
                                    gc.KeyTuple("md.spray_idx", spray), gc.KeyTuple("md.ctx", ctx)]),
                     t.make_data([gc.DataTuple("alt_spray", alt)], "Ingress.sublink_reroute"))

    def send_host(self, size, dscp):
        """-> (egress port, stamped link_id) for one host packet."""
        send_packet(self, HOST0_PORT, host_pkt(size, dscp))
        (_, port, raw, _) = testutils.dp_poll(self, timeout=2)
        assert raw is not None, "packet was black-holed: no egress at all"
        return port, Ether(raw)[Wit].link_id


class Test40NoEntryMeansNoAction(GateBase):
    """A context with no gate entry must be untouched: same physical link, no reroute."""
    def runTest(self):
        port, link_id = self.send_host(1500, 0x00)
        self.assertEqual(port, LOOP_A, "an unquarantined context must keep its spray choice")
        self.assertEqual(link_id >> 4, VLINK_A, "and be counted on the link it actually used")


class Test41BadContextIsRerouted(GateBase):
    """Quarantining one context reroutes exactly that context to the prevalidated backup."""
    def runTest(self):
        ctx = ctx_of(2, 0)                        # 1024..2047 B, class 0
        self.quarantine(ctx, spray=0, alt=1)
        port, link_id = self.send_host(1500, 0x00)
        self.assertEqual(port, LOOP_B, "the quarantined sublink must take the backup path")
        self.assertEqual(link_id >> 4, VLINK_B, "and be counted on the backup link")


class Test42HealthyContextKeepsTheSamePhysicalLink(GateBase):
    """THE POINT OF THE ABSTRACTION. With one context quarantined, a different context of the
    SAME physical link must still use it — that retained capacity is the whole contribution."""
    def runTest(self):
        bad = ctx_of(2, 0)
        self.quarantine(bad, spray=0, alt=1)
        p_bad, l_bad = self.send_host(1500, 0x00)          # quarantined context
        p_ok, l_ok = self.send_host(1500, 0x08)            # same size, different class
        p_ok2, l_ok2 = self.send_host(100, 0x00)           # same class, different size
        self.assertEqual(p_bad, LOOP_B, "the bad context reroutes")
        self.assertEqual(p_ok, LOOP_A, "a different service class keeps the original link")
        self.assertEqual(p_ok2, LOOP_A, "a different size bin keeps the original link")
        self.assertEqual(l_ok >> 4, VLINK_A)
        self.assertEqual(l_ok2 >> 4, VLINK_A)


class Test43CountersNameThePathActuallyTaken(GateBase):
    """The gate runs BEFORE the counted table, so the stamped link id must name the link the
    packet really left by. If the gate were applied after tbl_vlink this test fails, and the
    witness evidence would be attributed to the wrong link."""
    def runTest(self):
        ctx = ctx_of(3, 0)
        self.quarantine(ctx, spray=0, alt=1)
        port, link_id = self.send_host(4096, 0x00)
        self.assertEqual(port, LOOP_B)
        self.assertEqual(link_id >> 4, VLINK_B,
                         "the witness must be stamped with the REROUTED link, not the original")
        self.assertEqual(link_id & 0xF, ctx, "and keep the capsule context intact across reroute")


class Test44RevocationRestoresTheLink(GateBase):
    """Quarantine is the presence of an entry, so deleting it restores the sublink — no timers,
    no separate un-quarantine path to get wrong."""
    def runTest(self):
        ctx = ctx_of(2, 0)
        self.quarantine(ctx, spray=0, alt=1)
        self.assertEqual(self.send_host(1500, 0x00)[0], LOOP_B, "quarantined")
        self._clear_gate()
        port, link_id = self.send_host(1500, 0x00)
        self.assertEqual(port, LOOP_A, "deleting the entry restores the original path")
        self.assertEqual(link_id >> 4, VLINK_A, "and the counter follows it back")
