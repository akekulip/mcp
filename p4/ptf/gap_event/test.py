"""PTF model proofs for the P3 attributed event and audit-receipt paths.

The notification must be forced for every nonzero discontinuity, carry the exact behavioral
sublink and epoch, report the number of arrivals since the prior discontinuity, and remain silent
for contiguous traffic. The audit proof additionally requires production to obey quarantine while
a declared audit bypasses it, and requires the receipt to appear only after downstream arrival.
Session 2 is deliberately separate from probabilistic attention sampling.
"""
import struct

import bfrt_grpc.client as gc
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
from ptf.testutils import send_packet
from scapy.all import ByteField, Ether, IP, IntField, Packet, Raw, ShortField, UDP, bind_layers


PROG = "mcp_fabric_gate_event"
ETYPE_MCP_FABRIC = 0x88F0
ETYPE_MCP_MIRROR = 0x88F1
NXT_CSIG = 1
ROLE_HOST, ROLE_LOOP = 1, 2
HOST_IN, HOST_OUT, LOOP_IN, COLLECTOR, LOOP_B = 0, 1, 2, 3, 4
SUBLINK = (2 << 4) | 3
EPOCH = 77
GAP_EVENT_FLAG = 0x8
AUDIT_RECEIPT_FLAG = 0x10
AUDIT_UDP_DST = 4792
AUDIT_TOKEN, MISSING_TOKEN = 40001, 40002
AUDIT_VLINK, BACKUP_VLINK, TRANSIT_VLINK = 2, 3, 8
AUDIT_SUBLINK = AUDIT_VLINK << 4


class FabricShim(Packet):
    name = "FabricShim"
    fields_desc = [ShortField("vsw_id", 0), ShortField("hop", 2), ShortField("spray", 0),
                   ShortField("path_id", 0), ByteField("loops", 0), ByteField("flags", 0),
                   ByteField("nxt", NXT_CSIG), ByteField("pad", 3)]


class Csig(Packet):
    name = "Csig"
    fields_desc = [ShortField("worst_hop", 0), ShortField("worst_vlink", 0),
                   ShortField("worst_qdepth", 0), IntField("worst_tdelta", 0),
                   ShortField("path_id", 0), ShortField("epoch", EPOCH)]


class Wit(Packet):
    name = "Wit"
    fields_desc = [ShortField("link_id", SUBLINK), ShortField("seq", 0)]


bind_layers(Ether, FabricShim, type=ETYPE_MCP_FABRIC)
bind_layers(FabricShim, Csig, nxt=NXT_CSIG)
bind_layers(Csig, Wit)
bind_layers(Wit, IP)


def witness_packet(seq):
    return (Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01",
                  type=ETYPE_MCP_FABRIC) /
            FabricShim(hop=2, nxt=NXT_CSIG, pad=3) /
            Csig(epoch=EPOCH) / Wit(link_id=SUBLINK, seq=seq) /
            IP(src="10.0.1.1", dst="10.0.1.2") /
            UDP(sport=1234, dport=4791, chksum=0) / Raw(b"x" * 24))


def host_packet(sport, dport):
    return (Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01", type=0x0800) /
            IP(src="10.0.1.1", dst="10.0.1.2") /
            UDP(sport=sport, dport=dport, chksum=0) / Raw(b"a" * 64))


def decode_event(raw):
    """Fixed-offset decoder for the unchanged 30-byte mirror header and copied W4 frame."""
    if raw is None or len(raw) < 74:
        raise AssertionError("event copy is absent or truncated before the witness")
    if struct.unpack_from("!H", raw, 12)[0] != ETYPE_MCP_MIRROR:
        raise AssertionError("collector packet is not an MCP mirror copy")
    next_hop, sublink, gap, prior_arrivals, flags = struct.unpack_from("!HHHHH", raw, 14)
    inner_epoch = struct.unpack_from("!H", raw, 68)[0]
    inner_link, inner_seq = struct.unpack_from("!HH", raw, 70)
    return {"next_hop": next_hop, "sublink": sublink, "gap": gap,
            "observed_packets": prior_arrivals + 1, "flags": flags,
            "epoch": inner_epoch, "inner_link": inner_link, "inner_seq": inner_seq}


def decode_audit_receipt(raw):
    event = decode_event(raw)
    if len(raw) < 98:
        raise AssertionError("audit receipt is truncated before the copied UDP identity")
    event["udp_src"], event["udp_dst"] = struct.unpack_from("!HH", raw, 94)
    return event


class GapEventBase(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, 0, PROG)
        self.tgt = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.bfrt = self.interface.bfrt_info_get(PROG)
        self._ports()
        self._roles()
        self._delivery()
        self._mirror()
        self._reg_set("pipe.Ingress.reg_wit_expect", SUBLINK, 0)
        self._reg_set("pipe.Ingress.reg_wit_observed", SUBLINK, 0)

    def _upsert(self, table, key, data):
        try:
            table.entry_add(self.tgt, [key], [data])
        except gc.BfruntimeRpcException:
            table.entry_mod(self.tgt, [key], [data])

    def _ports(self):
        table = self.bfrt.table_get("$PORT")
        for port in (HOST_IN, HOST_OUT, LOOP_IN, COLLECTOR, LOOP_B):
            key = table.make_key([gc.KeyTuple("$DEV_PORT", port)])
            data = table.make_data([gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
                                    gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
                                    gc.DataTuple("$PORT_ENABLE", bool_val=True)])
            self._upsert(table, key, data)

    def _roles(self):
        table = self.bfrt.table_get("pipe.Ingress.tbl_port_role")
        for port, role in ((HOST_IN, ROLE_HOST), (HOST_OUT, ROLE_HOST),
                           (LOOP_IN, ROLE_LOOP), (LOOP_B, ROLE_LOOP),
                           (COLLECTOR, ROLE_HOST)):
            key = table.make_key([gc.KeyTuple("ig_intr_md.ingress_port", port)])
            audit_src = int(port in (HOST_IN, LOOP_IN, LOOP_B))
            data = table.make_data([gc.DataTuple("role", role), gc.DataTuple("src_leaf", 0),
                                    gc.DataTuple("audit_src", audit_src)],
                                   "Ingress.set_role")
            self._upsert(table, key, data)

    def _delivery(self):
        table = self.bfrt.table_get("pipe.Ingress.tbl_final")
        key = table.make_key([gc.KeyTuple("md.role", ROLE_LOOP), gc.KeyTuple("md.hop", 2),
                              gc.KeyTuple("md.dst_leaf", 0)])
        data = table.make_data([gc.DataTuple("port", HOST_OUT)], "Ingress.act_deliver")
        self._upsert(table, key, data)

    def _mirror(self):
        table = self.bfrt.table_get("$mirror.cfg")
        key = table.make_key([gc.KeyTuple("$sid", 2)])
        data = table.make_data([gc.DataTuple("$direction", str_val="INGRESS"),
                                gc.DataTuple("$ucast_egress_port", COLLECTOR),
                                gc.DataTuple("$ucast_egress_port_valid", bool_val=True),
                                gc.DataTuple("$session_enable", bool_val=True),
                                gc.DataTuple("$max_pkt_len", 128)], "$normal")
        self._upsert(table, key, data)

    def _reg_set(self, name, index, value):
        table = self.bfrt.table_get(name)
        gress = name.split(".")[1]
        field = "%s.%s.f1" % (gress, name.rsplit(".", 1)[-1])
        key = table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])
        data = table.make_data([gc.DataTuple(field, value)])
        table.entry_add(self.tgt, [key], [data])

    def send(self, seq):
        send_packet(self, LOOP_IN, witness_packet(seq))

    def poll_event(self, timeout=0.25):
        _, _, raw, _ = testutils.dp_poll(self, device_number=0, port_number=COLLECTOR,
                                         timeout=timeout)
        return raw


class Test50OneForcedEventPerDiscontinuity(GapEventBase):
    def runTest(self):
        self.send(0)
        self.assertIsNone(self.poll_event(), "contiguous sequence start must not mirror")
        self.send(1)
        self.assertIsNone(self.poll_event(), "contiguous traffic must not mirror")

        self.send(4)  # expected 2: packets 2 and 3 are missing
        event = decode_event(self.poll_event(timeout=1))
        self.assertEqual(event["flags"] & GAP_EVENT_FLAG, GAP_EVENT_FLAG)
        self.assertEqual(event["sublink"], SUBLINK)
        self.assertEqual(event["inner_link"], SUBLINK,
                         "mirror attribution must agree with the copied witness")
        self.assertEqual(event["gap"], 0xFFFE)
        self.assertEqual(event["observed_packets"], 3,
                         "two prior arrivals plus the survivor that exposed the gap")
        self.assertEqual(event["epoch"], EPOCH)
        self.assertEqual(event["inner_seq"], 4)

        self.send(5)
        self.assertIsNone(self.poll_event(),
                          "the unconditional resynchronisation must prevent repeated events")


class Test51AuditBypassesQuarantineButReceiptsRequireArrival(GapEventBase):
    """Production reroutes; audit uses the quarantined primary; only arrival proves liveness."""

    def setUp(self):
        GapEventBase.setUp(self)
        self._program_audit_path()

    def _program_audit_path(self):
        b = self.bfrt
        t = b.table_get("pipe.Ingress.tbl_vlink")
        for spray, vlink, port in ((0, AUDIT_VLINK, LOOP_IN),
                                   (1, BACKUP_VLINK, LOOP_B)):
            key = t.make_key([
                gc.KeyTuple("md.role", ROLE_HOST), gc.KeyTuple("md.hop", 0),
                gc.KeyTuple("md.src_leaf", 0), gc.KeyTuple("md.dst_leaf", 0),
                gc.KeyTuple("md.spray_idx", spray)])
            data = t.make_data([
                gc.DataTuple("vlink_id", vlink), gc.DataTuple("loop_port", port),
                gc.DataTuple("qid", 0), gc.DataTuple("next_vsw", 16),
                gc.DataTuple("path_id", spray)], "Ingress.to_loop")
            self._upsert(t, key, data)
        key = t.make_key([
            gc.KeyTuple("md.role", ROLE_LOOP), gc.KeyTuple("md.hop", 1),
            gc.KeyTuple("md.src_leaf", 0), gc.KeyTuple("md.dst_leaf", 0),
            gc.KeyTuple("md.spray_idx", 0)])
        data = t.make_data([
            gc.DataTuple("vlink_id", TRANSIT_VLINK), gc.DataTuple("loop_port", HOST_OUT),
            gc.DataTuple("qid", 0), gc.DataTuple("next_vsw", 0),
            gc.DataTuple("path_id", 0)], "Ingress.to_loop")
        self._upsert(t, key, data)

        t = b.table_get("pipe.Ingress.tbl_final")
        self._upsert(t, t.make_key([
            gc.KeyTuple("md.role", ROLE_HOST), gc.KeyTuple("md.hop", 0),
            gc.KeyTuple("md.dst_leaf", 0)]),
            t.make_data([gc.DataTuple("next_hop", 1), gc.DataTuple("epoch", EPOCH)],
                        "Ingress.act_enter"))
        self._upsert(t, t.make_key([
            gc.KeyTuple("md.role", ROLE_LOOP), gc.KeyTuple("md.hop", 1),
            gc.KeyTuple("md.dst_leaf", 0)]),
            t.make_data([gc.DataTuple("next_hop", 2)], "Ingress.act_transit"))

        t = b.table_get("pipe.Egress.tbl_eg_vlink")
        for port, vlink in ((LOOP_IN, AUDIT_VLINK), (LOOP_B, BACKUP_VLINK),
                            (HOST_OUT, TRANSIT_VLINK)):
            self._upsert(t, t.make_key([
                gc.KeyTuple("eg_intr_md.egress_port", port),
                gc.KeyTuple("eg_intr_md.egress_qid", 0)]),
                t.make_data([gc.DataTuple("vlink", vlink),
                             gc.DataTuple("vlink_base", vlink << 4)],
                            "Egress.set_eg_vlink"))

        t = b.table_get("pipe.Ingress.tbl_health_gate")
        self._upsert(t, t.make_key([
            gc.KeyTuple("md.src_leaf", 0), gc.KeyTuple("md.dst_leaf", 0),
            gc.KeyTuple("md.spray_idx", 0), gc.KeyTuple("md.ctx", 0)]),
            t.make_data([gc.DataTuple("alt_spray", 1)], "Ingress.sublink_reroute"))

        t = b.table_get("pipe.Ingress.tbl_audit_steer")
        for token in (AUDIT_TOKEN, MISSING_TOKEN):
            self._upsert(t, t.make_key([
                gc.KeyTuple("md.audit_src", 1),
                gc.KeyTuple("hdr.udp.dst_port", AUDIT_UDP_DST),
                gc.KeyTuple("hdr.udp.src_port", token)]),
                t.make_data([gc.DataTuple("spray", 0)], "Ingress.set_audit_spray"))

        for sublink in (AUDIT_SUBLINK, BACKUP_VLINK << 4):
            self._reg_set("pipe.Egress.reg_wit_seq", sublink, 0)
        self._reg_set("pipe.Ingress.reg_wit_expect", AUDIT_SUBLINK, 0)
        self._reg_set("pipe.Ingress.reg_wit_observed", AUDIT_SUBLINK, 0)

    def _source_output(self, packet, port, ingress_port=HOST_IN):
        send_packet(self, ingress_port, packet)
        _, _, raw, _ = testutils.dp_poll(
            self, device_number=0, port_number=port, timeout=1)
        self.assertIsNotNone(raw, "source packet did not leave on the expected physical path")
        return raw

    def runTest(self):
        production = self._source_output(host_packet(1234, 4791), LOOP_B)
        self.assertEqual(Ether(production)[Wit].link_id, BACKUP_VLINK << 4,
                         "production in the quarantined context must use the backup")

        unauthorized = self._source_output(
            host_packet(AUDIT_TOKEN, AUDIT_UDP_DST), LOOP_B, ingress_port=COLLECTOR)
        self.assertEqual(
            Ether(unauthorized)[Wit].link_id,
            BACKUP_VLINK << 4,
            "an audit-shaped packet from an unauthorized host must not bypass quarantine",
        )

        audit = self._source_output(host_packet(AUDIT_TOKEN, AUDIT_UDP_DST), LOOP_IN)
        self.assertEqual(Ether(audit)[Wit].link_id, AUDIT_SUBLINK,
                         "the declared audit must exercise the quarantined primary")
        self.assertIsNone(self.poll_event(),
                          "the source must not manufacture a receipt before link traversal")

        send_packet(self, LOOP_IN, audit)
        receipt = decode_audit_receipt(self.poll_event(timeout=1))
        self.assertEqual(receipt["flags"] & AUDIT_RECEIPT_FLAG, AUDIT_RECEIPT_FLAG)
        self.assertEqual(receipt["flags"] & GAP_EVENT_FLAG, 0)
        self.assertEqual(receipt["sublink"], AUDIT_SUBLINK)
        self.assertEqual(receipt["inner_link"], AUDIT_SUBLINK)
        self.assertEqual(receipt["epoch"], EPOCH)
        self.assertEqual((receipt["udp_src"], receipt["udp_dst"]),
                         (AUDIT_TOKEN, AUDIT_UDP_DST))

        missing = self._source_output(host_packet(MISSING_TOKEN, AUDIT_UDP_DST), LOOP_IN)
        self.assertEqual(Ether(missing)[Wit].link_id, AUDIT_SUBLINK)
        self.assertIsNone(self.poll_event(),
                          "a sent packet that never arrives must yield no positive receipt")
