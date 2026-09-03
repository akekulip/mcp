"""PTF model proofs for the RECEIVER LEDGER (`mcp_fabric_ledger.p4`).

WHAT THESE TESTS ARE FOR. `p4/witness/test_ledger_program.py` checks the ledger's *arithmetic*
in Python and greps the P4 source for register widths and table names. Neither of those runs a
packet. This suite runs the compiled program on the Tofino software model and asks the four
questions the redesign actually rests on:

  1. Does the pair (`hi`, `lo`) recover the EXACT number of packets lost on the wire?
     `lost = Dhi - Dlo`. The packets are stamped by the program's own egress and PTF then
     declines to re-inject some of them, so the loss is a genuine post-stamp wire loss --
     the only kind a post-TM witness is supposed to see.
  2. Does the widened 32-bit `reg_tx_frontier` really count past the old bit<8> ceiling?
     The compile gate measured the widening free in SRAM and stages; it never ran a packet
     through it. 255 is exactly where the old counter lied.
  3. Does the advance-only frontier stop a REORDER from manufacturing a phantom loss? This is
     HURDLES H33: on the deployed witness one adjacent reorder was reported as loss, because
     an unconditional resync let a late packet rewind the frontier.
  4. Does `tbl_eg_bern` drop at the probability it was configured with, on the model's own
     `Random<bit<16>>` and the model's own TCAM range semantics? The compile gate's rate test
     used CPython's RNG and a Python re-implementation of the range table.

Plus a regression that the deterministic one-shot injector `tbl_eg_fail` still works beside the
new stochastic one.

TOPOLOGY THE TESTS BUILD. One fabric transit hop, driven twice:

    PTF --(hop 1, ETYPE 0x88F0)--> dp2 LOOP_IN  [ingress: transit] --> dp4 LOOP_B
                                                [egress: tx frontier, wit stamp, injectors]
    PTF --(the stamped frame)----> dp4 LOOP_B   [ingress: RECEIVER LEDGER] --> dp1 HOST_OUT

The first pass is the SENDER: its egress consumes a sequence number from `reg_wit_seq`, bumps
`reg_tx_frontier`, and stamps `seq` on the wire. The second pass is the RECEIVER: its
ingress runs `wit_check` (`hi`) and `wit_count` (`lo`). Whether a stamped frame is re-injected at
all is the wire, and PTF plays the wire.

Overhead-reduction pass 2026-09-02 dropped `link_id` from the wire: the receiving ingress now
reconstructs `md.wit_link` from its OWN ingress port plus `hdr.fabric.spray`
(`tbl_wit_link_recon`) and a freshly re-derived ctx nibble (`tbl_wit_ctx_index`, fed by
`tbl_context`'s classification of `hdr.ipv4.diffserv`). This model's minimal topology reuses ONE
physical port (LOOP_IN) for the sender pass and ANOTHER (LOOP_B) for the receiver pass --
mirroring how a real deployment always sees the two passes on genuinely different front-panel
ports -- so `deliver()`/`arrive()` now inject into LOOP_B, and `spray`/`tos` on each crafted
packet (not a hand-picked wire value) select which sublink the reconstruction lands on. See
`LedgerBase._path()` for the exact entries.

The injection pass (`stamp()`) lands its own incidental ingress-side ledger check on whatever
`(vlink=9, ctx)` slot its own spray/tos combination reconstructs to -- distinct from both
SUBLINK and REORDER_SUBLINK by construction (a different loop port), so it never disturbs the
ledger slot under test and never raises a spurious gap-event mirror.

NOTHING HERE TOUCHES THE SHARED PHYSICAL TOFINO. Run with p4/ptf/model/run_ledger.sh.
"""
import struct
import sys

import bfrt_grpc.client as gc
import ptf.testutils as testutils
from bfruntime_client_base_tests import BfRuntimeTest
from ptf.testutils import send_packet
from scapy.all import ByteField, Ether, IP, IntField, Packet, Raw, ShortField, UDP, bind_layers


PROG = "mcp_fabric_ledger"

ETYPE_MCP_FABRIC = 0x88F0
ETYPE_MCP_MIRROR = 0x88F1
NXT_CSIG = 1
ROLE_HOST, ROLE_LOOP = 1, 2
HOST_IN, HOST_OUT, LOOP_IN, COLLECTOR, LOOP_B = 0, 1, 2, 3, 4
EPOCH = 77
GAP_EVENT_FLAG = 0x8

VLINK = 6
STRATUM = 3
SUBLINK = (VLINK << 4) | STRATUM      # the behavioural sublink under test
SCRATCH = (9 << 4) | 0                # ledger slot the sender-side pass touches; kept contiguous
REORDER_SUBLINK = (7 << 4) | 1        # fabricated-witness tests use their own slot

# Every register this suite reads, with the bfrt data-field name the schema exposes.
REGS = {
    "hi": ("pipe.Ingress.reg_wit_expect", "Ingress.reg_wit_expect.f1"),
    "lo": ("pipe.Ingress.reg_wit_observed", "Ingress.reg_wit_observed.f1"),
    "tx": ("pipe.Egress.reg_tx_frontier", "Egress.reg_tx_frontier.f1"),
    "seq": ("pipe.Egress.reg_wit_seq", "Egress.reg_wit_seq.f1"),
}


class FabricShim(Packet):
    name = "FabricShim"
    fields_desc = [ShortField("vsw_id", 0), ShortField("hop", 1), ShortField("spray", 0),
                   ShortField("path_id", VLINK), ByteField("clf_bank", 0), ByteField("flags", 0),
                   ByteField("nxt", NXT_CSIG), ByteField("pad", STRATUM)]


class Csig(Packet):
    name = "Csig"
    fields_desc = [ShortField("worst_hop", 0), ShortField("worst_vlink", 0),
                   ShortField("worst_qdepth", 0), IntField("worst_tdelta", 0),
                   ShortField("path_id", VLINK), ShortField("epoch", EPOCH)]


class Wit(Packet):
    name = "Wit"
    fields_desc = [ShortField("seq", 0)]


bind_layers(Ether, FabricShim, type=ETYPE_MCP_FABRIC)
bind_layers(FabricShim, Csig, nxt=NXT_CSIG)
bind_layers(Csig, Wit)
bind_layers(Wit, IP)


def fabric_packet(hop, seq, spray=0, tos=0, pad=STRATUM, payload=24):
    return (Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01",
                  type=ETYPE_MCP_FABRIC) /
            FabricShim(hop=hop, spray=spray, nxt=NXT_CSIG, pad=pad) /
            Csig(epoch=EPOCH) / Wit(seq=seq) /
            IP(src="10.0.1.1", dst="10.0.1.2", tos=tos) /
            UDP(sport=1234, dport=4791, chksum=0) / Raw(b"x" * payload))


def evidence(label, **kw):
    """Print the realised numbers of an arm before asserting on them.

    The repo's standing rule: a PASS with no printed values is a claim, not a measurement.
    Written to stderr so it survives PTF's stdout handling and lands in the runner log.
    """
    sys.stderr.write("EVIDENCE %-34s %s\n"
                     % (label, "  ".join("%s=%s" % kv for kv in sorted(kw.items()))))
    sys.stderr.flush()


def decode_event(raw):
    """Fixed-offset decoder for the 30-byte ingress mirror header.

    Layout is mirror_h: dmac48 smac48 etype16 | next_hop16 sublink16 gap16 arrivals16 flags16
    | tstamp48. set_gap_event fills vlink_id <- md.wit_link, mir_path <- gap,
    attn <- md.wit_result.arrivals, which is where sublink/gap/arrivals come from.
    """
    if raw is None or len(raw) < 24:
        raise AssertionError("event copy is absent or truncated before the mirror fields")
    if struct.unpack_from("!H", raw, 12)[0] != ETYPE_MCP_MIRROR:
        raise AssertionError("collector packet is not an MCP mirror copy")
    next_hop, sublink, gap, prior_arrivals, flags = struct.unpack_from("!HHHHH", raw, 14)
    return {"next_hop": next_hop, "sublink": sublink, "gap": gap,
            "prior_arrivals": prior_arrivals, "flags": flags}


class LedgerBase(BfRuntimeTest):
    """One transit hop, plus every register and injector table reset to a known state.

    Reset matters more than usual here: the model keeps register and direct-counter state
    across test cases in one PTF run, and `lo` is by design a never-reset lifetime counter,
    so a test that assumed a fresh chip would silently read the previous test's traffic.
    """

    def setUp(self):
        BfRuntimeTest.setUp(self, 0, PROG)
        self.tgt = gc.Target(device_id=0, pipe_id=0xFFFF)
        self.bfrt = self.interface.bfrt_info_get(PROG)
        self._ports()
        self._roles()
        self._mirror()
        self._path()
        self._clear("pipe.Egress.tbl_eg_bern")
        self._clear("pipe.Egress.tbl_eg_fail")
        self._scratch_seq = 0
        for idx in (SUBLINK, SCRATCH, REORDER_SUBLINK):
            self.reg_set("hi", idx, 0)
            self.reg_set("lo", idx, 0)
            self.reg_set("tx", idx, 0)
            self.reg_set("seq", idx, 0)
        self.drain(COLLECTOR)
        self.drain(LOOP_B)
        self.drain(HOST_OUT)

    # ---- control plane -------------------------------------------------------------

    def _upsert(self, table, key, data):
        try:
            table.entry_add(self.tgt, [key], [data])
        except gc.BfruntimeRpcException:
            table.entry_mod(self.tgt, [key], [data])

    def _clear(self, name):
        """Delete every installed entry. bfrt's entry_get yields (Data, Key) in that order --
        getting it backwards costs a KeyError on '$COUNTER_SPEC_BYTES', because the direct
        counter lives in the Data half."""
        table = self.bfrt.table_get(name)
        try:
            keys = [key for _data, key in table.entry_get(self.tgt, flags={"from_hw": False})]
        except gc.BfruntimeRpcException:
            return                                    # an empty table has nothing to read
        for key in keys:
            table.entry_del(self.tgt, [key])

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
            data = table.make_data([gc.DataTuple("role", role), gc.DataTuple("src_leaf", 0),
                                    gc.DataTuple("audit_src", 0)], "Ingress.set_role")
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

    def _path(self):
        t = self.bfrt.table_get("pipe.Ingress.tbl_vlink")
        self._upsert(t, t.make_key([gc.KeyTuple("md.role", ROLE_LOOP),
                                    gc.KeyTuple("md.hop", 1),
                                    gc.KeyTuple("md.src_leaf", 0),
                                    gc.KeyTuple("md.dst_leaf", 0),
                                    gc.KeyTuple("md.spray_idx", 0)]),
                     t.make_data([gc.DataTuple("vlink_id", VLINK),
                                  gc.DataTuple("loop_port", LOOP_B),
                                  gc.DataTuple("qid", 0),
                                  gc.DataTuple("next_vsw", 16),
                                  gc.DataTuple("path_id", VLINK)], "Ingress.to_loop"))

        t = self.bfrt.table_get("pipe.Ingress.tbl_final")
        self._upsert(t, t.make_key([gc.KeyTuple("md.role", ROLE_LOOP),
                                    gc.KeyTuple("md.hop", 1),
                                    gc.KeyTuple("md.dst_leaf", 0)]),
                     t.make_data([gc.DataTuple("next_hop", 2)], "Ingress.act_transit"))
        self._upsert(t, t.make_key([gc.KeyTuple("md.role", ROLE_LOOP),
                                    gc.KeyTuple("md.hop", 2),
                                    gc.KeyTuple("md.dst_leaf", 0)]),
                     t.make_data([gc.DataTuple("port", HOST_OUT)], "Ingress.act_deliver"))

        t = self.bfrt.table_get("pipe.Egress.tbl_eg_vlink")
        self._upsert(t, t.make_key([gc.KeyTuple("eg_intr_md.egress_port", LOOP_B),
                                    gc.KeyTuple("eg_intr_md.egress_qid", 0)]),
                     t.make_data([gc.DataTuple("vlink", VLINK),
                                  gc.DataTuple("vlink_base", VLINK << 4)],
                                 "Egress.set_eg_vlink"))

        # Overhead-reduction pass 2026-09-02: md.wit_link is reconstructed at
        # ingress, not read off the wire. LOOP_IN only ever carries the sender
        # pass in this rig, so its spray value is irrelevant (wildcard mask);
        # LOOP_B carries every receiver-pass arrival and disambiguates by
        # spray, mirroring how two different front-panel ports would do it on
        # real hardware.
        t = self.bfrt.table_get("pipe.Ingress.tbl_wit_link_recon")
        self._upsert(t, t.make_key([gc.KeyTuple("ig_intr_md.ingress_port", LOOP_IN),
                                    gc.KeyTuple("hdr.fabric.spray", 0, 0x0000),
                                    gc.KeyTuple("$MATCH_PRIORITY", 1)]),
                     t.make_data([gc.DataTuple("wit_vlink_base", 9 << 4)],
                                 "Ingress.set_wit_link"))
        self._upsert(t, t.make_key([gc.KeyTuple("ig_intr_md.ingress_port", LOOP_B),
                                    gc.KeyTuple("hdr.fabric.spray", 0, 0xFFFF),
                                    gc.KeyTuple("$MATCH_PRIORITY", 2)]),
                     t.make_data([gc.DataTuple("wit_vlink_base", VLINK << 4)],
                                 "Ingress.set_wit_link"))
        self._upsert(t, t.make_key([gc.KeyTuple("ig_intr_md.ingress_port", LOOP_B),
                                    gc.KeyTuple("hdr.fabric.spray", 1, 0xFFFF),
                                    gc.KeyTuple("$MATCH_PRIORITY", 3)]),
                     t.make_data([gc.DataTuple("wit_vlink_base", REORDER_SUBLINK >> 4 << 4)],
                                 "Ingress.set_wit_link"))

        # tbl_context re-derives the ctx nibble fresh from the packet's own IP
        # header at every hop (unchanged by this pass); ctx=0 is already its
        # default action, so only the two nonzero contexts this suite uses
        # need explicit entries.
        t = self.bfrt.table_get("pipe.Ingress.tbl_context")
        self._upsert(t, t.make_key([gc.KeyTuple("hdr.ipv4.total_len", low=0, high=65535),
                                    gc.KeyTuple("hdr.ipv4.diffserv", STRATUM, 0xFF),
                                    gc.KeyTuple("$MATCH_PRIORITY", 1)]),
                     t.make_data([gc.DataTuple("c", STRATUM)], "Ingress.set_ctx"))
        self._upsert(t, t.make_key([gc.KeyTuple("hdr.ipv4.total_len", low=0, high=65535),
                                    gc.KeyTuple("hdr.ipv4.diffserv", REORDER_SUBLINK & 0xF, 0xFF),
                                    gc.KeyTuple("$MATCH_PRIORITY", 2)]),
                     t.make_data([gc.DataTuple("c", REORDER_SUBLINK & 0xF)], "Ingress.set_ctx"))

    # ---- register access -----------------------------------------------------------

    def reg_set(self, which, index, value):
        name, field = REGS[which]
        table = self.bfrt.table_get(name)
        table.entry_add(self.tgt,
                        [table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])],
                        [table.make_data([gc.DataTuple(field, value)])])

    def reg_get(self, which, index):
        """Pipe 0's copy. Registers are per-pipe and every port here is in pipe 0."""
        name, field = REGS[which]
        table = self.bfrt.table_get(name)
        table.operations_execute(self.tgt, "Sync")
        data = next(table.entry_get(
            self.tgt, [table.make_key([gc.KeyTuple("$REGISTER_INDEX", index)])],
            {"from_hw": False}))[0].to_dict()
        value = data[field]
        return value[0] if isinstance(value, list) else value

    def counters(self, name):
        """[(key_dict, action, packets)] for every INSTALLED entry of a counted table.

        The default entry is excluded on purpose: its DirectCounter is one slot shared by
        every sublink, which is exactly why the control-plane recipe installs two real
        entries instead of leaning on the default for the survivor count.
        """
        table = self.bfrt.table_get(name)
        table.operations_execute(self.tgt, "SyncCounters")
        out = []
        for data, key in table.entry_get(self.tgt, flags={"from_hw": True}):
            d = data.to_dict()
            if d.get("is_default_entry"):
                continue
            out.append((key.to_dict(), d.get("action_name"), d.get("$COUNTER_SPEC_PKTS", 0)))
        return out

    # ---- injector arming -----------------------------------------------------------

    def arm_bernoulli(self, sublink, low, high, action, priority):
        t = self.bfrt.table_get("pipe.Egress.tbl_eg_bern")
        t.entry_add(self.tgt,
                    [t.make_key([gc.KeyTuple("md.sublink", sublink),
                                 gc.KeyTuple("md.eg_rnd", low=low, high=high),
                                 gc.KeyTuple("$MATCH_PRIORITY", priority)])],
                    [t.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0),
                                  gc.DataTuple("$COUNTER_SPEC_BYTES", 0)], action)])

    def arm_bernoulli_rate(self, sublink, p):
        """The two-entry tiling the compile gate's control-plane recipe specifies."""
        width = int(round(p * 65536))
        assert 0 < width < 65536, "p must be strictly between 0 and 1 for a two-entry tiling"
        self.arm_bernoulli(sublink, 0, width - 1, "Egress.eg_bern_drop", 1)
        self.arm_bernoulli(sublink, width, 65535, "Egress.eg_bern_none", 2)
        return width

    def arm_one_shot(self, sublink, seq):
        t = self.bfrt.table_get("pipe.Egress.tbl_eg_fail")
        t.entry_add(self.tgt,
                    [t.make_key([gc.KeyTuple("md.sublink", sublink),
                                 gc.KeyTuple("hdr.witness.seq", low=seq, high=seq),
                                 gc.KeyTuple("$MATCH_PRIORITY", 1)])],
                    [t.make_data([gc.DataTuple("$COUNTER_SPEC_PKTS", 0),
                                  gc.DataTuple("$COUNTER_SPEC_BYTES", 0)],
                                 "Egress.eg_fail_drop")])

    # ---- the wire ------------------------------------------------------------------

    def drain(self, port, timeout=0.2):
        n = 0
        while True:
            _, _, raw, _ = testutils.dp_poll(self, device_number=0, port_number=port,
                                             timeout=timeout)
            if raw is None:
                return n
            n += 1

    def stamp(self, timeout=0.5):
        """One SENDER pass. Returns the stamped frame, or None if egress dropped it.

        tos=STRATUM here is what lets `deliver()`'s later re-injection reconstruct ctx=STRATUM
        at the receiver: the IP header is unchanged by the fabric, so whatever tos this pass
        sets is what tbl_context will reclassify at every later hop. This pass's OWN incidental
        ingress-side ledger check (LOOP_IN, tbl_wit_link_recon's wildcard-spray entry) lands on
        (vlink=9, ctx=STRATUM) regardless -- distinct from SUBLINK's (vlink=6, ctx=STRATUM)
        because it is a different physical port, matching the module docstring's isolation
        argument.
        """
        pkt = fabric_packet(hop=1, seq=self._scratch_seq, spray=0, tos=STRATUM)
        self._scratch_seq = (self._scratch_seq + 1) & 0xFFFF
        send_packet(self, LOOP_IN, pkt)
        _, _, raw, _ = testutils.dp_poll(self, device_number=0, port_number=LOOP_B,
                                         timeout=timeout)
        return raw

    def deliver(self, raw, timeout=0.5):
        """One RECEIVER pass: put a stamped frame back on the wire into the ledger.

        Injected on LOOP_B, not LOOP_IN: tbl_wit_link_recon disambiguates the receiver pass
        from the sender pass by PORT (as two real front-panel ports would), and `raw` already
        carries the spray=0/tos=STRATUM stamp() gave it, which is exactly what LOOP_B's
        spray=0 entry maps to SUBLINK.
        """
        send_packet(self, LOOP_B, raw)
        testutils.dp_poll(self, device_number=0, port_number=HOST_OUT, timeout=timeout)

    def arrive(self, seq, timeout=0.5):
        """A fabricated arrival straight at the receiver, for the frontier-only tests.

        Every caller wants REORDER_SUBLINK, so spray=1/tos=1 (LOOP_B's second entry) is fixed
        here rather than threaded through every call site.
        """
        pkt = fabric_packet(hop=2, seq=seq, spray=1, tos=REORDER_SUBLINK & 0xF)
        send_packet(self, LOOP_B, pkt)
        testutils.dp_poll(self, device_number=0, port_number=HOST_OUT, timeout=timeout)

    def poll_event(self, timeout=0.25):
        _, _, raw, _ = testutils.dp_poll(self, device_number=0, port_number=COLLECTOR,
                                         timeout=timeout)
        return raw


# =================================================================================================
# 60 -- THE CORE ESTIMATOR
# =================================================================================================

class Test60LedgerRecoversTheExactLossCount(LedgerBase):
    """`Dhi - Dlo` must equal the number of packets lost on the wire, exactly.

    This is the claim the whole redesign rests on and it has never been run against the
    program. The pipeline stamps every packet itself; PTF then declines to re-inject five of
    them, which is a post-stamp loss the sender has already committed to and counted.
    """

    N = 40
    LOST = (3, 4, 5, 17, 28)     # deliberately not the last packet: see the trailing-loss note

    def runTest(self):
        hi0, lo0 = self.reg_get("hi", SUBLINK), self.reg_get("lo", SUBLINK)
        self.assertEqual((hi0, lo0), (0, 0), "the controller seeds both halves to zero")

        stamped = [self.stamp() for _ in range(self.N)]
        self.assertTrue(all(f is not None for f in stamped),
                        "every packet must leave the sender: no injector is armed here")

        seqs = [Ether(f)[Wit].seq for f in stamped]
        self.assertEqual(seqs, list(range(self.N)),
                         "the sender's own egress must stamp one sequence number per packet")

        for i, frame in enumerate(stamped):
            if i in self.LOST:
                continue                       # PTF plays the wire: this packet is lost
            self.deliver(frame)

        hi1, lo1 = self.reg_get("hi", SUBLINK), self.reg_get("lo", SUBLINK)
        delivered = self.N - len(self.LOST)
        evidence("60 estimator", stamped=self.N, injected_loss=len(self.LOST),
                 delivered=delivered, hi=hi1, lo=lo1, est=(hi1 - hi0) - (lo1 - lo0),
                 tx=self.reg_get("tx", SUBLINK))
        self.assertEqual(lo1 - lo0, delivered, "`lo` counts arrivals and nothing else")
        self.assertEqual(hi1 - hi0, self.N,
                         "`hi` reaches one past the highest sequence that arrived")
        self.assertEqual((hi1 - hi0) - (lo1 - lo0), len(self.LOST),
                         "Dhi - Dlo must equal the injected loss count exactly")

    def tearDown(self):
        self.drain(COLLECTOR)
        LedgerBase.tearDown(self)


class Test61TrailingLossIsInvisibleUntilTheNextSurvivor(LedgerBase):
    """The known and accepted limit of the estimator, pinned so it cannot be forgotten.

    `hi` only moves when a packet ARRIVES. Loss at the tail of an interval is therefore
    scored on the next read after the next survivor, never on the read that straddles it.
    The controller's read cadence has to be faster than the interval it wants to attribute.
    """

    def runTest(self):
        stamped = [self.stamp() for _ in range(6)]
        for frame in stamped[:4]:
            self.deliver(frame)
        hi, lo = self.reg_get("hi", SUBLINK), self.reg_get("lo", SUBLINK)
        self.assertEqual((hi, lo), (4, 4),
                         "four contiguous arrivals leave the two halves equal")
        # frames 4 and 5 are stamped and lost; nothing arrives to expose them
        self.assertEqual(hi - lo, 0, "trailing loss is NOT visible at this instant")

        tail = self.stamp()
        self.assertIsNotNone(tail)
        self.deliver(tail)
        hi, lo = self.reg_get("hi", SUBLINK), self.reg_get("lo", SUBLINK)
        evidence("61 trailing loss", hi=hi, lo=lo, est=hi - lo)
        self.assertEqual(hi - lo, 2, "the next survivor exposes both trailing losses at once")

    def tearDown(self):
        self.drain(COLLECTOR)
        LedgerBase.tearDown(self)


# =================================================================================================
# 62 -- THE 32-BIT TX FRONTIER
# =================================================================================================

class Test62TxFrontierCountsPastTheOld8BitCeiling(LedgerBase):
    """`reg_tx_frontier` must be exact past 255, driven by real traffic.

    The old register was 512 x bit<8> with a saturating add: at 255 a healthy sublink became
    indistinguishable from any other busy sublink, which is the defect the widening to
    2048 x bit<32> was bought to fix. The compile gate proved the widening costs nothing; it
    did not prove the wider counter counts. 300 packets is the smallest run that puts the
    answer unambiguously past both 255 (saturation) and 256 (an 8-bit wrap).
    """

    N = 300

    def runTest(self):
        self.assertEqual(self.reg_get("tx", SUBLINK), 0, "seeded by the controller")
        emerged = sum(1 for _ in range(self.N) if self.stamp() is not None)
        self.assertEqual(emerged, self.N, "every packet must leave the sender")

        tx = self.reg_get("tx", SUBLINK)
        evidence("62 tx frontier", sent=self.N, tx=tx, seq=self.reg_get("seq", SUBLINK),
                 old_bit8_would_read=min(self.N, 255))
        self.assertGreater(tx, 255, "an 8-bit saturating counter would have pinned here")
        self.assertNotEqual(tx, self.N % 256, "nor is this an 8-bit wrap")
        self.assertEqual(tx, self.N, "the 32-bit TX frontier is exact at 300")

        # The sender's sequence allocator is a separate 16-bit register on the same index;
        # if the two disagree the pair cannot be compared across the link at all.
        self.assertEqual(self.reg_get("seq", SUBLINK), self.N,
                         "reg_wit_seq advanced once per departure, like the TX frontier")

    def tearDown(self):
        self.drain(COLLECTOR)
        LedgerBase.tearDown(self)


# =================================================================================================
# 63/64 -- REORDER (HURDLES H33)
# =================================================================================================

class Test63ReorderManufacturesNoPhantomLoss(LedgerBase):
    """H33 directly. A single adjacent reorder with NO loss must score zero loss.

    Arrival order 0, 1, 3, 2, 4 on one sublink. Under the OLD unconditional resync
    (`hi = seq + 1` every time) the late `2` rewinds the frontier to 3, and the following
    in-order `4` then reads as a fresh hole -- one reorder reported as loss, twice. The
    advance-only SALU must leave the frontier alone for the late packet, so that:
      * the frontier never decreases,
      * the in-order packet after the reorder raises NO event, and
      * Dhi - Dlo is exactly zero, because nothing was actually lost.

    Fabricated witness headers are used here (not the stamping egress) so that the arrival
    ORDER is under the test's control rather than the model's scheduler.
    """

    ORDER = (0, 1, 3, 2, 4)

    def runTest(self):
        frontier = []
        events = []
        for seq in self.ORDER:
            self.arrive(seq)
            raw = self.poll_event()
            events.append(None if raw is None else decode_event(raw))
            frontier.append(self.reg_get("hi", REORDER_SUBLINK))

        evidence("63 reorder", order=list(self.ORDER), frontier=frontier,
                 gaps=[None if e is None else hex(e["gap"]) for e in events])
        self.assertEqual(frontier, sorted(frontier),
                         "ADVANCE-ONLY: the frontier must never rewind (H33's root cause)")
        self.assertEqual(frontier, [1, 2, 4, 4, 5],
                         "the late packet leaves the frontier where the hole put it")

        self.assertIsNone(events[0], "a contiguous first packet raises nothing")
        self.assertIsNone(events[1], "a contiguous packet raises nothing")

        self.assertIsNotNone(events[2], "the forward hole IS an event")
        self.assertEqual(events[2]["gap"], 0xFFFF,
                         "a hole of one reads as a large (signed-negative) gap")
        self.assertEqual(events[2]["sublink"], REORDER_SUBLINK)

        self.assertIsNotNone(events[3], "the late arrival is also reported, by design")
        self.assertEqual(events[3]["gap"], 2,
                         "but as a SMALL positive gap -- late arrival, not a hole, and the "
                         "two are separable by magnitude")

        self.assertIsNone(events[4],
                          "THE REGRESSION: the in-order packet after the reorder must raise "
                          "nothing. Under the old resync it read as a fresh hole.")

        hi = self.reg_get("hi", REORDER_SUBLINK)
        lo = self.reg_get("lo", REORDER_SUBLINK)
        evidence("63 reorder ledger", hi=hi, lo=lo, est=hi - lo)
        self.assertEqual(lo, len(self.ORDER), "every packet arrived")
        self.assertEqual(hi - lo, 0, "a pure reorder with no loss must score ZERO loss")

    def tearDown(self):
        self.drain(COLLECTOR)
        LedgerBase.tearDown(self)


class Test64DuplicateDrivesTheEstimateNegative(LedgerBase):
    """A duplicate makes `Dhi - Dlo` go NEGATIVE. This is a property, not a defect.

    A duplicate bumps `lo` without advancing `hi`, so the estimator underflows below zero.
    `p4/witness/test_ledger_program.py` pins this in the software model; it is pinned here
    against the compiled program because the consequence is a CONTROLLER requirement: the
    controller must clamp at zero and must not mistake the negative for an underflow of the
    modular subtraction on `hi`.
    """

    ORDER = (0, 1, 2, 2)

    def runTest(self):
        for seq in self.ORDER:
            self.arrive(seq)
        hi = self.reg_get("hi", REORDER_SUBLINK)
        lo = self.reg_get("lo", REORDER_SUBLINK)
        evidence("64 duplicate", order=list(self.ORDER), hi=hi, lo=lo, est=hi - lo)
        self.assertEqual((hi, lo), (3, 4),
                         "the duplicate is counted as an arrival but advances nothing")
        self.assertEqual(hi - lo, -1, "the raw estimate is NEGATIVE and must be clamped")

    def tearDown(self):
        self.drain(COLLECTOR)
        LedgerBase.tearDown(self)


# =================================================================================================
# 65/66 -- THE BERNOULLI INJECTOR
# =================================================================================================

class Test65BernoulliRealisedRateMatchesConfiguration(LedgerBase):
    """`tbl_eg_bern` must drop at the probability the control plane configured.

    Two things are checked, and only one of them is statistical.

    EXACT: offered = drop_ctr + none_ctr must equal the number of packets presented. The two
    installed ranges are [0, W-1] and [W, 65535]; if either bound were exclusive, or the pair
    failed to tile the draw space, some packets would fall through to the shared default entry
    and the two per-sublink counters would not add up. This is the counter identity the
    control-plane recipe in LEDGER-COMPILE-GATE.md §5 depends on.

    STATISTICAL: p_hat = drop/offered must lie within 4 sigma of the configured p. With
    N = 800 and p = 0.25, sigma = sqrt(p(1-p)/N) = 0.0153, so the band is +/- 0.061. That is
    decisive against a gross error -- inverted bounds, a factor-of-two scale mistake, a stuck
    RNG -- and is NOT sensitive to a few-percent bias, which would need N ~ 10^4 and hours of
    model time. The band is stated rather than tuned after seeing the result.
    """

    N = 800
    P = 0.25
    SIGMAS = 4

    def runTest(self):
        width = self.arm_bernoulli_rate(SUBLINK, self.P)
        self.assertEqual(width, 16384, "W = round(p * 65536)")

        survivors = sum(1 for _ in range(self.N) if self.stamp(timeout=0.15) is not None)

        rows = {act: pkts for _, act, pkts in self.counters("pipe.Egress.tbl_eg_bern")}
        self.assertEqual(set(rows), {"Egress.eg_bern_drop", "Egress.eg_bern_none"},
                         "exactly the two armed entries must be installed")
        drop = rows["Egress.eg_bern_drop"]
        none = rows["Egress.eg_bern_none"]
        offered = drop + none

        self.assertEqual(offered, self.N,
                         "EXACT: the two ranges must tile the draw space with no packet "
                         "falling through to the default entry (offered=%d drop=%d none=%d)"
                         % (offered, drop, none))
        self.assertEqual(survivors, none,
                         "every non-dropped packet must actually reach the wire")

        p_hat = float(drop) / offered
        evidence("65 bernoulli rate", N=self.N, W=width, p_cfg=self.P, drop=drop, none=none,
                 offered=offered, survivors=survivors, p_hat=round(p_hat, 5),
                 band=round(self.SIGMAS * (self.P * (1.0 - self.P) / self.N) ** 0.5, 5))
        tolerance = self.SIGMAS * (self.P * (1.0 - self.P) / self.N) ** 0.5
        self.assertLess(abs(p_hat - self.P), tolerance,
                        "realised p_hat=%.4f (drop=%d of %d) outside %.4f +/- %.4f"
                        % (p_hat, drop, offered, self.P, tolerance))

    def tearDown(self):
        self.drain(COLLECTOR)
        LedgerBase.tearDown(self)


class Test66BernoulliEndpointsAreInclusiveInBothDirections(LedgerBase):
    """The two saturating configurations, which are deterministic and need no statistics.

    A single entry covering the whole draw space [0, 65535] must drop EVERY packet if it is
    armed to drop and NO packet if it is armed to pass. Anything less than all-or-nothing
    means a range endpoint is not inclusive, which would also silently bias every rate the
    two-entry tiling in Test65 configures.
    """

    N = 30

    def runTest(self):
        self.arm_bernoulli(SUBLINK, 0, 65535, "Egress.eg_bern_drop", 1)
        survivors = sum(1 for _ in range(self.N) if self.stamp(timeout=0.15) is not None)
        rows = {act: pkts for _, act, pkts in self.counters("pipe.Egress.tbl_eg_bern")}
        evidence("66 bernoulli all-drop", N=self.N, survivors=survivors,
                 drop=rows.get("Egress.eg_bern_drop"), none=rows.get("Egress.eg_bern_none"))
        self.assertEqual(survivors, 0, "a full-range drop entry must be a total blackhole")
        self.assertEqual(rows.get("Egress.eg_bern_drop"), self.N,
                         "and every draw in [0, 65535] must have matched it")

        self._clear("pipe.Egress.tbl_eg_bern")
        self.arm_bernoulli(SUBLINK, 0, 65535, "Egress.eg_bern_none", 1)
        survivors = sum(1 for _ in range(self.N) if self.stamp() is not None)
        rows = {act: pkts for _, act, pkts in self.counters("pipe.Egress.tbl_eg_bern")}
        evidence("66 bernoulli all-pass", N=self.N, survivors=survivors,
                 drop=rows.get("Egress.eg_bern_drop"), none=rows.get("Egress.eg_bern_none"))
        self.assertEqual(survivors, self.N, "a full-range pass entry must drop nothing")
        self.assertEqual(rows.get("Egress.eg_bern_none"), self.N)

    def tearDown(self):
        self.drain(COLLECTOR)
        LedgerBase.tearDown(self)


# =================================================================================================
# 67 -- THE DETERMINISTIC ONE-SHOT, STILL WORKING BESIDE THE NEW ARM
# =================================================================================================

class Test67OneShotInjectorStillDropsExactlyOnePacket(LedgerBase):
    """Regression for `tbl_eg_fail`, plus the first real IN-PIPELINE post-TM drop.

    `p4/ptf/PTF-MODEL.md` left "a real post-TM drop" open: the W4 suite's loss was inflicted by
    PTF on the wire. Here the program drops the packet itself, after its own egress has already
    consumed the sequence number, and the downstream ledger scores it. That is the full loop.

    The width-1 range [3, 3] is also the cleanest available proof that a TCAM range bound is
    inclusive at BOTH ends on this target: exactly one sequence number matches it.
    """

    N = 6
    ARMED_SEQ = 3

    def runTest(self):
        self.arm_one_shot(SUBLINK, self.ARMED_SEQ)

        stamped = [self.stamp() for _ in range(self.N)]
        survived = [i for i, f in enumerate(stamped) if f is not None]
        self.assertEqual(survived, [0, 1, 2, 4, 5],
                         "exactly the armed sequence number must die at the sender's egress")

        rows = {act: pkts for _, act, pkts in self.counters("pipe.Egress.tbl_eg_fail")}
        self.assertEqual(rows.get("Egress.eg_fail_drop"), 1,
                         "the injector's own DirectCounter must say it fired once")

        bern = self.counters("pipe.Egress.tbl_eg_bern")
        self.assertEqual(bern, [], "the stochastic arm is unarmed and must not interfere")

        for frame in stamped:
            if frame is not None:
                self.deliver(frame)

        hi, lo = self.reg_get("hi", SUBLINK), self.reg_get("lo", SUBLINK)
        evidence("67 one-shot", N=self.N, armed_seq=self.ARMED_SEQ, survived=survived,
                 fail_ctr=rows.get("Egress.eg_fail_drop"), hi=hi, lo=lo, est=hi - lo,
                 tx=self.reg_get("tx", SUBLINK))
        self.assertEqual(lo, self.N - 1, "five packets arrived")
        self.assertEqual(hi, self.N, "the frontier reached one past the last sequence")
        self.assertEqual(hi - lo, 1,
                         "the ledger scores the in-pipeline post-TM drop as exactly one loss")

    def tearDown(self):
        self.drain(COLLECTOR)
        LedgerBase.tearDown(self)


class Test68ModelRandomIsUniformAndRangesTile(LedgerBase):
    """The gap LEDGER-COMPILE-GATE.md left open: `tbl_eg_bern`'s rate was only ever validated
    against CPython's RNG and a Python re-implementation of the range table. This measures the
    MODEL's own `Random<bit<16>>` and the MODEL's own TCAM range arithmetic.

    Eight disjoint all-pass entries tile [0, 65535] at 8192 apiece, so nothing is dropped and
    the eight DirectCounters are a pure histogram of md.eg_rnd. Three claims:

      * EXACT: the eight counters sum to the number of packets presented. An eight-way tiling
        with no packet falling through to the shared default entry is much stronger evidence
        that range bounds are inclusive on both ends than a two-way one.
      * Every bucket is occupied -- a stuck or low-entropy draw would leave holes.
      * chi-square against uniform is below 29.88, the 1-in-10^4 critical value on 7 degrees of
        freedom. Chosen before the measurement, and it bounds the FALSE-FAILURE rate of this
        test at 10^-4; it is not a claim that the draw is uniform to within 1 %.

    Why this and not simply a bigger sample in Test65: separating the draw from the drop means
    a failure names which of the two is wrong. Test65 conflates them by construction.
    """

    N = 2400
    BUCKETS = 8
    CHI2_LIMIT = 29.88          # chi-square, 7 df, upper 1e-4 tail

    def runTest(self):
        width = 65536 // self.BUCKETS
        bounds = [(b * width, (b + 1) * width - 1) for b in range(self.BUCKETS)]
        for i, (low, high) in enumerate(bounds):
            self.arm_bernoulli(SUBLINK, low, high, "Egress.eg_bern_none", i + 1)

        survivors = sum(1 for _ in range(self.N) if self.stamp() is not None)

        hist = {}
        for key, action, pkts in self.counters("pipe.Egress.tbl_eg_bern"):
            self.assertEqual(action, "Egress.eg_bern_none", "no bucket drops in this test")
            rk = key["md.eg_rnd"]
            hist[rk["low"] if isinstance(rk, dict) else rk] = pkts
        counts = [hist.get(low, 0) for low, _ in bounds]

        expected = float(self.N) / self.BUCKETS
        chi2 = sum((c - expected) ** 2 / expected for c in counts)
        evidence("68 draw histogram", N=self.N, counts=counts, expected=expected,
                 chi2=round(chi2, 3), total=sum(counts), survivors=survivors,
                 low_quarter_frac=round((counts[0] + counts[1]) / float(self.N), 5))

        self.assertEqual(sum(counts), self.N,
                         "EXACT: eight ranges must tile [0, 65535] with nothing falling "
                         "through to the default entry (got %d of %d)" % (sum(counts), self.N))
        self.assertEqual(survivors, self.N, "an all-pass tiling must drop nothing")
        self.assertTrue(all(c > 0 for c in counts),
                        "every bucket must be reachable: %r" % (counts,))
        self.assertLess(chi2, self.CHI2_LIMIT,
                        "the model's Random<bit<16>> is not uniform across the range space: "
                        "chi2=%.3f counts=%r" % (chi2, counts))

    def tearDown(self):
        self.drain(COLLECTOR)
        LedgerBase.tearDown(self)
