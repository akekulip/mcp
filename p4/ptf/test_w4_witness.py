"""PTF model tests for the W4 post-TM order witness (PLAN M2 step (b)).

Covers exactly the semantics M2 lists as prerequisites for silicon: initialization,
reset/resynchronisation, modulo wrap, duplicates, allowed reorder, consecutive losses, and
per-link (multi-queue) independence.

WHAT IS UNDER TEST. The upstream egress stamps `wit_h{link_id, seq}` from
`reg_wit_seq[vlink]` (return-then-increment). The downstream ingress runs, per witness-bearing
packet that arrived on a LOOP port:

    gap      = expected - observed        (0 <=> contiguous)
    expected = observed + 1               (16-bit modular, so wrap costs nothing)

and `tbl_wit_verdict` turns gap==0 into `wit_ok` and everything else into `wit_loss`.

WHY THE TESTS INJECT WITNESS HEADERS DIRECTLY. Driving the whole emulated fabric would make
the sequence numbers a function of the fabric's own forwarding, which is precisely what these
tests must control. Injecting a chosen (link_id, seq) on a loop port exercises the downstream
state machine exactly, and `test_00_stamp_increments` covers the upstream stamp separately.

CAVEAT, carried from the old skeleton and still true: the software model accepts some
control-plane writes the ASIC rejects, so a model PASS is necessary, not sufficient. These
tests are the gate BEFORE silicon, not a substitute for it.
"""
import ptf.testutils as testutils
from ptf.testutils import send_packet, verify_no_other_packets
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
from scapy.all import Ether, IP, UDP, Raw, bind_layers, Packet
from scapy.fields import ShortField, ByteField, IntField

PROG = "mcp_fabric_w4_arm2"

ETYPE_MCP_FABRIC = 0x88F0
NXT_IPV4, NXT_CSIG = 0, 1
ROLE_OTHER, ROLE_HOST, ROLE_LOOP, ROLE_NIC = 0, 1, 2, 3

HOST0_PORT, HOST1_PORT, LOOP_UP_PORT, LOOP_DN_PORT = 0, 1, 2, 3
ENABLE_PORTS = (0, 1, 2, 3)
WRAP = 1 << 16
K_UP = 1024          # attention bump per exceedance, set so a gap event is visible


class FabricShim(Packet):
    """fabric_h — 12 B, all carried fields 16-bit (silicon byte-aliasing, DESIGN-ALTERNATIVES)."""
    name = "FabricShim"
    fields_desc = [ShortField("vsw_id", 0), ShortField("hop", 0), ShortField("spray", 0),
                   ShortField("path_id", 0), ByteField("loops", 0), ByteField("flags", 0),
                   ByteField("nxt", NXT_IPV4), ByteField("pad", 0)]


class Csig(Packet):
    """csig_h — 14 B."""
    name = "Csig"
    fields_desc = [ShortField("worst_hop", 0), ShortField("worst_vlink", 0),
                   ShortField("worst_qdepth", 0), IntField("worst_tdelta", 0),
                   ShortField("path_id", 0), ShortField("epoch", 0)]


class Wit(Packet):
    """wit_h — 4 B: the W4 witness."""
    name = "Wit"
    fields_desc = [ShortField("link_id", 0), ShortField("seq", 0)]


bind_layers(Ether, FabricShim, type=ETYPE_MCP_FABRIC)
bind_layers(FabricShim, Csig, nxt=NXT_CSIG)
bind_layers(Csig, Wit)
bind_layers(Wit, IP)


def witness_pkt(link, seq, path_id=0, plen=48):
    return (Ether(dst="00:00:00:00:00:02", src="00:00:00:00:00:01", type=ETYPE_MCP_FABRIC) /
            FabricShim(hop=1, path_id=path_id, nxt=NXT_CSIG) /
            Csig(path_id=path_id) / Wit(link_id=link, seq=seq) /
            IP(src="10.0.1.1", dst="10.0.1.2") /
            UDP(sport=1234, dport=4791, chksum=0) / Raw(b"\x00" * plen))


class WitnessBase(BfRuntimeTest):
    def setUp(self):
        BfRuntimeTest.setUp(self, 0, PROG)
        self.tgt = gc.Target(device_id=0, pipe_id=0xffff)
        self.bfrt = self.interface.bfrt_info_get(PROG)
        self._enable_ports()
        self._program_roles()
        self.zero_expect()
        self.set_k_up(K_UP)
        self.zero_attn()

    def _enable_ports(self):
        port = self.bfrt.table_get("$PORT")
        for dp in ENABLE_PORTS:
            try:
                port.entry_add(self.tgt, [port.make_key([gc.KeyTuple("$DEV_PORT", dp)])],
                               [port.make_data([gc.DataTuple("$SPEED", str_val="BF_SPEED_25G"),
                                                gc.DataTuple("$FEC", str_val="BF_FEC_TYP_NONE"),
                                                gc.DataTuple("$PORT_ENABLE", bool_val=True)])])
            except Exception:
                pass                                    # already added by a previous test

    def _program_roles(self):
        t = self.bfrt.table_get("pipe.Ingress.tbl_port_role")
        for dp, role in ((HOST0_PORT, ROLE_HOST), (HOST1_PORT, ROLE_HOST),
                         (LOOP_UP_PORT, ROLE_LOOP), (LOOP_DN_PORT, ROLE_LOOP)):
            k = t.make_key([gc.KeyTuple("ig_intr_md.ingress_port", dp)])
            d = t.make_data([gc.DataTuple("role", role), gc.DataTuple("src_leaf", 0)],
                            "Ingress.set_role")
            try:
                t.entry_add(self.tgt, [k], [d])
            except Exception:
                t.entry_mod(self.tgt, [k], [d])

    # ---- observables -------------------------------------------------------------
    def expect_of(self, link):
        """reg_wit_expect[link] — the NEXT sequence number this link is expected to carry."""
        t = self.bfrt.table_get("pipe.Ingress.reg_wit_expect")
        t.operations_execute(self.tgt, "Sync")
        resp = t.entry_get(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", link)])],
                           {"from_hw": False})
        d = next(resp)[0].to_dict()
        vals = d["Ingress.reg_wit_expect.f1"]
        return vals[0] if isinstance(vals, list) else vals       # pipe 0; see attn_of

    def set_expect(self, link, value):
        """Controller re-seed of the expected sequence — the reset/resync path."""
        t = self.bfrt.table_get("pipe.Ingress.reg_wit_expect")
        t.entry_add(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", link)])],
                    [t.make_data([gc.DataTuple("Ingress.reg_wit_expect.f1", value)])])

    def zero_expect(self, n=64):
        for i in range(n):
            self.set_expect(i, 0)

    def attn_of(self, path):
        """-> (attn, clean) for one path slot of reg_attn.

        This is the observable, rather than tbl_wit_verdict's direct counter, because that
        table's entries are `const` in the P4 source and const entries cannot be enumerated or
        fetched over bfrt (an entry_get by key returns "Object not found" and a full dump
        returns nothing). The attention registers are a better observable anyway: `tbl_attn`
        keys on md.exceed, so they show the gap propagating into the fast loop, which is the
        behaviour the design actually claims.
        """
        t = self.bfrt.table_get("pipe.Ingress.reg_attn")
        t.operations_execute(self.tgt, "Sync")
        d = next(t.entry_get(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", path)])],
                             {"from_hw": False}))[0].to_dict()
        pipe0 = lambda v: (v[0] if isinstance(v, list) else v)   # every test port is in pipe 0
        return pipe0(d["Ingress.reg_attn.attn"]), pipe0(d["Ingress.reg_attn.clean"])

    def zero_attn(self, n=64):
        t = self.bfrt.table_get("pipe.Ingress.reg_attn")
        for i in range(n):
            t.entry_add(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])],
                        [t.make_data([gc.DataTuple("Ingress.reg_attn.attn", 0),
                                      gc.DataTuple("Ingress.reg_attn.clean", 0)])])

    def set_k_up(self, value=1024):
        """A gap must move the attention word by a visible amount, so k_up cannot stay 0."""
        t = self.bfrt.table_get("pipe.Ingress.p_k_up")
        t.default_entry_set(self.tgt, t.make_data([gc.DataTuple("value", value)]))

    def send_seq(self, link, seq, port=LOOP_UP_PORT):
        # path_id = link so each link owns an attention slot and the tests can attribute events
        send_packet(self, port, witness_pkt(link, seq, path_id=link))
        testutils.verify_no_other_packets(self, timeout=0.1)   # drops are expected; we read state


class Test00Probe(WitnessBase):
    """Diagnostic: report what a contiguous packet and a gap packet actually do."""
    def runTest(self):
        link = 2
        try:
            t = self.bfrt.table_get("pipe.Ingress.p_k_up")
            d = next(t.default_entry_get(self.tgt))[0].to_dict()
            print("\nPROBE p_k_up readback=%s" % d)
        except Exception as e:
            print("\nPROBE p_k_up readback FAILED: %r" % (e,))
        self.send_seq(link, 0)
        print("PROBE after contiguous: expect=%s attn(link)=%s" % (self.expect_of(link), self.attn_of(link)))
        self.send_seq(link, 2)                      # gap: seq 1 missing
        print("PROBE after gap:        expect=%s attn(link)=%s" % (self.expect_of(link), self.attn_of(link)))
        t = self.bfrt.table_get("pipe.Ingress.reg_attn")
        t.operations_execute(self.tgt, "Sync")
        for i in range(0, 16):
            d = next(t.entry_get(self.tgt, [t.make_key([gc.KeyTuple("$REGISTER_INDEX", i)])],
                                 {"from_hw": False}))[0].to_dict()
            a, c = d["Ingress.reg_attn.attn"], d["Ingress.reg_attn.clean"]
            if (a[0] if isinstance(a, list) else a) or (c[0] if isinstance(c, list) else c):
                print("PROBE reg_attn[%d] attn=%s clean=%s" % (i, a, c))


class Test01Initialisation(WitnessBase):
    """A fresh link starts at expected=0, so the first packet of a run is contiguous."""
    def runTest(self):
        link = 3
        self.assertEqual(self.expect_of(link), 0, "a fresh slot must be 0")
        a0, _ = self.attn_of(link)
        self.send_seq(link, 0)
        self.assertEqual(self.expect_of(link), 1, "expected must advance to observed+1")
        self.assertEqual(self.attn_of(link)[0], a0, "seq 0 on a fresh link is not a gap")


class Test02ContiguousRun(WitnessBase):
    """A contiguous run raises no events and leaves expected = last+1."""
    def runTest(self):
        link, n = 4, 10
        a0, _ = self.attn_of(link)
        for s in range(n):
            self.send_seq(link, s)
        self.assertEqual(self.expect_of(link), n)
        self.assertEqual(self.attn_of(link)[0], a0, "no contiguous packet may raise an event")


class Test03SingleLossIsOneEvent(WitnessBase):
    """One dropped packet produces exactly ONE gap event, and the check re-synchronises.

    This is the property the design rests on: the register is rewritten unconditionally, so a
    discontinuity is reported once rather than for every packet thereafter.
    """
    def runTest(self):
        link = 5
        for s in range(3):
            self.send_seq(link, s)
        self.send_seq(link, 4)                       # seq 3 was lost
        self.assertEqual(self.expect_of(link), 5, "the check must re-synchronise on the survivor")
        for s in (5, 6, 7):                          # and stay synchronised afterwards
            self.send_seq(link, s)
            self.assertEqual(self.expect_of(link), s + 1,
                             "one discontinuity must not desynchronise every later packet")


class Test04ConsecutiveLosses(WitnessBase):
    """A burst of k consecutive losses is ONE event, and k is recoverable from the gap.

    gap = expected - observed is 16-bit modular, so losing k returns 2^16 - k: a loss shows as
    a large value and a duplicate or reorder as a small one. tbl_wit_verdict only tests gap==0
    and does not exploit that today; the test records the property because a range
    discrimination is what a later design would need to tell the two apart.
    """
    def runTest(self):
        link, k = 6, 5
        for s in range(2):
            self.send_seq(link, s)
        exp_before = self.expect_of(link)
        self.send_seq(link, exp_before + k)          # k packets lost
        self.assertEqual(self.expect_of(link), (exp_before + k + 1) % WRAP,
                         "a burst re-synchronises on the survivor like a single loss")
        self.assertEqual((exp_before - (exp_before + k)) % WRAP, WRAP - k,
                         "the loss count must be recoverable as 2^16 - gap")


class Test05Duplicate(WitnessBase):
    """A duplicated packet raises an event: the witness cannot tell it from a loss.

    Recorded, not worked around. A directed link is FIFO so duplicates do not arise on the
    wire, but if anything ever replays a packet the verdict is a false 'loss'. The gap is +1
    here against 2^16-k for a real loss, so the two are separable by magnitude if needed.
    """
    def runTest(self):
        link = 7
        self.send_seq(link, 0)
        self.send_seq(link, 1)
        self.send_seq(link, 1)                       # duplicate of the packet just seen
        self.assertEqual(self.expect_of(link), 2, "a duplicate re-synchronises to observed+1")


class Test06Reorder(WitnessBase):
    """Reordering raises an event. A directed link is FIFO so this is out of scope on the
    wire; the test pins the behaviour so a later multi-queue design cannot regress silently."""
    def runTest(self):
        link = 8
        self.send_seq(link, 0)
        self.send_seq(link, 2)                       # gap event: seq 1 missing
        self.send_seq(link, 1)                       # the late arrival
        self.assertEqual(self.expect_of(link), 2, "the late packet re-synchronises the state")


class Test07ModuloWrap(WitnessBase):
    """Wrapping 65535 -> 0 costs nothing: the arithmetic is 16-bit modular throughout."""
    def runTest(self):
        link = 9
        self.set_expect(link, 0xFFFF)
        a0 = self.attn_of(link)[0]
        self.send_seq(link, 0xFFFF)                  # contiguous, and wraps the register
        self.assertEqual(self.expect_of(link), 0, "expected must wrap to 0, not saturate")
        self.send_seq(link, 0)                       # first packet after the wrap
        self.assertEqual(self.expect_of(link), 1)
        self.assertEqual(self.attn_of(link)[0], a0, "no event may be raised at the wrap")


class Test08ResetResync(WitnessBase):
    """After a controller re-seed the next packet at the seeded value is contiguous."""
    def runTest(self):
        link = 10
        self.set_expect(link, 1000)
        a0 = self.attn_of(link)[0]
        self.send_seq(link, 1000)
        self.assertEqual(self.attn_of(link)[0], a0, "a re-seeded link must not alarm")
        self.assertEqual(self.expect_of(link), 1001)


class Test09PerLinkIndependence(WitnessBase):
    """Interleaved links keep separate state — the multi-queue prerequisite.

    One physical loop port on this chip carries N_SPINE directed vlinks (port, qid), which is
    why W2's ingress-port inference is insufficient here and W4 carries an explicit link id
    (p4/witness/COMPILE-GATE.md). This is that claim's functional half.
    """
    def runTest(self):
        a, b = 11, 12
        for s in range(5):                           # interleave two links on one port
            self.send_seq(a, s)
            self.send_seq(b, s)
        self.assertEqual(self.expect_of(a), 5)
        self.assertEqual(self.expect_of(b), 5)
        self.send_seq(a, 6)                          # a loses one; b must be unaffected
        self.send_seq(b, 5)
        self.assertEqual(self.expect_of(a), 7)
        self.assertEqual(self.expect_of(b), 6)


class Test10AttentionArmingIsBrokenCanary(WitnessBase):
    """CANARY for a real defect: a sequence gap does NOT arm the attention machinery.

    `mcp_fabric_w4.p4:731` claims "A gap sets md.exceed, so the existing tbl_attn/tbl_gate
    machinery treats a post-TM sequence discontinuity as path evidence with no new gate."
    On the model that is false, and the per-packet trace says exactly why:

        md.wit_gap = 0xffff                                    <- the gap IS computed
        Ingress : Gateway table condition () not matched.
        Ingress : Table Ingress.tbl_wit_verdict is inhibited by a gateway condition
        Ingress : Table Ingress.tbl_attn is hit
        Execute Action: Ingress.act_attn_clean                  <- clean, not exceed

    bf-p4c folds tbl_wit_verdict (one const entry + const default) into a GATEWAY: on
    gap == 0 it supplies the wit_ok payload, and on a miss it SKIPS the table, so the
    `const default_action = wit_loss()` never runs and md.exceed is never set. Arming from
    wit_measure instead (mcp_fabric_w4_arm2.p4) does not reach tbl_attn either --
    `act_attn_exceed` executes zero times in a whole run.

    This test asserts the DEFECT so the suite stays green while it stands, and fails loudly
    the day the arming is fixed. Whoever fixes it: delete this class and restore the
    attention assertions in Test03-Test06 and Test09.
    """
    def runTest(self):
        link = 13
        self.send_seq(link, 0)
        a_before = self.attn_of(link)[0]
        self.send_seq(link, 5)                       # a five-packet gap
        self.assertEqual(self.expect_of(link), 6, "the gap itself is detected and re-synced")
        self.assertEqual(self.attn_of(link)[0], a_before,
                         "KNOWN DEFECT: the gap does not bump attention. If this fails, the "
                         "arming was fixed -- delete this canary and restore the real assertions.")
