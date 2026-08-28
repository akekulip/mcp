#!/usr/bin/env python3
"""Generate the M2 order-witness variants from the frozen baseline copy.

Every variant is produced by explicit, auditable text substitutions on
p4/witness/mcp_fabric_base.p4 (a byte-identical copy of p4/mcp_fabric.p4), so the
resource delta measured later is attributable to exactly these edits and nothing
else.  Nothing outside p4/witness/ is read or written.
"""
import pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
BASE = (HERE / "mcp_fabric_base.p4").read_text()


def sub(text, old, new, what):
    n = text.count(old)
    if n != 1:
        sys.exit("ERROR: anchor for %r matched %d times (expected 1)" % (what, n))
    return text.replace(old, new)


# --------------------------------------------------------------------------- #
# Shared edit fragments.  W2 = 2 B (seq only); W4 = 4 B (link_id + seq).
# --------------------------------------------------------------------------- #

HDR_W2 = '''
/* ---- M2 order witness (variant W2: 2 bytes, sequence only) ------------------
 * A STANDALONE byte-aligned header.  It is deliberately NOT packed into
 * csig_h.epoch: that container cannot be filled from the egress sources this
 * mechanism needs (bf-p4c Class 13, one PHV source per packed container in an
 * egress action) — DESIGN-ALTERNATIVES "Tag insertion" row.
 *
 * The upstream EGRESS stamps seq from a modular 16-bit per-directed-vlink
 * counter after tbl_eg_vlink has resolved (port,qid) -> vlink.  The downstream
 * INGRESS compares it against per-link expected state.  W2 carries no link id,
 * so link identity must come from the ingress port plus topology. */
header wit_h {
    bit<16> seq;
}
'''

HDR_W4 = '''
/* ---- M2 order witness (variant W4: 4 bytes, explicit link id + sequence) ----
 * As W2, but the upstream egress also stamps the directed vlink id, so the
 * downstream does not have to infer link identity from its ingress port.
 *
 * link_id and seq are adjacent 16-bit fields and therefore share one 32-bit PHV
 * container.  Their egress sources differ (tbl_eg_vlink action data vs the SALU
 * return), which is exactly bf-p4c Class 13.  Mitigation is the csig_replace_a/b
 * precedent: two actions in two tables, each supplying one source. */
header wit_h {
    bit<16> link_id;
    bit<16> seq;
}
'''

# 1. header type, inserted immediately before ipv4_h.
ANCHOR_IPV4 = "header ipv4_h {"

# 2. header stacks.
OLD_HDRS = """struct headers_t {
    ethernet_h ethernet;
    fabric_h   fabric;
    csig_h     csig;
    ipv4_h     ipv4;"""
NEW_HDRS = """struct headers_t {
    ethernet_h ethernet;
    fabric_h   fabric;
    csig_h     csig;
    wit_h      witness;
    ipv4_h     ipv4;"""

OLD_EGH = """    ethernet_h ethernet;
    fabric_h   fabric;
    csig_h     csig;
}"""
NEW_EGH = """    ethernet_h ethernet;
    fabric_h   fabric;
    csig_h     csig;
    wit_h      witness;
}"""

# 3. ingress parser: csig -> witness -> ipv4.
OLD_IG_PARSE_CSIG = """    state parse_csig {
        pkt.extract(hdr.csig);
        transition parse_ipv4;
    }"""
NEW_IG_PARSE_CSIG_W2 = """    state parse_csig {
        pkt.extract(hdr.csig);
        transition parse_witness;
    }

    /* The witness rides with the CSIG tag: act_enter sets nxt = NXT_CSIG and
     * validates both, so one parser state covers every fabric pass.  W2 lifts no
     * field here — its link identity comes from tbl_port_role's action data. */
    state parse_witness {
        pkt.extract(hdr.witness);
        transition parse_ipv4;
    }"""
NEW_IG_PARSE_CSIG_W4 = """    state parse_csig {
        pkt.extract(hdr.csig);
        transition parse_witness;
    }

    /* The witness rides with the CSIG tag: act_enter sets nxt = NXT_CSIG and
     * validates both, so one parser state covers every fabric pass.  md.wit_link
     * is a same-width 16->16 copy (the silicon byte-aliasing of an 8->16 parser
     * cast is why every carried field in this program is 16 bits), and it is
     * assigned ONLY here — a Tofino parser field may be written in one state per
     * path, which is why the start state does not zero it. */
    state parse_witness {
        pkt.extract(hdr.witness);
        md.wit_link = hdr.witness.link_id;
        transition parse_ipv4;
    }"""

# 4. egress parser.
OLD_EG_PARSE_CSIG = """    state parse_csig {
        pkt.extract(hdr.csig);
        transition accept;
    }
}

control Egress"""
NEW_EG_PARSE_CSIG = """    state parse_csig {
        pkt.extract(hdr.csig);
        transition parse_witness;
    }

    state parse_witness {
        pkt.extract(hdr.witness);
        transition accept;
    }
}

control Egress"""

# 5. ingress metadata.
OLD_MD = "    bit<16> mir_etype;\n}"
NEW_MD_W2 = """    bit<16> mir_etype;
    /* M2 witness.  bit<16> like everything else here (Class 3 / N12). */
    bit<16> wit_link;    // directed link this packet ARRIVED on, from tbl_port_role
    bit<16> wit_gap;     // expected_seq - observed_seq; 0 <=> no discontinuity
}"""
NEW_MD_W4 = """    bit<16> mir_etype;
    /* M2 witness.  bit<16> like everything else here (Class 3 / N12).
     * wit_link is written ONLY in parse_witness (see the parser note), so it is
     * not zeroed in the start state and is read only under hdr.witness.isValid(). */
    bit<16> wit_link;    // directed link this packet ARRIVED on, from the witness
    bit<16> wit_gap;     // expected_seq - observed_seq; 0 <=> no discontinuity
}"""

# W2 only: the start state zeroes wit_link because tbl_port_role writes it in the MAU.
OLD_START_ZERO = "        md.mir_etype  = ETYPE_MCP_MIRROR;"
NEW_START_ZERO_W2 = """        md.mir_etype  = ETYPE_MCP_MIRROR;
        md.wit_link   = 0;      // MAU-written by tbl_port_role; safe to zero here
        md.wit_gap    = 0;"""
NEW_START_ZERO_W4 = """        md.mir_etype  = ETYPE_MCP_MIRROR;
        md.wit_gap    = 0;"""

# 6. W2 only: tbl_port_role carries the link id (topology mapping, control-plane data).
OLD_SET_ROLE = """    action set_role(bit<16> role, bit<16> src_leaf) {
        md.role     = role;
        md.src_leaf = src_leaf;
        md.tstamp   = ig_intr_md.ingress_mac_tstamp;   // for mirror_h.tstamp (H7 tau_fast)
    }

    table tbl_port_role {
        key     = { ig_intr_md.ingress_port : exact; }
        actions = { set_role; }
        size    = 64;
        const default_action = set_role(ROLE_OTHER, 0);
    }"""
NEW_SET_ROLE_W2 = """    action set_role(bit<16> role, bit<16> src_leaf, bit<16> wit_link) {
        md.role     = role;
        md.src_leaf = src_leaf;
        md.tstamp   = ig_intr_md.ingress_mac_tstamp;   // for mirror_h.tstamp (H7 tau_fast)
        /* W2 carries no link id on the wire, so the DOWNSTREAM link identity is
         * whatever the control plane says this ingress port means.  Folded into
         * the existing action rather than given its own table: that is the only
         * way W2 stays cheaper than W4 in stages as well as in bytes. */
        md.wit_link = wit_link;
    }

    table tbl_port_role {
        key     = { ig_intr_md.ingress_port : exact; }
        actions = { set_role; }
        size    = 64;
        const default_action = set_role(ROLE_OTHER, 0, 0);
    }"""

# 7. ingress witness check (both variants; identical text).
WIT_INGRESS = '''
    /* ---- M2: downstream order check ------------------------------------------
     * One 16-bit register slot per directed link holds the NEXT EXPECTED sequence
     * number.  Every witness-bearing packet both tests and re-synchronises it:
     *
     *     gap = expected - observed      (0 <=> contiguous)
     *     expected = observed + 1        (modular in 16 bits, so wrap is free)
     *
     * Re-synchronising unconditionally is what makes the check self-healing after
     * a loss burst, a reset or a controller re-seed: exactly one gap event is
     * raised per discontinuity, not one per packet forever.  It also means the
     * SALU takes a single PHV input (hdr.witness.seq) plus memory.
     *
     * A gap sets md.exceed, so the existing tbl_attn/tbl_gate machinery treats a
     * post-TM sequence discontinuity as path evidence with no new gate. */
    Register<bit<16>, bit<16>>(64, 0) reg_wit_expect;
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_wit_expect) wit_check = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = v - hdr.witness.seq;
            v  = hdr.witness.seq + 1;
        }
    };

    action wit_measure() { md.wit_gap = wit_check.execute(md.wit_link); }

    /* Class 11: a stateful action whose index is a PHV field cannot be a table's
     * DEFAULT action ("requires the hash distribution unit").  Same fix as
     * tbl_attn: a real key with const entries.  Keying on md.role also gives the
     * right scope for free — only a loop-port arrival carries an upstream
     * witness; a host-port arrival is pre-fabric. */
    table tbl_wit_check {
        key     = { md.role : exact; }
        actions = { wit_measure; @defaultonly NoAction; }
        size    = 4;
        const default_action = NoAction();
        const entries = { ROLE_LOOP : wit_measure(); }
    }

    /* Ground truth for the F0 false-gap floor and the F1 gap-to-reaction split:
     * the counter is on-chip and, per PREREG, unread by the detector. */
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) wit_ctr;
    action wit_ok()   { wit_ctr.count(); }
    action wit_loss() { %ARM%wit_ctr.count(); }

    table tbl_wit_verdict {
        key      = { md.wit_gap : exact; }
        actions  = { wit_ok; wit_loss; }
        counters = wit_ctr;
        size     = 2;
        const default_action = wit_loss();
        const entries = { 16w0 : wit_ok(); }
    }
'''

ANCHOR_IG_INSERT = "    /* ---- S8: final forward, shim write / strip"

# 8. act_enter / act_deliver.
OLD_ENTER_TAIL_W2 = """        hdr.csig.path_id      = md.attn_idx;
        hdr.csig.epoch        = epoch;
    }"""
NEW_ENTER_TAIL_W2 = """        hdr.csig.path_id      = md.attn_idx;
        hdr.csig.epoch        = epoch;
        /* The witness is inserted and zeroed in INGRESS for the same reason the
         * CSIG tag is: ingress action data is unconstrained, egress packed-
         * container writes are not (Class 13).  Egress only stamps. */
        hdr.witness.setValid();
        hdr.witness.seq       = 0;
    }"""
NEW_ENTER_TAIL_W4 = """        hdr.csig.path_id      = md.attn_idx;
        hdr.csig.epoch        = epoch;
        /* The witness is inserted and zeroed in INGRESS for the same reason the
         * CSIG tag is: ingress action data is unconstrained, egress packed-
         * container writes are not (Class 13).  Egress only stamps.  Zeroing both
         * halves from one constant source in ONE ingress action is legal; the
         * same pair written from two different sources in egress is not. */
        hdr.witness.setValid();
        hdr.witness.link_id   = 0;
        hdr.witness.seq       = 0;
    }"""

OLD_DELIVER = """    action act_deliver(bit<9> port) {
        hdr.fabric.setInvalid();
        hdr.csig.setInvalid();"""
NEW_DELIVER = """    action act_deliver(bit<9> port) {
        hdr.fabric.setInvalid();
        hdr.csig.setInvalid();
        hdr.witness.setInvalid();"""

# 9. ingress apply: run the check where the other exceedance sources run.
OLD_APPLY = """            /* Evidence packets terminate here:"""
NEW_APPLY = """            /* M2: did the directed link this packet arrived on skip a sequence
             * number between the upstream egress and here?
             *
             * PLACEMENT IS LOAD-BEARING, measured this session on 9.13.2.  This
             * block sits AFTER tbl_exceed_evid / tbl_exceed_csig.  Moving it
             * BEFORE them costs one extra ingress stage even though the table
             * dependency graph is unchanged, because tbl_wit_verdict and
             * tbl_exceed_* both write md.exceed and the compiler must honour
             * program order on that write-after-write. */
            if (hdr.witness.isValid()) {
                tbl_wit_check.apply();
                tbl_wit_verdict.apply();
            }

            /* Evidence packets terminate here:"""

# 10. egress stamp.
WIT_EGRESS_W2 = '''
    /* ---- M2: upstream sequence allocation (post-TM) ---------------------------
     * One modular 16-bit counter per directed vlink, read-then-increment.  It runs
     * AFTER tbl_eg_vlink so the index is the directed link the packet is actually
     * leaving on, and it runs in EGRESS so it counts what the TM released, not
     * what ingress hoped to send. */
    Register<bit<16>, bit<16>>(64, 0) reg_wit_seq;
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_wit_seq) wit_next = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = v;
            v  = v + 1;
        }
    };

    action wit_stamp() { hdr.witness.seq = wit_next.execute(md.vlink); }

    /* Class 11 again: a keyless table cannot make a computed-index stateful action
     * its default.  hdr.fabric.nxt has a two-value compile-time domain, so const
     * entries cost nothing and express the intent (stamp the tag stack only). */
    table tbl_wit_stamp {
        key     = { hdr.fabric.nxt : exact; }
        actions = { wit_stamp; @defaultonly NoAction; }
        size    = 4;
        const default_action = NoAction();
        const entries = { NXT_CSIG : wit_stamp(); }
    }
'''

WIT_EGRESS_W4 = '''
    /* ---- M2: upstream sequence allocation (post-TM) ---------------------------
     * One modular 16-bit counter per directed vlink, read-then-increment.  It runs
     * AFTER tbl_eg_vlink so the index is the directed link the packet is actually
     * leaving on, and it runs in EGRESS so it counts what the TM released, not
     * what ingress hoped to send. */
    Register<bit<16>, bit<16>>(64, 0) reg_wit_seq;
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_wit_seq) wit_next = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = v;
            v  = v + 1;
        }
    };

    action wit_stamp() { hdr.witness.seq     = wit_next.execute(md.vlink); }
    action wit_link()  { hdr.witness.link_id = md.vlink; }

    /* Class 11 again: a keyless table cannot make a computed-index stateful action
     * its default.  hdr.fabric.nxt has a two-value compile-time domain, so const
     * entries cost nothing and express the intent (stamp the tag stack only).
     *
     * Class 13: link_id and seq share a 32-bit container and their sources differ
     * (tbl_eg_vlink action data vs the SALU return), so they are written by two
     * actions in two tables — the csig_replace_a / csig_replace_b precedent. */
    table tbl_wit_stamp {
        key     = { hdr.fabric.nxt : exact; }
        actions = { wit_stamp; @defaultonly NoAction; }
        size    = 4;
        const default_action = NoAction();
        const entries = { NXT_CSIG : wit_stamp(); }
    }

    table tbl_wit_link {
        key     = { hdr.fabric.nxt : exact; }
        actions = { wit_link; @defaultonly NoAction; }
        size    = 4;
        const default_action = NoAction();
        const entries = { NXT_CSIG : wit_link(); }
    }
'''

ANCHOR_EG_INSERT = "    action set_eg_vlink(bit<16> vlink) {"

OLD_EG_APPLY = """        if (hdr.csig.isValid()) {
            tbl_eg_vlink.apply();
            tbl_csig_diff.apply();"""
NEW_EG_APPLY_W2 = """        if (hdr.csig.isValid()) {
            tbl_eg_vlink.apply();
            tbl_wit_stamp.apply();
            tbl_csig_diff.apply();"""
NEW_EG_APPLY_W4 = """        if (hdr.csig.isValid()) {
            tbl_eg_vlink.apply();
            tbl_wit_stamp.apply();
            tbl_wit_link.apply();
            tbl_csig_diff.apply();"""


EG_FAIL = '''
    /* ---- M2 requirement: fault injection AFTER sequence allocation ------------
     * The baseline injects faults in INGRESS (tbl_fail), which for this mechanism
     * is a pre-increment drop: the dropped packet never reaches the upstream
     * egress, never consumes a sequence number, and therefore produces NO gap
     * downstream.  Wire-loss semantics can only be exercised by dropping AFTER
     * the stamp, which is what this table does.  Same shape as ingress tbl_fail:
     * a hardware Random draw as a TCAM range key, a DirectCounter for ground
     * truth, and control-plane range bounds so the rate retunes without a
     * recompile (drop probability = (high - low + 1)/65536).
     *
     * Class 2: one 16-bit range key = 4 of the 5 range nibbles.  Do not add a
     * second range field to this table. */
    Random<bit<16>>() rng_eg_fail;
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) eg_fail_ctr;

    action eg_inj_drop() { eg_dprsr_md.drop_ctl = 1; eg_fail_ctr.count(); }
    action eg_inj_none() { eg_fail_ctr.count(); }

    table tbl_eg_fail {
        key = {
            md.vlink       : exact;
            md.eg_rnd_fail : range;
        }
        actions  = { eg_inj_drop; eg_inj_none; }
        counters = eg_fail_ctr;
        size     = 64;
        const default_action = eg_inj_none();
    }
'''

OLD_EGMD = "    bit<32> tdelta;     // eg_intr_md.deq_timedelta (18-bit) widened here"
NEW_EGMD = OLD_EGMD + "\n    bit<16> eg_rnd_fail;  // range key: exactly 16 bits = 4 of the 5 range nibbles (Class 2)"
OLD_EGPARSE_INIT = "        md.tdelta = 0;"
NEW_EGPARSE_INIT = OLD_EGPARSE_INIT + "\n        md.eg_rnd_fail = 0;"


def build(variant, arm=False, egdrop=False):
    t = BASE
    hdr = HDR_W2 if variant == "w2" else HDR_W4
    t = sub(t, ANCHOR_IPV4, hdr.lstrip("\n") + "\n" + ANCHOR_IPV4, "ipv4 header anchor")
    t = sub(t, OLD_HDRS, NEW_HDRS, "headers_t")
    t = sub(t, OLD_EGH, NEW_EGH, "eg_headers_t")
    t = sub(t, OLD_IG_PARSE_CSIG,
            NEW_IG_PARSE_CSIG_W2 if variant == "w2" else NEW_IG_PARSE_CSIG_W4,
            "ingress parse_csig")
    t = sub(t, OLD_EG_PARSE_CSIG, NEW_EG_PARSE_CSIG, "egress parse_csig")
    t = sub(t, OLD_MD, NEW_MD_W2 if variant == "w2" else NEW_MD_W4, "ig_md_t")
    t = sub(t, OLD_START_ZERO,
            NEW_START_ZERO_W2 if variant == "w2" else NEW_START_ZERO_W4,
            "parser start zeroes")
    if variant == "w2":
        t = sub(t, OLD_SET_ROLE, NEW_SET_ROLE_W2, "tbl_port_role")
    wit_ig = WIT_INGRESS.replace("%ARM%", "md.exceed = 1; " if arm else "")
    t = sub(t, ANCHOR_IG_INSERT, wit_ig.lstrip("\n") + "\n" + ANCHOR_IG_INSERT,
            "ingress witness block")
    t = sub(t, OLD_ENTER_TAIL_W2 if variant == "w2" else OLD_ENTER_TAIL_W2,
            NEW_ENTER_TAIL_W2 if variant == "w2" else NEW_ENTER_TAIL_W4, "act_enter")
    t = sub(t, OLD_DELIVER, NEW_DELIVER, "act_deliver")
    t = sub(t, OLD_APPLY, NEW_APPLY, "ingress apply")
    t = sub(t, ANCHOR_EG_INSERT,
            (WIT_EGRESS_W2 if variant == "w2" else WIT_EGRESS_W4).lstrip("\n")
            + "\n" + ANCHOR_EG_INSERT, "egress witness block")
    t = sub(t, OLD_EG_APPLY,
            NEW_EG_APPLY_W2 if variant == "w2" else NEW_EG_APPLY_W4, "egress apply")
    if egdrop:
        t = sub(t, OLD_EGMD, NEW_EGMD, "eg_md_t rnd")
        t = sub(t, OLD_EGPARSE_INIT, NEW_EGPARSE_INIT, "egress parser init")
        t = sub(t, ANCHOR_EG_INSERT, EG_FAIL.lstrip("\n") + "\n" + ANCHOR_EG_INSERT,
                "egress fail block")
        anchor = "            tbl_csig_diff.apply();"
        t = sub(t, anchor,
                "            md.eg_rnd_fail = rng_eg_fail.get();\n"
                "            tbl_eg_fail.apply();\n" + anchor, "egress fail apply")
    return t


VARIANTS = [
    ("mcp_fabric_w2",        dict(variant="w2")),
    ("mcp_fabric_w4",        dict(variant="w4")),
    ("mcp_fabric_w2_arm",    dict(variant="w2", arm=True)),
    ("mcp_fabric_w4_arm",    dict(variant="w4", arm=True)),
    ("mcp_fabric_w4_egdrop", dict(variant="w4", arm=True, egdrop=True)),
]
for name, kw in VARIANTS:
    src = build(**kw)
    (HERE / (name + ".p4")).write_text(src)
    print("wrote %-26s %4d lines" % (name + ".p4", len(src.splitlines())))
