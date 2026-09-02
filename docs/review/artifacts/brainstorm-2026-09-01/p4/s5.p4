/* mcp_fabric.p4 — Tofino 1 (TNA) emulation of a packet-sprayed leaf-spine fabric.
 *
 * Implements docs/P4-DESIGN-SPACE.md.  STEPS 1-5 of the §9.2 offline compile
 * sequence: headers/parser/deparser, forwarding + virtual-link resolve, spraying,
 * failure injection, (step 5) the in-switch attention register with the PREREG
 * §7.4 update rule + the probabilistic measurement gate, and (step 6) truncated
 * ingress mirrors: session 3 on every injected fault (§5.6 mirror-on-drop), session
 * 1 on every gated sample (§5.4), and (step 7) the fixed 12-byte CSIG-style tag
 * inserted / compare-and-replaced in EGRESS (§5.5).  Step 8 (evidence reflection)
 * is NOT here yet — see p4/README.md.
 *
 * Fabric shape is entirely control-plane data.  The reference bring-up
 * (p4/control/setup_skeleton.py) programs 2 leaves x 4 spines = 16 virtual links
 * (8 uplinks + 8 downlinks) over 16 real TM queues on two loop ports; nothing in
 * this file hard-codes 2x4.
 *
 * Three passes per packet (§1):
 *   hop 0  from a host port      -> source leaf: spray, pick spine, shim on, to loop
 *   hop 1  from a loop port      -> spine:       forward to destination leaf, to loop
 *   hop 2  from a loop port      -> dest leaf:   strip shim, deliver to the host port
 *
 * Wire format inside the fabric (§3, alternative A2):
 *
 *   eth(etype=0x88F0) | fabric_h 12B | [csig_h 14B] | ipv4 | udp | [bth 12B | evid 8B]
 *
 * LOAD-BEARING (§3 recommendation, carriage detail 1): the fabric shim and the CSIG
 * tag are L2 shims — they sit BETWEEN the Ethernet header and the original L3 header.
 * Therefore no IPv4 total_len and no IPv4/UDP checksum is ever updated anywhere in
 * this program, which removes bf-p4c constraint Class 6 (the silent ICE on
 * end-around-carry checksum updates) from the entire build.  Do not "clean this up"
 * by moving either header after IPv4.  (constraints.md operational caveat B.)
 *
 * Build (local SDE 9.13.1; the switch runs 9.13.2 — see p4/README.md):
 *   export SDE=/home/philip/bf-sde-9.13.1
 *   export SDE_INSTALL=$SDE/install
 *   $SDE_INSTALL/bin/bf-p4c --target tofino --arch tna \
 *       -o mcp_fabric.tofino --bf-rt-schema mcp_fabric.bfrt.json mcp_fabric.p4
 */
#include <core.p4>
#include <tna.p4>

/* ======================= constants ======================= */

const bit<16> ETYPE_IPV4        = 0x0800;
const bit<16> ETYPE_MCP_FABRIC  = 0x88F0;   // private, internal only (§3)
const bit<16> ETYPE_MCP_MIRROR  = 0x88F1;   // mirrored copies to the collector (step 6)
/* The mirror header's fake Ethernet fields (dst A5:A5:A5:A5:A5:A5, src 02:00:00:00:4D:43)
 * cannot be constants in the emit field list ("Non-zero constant value ... in digest
 * field list is not supported on tofino"): the parser start state writes them into metadata. */

/* fabric_h.nxt — what follows the shim.  A parser select on a whole 8-bit value,
 * never a chain of runtime bit tests (§8.4/N11). */
const bit<8>  NXT_IPV4          = 0;
const bit<8>  NXT_CSIG          = 1;

const bit<8>  IP_PROTO_UDP      = 17;
const bit<16> UDP_PORT_ROCEV2   = 4791;
const bit<16> AUDIT_UDP_DST = 4792;
const bit<16> UDP_PORT_EVIDENCE = 0xE5E5;

/* Port roles, written by tbl_port_role from the ingress port (§3 carriage detail 2). */
const bit<16> ROLE_OTHER = 0;
const bit<16> ROLE_HOST  = 1;   // dp9 — traffic source/sink
const bit<16> ROLE_LOOP  = 2;   // dp68 / dp8 — the loop ports carrying the virtual links
const bit<16> ROLE_NIC   = 3;   // dp65 — Agilio: evidence in, mirrored copies out

/* Number of fabric passes.  hop == LAST_HOP is the destination leaf, which delivers
 * to a host port instead of resolving another virtual link.  A 3-level fabric is
 * LAST_HOP = 4 and needs no other change here. */
const bit<16> LAST_HOP = 2;

/* ======================= headers ======================= */

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

/* §3 A2.  12 bytes.  Every field the PARSER lifts into 16-bit metadata is itself 16 bits:
 * on silicon (2026-08-26, p4/reports/step4-silicon.md) `md.hop = (bit<16>)hdr.fabric.hop`
 * with an 8-bit hop did NOT zero-extend — the high byte held the neighbouring shim byte
 * (md.hop == vsw_id<<8 | hop).  Same-width parser copies are clean container moves. */
header fabric_h {
    bit<16> vsw_id;   // which virtual switch handles this pass
    bit<16> hop;      // 0 = fresh from host; incremented per pass
    bit<16> spray;    // spray index chosen at the source leaf (§4) — the substitute
                      // for a Random<> seed: the path is recoverable from a capture
    bit<16> path_id;  // (dst_leaf, spray) path id, written at the source leaf; egress
                      // stamps it into the CSIG tag and every pass indexes reg_attn by it
    bit<8>  clf_bank; // CLF frontier bank parity (0 or 1), stamped at the SOURCE.
                      // Was `loops` (§7.4 L1 extra latency loops): declared, written to 0
                      // once in act_enter, never read, never implemented.  Reusing that
                      // dead byte costs no wire bytes and -- the reason it is HERE and not
                      // in `flags` -- act_transit does not write it, so the parity survives
                      // every transit hop by construction.  Packing it into `flags` cannot
                      // work: bit 3 is already set_gap_event's marker, and preserving a bit
                      // across act_transit needs a mask+OR, which bf-p4c rejects as
                      // "action spanning multiple stages" (constraint class 5).
    bit<8>  flags;    // bit0 measured, bit1 dropped, bit2 corrupted (never parsed into md)
    bit<8>  nxt;      // NXT_IPV4 | NXT_CSIG — parser select only
    bit<8>  pad;
}

/* §5.5.  Fixed-size "worst hop so far" tag, not a growing INT stack.  14 bytes, all
 * fields >= 16 bits.  bf-p4c packs adjacent header fields into one PHV container and an
 * action may fill a container from at most 2 PHV sources and NO constant — so no 8-bit
 * pairs, no pad written with a constant, and no zero-extending casts inside the
 * insert/replace actions (a cast counts as a constant source); the egress metadata
 * below is pre-widened in set_eg_vlink instead. */
header csig_h {
    bit<16> worst_hop;
    bit<16> worst_vlink;
    bit<16> worst_qdepth;   // eg_intr_md.deq_qdepth[15:0], 1-cell granularity (see Egress)
    bit<32> worst_tdelta;   // eg_intr_md.deq_timedelta (18-bit on Tofino 1, widened)
    bit<16> path_id;        // written in INGRESS at insertion (act_enter), never in egress
    bit<16> epoch;          // idem (tbl_final action data): egress only touches worst_*
}

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

header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header udp_h {
    bit<16> src_port;   // per-packet spray entropy written by the sending NIC (§4 B2)
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

/* RoCEv2 Base Transport Header, carried as OPAQUE bytes (§7.2 F2).  Nothing in this
 * program interprets it; it is parsed so that (a) the layout is exercised and (b) a
 * later PSN-based loss check has the bytes in PHV without a parser change. */
header bth_h {
    bit<32> w0;
    bit<32> w1;
    bit<32> w2;
}

/* Step 6.  Ingress Mirror.emit() copies the packet AS IT ARRIVED — none of this pass's
 * header edits are in the copy (measured on silicon: the copy's flags tracked the
 * PREVIOUS pass, p4/reports/step5-7-silicon.md).  So the copy carries this pass's
 * verdict in a header prepended by the mirror engine, laid out as a complete Ethernet
 * frame so the collector sees eth(dst A5:A5:…, etype 0x88F1) | mirror_meta | the
 * original frame.  30 bytes.  The egress parser recognises the 0xA5A5 prefix and
 * leaves copies alone (no CSIG on copies). */
header mirror_h {
    bit<48> dmac;
    bit<48> smac;
    bit<16> etype;
    bit<16> next_hop;  // hdr.fabric.hop AFTER this pass's act_enter/act_transit, i.e. the
                       // mirroring pass + 1 (silicon: source-leaf copy = 1, spine copy = 2).
                       // md.hop cannot be emitted (Class 14); the inner frame's ethertype
                       // (0x0800 source-leaf, 0x88F0 spine) is the unambiguous discriminator.
    bit<16> vlink;     // virtual link the packet was on (0 at the delivery pass)
    bit<16> path_id;
    bit<16> attn;      // attention weight read for this path on this pass
    bit<16> flags;     // bit0 measured, bit1 dropped, bit2 corrupted
    bit<48> tstamp;    // ig_intr_md.ingress_mac_tstamp of the mirrored packet (ns): the
                       // switch's own clock, for PREREG H7 tau_fast without host clocks
}

/* §6 D1 — NIC-side evidence. */
header evid_h {
    bit<8>  magic;
    bit<8>  path_id;
    bit<8>  rtt_q;
    bit<8>  loss_q;
    bit<8>  ecn_q;
    bit<8>  flags;
    bit<16> seq;
}

struct headers_t {
    ethernet_h ethernet;
    fabric_h   fabric;
    csig_h     csig;
    wit_h      witness;
    ipv4_h     ipv4;
    udp_h      udp;
    bth_h      bth;
    evid_h     evid;
}

/* Egress only ever touches the L2 shims (§5.5): everything from IPv4 on is left as
 * unparsed residual, which the deparser re-appends untouched. */
struct eg_headers_t {
    mirror_h   mirror;    // present on mirrored copies only; the rest is residual
    ethernet_h ethernet;
    fabric_h   fabric;
    csig_h     csig;
    wit_h      witness;
}

/* Step 5 attention word: two 16-bit halves in one 32-bit SALU register (§7.4 ii). */
struct attn_pair_t {
    bit<16> attn;
    bit<16> clean;
}


struct wit_result_t {
    bit<16> gap;
    bit<16> observed;
}

/* ======================= metadata ======================= */

/* Every field is bit<16> even where one bit would do: constraint Class 3 (sub-byte
 * fields next to register outputs -> invalid SuperCluster) sets the floor at bit<8>,
 * and N12 (the 8-bit MAU PHV group saturates long before the chip does) makes
 * bit<16> the default for anything new. */
struct ig_md_t {
    bit<16> role;        // 0 other, 1 host, 2 loop, 3 nic  (set by tbl_port_role)
    bit<16> src_leaf;
    bit<16> dst_leaf;
    bit<16> hop;         // from fabric_h.hop, or 0 when fresh from a host
    bit<16> vsw_id;
    bit<16> next_vsw;
    bit<16> path_id;
    bit<16> spray_idx;
    bit<16> spray_rand;
    bit<16> spray_hash;
    bit<16> spray_rr;
    bit<16> spray_sel;
    bit<16> vlink_id;
    bit<16> rnd_fail;    // range key: exactly 16 bits = 4 of the 5 range nibbles (Class 2)
    bit<16> rnd_attn;
    bit<16> attn;        // attention weight of this packet's path, read by the SALU
    bit<16> attn_idx;    // reg_attn index = path id (from tbl_vlink, csig or evid)
    bit<16> exceed;      // 1 = this packet is threshold-exceedance evidence for attn_idx
    bit<16> do_measure;
    bit<16> is_audit;   // reserved P3 probation/liveness packet
    bit<16> audit_src;  // H35: 1 = this ingress port may use the audit path (set_role action data)
    bit<16> fault;       // 0 none, 2 dropped, 4 corrupted (bit0 is reserved for "measured")
    bit<16> flags_out;   // fabric_h.flags to write: fault | measured
    bit<16> clf_idx;     // (bank << 8) | upstream sublink -- RX frontier index, INGRESS
    bit<32> clf_rx_prev;
    MirrorId_t mirror_sid;   // bit<10>: Mirror.emit() wants a plain field, no cast/slice
    bit<48> tstamp;          // ig_intr_md.ingress_mac_tstamp copied by set_role (MAU-written = emit-safe)
    bit<16> mir_path;        // md.attn_idx copied by tbl_attn's actions: evidence packets have no
                             // shim, so hdr.fabric.path_id reads 0 in their copies (silicon, h7-F1)
    bit<48> mir_dmac;        // mirror header constants, from the parser start state
    bit<48> mir_smac;
    bit<16> mir_etype;
    /* M2 witness.  bit<16> like everything else here (Class 3 / N12).
     * wit_link is written ONLY in parse_witness (see the parser note), so it is
     * not zeroed in the start state and is read only under hdr.witness.isValid(). */
    bit<16> wit_link;    // directed link this packet ARRIVED on, from the witness
    bit<8>  ctx;        // capsule: size bin x service class
    wit_result_t wit_result; // gap plus saturating arrivals since prior gap
}

struct eg_md_t {
    bit<16> clf_tx_idx;   // (bank << 8) | outgoing sublink   (TX)
    bit<32> clf_tx_prev;
    bit<16> tx_count;
    bit<16> eg_rnd;
    bit<16> this_q;     // eg_intr_md.deq_qdepth[15:0]: a LOW slice.  §5.5's [18:3] needs a
                        // shift on intrinsic metadata and the egress PHV allocator then fails
                        // ("Unable to slice ... eg_intr_md.*"); [15:0] = 64K cells, plenty
    bit<16> diff;       // worst_qdepth |-| this_q : 0 <=> this hop is the worst so far
    bit<16> vlink;      // this egress (port, qid) as a virtual-link id, from tbl_eg_vlink
    bit<16> hop;        // hdr.fabric.hop widened here, not inside the tag actions
    bit<8>  ctx;        // capsule read off the shim
    bit<16> stratum;    // C-W4: the behavioral-sublink context of this packet
    bit<16> sublink;    // (vlink << 4) | stratum, precomputed for the SALU index
    bit<32> tdelta;     // eg_intr_md.deq_timedelta (18-bit) widened here
}

/* ======================= ingress parser ======================= */

parser IgParser(packet_in pkt, out headers_t hdr, out ig_md_t md,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        md.role       = 0;
        md.src_leaf   = 0;
        md.dst_leaf   = 0;
        md.hop        = 0;
        md.vsw_id     = 0;
        md.next_vsw   = 0;
        md.path_id    = 0;
        md.spray_idx  = 0;
        md.spray_rand = 0;
        md.spray_hash = 0;
        md.spray_rr   = 0;
        md.spray_sel  = 0;
        md.vlink_id   = 0;
        md.rnd_fail   = 0;
        md.rnd_attn   = 0;
        md.attn       = 0;
        /* md.attn_idx is deliberately NOT zeroed here: parse_csig / parse_evid assign it
         * and a Tofino parser field may be written in only one state on a path. Hop-0
         * data packets get it from tbl_vlink action data instead. */
        md.exceed     = 0;
        md.do_measure = 0;
        md.is_audit   = 0;
        md.audit_src  = 0;
        md.fault      = 0;
        md.flags_out  = 0;
        md.mirror_sid = 0;
        /* Mirror header Ethernet fields: constants are free in the parser, forbidden in
         * the emit field list, and expensive as MAU action data (112 immediate bits). */
        md.tstamp     = 0;
        md.mir_path   = 0;
        md.mir_dmac   = 48w0xA5A5A5A5A5A5;
        md.mir_smac   = 48w0x020000004D43;
        md.mir_etype  = ETYPE_MCP_MIRROR;
        md.ctx        = 0;
        md.wit_result.gap = 0;
        md.wit_result.observed = 0;
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETYPE_MCP_FABRIC : parse_fabric;
            ETYPE_IPV4       : parse_ipv4;
            default          : accept;
        }
    }

    state parse_fabric {
        pkt.extract(hdr.fabric);
        /* Lift the wire-carried pass state into metadata HERE rather than in a MAU
         * gateway: the parser is free, and an `if (hdr.fabric.isValid())` block in the
         * MAU would become its own logical table (§8.4/N10).  Re-assigning md fields
         * that the start state already zeroed is legal on bf-p4c 9.13.1. */
        md.hop    = hdr.fabric.hop;
        md.vsw_id = hdr.fabric.vsw_id;
        /* The spray index is chosen ONCE, at the source leaf, and then carried on the
         * wire (§4, "determinism, stated honestly").  Later passes reuse it rather
         * than re-drawing, which is both correct — the spine a packet is on cannot
         * change mid-flight — and what makes a capture at the collector sufficient to
         * reconstruct the path even in the unseeded Random mode. */
        md.spray_idx = hdr.fabric.spray;
        md.attn_idx  = hdr.fabric.path_id;
        transition select(hdr.fabric.nxt) {
            NXT_CSIG : parse_csig;
            default  : parse_ipv4;
        }
    }

    state parse_csig {
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
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_UDP : parse_udp;
            default      : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            UDP_PORT_ROCEV2   : parse_bth;
            UDP_PORT_EVIDENCE : parse_evid;
            default           : accept;
        }
    }

    state parse_bth {
        pkt.extract(hdr.bth);
        transition accept;
    }

    state parse_evid {
        pkt.extract(hdr.evid);
        /* attn_idx comes from tbl_exceed_evid's actions, not here: parse_csig is on the
         * same parser path and a field may be assigned in only one state per path. */
        transition accept;
    }
}

/* ======================= ingress ======================= */

control Ingress(inout headers_t hdr, inout ig_md_t md,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {

    /* ---- S0: port role ------------------------------------------------------
     * §8.1 notes a lever here: classifying ig_intr_md.ingress_port in the PARSER
     * removes this stage entirely.  Kept as a table for now because the role map is
     * the thing an operator most wants to change at runtime; revisit if the stage
     * budget tightens (README, "levers not yet spent"). */
    action set_role(bit<16> role, bit<16> src_leaf, bit<16> audit_src) {
        md.role      = role;
        md.src_leaf  = src_leaf;
        md.audit_src = audit_src;
        md.tstamp   = ig_intr_md.ingress_mac_tstamp;   // for mirror_h.tstamp (H7 tau_fast)
    }

    table tbl_port_role {
        key     = { ig_intr_md.ingress_port : exact; }
        actions = { set_role; }
        size    = 64;
        const default_action = set_role(ROLE_OTHER, 0, 0);
    }

    /* ---- H35: provenance for the audit path (campaign blocker B5) ---------------
     * tbl_audit_steer admits a packet to a DELIBERATE tbl_health_gate bypass -- that
     * bypass is how probation traffic reaches a sublink the gate has emptied -- on
     * (udp.dst_port == 4792, udp.src_port == declared_token) alone.  Nothing in the
     * key said the packet came from the controller, so any host that could emit UDP
     * to 4792 and guess a 16-bit token could push traffic onto a link the system had
     * just decided was faulty.  That is an authorization boundary with no
     * authentication on it, and a selective-drop adversary wants exactly that
     * primitive.  md.audit_src carries the missing provenance.
     *
     * The discriminator, chosen after rejecting the obvious one.  md.role does NOT
     * work: in this testbed the controller shares dp9 with production traffic and
     * dp9 must stay ROLE_HOST (tbl_vlink and the injected-fabric-frame drop both key
     * on it), and Hulk on dp10 is ROLE_HOST too -- so a role key would admit both
     * host ports and authenticate nothing.  The finest provenance the chip actually
     * has is the ingress dev_port, which tbl_port_role already matches on, so the
     * permission rides as action data on the row that is already there.
     *
     * Why action data and not a second table keyed on ingress_port: measured on
     * bf-p4c 9.13.1, a separate tbl_audit_port costs ONE INGRESS STAGE (11 -> 12)
     * even though the critical path stays at 11 -- tbl_audit_steer slips from stage
     * 4 to stage 5 and every table below it shifts down.  As action data it is free.
     *
     * Why the flag is not folded into md.role instead: `md.role == ROLE_HOST` is a
     * gateway predicate and tbl_vlink keys on md.role, so a new role value or a spare
     * bit in that field would change both.
     *
     * Why this is a PER-PORT permission and not simply "the controller's port":
     * tbl_audit_steer re-fires on EVERY hop.  The ingress parser reaches hdr.udp on
     * fabric passes as well as at the source leaf, and md.is_audit is re-derived at
     * each hop -- the audit RECEIPT mirror at the destination leaf is gated on
     * `md.hop != 0 && md.is_audit != 0`.  So the LOOP ports must also carry
     * audit_src = 1 or P3 liveness evidence disappears while the program still
     * compiles.  The bypass itself is a hop-0 decision (`md.hop == 0 &&
     * md.is_audit == 0` guards tbl_health_gate) and a frame carrying the internal
     * fabric ethertype is dropped on arrival at a host port, so an off-path host can
     * only ever enter at hop 0 -- which is the point this authenticates.
     *
     * WHAT THIS GUARANTEES, AND WHERE:
     *   deployment (dedicated controller port, audit_src = 1 on it and on the fabric
     *     links only): the bypass is unreachable from every leaf host port.  This is
     *     the property H35 asks for.
     *   THIS EMULATION: the controller and production traffic share dp9, so dp9 must
     *     carry audit_src = 1 and any process on Vision retains the old capability.
     *     The surface shrinks from "any host anywhere on the fabric" (Hulk on dp10
     *     included) to "the one machine on the controller's port"; it does not go to
     *     zero, and the testbed cannot demonstrate the deployment guarantee.  Do not
     *     claim that it does.
     *
     * CONTROL PLANE, and this is the H39b failure mode: set_role's arity changes
     * from (role, src_leaf) to (role, src_leaf, audit_src).  A writer that still
     * passes two arguments fails as wrong action arity or a silently empty table.
     * tbl_port_role's default is set_role(ROLE_OTHER, 0, 0), so an unclassified port
     * has no audit path at all -- fail-closed -- and a switch whose role rows have
     * not been reinstalled has no audit path either. */


    /* ---- S1: destination leaf ------------------------------------------------
     * path_base is (dst_leaf << 2) computed by the CONTROL PLANE and shipped as
     * action data.  Folding the shift into action data is the Class 5 mitigation
     * named in §8.4: the data plane only ORs in the spray index later. */
    action set_dst(bit<16> dst_leaf, bit<16> path_base) {
        md.dst_leaf = dst_leaf;
        md.path_id  = path_base;
    }

    table tbl_dst_leaf {
        key     = { hdr.ipv4.dst_addr : exact; }
        actions = { set_dst; }
        size    = 1024;
        const default_action = set_dst(0, 0);
    }

    /* ---- S1/S2: spray (§4) ---------------------------------------------------
     * Three modes in ONE binary, selected at runtime by which action the control
     * plane installs in tbl_spray_mode.  The evaluation needs uniform-random,
     * hash-of-entropy and perfect round-robin as baselines against each other; a
     * runtime switch removes three recompiles and three chances for the pipelines to
     * differ in some other way (§4 recommendation).
     *
     *   B1 Random<>            — genuinely per-packet, NOT replayable (Tofino 1 has
     *                            no control-plane seed for Random<>)
     *   B2 hash of the NIC's per-packet UDP source-port entropy  ★ default
     *   B4 control-plane-seeded round-robin via a SALU counter, indexed by src_leaf
     *
     * All three candidates are computed unconditionally at the source leaf; the mode
     * table then picks one. That costs one extra stage versus branching and is far
     * easier to debug on hardware, which is the tie-breaker (§4). */
    Random<bit<16>>() rng_spray;

    /* Class 7: a Hash instance is bound to the field list of its FIRST .get().  This
     * one is only ever called on this 3-tuple.  A second tuple shape needs a second
     * CRCPolynomial + Hash instance — watch for the warning "Expected single call to
     * get for hash instance", which is the canary. */
    CRCPolynomial<bit<32>>(coeff = 32w0x04C11DB7, reversed = true, msb = false,
                           extended = false, init = 32w0xFFFFFFFF,
                           xor = 32w0xFFFFFFFF) poly_spray;
    Hash<bit<16>>(HashAlgorithm_t.CUSTOM, poly_spray) h_spray;

    /* One counter per source leaf, so multi-leaf distribution cannot skew the way a
     * single shared counter does.  Class 8: the control plane SEEDS every slot at
     * startup; nothing here relies on an in-SALU `v == 0` sentinel. */
    Register<bit<16>, bit<16>>(64, 0) reg_spray_rr;
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_spray_rr) rr_next = {
        void apply(inout bit<16> value, out bit<16> rv) {
            rv    = value;
            value = value + 1;
        }
    };

    /* B3 ActionSelector.  Group membership lives in the control plane, so removing a
     * spine from the group emulates link-down-plus-REROUTE (§7.5) rather than the
     * silent sink that deleting a tbl_vlink row gives.  RESILIENT mode would reshuffle
     * only the removed member's share; FAIR is used here because max_group_size is
     * small and FAIR needs a 14-bit selector hash instead of 51. */
    ActionProfile(size = 64) spray_prof;
    Hash<bit<14>>(HashAlgorithm_t.IDENTITY) sel_hash_fn;
    ActionSelector(action_profile = spray_prof,
                   hash           = sel_hash_fn,
                   mode           = SelectorMode_t.FAIR,
                   max_group_size = 8,
                   num_groups     = 16) spray_sel_impl;

    action spray_member(bit<16> idx) { md.spray_sel = idx; }

    table tbl_spray_sel {
        key = { md.src_leaf   : exact;
                md.spray_hash : selector; }
        actions        = { spray_member; }
        size           = 64;
        implementation = spray_sel_impl;
    }

    /* mask is action data = k-1 (3 for 4 spines).  Keeping k in the control plane is
     * what makes 2x4 vs 4x2 a table edit rather than a recompile. */
    action spray_from_random(bit<16> mask) { md.spray_idx = md.spray_rand & mask; }
    action spray_from_hash  (bit<16> mask) { md.spray_idx = md.spray_hash & mask; }
    action spray_from_rr    (bit<16> mask) { md.spray_idx = md.spray_rr   & mask; }
    action spray_from_sel   (bit<16> mask) { md.spray_idx = md.spray_sel  & mask; }

    table tbl_spray_mode {
        key     = { md.role : exact; md.hop : exact; }
        actions = { spray_from_random; spray_from_hash; spray_from_rr; spray_from_sel;
                    @defaultonly NoAction; }
        size    = 16;
        const default_action = NoAction();
    }

    /* ---- S3: virtual-link resolve -------------------------------------------
     * THE load-bearing table.  It maps (role, hop, src_leaf, dst_leaf, spray_idx)
     * onto one real TM queue on one real loop port — §3 mapping option M2:
     *   vlink_id[3]   selects the loop port, vlink_id[2:0] is the qid.
     * The control plane owns that encoding; the data plane just writes what the
     * action data says.
     *
     * Black hole (§7.5) = DELETE the row.  The default action drops and counts, so
     * the number of black-holed packets is exact ground truth (§7.6). */
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) vlink_ctr;

    action to_loop(bit<16> vlink_id, bit<9> loop_port, bit<5> qid, bit<16> next_vsw,
                   bit<16> path_id) {
        md.vlink_id                = vlink_id;
        md.next_vsw                = next_vsw;
        md.attn_idx                = path_id;   // (dst_leaf, spray) -> path, control-plane data
        ig_tm_md.ucast_egress_port = loop_port;
        ig_tm_md.qid               = qid;
        vlink_ctr.count();
    }

    action black_hole() {
        ig_dprsr_md.drop_ctl = 1;
        vlink_ctr.count();
    }

    table tbl_vlink {
        key = {
            md.role      : exact;
            md.hop       : exact;
            md.src_leaf  : exact;
            md.dst_leaf  : exact;
            md.spray_idx : exact;
        }
        actions  = { to_loop; black_hole; }
        counters = vlink_ctr;
        size     = 256;
        const default_action = black_hole();
    }

    /* ---- S4: failure injection (§7) -----------------------------------------
     * Forked from sdnp_exp.p4:54-89, which is silicon-verified (2026-06-27).  Same
     * shape: a hardware Random draw as a TCAM RANGE key, a DirectCounter for ground
     * truth, and a control plane that retunes the drop probability by rewriting the
     * range bounds — no recompile.  Drop probability = (high - low + 1)/65536.
     *
     * Keyed on md.vlink_id, which already encodes DIRECTION (uplink L->S and downlink
     * S->L are distinct ids), so one-direction asymmetry (§7.3) is free: install the
     * row for the uplink id only.
     *
     * Why a range table and not `if (md.rnd_fail < reg_dropprob[vlink])`: that is two
     * runtime 16-bit operands, which is legal alone but overflows the 44-bit gateway
     * budget the moment it is combined with anything else (Class 1), and it costs an
     * extra register-read stage.  The range table costs TCAM, which this program is
     * not otherwise using at all.
     *
     * Class 2 check: a 16-bit range key consumes 4 of the 5 available range nibbles.
     * DO NOT add a second range field to this table — put it in a second table. */
    Random<bit<16>>() rng_fail;
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) fail_ctr;

    /* §5.6: arm the fault-evidence mirror (sid 3, 64 B) BEFORE dropping.  The mirror
     * is taken in the ingress deparser, so it still fires on a dropped packet
     * (simple_l3_mirror.p4:456).  Session id in METADATA, never a literal (§5.4 #1). */
    action inj_drop() {
        ig_dprsr_md.drop_ctl    = 1;
        ig_dprsr_md.mirror_type = 3w1;
        md.mirror_sid           = 3;
        md.fault                = 2;      // recorded into fabric_h.flags by tbl_final
        md.flags_out            = 2;
        fail_ctr.count();
    }

    /* §7.2 F1.  RoCEv2 normally carries UDP checksum 0 (ignored); a wrong non-zero
     * value makes the receiving NIC drop the frame — the same observable as a
     * corrupted ICRC, for one 16-bit CONSTANT write.  A constant write, not carry
     * arithmetic, so it stays clear of Class 6. */
    action inj_corrupt() {
        hdr.udp.checksum        = 16w0xBAD1;
        ig_dprsr_md.mirror_type = 3w1;
        md.mirror_sid           = 3;
        md.fault                = 4;
        md.flags_out            = 4;
        fail_ctr.count();
    }

    action inj_none() {
        fail_ctr.count();
    }

    table tbl_fail {
        key = {
            md.vlink_id : exact;
            md.rnd_fail : range;
        }
        actions  = { inj_drop; inj_corrupt; inj_none; }
        counters = fail_ctr;
        size     = 64;
        const default_action = inj_none();
    }

    /* ---- S5/S6: attention register + update rule + gate (step 5, PREREG §7.4) --
     * ONE 32-bit SALU word per path: attn (low 16) | clean (high 16).  Exactly one
     * RegisterAction executes per packet, selected by tbl_attn on md.exceed:
     *
     *   exceedance packet (md.exceed == 1):
     *       attn = attn |+| k_up   (saturating: a_max = 65535, fixed)
     *       clean = 0
     *   clean sample (every other packet on the path):
     *       if (clean >= n_clean - 1) { clean = 0; if (attn > a_min) attn = attn - 1; }
     *       else                      { clean = clean + 1; }
     *
     * The controller sets only the constants (RegisterParams p_*) and may re-seed the
     * array each epoch (§5.7); the switch moves attn[p] per packet on its own, which
     * is what makes ablation A6 (fast loop only) and hypothesis H7 well defined.
     * Gate: measure with probability attn/65536, quantized to attn[15:8]/256.  A
     * gateway can only magnitude-compare against a CONSTANT ("one operand must be
     * constant") — two runtime fields are rejected whatever their width — so the
     * compare is a 256-row TCAM table instead: key attn[15:8] exact + rnd_attn range,
     * row L matches rnd_attn in [0, L<<8).  Installed by the controller, no recompile.
     * All fields are bit<16> (Class 3).
     *
     * Exceedance sources visible in INGRESS on Tofino 1 (queue depth is egress-only):
     *   (a) a NIC evidence packet (§6 D1) whose loss_q / rtt_q exceeds its threshold —
     *       two 8-bit range keys = 4 of 5 range nibbles (Class 2);
     *   (b) the CSIG tag written by the PREVIOUS hop's egress (§5.5), whose
     *       worst_qdepth exceeds q_thr — one 16-bit range key, its own table (Class 2).
     * Thresholds are range bounds installed by the controller, no recompile. */
    Random<bit<16>>() rng_attn;

    /* bf-p4c: a register's actions may use at most 4 parameter slots (RegisterParams +
     * large constants) in total.  So there is no a_max parameter: the bump is a
     * saturating add and a_max = 65535 is fixed (PREREG v1.3). */
    RegisterParam<bit<16>>(16w1024)  p_k_up;       // attention gain (§3.2 tuning knob)
    RegisterParam<bit<16>>(16w256)   p_a_min;      // decay floor
    RegisterParam<bit<16>>(16w4095)  p_n_clean_m1; // n_clean - 1

    Register<attn_pair_t, bit<16>>(256) reg_attn;

    RegisterAction<attn_pair_t, bit<16>, bit<16>>(reg_attn) attn_on_exceed = {
        void apply(inout attn_pair_t v, out bit<16> rv) {
            v.attn  = v.attn |+| p_k_up.read();   // saturating: a_max = 65535, fixed
            v.clean = 0;
            rv = v.attn;
        }
    };

    RegisterAction<attn_pair_t, bit<16>, bit<16>>(reg_attn) attn_on_clean = {
        void apply(inout attn_pair_t v, out bit<16> rv) {
            if (v.clean >= p_n_clean_m1.read() && v.attn > p_a_min.read()) {
                v.clean = 0;
                v.attn  = v.attn - 1;
            } else if (v.clean >= p_n_clean_m1.read()) {
                v.clean = 0;
            } else {
                v.clean = v.clean + 1;
            }
            rv = v.attn;
        }
    };

    action set_exceed() { md.exceed = 1; }

    /* §6 D1: the NIC names the path.  Both actions set the index so an evidence
     * packet always addresses the right register slot. */
    action evid_exceed() { md.exceed = 1; md.attn_idx = (bit<16>)hdr.evid.path_id; }
    action evid_clean()  { md.attn_idx = (bit<16>)hdr.evid.path_id; }

    table tbl_exceed_evid {
        key = { hdr.evid.loss_q : range; hdr.evid.rtt_q : range; }
        actions = { evid_exceed; @defaultonly evid_clean; }
        size    = 8;
        const default_action = evid_clean();
    }

    table tbl_exceed_csig {
        key = { hdr.csig.worst_qdepth : range; }
        actions = { set_exceed; @defaultonly NoAction; }
        size    = 4;
        const default_action = NoAction();
    }

    action act_attn_exceed() { md.attn = attn_on_exceed.execute(md.attn_idx); md.mir_path = md.attn_idx; }
    action act_attn_clean()  { md.attn = attn_on_clean.execute(md.attn_idx);  md.mir_path = md.attn_idx; }

    /* A stateful action with a computed index cannot be a table default ("requires
     * the hash distribution unit"), hence const entries. */
    table tbl_attn {
        key     = { md.exceed : exact; }
        actions = { act_attn_exceed; act_attn_clean; }
        size    = 2;
        const entries = {
            16w0 : act_attn_clean();
            16w1 : act_attn_exceed();
        }
    }

    /* Gated sample -> mirror session 1 (§5.4).  Composed with OR so a packet that was
     * also fault-injected keeps sid 3 (3 | 1 == 3): the fault evidence wins. */
    action set_measure() {
        md.do_measure           = 1;
        md.flags_out            = md.flags_out | 1;
        ig_dprsr_md.mirror_type = 3w1;
        md.mirror_sid           = md.mirror_sid | 1;
    }

    table tbl_gate {
        key = { md.attn[15:8] : exact; md.rnd_attn : range; }
        actions = { set_measure; @defaultonly NoAction; }
        size    = 256;
        const default_action = NoAction();
    }

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
    Register<bit<16>, bit<16>>(1024, 0) reg_wit_expect;
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_wit_expect) wit_check = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = v - hdr.witness.seq;
            if ((int<16>)(v - hdr.witness.seq) <= 0) {
                v = hdr.witness.seq + 1;
            }
        }
    };

    action wit_measure() { md.wit_result.gap = wit_check.execute(md.wit_link); }

    /* A second single-field SALU counts ARRIVALS, saturating so a long clean run
     * cannot wrap to zero and be mistaken for silence. It runs after wit_check and
     * resets stored state only when this packet closes a discontinuity; the returned
     * value still includes that survivor. Tofino forbids the equivalent packed-state
     * subtraction, so the split is a compiler constraint, not a semantic choice. */
    Register<bit<16>, bit<16>>(1024, 0) reg_wit_observed;
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_wit_observed) wit_count = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = v;
            if (md.wit_result.gap != 0) {
                v = 0;
            } else {
                v = v |+| 1;
            }
        }
    };

    action wit_count_arrival() {
        md.wit_result.observed = wit_count.execute(md.wit_link);
    }

    table tbl_wit_count {
        key     = { md.role : exact; }
        actions = { wit_count_arrival; @defaultonly NoAction; }
        size    = 4;
        const default_action = NoAction();
        const entries = { ROLE_LOOP : wit_count_arrival(); }
    }

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
    action wit_loss() { wit_ctr.count(); }

    /* A sequence discontinuity arms the fast loop: md.exceed feeds the existing
     * tbl_attn / tbl_gate machinery, so a post-TM gap becomes path evidence with no
     * new gate. Verified on the model: act_attn_exceed fires exactly once per nonzero
     * md.wit_result.gap (p4/ptf/PTF-MODEL.md). */
    action wit_arm() { md.exceed = 1; }

    table tbl_wit_arm {
        key     = { md.role : exact; }
        actions = { wit_arm; @defaultonly NoAction; }
        size    = 4;
        const default_action = NoAction();
        const entries = { ROLE_LOOP : wit_arm(); }
    }


    table tbl_wit_verdict {
        key      = { md.wit_result.gap : exact; }
        actions  = { wit_ok; wit_loss; }
        counters = wit_ctr;
        size     = 2;
        const default_action = wit_loss();
        const entries = { 16w0 : wit_ok(); }
    }

    /* ---- CONTEXT CAPSULE (P1) --------------------------------------------------
     * The source leaf is the only place in the fabric where the IPv4 header is still
     * parsed, so it is the only place that can see SERVICE CLASS. C-W4's egress
     * classifier could only read eg_intr_md.pkt_length, which is why the capacity
     * gate showed a 25-point oracle gap on a service-class-only fault and another on
     * a boundary inside one coarse size bin.
     *
     * So classify once, at the source, into a 4-bit context id = size bin x DSCP
     * class, and carry it in the shim's EXISTING pad byte -- zero added wire bytes.
     * Every hop then indexes its witness by (vlink << 4) | context, and transit and
     * downstream agree because they read the same carried label rather than
     * re-deriving it from what they can see.
     *
     * Class 2: a range key is at most 20 bits over 5 nibble pairs. total_len is 16,
     * which leaves one nibble pair -- enough for the DSCP class as a second range
     * field only if it is 4 bits. It is kept EXACT here to stay clear of the budget. */
    action set_ctx(bit<8> c) { md.ctx = c; }

    table tbl_context {
        key     = {
            hdr.ipv4.total_len : range;
            hdr.ipv4.diffserv  : ternary;
        }
        actions = { set_ctx; }
        size    = 32;
        const default_action = set_ctx(0);
    }

    /* ---- BEHAVIORAL HEALTH GATE (P2) -------------------------------------------
     * The point of behavioural sublinks is to keep using the parts of a link that
     * are still proven good. This is the table that does it: when a (source, dest,
     * spray path, context) sublink is quarantined, the packet's SPRAY CHOICE is
     * rewritten to a prevalidated backup, and tbl_vlink then resolves and counts the
     * path that was actually taken.
     *
     * IT MUST RUN BEFORE tbl_vlink, never after. tbl_vlink is the counted table --
     * overriding forwarding downstream of it would leave the ground-truth counter
     * naming a link the packet never used, which would corrupt exactly the evidence
     * the witness exists to provide.
     *
     * Default is NoAction: a healthy context, or one with no entry at all, is
     * untouched and keeps using the same physical link. Quarantine is therefore
     * expressed as the PRESENCE of an entry, so revocation is an entry delete. */
    action sublink_reroute(bit<16> alt_spray) { md.spray_idx = alt_spray; }

    table tbl_health_gate {
        key = {
            md.src_leaf  : exact;
            md.dst_leaf  : exact;
            md.spray_idx : exact;
            md.ctx       : exact;
        }
        actions = { sublink_reroute; @defaultonly NoAction; }
        size    = 256;
        const default_action = NoAction();
    }

    /* P3 liveness/probation. Packets on the reserved audit UDP destination are
     * controller-owned evidence, not production. A tiny exact table selects the
     * physical spray requested by the audit sender and marks the packet so the P2
     * quarantine gate is bypassed. The packet keeps the ordinary size/DSCP context,
     * receives the ordinary C-W4 stamp, and is force-mirrored only when it arrives
     * downstream. Silence is therefore meaningful relative to a declared send set. */
    action set_audit_spray(bit<16> spray) {
        md.spray_idx = spray;
        md.is_audit  = 1;
    }

    table tbl_audit_steer {
        key = {
            md.audit_src     : exact;   /* H35: controller provenance, from tbl_port_role */
            hdr.udp.dst_port : exact;
            hdr.udp.src_port : exact;
        }
        actions = { set_audit_spray; @defaultonly NoAction; }
        size = 16;
        const default_action = NoAction();
    }

    /* P3: a discontinuity is a guaranteed notification, not a probabilistic
     * attention sample. This action runs last so these mirror-only fields cannot
     * be overwritten by tbl_vlink/tbl_attn/tbl_final. Session 2 retains enough of
     * the copied ingress frame for the controller to validate CSIG epoch and W4 id. */
    action set_gap_event() {
        ig_dprsr_md.mirror_type = 3w1;
        md.mirror_sid           = 2;
        md.flags_out            = md.flags_out | 8;
        md.vlink_id             = md.wit_link;
        md.mir_path             = md.wit_result.gap;
        md.attn                 = md.wit_result.observed;
    }

    action set_audit_receipt() {
        ig_dprsr_md.mirror_type = 3w1;
        md.mirror_sid           = 2;
        md.flags_out            = md.flags_out | 16;
        md.vlink_id             = md.wit_link;
        md.mir_path             = md.wit_result.gap;
        md.attn                 = md.wit_result.observed;
    }

    action set_audit_gap_event() {
        ig_dprsr_md.mirror_type = 3w1;
        md.mirror_sid           = 2;
        md.flags_out            = md.flags_out | 24;
        md.vlink_id             = md.wit_link;
        md.mir_path             = md.wit_result.gap;
        md.attn                 = md.wit_result.observed;
    }

    /* ---- S8: final forward, shim write / strip -------------------------------
     * next_hop arrives as action data instead of being computed as md.hop + 1: hop
     * is already a key of this table, so the increment is free in the control plane
     * and costs no data-plane ALU op. */
    /* Step 7: the CSIG tag is inserted and zeroed HERE (source leaf, ingress) — the
     * egress allocator refuses to fill the (path_id|epoch) container from two
     * sources whatever the field widths, while ingress action data is unconstrained.
     * Egress then only compare-and-replaces the worst_* fields, first at this very
     * pass (worst_qdepth starts at 0, so hop 0's own queue depth is recorded). */
    /* CLF bank parity.  `bank` is action data the control plane flips once per measurement
     * epoch, and it is stamped into hdr.fabric.clf_bank at the SOURCE so every switch the
     * packet traverses agrees which frontier bank the packet belongs to.  It is a property
     * of the PACKET, not of the table, so transit must carry it rather than restamp it --
     * which is why it lives in a byte act_transit never writes.  When it lived in flags,
     * act_transit's `flags = md.flags_out` erased it: TX is marked at the source's egress
     * and RX at the spine's, act_transit runs between them, so RX always landed in bank 0
     * while TX landed in bank B.  With B=1 every sublink showed TX with no RX -- a false
     * blackhole on every one, on exactly the bank-1 trials, 5 of 5.
     *
     * Without this the double buffering is inert.  Measured consequence of leaving it
     * unimplemented: bank 0 is the only bank ever written, so a reader must ZERO the active
     * bank -- and on a live fabric background traffic is continuous, so clearing TX while
     * packets are already in flight sets RX with no matching TX. That is the TX=0/RX=1
     * "IMPOSSIBLE" state, and it appeared in 50 of 50 trials once a single-context probe
     * stopped masking it (docs/review/artifacts/HW-CLF-RATES.md).
     *
     * With it, a reader never clears anything: the control plane flips the parity, waits a
     * guard interval for in-flight packets to land in the new bank, and reads the now-
     * INACTIVE bank, which is complete and immutable. */
    action act_enter(bit<16> next_hop, bit<16> epoch, bit<8> bank) {
        hdr.fabric.setValid();
        hdr.fabric.vsw_id = md.next_vsw;
        hdr.fabric.hop    = next_hop;
        hdr.fabric.spray  = md.spray_idx;
        hdr.fabric.clf_bank = bank;
        hdr.fabric.flags  = (bit<8>)md.flags_out;
        hdr.fabric.nxt    = NXT_CSIG;
        hdr.fabric.pad    = md.ctx;   /* capsule rides the existing pad byte */
        hdr.fabric.path_id = md.attn_idx;
        hdr.ethernet.ether_type = ETYPE_MCP_FABRIC;
        hdr.csig.setValid();
        hdr.csig.worst_hop    = 0;
        hdr.csig.worst_vlink  = 0;
        hdr.csig.worst_qdepth = 0;
        hdr.csig.worst_tdelta = 0;
        hdr.csig.path_id      = md.attn_idx;
        hdr.csig.epoch        = epoch;
        /* The witness is inserted and zeroed in INGRESS for the same reason the
         * CSIG tag is: ingress action data is unconstrained, egress packed-
         * container writes are not (Class 13).  Egress only stamps.  Zeroing both
         * halves from one constant source in ONE ingress action is legal; the
         * same pair written from two different sources in egress is not. */
        hdr.witness.setValid();
        hdr.witness.link_id   = 0;
        hdr.witness.seq       = 0;
    }

    action act_transit(bit<16> next_hop) {
        hdr.fabric.vsw_id = md.next_vsw;
        hdr.fabric.hop    = next_hop;
        hdr.fabric.flags  = (bit<8>)md.flags_out;
    }

    action act_deliver(bit<9> port) {
        hdr.fabric.setInvalid();
        hdr.csig.setInvalid();
        hdr.witness.setInvalid();
        hdr.ethernet.ether_type    = ETYPE_IPV4;
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.qid               = 0;
    }

    action act_drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    /* Step 5/8, per-pipe registers: reg_attn is one instance PER PIPE.  NIC evidence
     * arrives on the host port (pipe of dp9) while CSIG exceedance is observed on the
     * loop ports (their pipe), so an evidence packet updates the host pipe's register
     * and is then FORWARDED to a loop port, where the loop pass updates that pipe's
     * register and drops it.  Port is control-plane data (a loop port of leaf 0). */
    action evid_to_loop(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.qid               = 0;
    }
    action evid_drop() { ig_dprsr_md.drop_ctl = 1; }

    table tbl_evid_fwd {
        key     = { md.role : exact; }
        actions = { evid_to_loop; evid_drop; }
        size    = 4;
        const default_action = evid_drop();
    }

    /* dst_leaf is part of the key because the destination leaf's host port is what
     * act_deliver has to write, and a 2-leaf fabric has two of them (dp9 and dp65).
     * It costs no stage: tbl_final already sits downstream of tbl_dst_leaf. */
    table tbl_final {
        key     = { md.role : exact; md.hop : exact; md.dst_leaf : exact; }
        actions = { act_enter; act_transit; act_deliver; act_drop; }
        size    = 64;
        const default_action = act_drop();
    }


    /* ---- CLF receiver half, in INGRESS -------------------------------------------
     * RX_frontier records which behavioural sublinks actually ARRIVED off the wire.
     * It is in INGRESS, i.e. PRE-TM, and that placement is the mirror image of TX's
     * post-TM placement, for the mirror-image reason.  TX is post-TM so OUR OWN
     * queueing cannot be blamed on the link; RX is pre-TM so the RECEIVER'S queueing
     * cannot be either.
     *
     * Measured on silicon 2026-08-30 with RX still in egress: with the spine's own
     * downlink queue shaped to 100 kb/s and no fault injected anywhere, all 400 probe
     * packets crossed the link and were counted at the spine's hop-1 ingress -- and
     * at most ~6% of them survived the spine's TM to reach the egress where RX was
     * marked.  The link delivered everything and the frontier saw almost none of it.
     * Post-TM RX puts the receiver's queue inside the link's measurement.
     *
     * Indexed by md.wit_link, the UPSTREAM sublink the sender stamped, so it pairs
     * with the sender's TX index for the same directed link.
     *
     * Saturating count, not a presence bit.  `v = 1` discarded how many packets
     * arrived, so RX>0 meant "at least one packet, from any source, at any time in
     * this epoch" -- and a single stray packet was indistinguishable from a healthy
     * link.  Every masking failure in HW-CLF-FRONTIER-HOP.md was silent for exactly
     * that reason: a 1-bit flag cannot express "implausibly few".  The register was
     * already bit<8>; seven of those bits were simply unused. */
    Register<bit<32>, bit<16>>(2048, 0) reg_rx_frontier;
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_rx_frontier) rx_seen = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            v  = v |+| 1;      // saturating at 255; see tbl_rx_frontier
        }
    };

    action rx_frontier_mark() { md.clf_rx_prev = rx_seen.execute(md.clf_idx); }

    table tbl_rx_frontier {
        key     = { md.hop : exact; }
        actions = { rx_frontier_mark; @defaultonly NoAction; }
        size    = 8;
        const default_action = NoAction();
        /* In INGRESS md.hop names the hop the packet is AT: 0 = host injection (no
         * upstream link), 1 = arrived at the spine over the source->spine link,
         * 2 = arrived at the destination leaf over the spine->leaf link.  In the old
         * egress placement, the same field named the NEXT hop and could mark the
         * source leaf's own departure as an arrival.
         *
         * Both are listed, matching tbl_tx_frontier: hop 1 is the arrival at the spine over
         * the source->spine link and hop 2 the arrival at the destination leaf over the
         * spine->leaf link.  See tbl_tx_frontier for why these were briefly reverted to
         * {1} and why that reasoning was wrong (tbl_eg_vlink was empty). */
        const entries = { 1 : rx_frontier_mark(); 2 : rx_frontier_mark(); }
    }

    apply {
        tbl_port_role.apply();

        /* §3 carriage detail 2.  The fabric ethertype is internal-only, so a frame
         * carrying it that arrives on a HOST port is injected, not looped: drop it.
         * One 16-bit equality plus one validity bit = 17 of the 44 gateway bits
         * (Class 1). */
        if (md.role == ROLE_HOST && hdr.fabric.isValid()) {
            ig_dprsr_md.drop_ctl = 1;
        } else {
            tbl_dst_leaf.apply();
            tbl_context.apply();

            /* CLF receiver mark.  No isValid() guard is needed and none is wanted:
             * md.hop is 0 unless the parser lifted it out of a fabric shim, so a
             * frame with no fabric header cannot match either entry, and an
             * `if (hdr.fabric.isValid())` here would cost its own logical table. */
            md.clf_idx = md.wit_link;
            if (hdr.fabric.clf_bank != 0) {
                md.clf_idx = md.clf_idx | 16w0x400;
            }
            tbl_rx_frontier.apply();

            /* Drawn on EVERY fabric pass (each pass crosses one virtual link), and
             * drawn here rather than next to tbl_fail so it co-places with the other
             * independent draws instead of serialising behind tbl_vlink. */
            md.rnd_fail = rng_fail.get();
            md.rnd_attn = rng_attn.get();

            /* Spray only at the SOURCE leaf (hop 0).  Later passes reuse the index
             * the parser lifted out of the shim.  Gating the round-robin SALU here
             * also keeps it advancing once per PACKET rather than once per pass. */
            if (md.hop == 0) {
                md.spray_rand = rng_spray.get();
                md.spray_hash = h_spray.get({ hdr.ipv4.src_addr,
                                              hdr.ipv4.dst_addr,
                                              hdr.udp.src_port });
                md.spray_rr   = rr_next.execute(md.src_leaf);
                tbl_spray_sel.apply();
                tbl_spray_mode.apply();
            }
            tbl_audit_steer.apply();
            if (md.hop == 0 && md.is_audit == 0) {
                tbl_health_gate.apply();
            }

            /* The destination leaf delivers; it does not resolve another link, and a
             * link it is not on cannot fail it. */
            /* Step 5: is this packet threshold-exceedance evidence for its path? */
            /* s5: attention/gate path removed */

            /* M2: did the directed link this packet arrived on skip a sequence
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
                tbl_wit_count.apply();
                tbl_wit_verdict.apply();
                if (md.wit_result.gap != 0) {          /* a discontinuity arms the fast loop */
                    tbl_wit_arm.apply();
                }
            }

            /* Evidence packets terminate here: they update attention and are never
             * sprayed into the fabric (§7.4 open decision iv: the evidence path is
             * itself ungated, so the loop cannot starve). */
            if (md.hop != LAST_HOP && !hdr.evid.isValid()) {
                tbl_vlink.apply();
                tbl_fail.apply();
            }

            /* Attention is updated on the two FABRIC passes of a data packet (hops 0
             * and 1) and by evidence packets; the delivery pass is not a sample. */
            if (md.hop != LAST_HOP || hdr.evid.isValid()) {
                /* s5: attention/gate path removed */
            }

            if (hdr.evid.isValid()) {
                tbl_evid_fwd.apply();
            } else {
                tbl_final.apply();
                if (md.hop != 0 && hdr.witness.isValid() && md.is_audit != 0) {
                    if (md.wit_result.gap != 0) {
                        set_audit_gap_event();
                    } else {
                        set_audit_receipt();
                    }
                } else if (md.wit_result.gap != 0) {
                    set_gap_event();
                }
            }
        }
    }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in ig_md_t md,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Mirror() mcp_mirror;   // no-arg constructor (§5.4 #2); emit() appends the whole
                           // post-MAU frame, shim and all (§5.4 #3); $max_pkt_len truncates
    apply {
        if (ig_dprsr_md.mirror_type == 3w1) {
            /* hop and path_id come from the SHIM, not md.hop / md.attn_idx: emitting
             * those parser-written key fields here breaks the stage-1 RNG/hash table
             * placement ("immediate pathway 64 > 32 bits"); header fields and the
             * MAU-written md fields do not.  The shim is valid post-MAU on every pass
             * that can mirror (act_enter sets it at hop 0). */
            mcp_mirror.emit<mirror_h>(md.mirror_sid,
                { md.mir_dmac, md.mir_smac, md.mir_etype,
                  hdr.fabric.hop, md.vlink_id, md.mir_path, md.attn, md.flags_out,
                  md.tstamp });
        }
        pkt.emit(hdr);
    }
}

/* ======================= egress ======================= */

parser EgParser(packet_in pkt, out eg_headers_t hdr, out eg_md_t md,
                out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        md.this_q = 0;
        md.diff   = 0;
        md.vlink  = 0;
        md.hop    = 0;
        md.ctx = 0;
        md.stratum = 0;
        md.sublink = 0;
        md.tdelta = 0;
        md.tx_count = 0;
        md.eg_rnd = 0;
        transition select(pkt.lookahead<bit<16>>()) {
            16w0xA5A5 : parse_mirror;
            default   : parse_ethernet;
        }
    }

    state parse_mirror {
        pkt.extract(hdr.mirror);
        transition accept;      // original frame stays residual: no CSIG on copies
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETYPE_MCP_FABRIC : parse_fabric;
            default          : accept;
        }
    }

    state parse_fabric {
        pkt.extract(hdr.fabric);
        md.ctx = hdr.fabric.pad;
        transition select(hdr.fabric.nxt) {
            NXT_CSIG : parse_csig;
            default  : accept;
        }
    }

    state parse_csig {
        pkt.extract(hdr.csig);
        transition parse_witness;
    }

    state parse_witness {
        pkt.extract(hdr.witness);
        transition accept;
    }
}

control Egress(inout eg_headers_t hdr, inout eg_md_t md,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    /* ---- step 7: CSIG-style "worst hop so far" tag (§5.5) ------------------------
     * Inserted (zeroed) by ingress act_enter at the source leaf, then compare-and-
     * replaced at EVERY hop's egress including that first one.  Stripped in INGRESS
     * by act_deliver together with the shim, so nothing here runs at delivery.
     *
     * No bridged metadata: hop comes from the shim, the virtual link from the egress
     * (port, qid) via tbl_eg_vlink (control-plane data, same encoding as ingress), and
     * path_id from the shim (written at the source leaf).
     *
     * Class 9: "this_q > worst_qdepth" is two runtime operands and cannot be a gateway
     * predicate.  So: diff = worst |-| this_q (saturating, one ALU op); the gateway
     * tests diff == 0 (equality with a constant), i.e. this_q >= worst. */
    /* The capsule is carried, so the egress does not classify -- it reads the label the
     * source wrote and writes its low nibble into the sublink index. The parser copy is
     * deliberately 8 -> 8 bits: widening the packed pad byte to 16 bits in the parser also
     * copied the adjacent NXT_CSIG byte on Tofino (ctx 0 became 0x0100). */
    action ctx_index() { md.sublink[3:0] = md.ctx[3:0]; }

    table tbl_ctx_index {
        key     = { hdr.fabric.nxt : exact; }
        actions = { ctx_index; @defaultonly NoAction; }
        size    = 4;
        const default_action = NoAction();
        const entries = { NXT_CSIG : ctx_index(); }
    }

    /* ---- M2: upstream sequence allocation (post-TM) ---------------------------
     * One modular 16-bit counter per directed vlink, read-then-increment.  It runs
     * AFTER tbl_eg_vlink so the index is the directed link the packet is actually
     * leaving on, and it runs in EGRESS so it counts what the TM released, not
     * what ingress hoped to send. */
    Register<bit<16>, bit<16>>(1024, 0) reg_wit_seq;
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_wit_seq) wit_next = {
        void apply(inout bit<16> v, out bit<16> rv) {
            rv = v;
            v  = v + 1;
        }
    };

    action wit_stamp() { hdr.witness.seq     = wit_next.execute(md.sublink); }
    action wit_link()  { hdr.witness.link_id = md.sublink; }

    /* Class 11 again: a keyless table cannot make a computed-index stateful action
     * its default.  hdr.fabric.nxt has a two-value compile-time domain, so const
     * entries cost nothing and express the intent (stamp the tag stack only).
     *
     * Class 13: link_id and seq share a 32-bit container and their sources differ
     * (tbl_eg_vlink action data vs the SALU return), so they are written by two
     * actions in two tables — the csig_replace_a / csig_replace_b precedent. */
    /* ===================== CONTEXT LIVENESS FRONTIER (CLF), sender half ============
     * The receiver half is in ingress above, before the receiver's TM.  This egress half
     * records which contexts actually DEPARTED on a directed
     * link.  It is deliberately in egress, i.e. POST-TM: a packet dropped by the traffic
     * manager never reaches here, so congestion loss inside our own switch can never be
     * mistaken for the link having gone dark.  That is the difference between "we sent it"
     * and "we intended to send it", and it is the whole basis for reading TX=1, RX=0 as a
     * blackhole rather than as an artefact of our own queueing.
     *
     * Indexed by md.sublink, the OUTGOING behavioural sublink that tbl_eg_vlink and
     * tbl_ctx_index have already composed -- the same identity the witness stamps, so the
     * two frontiers are directly comparable across the link. */
    Register<bit<32>, bit<16>>(2048, 0) reg_tx_frontier;
    RegisterAction<bit<32>, bit<16>, bit<32>>(reg_tx_frontier) tx_seen = {
        void apply(inout bit<32> v, out bit<32> rv) {
            rv = v;
            v  = v |+| 1;      // saturating at 255, to match reg_rx_frontier
        }
    };

    /* SELF-SEALING EPOCH (scratch item 2).  Per-sublink POST-TM departure counter.
     * The bank parity is bit k of that count, extracted by a 2-entry TERNARY table
     * (mask = 1<<k) rather than inside the SALU, because bf-p4c rejects
     * "slice of register value in condition".  Bonus: N = 2^k is control-plane data. */
    Register<bit<16>, bit<16>>(1024, 0) reg_tx_epoch;
    RegisterAction<bit<16>, bit<16>, bit<16>>(reg_tx_epoch) tx_tick = {
        void apply(inout bit<16> v, out bit<16> rv) {
            v  = v + 1;
            rv = v;
        }
    };
    action epoch_tick() { md.tx_count = tx_tick.execute(md.sublink); }
    table tbl_clf_tick {
        key     = { hdr.fabric.nxt : exact; }
        actions = { epoch_tick; @defaultonly NoAction; }
        size    = 4;
        const default_action = NoAction();
        const entries = { NXT_CSIG : epoch_tick(); }
    }

    /* One PHV source for the whole byte (action data), and nothing else in that
     * container is written in egress -- Class 13 respected. */
    action set_bank(bit<8> b) { hdr.fabric.clf_bank = b; }
    table tbl_clf_bank {
        key     = { md.tx_count : ternary; }
        actions = { set_bank; @defaultonly NoAction; }
        size    = 8;
        const default_action = NoAction();
    }

    action tx_frontier_mark() { md.clf_tx_prev = tx_seen.execute(md.clf_tx_idx); }

    table tbl_tx_frontier {
        key     = { md.hop : exact; }
        actions = { tx_frontier_mark; @defaultonly NoAction; }
        size    = 8;
        const default_action = NoAction();
        /* md.hop in EGRESS is the hop the packet is being sent TO: ingress has already
         * advanced hdr.fabric.hop (act_enter -> 1, act_transit -> 2).  So md.hop == 1 is
         * the source leaf committing onto the source->spine link and md.hop == 2 is the
         * spine committing onto the spine->leaf link.  An entry for 0 is dead: nothing
         * presents md.hop == 0 in egress.
         *
         * Both hops that put a packet onto a directed link commit it: md.hop == 1 is the
         * source leaf committing onto the source->spine link, md.hop == 2 the spine
         * committing onto the spine->leaf link.
         *
         * These were briefly reverted to {1} after 10 probe packets read TX=20 RX=20, which
         * was diagnosed as the second link having no distinct sublink identity.  The
         * doubling was real but the diagnosis was wrong: tbl_eg_vlink was simply EMPTY,
         * because it is installed by setup_attention.py and bring-up only ran
         * setup_skeleton.py.  Its miss action is set_eg_vlink(0, 0), so every packet
         * reported virtual link 0 and both hops indexed the same slot.  With the table
         * populated the two hops resolve to different vlinks and each link gets its own
         * counters.  bringup.sh now installs and verifies that table. */
        const entries = { 1 : tx_frontier_mark(); 2 : tx_frontier_mark(); }
    }



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

    /* ---- H39a: POST-STAMP fault injection (campaign blocker B1) -----------------
     * The ingress injector tbl_fail cannot produce a witness gap.  It runs AFTER
     * tbl_wit_check, so a packet is counted by the downstream witness and only then
     * discarded, and the next arrival lands exactly where the witness expects: the
     * sequence stays contiguous and no discontinuity is ever observable.  A gap
     * requires loss strictly BETWEEN the upstream egress deparser and the downstream
     * ingress check, and until now no table occupied that window.
     *
     * This table does.  It runs immediately after tbl_wit_stamp / tbl_wit_link, so
     * the packet has already consumed a sequence number from reg_wit_seq and already
     * carries it in hdr.witness.seq; eg_dprsr_md.drop_ctl then discards the frame in
     * the egress deparser.  The counter advances, the packet never arrives, and the
     * next packet on that sublink shows the downstream witness a hole.
     *
     * Key shape, deliberately:
     *   md.sublink : exact  — the injected fault IS a behavioural-sublink fault, on
     *       the SAME index (vlink << 4 | ctx) the witness stamps and checks, so the
     *       injector and the detector cannot disagree about which stratum a packet
     *       is in.  It is written by tbl_eg_vlink + tbl_ctx_index, both upstream.
     *   hdr.witness.seq : range  — one field, both modes.  A width-1 range is a
     *       controller-armed deterministic ONE-SHOT (read reg_wit_seq[sublink], arm
     *       [S,S] a little ahead, drop exactly the packet that draws S) which is what
     *       the end-to-end latency reps need; a range of width p*65536 is a periodic
     *       rate for the lifecycle figure.  It is the value THIS hop just stamped,
     *       not an upstream one: the enclosing hdr.csig.isValid() gate is exactly the
     *       NXT_CSIG condition under which wit_stamp ran (the egress parser extracts
     *       csig and witness together, only on NXT_CSIG).
     *
     * DirectCounter, not an assumption: "the injector fired N times" must be readable
     * independently of "the witness saw N gaps", because equating them is precisely
     * the thing the campaign is trying to measure.  Only eg_fail_drop counts; a miss
     * is not an event.
     *
     * Class 2: one 16-bit range key consumes 4 of the 5 available range nibbles.  DO
     * NOT add a second range field to this table.  A Bernoulli (rate-without-arming)
     * arm needs its own table with its own Random<bit<16>>; the precedent is
     * mcp_fabric_w4_egdrop.p4 tbl_eg_fail. */
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) eg_fail_ctr;

    /* Probabilistic (Bernoulli) gray loss: p = (hi-lo+1)/65536, control-plane data.
     * Its OWN table and its OWN Random because tbl_eg_fail already spends 4 of the
     * 5 range nibbles on hdr.witness.seq (Class 2). */
    Random<bit<16>>() rng_eg_bern;
    DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) eg_bern_ctr;
    action eg_bern_drop() { eg_dprsr_md.drop_ctl = 1; eg_bern_ctr.count(); }
    action eg_bern_none() { eg_bern_ctr.count(); }
    table tbl_eg_bern {
        key = { md.sublink : exact; md.eg_rnd : range; }
        actions  = { eg_bern_drop; eg_bern_none; }
        counters = eg_bern_ctr;
        size     = 64;
        const default_action = eg_bern_none();
    }

    action eg_fail_drop() {
        eg_dprsr_md.drop_ctl = 1;
        eg_fail_ctr.count();
    }

    table tbl_eg_fail {
        key = {
            md.sublink      : exact;
            hdr.witness.seq : range;
        }
        actions  = { eg_fail_drop; @defaultonly NoAction; }
        counters = eg_fail_ctr;
        size     = 32;
        const default_action = NoAction();
    }

    action set_eg_vlink(bit<16> vlink, bit<16> vlink_base) {
        md.vlink  = vlink;
        md.sublink = vlink_base;   /* C-W4: (vlink << 4), computed control-plane side */
        md.this_q = eg_intr_md.deq_qdepth[15:0];
        md.hop    = hdr.fabric.hop;
        md.tdelta = (bit<32>)eg_intr_md.deq_timedelta;
    }

    table tbl_eg_vlink {
        key     = { eg_intr_md.egress_port : exact; eg_intr_md.egress_qid : exact; }
        actions = { set_eg_vlink; }
        size    = 64;
        const default_action = set_eg_vlink(0, 0);
    }

    /* Adjacent 16-bit tag fields share a 32-bit container and one action may fill a
     * container from ONE source, so the (worst_hop|worst_vlink) pair is written by two
     * actions in two tables. */

    action csig_diff() {
        md.diff = hdr.csig.worst_qdepth |-| md.this_q;
    }

    action csig_replace_a() {
        hdr.csig.worst_hop    = md.hop;
        hdr.csig.worst_qdepth = md.this_q;
    }
    action csig_replace_b() {
        hdr.csig.worst_vlink  = md.vlink;
        hdr.csig.worst_tdelta = md.tdelta;
    }

    table tbl_csig_diff      { actions = { csig_diff;      } const default_action = csig_diff();      size = 1; }
    table tbl_csig_replace_a { actions = { csig_replace_a; } const default_action = csig_replace_a(); size = 1; }
    table tbl_csig_replace_b { actions = { csig_replace_b; } const default_action = csig_replace_b(); size = 1; }

    apply {
        if (hdr.csig.isValid()) {
            tbl_eg_vlink.apply();
            tbl_ctx_index.apply();
            /* TX commitment, after tbl_ctx_index has composed md.sublink.  The receiver
             * mark is no longer here: it moved to INGRESS so the receiver's own traffic
             * manager sits OUTSIDE the link measurement. */
            tbl_clf_tick.apply();     /* count the departure ... */
            tbl_clf_bank.apply();     /* ... and stamp bit k of the count as the bank */
            md.clf_tx_idx = md.sublink;
            if (hdr.fabric.clf_bank != 0) {
                md.clf_tx_idx = md.clf_tx_idx | 16w0x400;
            }
            tbl_tx_frontier.apply();
            tbl_wit_stamp.apply();
            tbl_wit_link.apply();
            tbl_eg_fail.apply();     /* H39a: drop AFTER the sequence is consumed */
            md.eg_rnd = rng_eg_bern.get();
            tbl_eg_bern.apply();     /* stochastic gray loss, same post-stamp window */
            tbl_csig_diff.apply();
            if (md.diff == 0) {
                tbl_csig_replace_a.apply();
                tbl_csig_replace_b.apply();
            }
        }
    }
}

control EgDeparser(packet_out pkt, inout eg_headers_t hdr, in eg_md_t md,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { pkt.emit(hdr); }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
