/* mcp_fabric.p4 — Tofino 1 (TNA) emulation of a packet-sprayed leaf-spine fabric.
 *
 * Implements docs/P4-DESIGN-SPACE.md.  STEP 1 of the §9.2 offline compile sequence:
 * headers, parser, deparser, EMPTY controls.  This step exists only to prove the
 * on-the-wire header layout parses and deparses and to give a baseline PHV report.
 *
 * Wire format inside the fabric (§3, alternative A2):
 *
 *   eth(etype=0x88F0) | fabric_h 6B | [csig_h 12B] | ipv4 | udp | [bth 12B | evid 8B]
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

/* fabric_h.nxt — what follows the shim.  A parser select on a whole 8-bit value,
 * never a chain of runtime bit tests (§8.4/N11). */
const bit<8>  NXT_IPV4          = 0;
const bit<8>  NXT_CSIG          = 1;

const bit<8>  IP_PROTO_UDP      = 17;
const bit<16> UDP_PORT_ROCEV2   = 4791;
const bit<16> UDP_PORT_EVIDENCE = 0xE5E5;

/* ======================= headers ======================= */

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

/* §3 A2.  6 bytes, laid out as three 16-bit-friendly pairs (§8.3/N12). */
header fabric_h {
    bit<8> vsw_id;   // which virtual switch handles this pass
    bit<8> hop;      // 0 = fresh from host; incremented per pass
    bit<8> spray;    // spray index chosen at the source leaf (§4) — the substitute
                     // for a Random<> seed: the path is recoverable from a capture
    bit<8> loops;    // remaining extra latency loops (§7.4 L1)
    bit<8> flags;    // bit0 measured, bit1 mirrored, bit2 fault-injected
    bit<8> nxt;      // NXT_IPV4 | NXT_CSIG  (design called this rsvd; see README)
}

/* §5.5.  Fixed-size "worst hop so far" tag, not a growing INT stack. */
header csig_h {
    bit<8>  worst_hop;
    bit<8>  worst_vlink;
    bit<16> worst_qdepth;   // eg_intr_md.deq_qdepth[18:3], 8-cell granularity
    bit<32> worst_tdelta;   // eg_intr_md.deq_timedelta (ns)
    bit<16> path_id;
    bit<16> epoch;
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
    ipv4_h     ipv4;
    udp_h      udp;
    bth_h      bth;
    evid_h     evid;
}

/* Egress only ever touches the L2 shims (§5.5): everything from IPv4 on is left as
 * unparsed residual, which the deparser re-appends untouched. */
struct eg_headers_t {
    ethernet_h ethernet;
    fabric_h   fabric;
    csig_h     csig;
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
    bit<16> vlink_id;
    bit<16> rnd_fail;    // range key: exactly 16 bits = 4 of the 5 range nibbles (Class 2)
    bit<16> rnd_attn;
    bit<16> attn;
    bit<16> do_measure;
    bit<16> fault;
    bit<16> mirror_sid;
}

struct eg_md_t {
    bit<16> pad;
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
        md.vlink_id   = 0;
        md.rnd_fail   = 0;
        md.rnd_attn   = 0;
        md.attn       = 0;
        md.do_measure = 0;
        md.fault      = 0;
        md.mirror_sid = 0;
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
        transition select(hdr.fabric.nxt) {
            NXT_CSIG : parse_csig;
            default  : parse_ipv4;
        }
    }

    state parse_csig {
        pkt.extract(hdr.csig);
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
        transition accept;
    }
}

/* ======================= ingress ======================= */

control Ingress(inout headers_t hdr, inout ig_md_t md,
                in    ingress_intrinsic_metadata_t              ig_intr_md,
                in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md) {
    apply { }
}

control IgDeparser(packet_out pkt, inout headers_t hdr, in ig_md_t md,
                   in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply { pkt.emit(hdr); }
}

/* ======================= egress ======================= */

parser EgParser(packet_in pkt, out eg_headers_t hdr, out eg_md_t md,
                out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        md.pad = 0;
        transition parse_ethernet;
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
        transition select(hdr.fabric.nxt) {
            NXT_CSIG : parse_csig;
            default  : accept;
        }
    }

    state parse_csig {
        pkt.extract(hdr.csig);
        transition accept;
    }
}

control Egress(inout eg_headers_t hdr, inout eg_md_t md,
               in    egress_intrinsic_metadata_t                 eg_intr_md,
               in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply { }
}

control EgDeparser(packet_out pkt, inout eg_headers_t hdr, in eg_md_t md,
                   in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply { pkt.emit(hdr); }
}

Pipeline(IgParser(), Ingress(), IgDeparser(), EgParser(), Egress(), EgDeparser()) pipe;
Switch(pipe) main;
