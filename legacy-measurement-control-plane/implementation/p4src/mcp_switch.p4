/* mcp_switch.p4 — Measurement Control Plane switch program
 *
 * This P4 program runs on BMv2 simple_switch_grpc.
 * It implements three layers of functionality:
 *
 *   1. FORWARDING — basic IPv4 L3 routing
 *   2. MEASUREMENT — four primitives that MCP can allocate:
 *      a) Count-Min Sketch (registers + hashing) — controllable via cms_enable
 *      b) Watchlist table for per-suspicious-flow counting
 *      c) Packet sampling via clone for IDS feeding
 *      d) Per-flow byte counter (via direct counters on forwarding table)
 *   3. TELEMETRY EXPORT — digest messages to controller
 *
 * MCP (running in the control plane) configures these primitives
 * at runtime via P4Runtime:
 *   - Adds/removes forwarding rules in ipv4_lpm
 *   - Adds/removes watchlist entries in watchlist_table
 *   - Reads counter and register values
 *   - Enables/disables CMS via cms_enable register
 *   - Adjusts sampling via sample_table entries
 *
 * Target: BMv2 v1model (simple_switch_grpc)
 */

#include <core.p4>
#include <v1model.p4>

/*======================================================================
 * CONSTANTS
 *====================================================================*/

/* CMS dimensions: 4 rows x 4096 columns = 64 KB */
const bit<32> CMS_WIDTH = 4096;
const bit<32> CMS_ROWS  = 4;

/* Clone session for sampled packets */
const bit<32> SAMPLE_CLONE_SESSION = 500;

/* Digest type identifiers */
const bit<8> DIGEST_TYPE_SKETCH    = 1;
const bit<8> DIGEST_TYPE_WATCHLIST = 2;

/*======================================================================
 * HEADERS
 *====================================================================*/

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<9>  port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

struct metadata {
    /* CMS hash indices */
    bit<32> cms_idx0;
    bit<32> cms_idx1;
    bit<32> cms_idx2;
    bit<32> cms_idx3;

    /* Measurement flags */
    bit<1>  do_sample;
    bit<1>  is_watched;
    bit<32> cms_min_count;

    /* CMS enable flag (read from register) */
    bit<32> cms_active;
}

/*======================================================================
 * PARSER
 *====================================================================*/

parser MCPParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6:  parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

/*======================================================================
 * CHECKSUM VERIFICATION
 *====================================================================*/

control MCPVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*======================================================================
 * INGRESS PROCESSING
 *====================================================================*/

control MCPIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

    /* ---- RESOURCE 1: Forwarding table ---- */

    direct_counter(CounterType.packets_and_bytes) fwd_counter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstMac, port_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        fwd_counter.count();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
        counters = fwd_counter;
    }

    /* ---- RESOURCE 2: Count-Min Sketch ---- */

    /* CMS enable register: MCP writes 1 to activate, 0 to deactivate.
     * This lets MCP control whether the sketch consumes register
     * resources this epoch. */
    register<bit<32>>(1) cms_enable;

    register<bit<32>>(CMS_WIDTH) cms_row0;
    register<bit<32>>(CMS_WIDTH) cms_row1;
    register<bit<32>>(CMS_WIDTH) cms_row2;
    register<bit<32>>(CMS_WIDTH) cms_row3;

    action compute_cms_hashes() {
        hash(meta.cms_idx0, HashAlgorithm.crc32,
             (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
             CMS_WIDTH);
        hash(meta.cms_idx1, HashAlgorithm.crc32_custom,
             (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
             CMS_WIDTH);
        hash(meta.cms_idx2, HashAlgorithm.crc16,
             (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
             CMS_WIDTH);
        hash(meta.cms_idx3, HashAlgorithm.identity,
             (bit<32>)0, {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr},
             CMS_WIDTH);
    }

    action update_cms() {
        bit<32> val0; bit<32> val1; bit<32> val2; bit<32> val3;

        cms_row0.read(val0, meta.cms_idx0);
        val0 = val0 + 1;
        cms_row0.write(meta.cms_idx0, val0);

        cms_row1.read(val1, meta.cms_idx1);
        val1 = val1 + 1;
        cms_row1.write(meta.cms_idx1, val1);

        cms_row2.read(val2, meta.cms_idx2);
        val2 = val2 + 1;
        cms_row2.write(meta.cms_idx2, val2);

        cms_row3.read(val3, meta.cms_idx3);
        val3 = val3 + 1;
        cms_row3.write(meta.cms_idx3, val3);

        /* CMS estimate = min across rows */
        meta.cms_min_count = val0;
        if (val1 < meta.cms_min_count) { meta.cms_min_count = val1; }
        if (val2 < meta.cms_min_count) { meta.cms_min_count = val2; }
        if (val3 < meta.cms_min_count) { meta.cms_min_count = val3; }
    }

    /* ---- RESOURCE 3: Watchlist table ---- */

    direct_counter(CounterType.packets_and_bytes) watchlist_counter;

    action mark_watched() {
        meta.is_watched = 1;
        watchlist_counter.count();
    }

    table watchlist_table {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
        }
        actions = {
            mark_watched;
            NoAction;
        }
        size = 512;
        default_action = NoAction();
        counters = watchlist_counter;
    }

    /* ---- RESOURCE 4: Sampling ---- */

    action do_clone_to_collector() {
        meta.do_sample = 1;
        clone_preserving_field_list(CloneType.I2E,
            SAMPLE_CLONE_SESSION, 0);
    }

    table sample_table {
        key = {
            hdr.ipv4.srcAddr: ternary;
            hdr.ipv4.dstAddr: ternary;
            hdr.ipv4.protocol: exact;
        }
        actions = {
            do_clone_to_collector;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    /* ---- MAIN PIPELINE ---- */

    apply {
        if (hdr.ipv4.isValid()) {
            /* Step 1: Forward */
            ipv4_lpm.apply();

            /* Step 2: CMS update (only if enabled by MCP) */
            cms_enable.read(meta.cms_active, 0);
            if (meta.cms_active != 0) {
                compute_cms_hashes();
                update_cms();
            }

            /* Step 3: Watchlist check */
            watchlist_table.apply();

            /* Step 4: Sampling check */
            sample_table.apply();
        }
    }
}

/*======================================================================
 * EGRESS
 *====================================================================*/

control MCPEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply { }
}

/*======================================================================
 * CHECKSUM COMPUTATION
 *====================================================================*/

control MCPComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*======================================================================
 * DEPARSER
 *====================================================================*/

control MCPDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*======================================================================
 * SWITCH INSTANTIATION
 *====================================================================*/

V1Switch(
    MCPParser(),
    MCPVerifyChecksum(),
    MCPIngress(),
    MCPEgress(),
    MCPComputeChecksum(),
    MCPDeparser()
) main;
