#!/usr/bin/env python3
"""hw_adapter.py — sample adapter for the hardware (Tofino) arm of MCP.

Turns one epoch's observations into `Sample` records for `controller.infer`:

  * per-vlink packet counters from `pipe.Ingress.tbl_vlink` (SyncCounters first,
    deltas since the previous epoch)              -> Sample(element="vlink:<id>", lost=0)
  * mirrored copies (sid 1 measured / sid 3 fault evidence) from a pcap or a live
    raw socket on the collector                   -> Sample(element="path:<id>", ...)
  * a `reg_attn` snapshot (attn, clean per pipe) for logging and §2.3 cost accounting.

`tbl_fail` counters are GROUND TRUTH.  They are read only into `Observation.fail_truth`
for the run manifest/log and are never turned into samples.

Wire format of a copy (p4/mcp_fabric.p4 `mirror_h`, 30 B) followed by the original frame:
  dmac48 smac48 etype16=0x88F1 | next_hop16 vlink16 path_id16 attn16 flags16 tstamp48
  inner: eth(0x0800) ipv4 ...                                (source-leaf copy, hop 0)
         eth(0x88F0) fabric_h(12) [csig_h(14) if fabric.nxt==1] ipv4 ...   (spine copy)
Flags: bit0 measured (sid 1), bit1 dropped, bit2 corrupted (sid 3), bit3 C-W4 gap event,
bit4 declared-audit receipt (sid 2). Event copies reuse the mirror metadata as
``sublink, gap, observed`` and carry the authoritative epoch and witness identity in the copied
inner frame. Audit copies additionally retain the reserved UDP source port as the probe token.

STATUS: the pure parsing/aggregation path is unit-tested (controller/tests).  The bfrt
path (`BfrtAdapter`) HAS run on silicon: `p4/reports/slow-loop-silicon.md` §5 records it
connecting, reading counters, reading and writing `reg_attn`, and honouring
`--freeze-controller`, with paired timings (read_attn 47.5 ms keyless vs 54.7 ms with 256
explicit keys).  That run used the default program `mcp_fabric`; the `program=` argument
and `verify_program` are newer and have NOT been exercised on the switch.  Idioms are copied from
p4/control/setup_attention.py (connect, reg_attn) and setup_skeleton.py (counters).

NOT YET DRIVEN: `mcp_fabric_ledger.p4` (`docs/review/artifacts/LEDGER-COMPILE-GATE.md`).
`gap_event_from_copy`'s `observed_packets` is exact and self-contained for every program
this module has driven so far, but is NOT usable as-is against that program -- see its
docstring. The hardware P3 loop for that program, `p4/hw/loop/controller_loop.py`
(`--ledger` mode), derives `observed_packets` from a targeted census read instead and
discards the value this function computes; `BfrtAdapter` has no equivalent path yet.
Neither has been exercised against a live agent or the switch, only by unit tests.
"""
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEV = 0
PROG = "mcp_fabric"        # DEFAULT only — pass program=/--program for another binary
GRPC_ADDR = "localhost:50052"
CLIENT_ID = 4              # epoch controller; 0 = setup_skeleton, 2 = setup_attention
N_PATHS = 256              # reg_attn slots
N_LEAF = 4
N_SPINE = 2
N_VLINKS = 16

MIRROR_ETYPE = 0x88F1
FABRIC_ETYPE = 0x88F0
IPV4_ETYPE = 0x0800
MIRROR_DMAC = bytes.fromhex("a5a5a5a5a5a5")
MIRROR_SMAC = bytes.fromhex("020000004d43")
MIRROR_H_LEN = 30
ETH_H_LEN = 14
FABRIC_H_LEN = 12
CSIG_H_LEN = 14
NXT_CSIG = 1
AUDIT_UDP_DST = 4792
FLAG_MEASURED, FLAG_DROPPED, FLAG_CORRUPTED = 0x1, 0x2, 0x4
FLAG_GAP_EVENT, FLAG_AUDIT_RECEIPT = 0x8, 0x10

_MIRROR_META = struct.Struct("!HHHHH")     # next_hop vlink path_id attn flags (tstamp48 apart)
_FABRIC = struct.Struct("!HHHHBBBB")
_CSIG = struct.Struct("!HHHIHH")
# Overhead-reduction pass 2026-09-02 (docs/review/artifacts/LEDGER-WIRE-REDUCTION-2026-09-02.md):
# wit_h dropped link_id from the wire (seq only now). The receiver reconstructs md.wit_link from
# its own ingress port + hdr.fabric.spray instead of reading it, so there is no wire-carried
# link_id left to copy into a mirror and no independent second source to cross-check mirror_h.vlink
# against -- that check (below) is gone by necessity, not by oversight.
_WITNESS = struct.Struct("!H")


# ----------------------------------------------------------------------------- encoding
def vlink_up(leaf: int, spine: int) -> int:
    return leaf * N_SPINE + spine


def vlink_dn(spine: int, leaf: int) -> int:
    return 8 + spine * N_LEAF + leaf


def path_id(dst_leaf: int, spray: int) -> int:
    return dst_leaf * N_SPINE + spray


def path_static_links(pid: int) -> List[str]:
    """Links every packet on `pid` must cross regardless of source leaf: the downlink.
    The uplink depends on the (unknown) source leaf and is learned from copies."""
    dst, spray = divmod(pid, N_SPINE)
    if dst >= N_LEAF:
        return []
    return ["vlink:%d" % vlink_dn(spray, dst)]


# ----------------------------------------------------------------------------- parsing
def parse_copy(buf: bytes) -> Dict[str, Any]:
    """Parse one mirrored copy (mirror_h + original frame).  Pure; raises ValueError
    on frames that are not MCP copies."""
    if len(buf) < MIRROR_H_LEN:
        raise ValueError("copy too short: %d B" % len(buf))
    etype = struct.unpack_from("!H", buf, 12)[0]
    if etype != MIRROR_ETYPE:
        raise ValueError("not a mirror copy: etype 0x%04x" % etype)
    next_hop, vlink, pid, attn, flags = _MIRROR_META.unpack_from(buf, 14)
    tstamp_ns = int.from_bytes(buf[24:30], "big")
    out: Dict[str, Any] = {
        "next_hop": next_hop, "vlink": vlink, "path_id": pid, "attn": attn,
        "flags": flags, "tstamp_ns": tstamp_ns,
        "measured": bool(flags & FLAG_MEASURED),
        "dropped": bool(flags & FLAG_DROPPED),
        "corrupted": bool(flags & FLAG_CORRUPTED),
        "gap_event": bool(flags & FLAG_GAP_EVENT),
        "audit_receipt": bool(flags & FLAG_AUDIT_RECEIPT),
        "length": len(buf), "inner_etype": None, "fabric": None, "csig": None,
        "witness": None, "ipv4": None, "udp": None, "worst_tdelta_ns": None,
    }
    inner = buf[MIRROR_H_LEN:]
    if len(inner) >= ETH_H_LEN:
        out["inner_etype"] = struct.unpack_from("!H", inner, 12)[0]
    if out["inner_etype"] == IPV4_ETYPE and len(inner) >= ETH_H_LEN + 20:
        off = ETH_H_LEN
        version_ihl = inner[off]
        ihl = (version_ihl & 0x0F) * 4
        if version_ihl >> 4 == 4 and ihl >= 20 and len(inner) >= off + ihl:
            total_len = struct.unpack_from("!H", inner, off + 2)[0]
            protocol = inner[off + 9]
            out["ipv4"] = {
                "diffserv": inner[off + 1],
                "total_len": total_len,
                "protocol": protocol,
                "src": socket.inet_ntoa(inner[off + 12:off + 16]),
                "dst": socket.inet_ntoa(inner[off + 16:off + 20]),
            }
            if protocol == 17 and len(inner) >= off + ihl + 8:
                src_port, dst_port = struct.unpack_from("!HH", inner, off + ihl)
                out["udp"] = {"src_port": src_port, "dst_port": dst_port}
    if out["inner_etype"] == FABRIC_ETYPE and len(inner) >= ETH_H_LEN + FABRIC_H_LEN:
        f = _FABRIC.unpack_from(inner, ETH_H_LEN)
        out["fabric"] = dict(zip(("vsw_id", "hop", "spray", "path_id", "clf_bank",
                                  "flags", "nxt", "pad"), f))
        off = ETH_H_LEN + FABRIC_H_LEN
        if out["fabric"]["nxt"] == NXT_CSIG and len(inner) >= off + CSIG_H_LEN:
            c = _CSIG.unpack_from(inner, off)
            out["csig"] = dict(zip(("worst_hop", "worst_vlink", "worst_qdepth",
                                    "worst_tdelta", "path_id", "epoch"), c))
            out["worst_tdelta_ns"] = c[3]
            off += CSIG_H_LEN
            if out["gap_event"] or out["audit_receipt"]:
                if len(inner) < off + _WITNESS.size:
                    raise ValueError("event copy is missing the copied C-W4 witness")
                seq, = _WITNESS.unpack_from(inner, off)
                out["witness"] = {"seq": seq}
                off += _WITNESS.size
                if out["audit_receipt"] and len(inner) >= off + 20:
                    version_ihl = inner[off]
                    ihl = (version_ihl & 0x0F) * 4
                    if version_ihl >> 4 == 4 and ihl >= 20 and len(inner) >= off + ihl + 8:
                        protocol = inner[off + 9]
                        if protocol == 17:
                            src_port, dst_port = struct.unpack_from("!HH", inner, off + ihl)
                            out["udp"] = {"src_port": src_port, "dst_port": dst_port}
    if out["gap_event"] or out["audit_receipt"]:
        if out["csig"] is None or out["witness"] is None:
            raise ValueError("event copy requires copied CSIG epoch and C-W4 witness")
        # No mirror-vs-witness cross-check here anymore: mirror_h.vlink IS md.wit_link, and
        # since the overhead-reduction pass md.wit_link is reconstructed at ingress (port +
        # spray + ctx) rather than copied from a wire-carried link_id, there is no longer an
        # independent second value in this same copy to check it against. The equivalent
        # validation now happens once, at bring-up, against the installed
        # tbl_wit_link_recon/tbl_context entries (setup_attention.py + the hardware compile
        # gate) rather than per-packet here.
    if out["gap_event"]:
        if out["path_id"] == 0:
            raise ValueError("gap event carries a zero discontinuity")
    if out["audit_receipt"]:
        if out["udp"] is None:
            raise ValueError("audit receipt is missing its copied audit UDP identity")
        if out["udp"]["dst_port"] != AUDIT_UDP_DST:
            raise ValueError("audit receipt has the wrong UDP destination")
    return out


def build_copy(vlink: int, pid: int, flags: int, tstamp_ns: int, attn: int = 4096,
               next_hop: int = 1, inner_etype: int = 0x0800,
               csig: Optional[Dict[str, int]] = None, payload_len: int = 32,
               witness: Optional[Dict[str, int]] = None,
               udp_src_port: Optional[int] = None,
               udp_dst_port: Optional[int] = None) -> bytes:
    """Hand-build a copy exactly as the deparser would emit it.  Used by the synthetic
    adapter and the unit tests; NOT a parser — see parse_copy."""
    hdr = MIRROR_DMAC + MIRROR_SMAC + struct.pack("!H", MIRROR_ETYPE)
    hdr += _MIRROR_META.pack(next_hop, vlink, pid, attn, flags)
    hdr += (tstamp_ns & ((1 << 48) - 1)).to_bytes(6, "big")
    inner = b"\x00\x11\x22\x33\x44\x55" + b"\x00\x11\x22\x33\x44\x66"
    inner += struct.pack("!H", inner_etype)
    if inner_etype == FABRIC_ETYPE:
        nxt = NXT_CSIG if csig else 0
        inner += _FABRIC.pack(0, next_hop - 1, pid % N_SPINE, pid, 0, flags & 0xFF, nxt, 0)
        if csig:
            inner += _CSIG.pack(csig.get("worst_hop", 0), csig.get("worst_vlink", 0),
                                csig.get("worst_qdepth", 0), csig.get("worst_tdelta", 0),
                                csig.get("path_id", pid), csig.get("epoch", 0))
            if witness:
                inner += _WITNESS.pack(witness.get("seq", 0))
    if udp_src_port is not None or udp_dst_port is not None:
        if udp_src_port is None or udp_dst_port is None:
            raise ValueError("both UDP ports are required")
        if inner_etype != FABRIC_ETYPE or not csig or not witness:
            raise ValueError("audit UDP copies require fabric, CSIG, and witness headers")
        total_len = 20 + 8 + payload_len
        inner += struct.pack("!BBHHHBBHII", 0x45, 0, total_len, 0, 0, 64, 17, 0, 0, 0)
        inner += struct.pack("!HHHH", udp_src_port, udp_dst_port, 8 + payload_len, 0)
    return hdr + inner + bytes(payload_len)


def gap_event_from_copy(copy: Dict[str, Any]) -> Optional[Any]:
    """Convert one validated event copy into the P3 decision-core record.

    `observed_packets` is `int(copy["attn"]) + 1`: on the base/CLF-frontier programs
    (`mcp_fabric`, `mcp_fabric_clf_eg`, ...) the mirror's `attn` slot is already
    "arrivals since the previous gap on this sublink" (the advance-only SALU resets to 0
    on a gap and returns the PRE-reset value), so the triggering packet itself is
    credited with the `+ 1`. This is exact and self-contained for those programs.

    On the receiver-ledger program (`p4/witness/mcp_fabric_ledger.p4`) the same mirror
    slot instead carries the low 16 bits of the ledger's never-reset lifetime arrivals
    counter (`reg_wit_observed`), so a single copy no longer names a self-contained
    delta -- an EARLIER version of this function tried to recover one from the mirror
    field alone (a `(lifetime - previous) & 0xFFFF` wraparound heuristic) and two review
    passes found it decision-affecting-wrong: it aliased at this project's own
    pre-registered 1e-5 sweep floor, and it double-counted against the periodic census's
    independent clean-evidence stream once the ledger's counters stopped resetting.
    **For that program, the CALLER must not use this function's `observed_packets` at
    all** -- see `p4/hw/loop/controller_loop.py`'s `--ledger` mode, which derives it
    instead from a targeted, exact 32-bit census read (`reg_wit_observed` via the `R`
    command) folded into the SAME shared baseline the periodic census uses, so the two
    evidence paths can never overlap. The `vlink`/`context`/`epoch`/`gap` fields this
    function parses remain correct and are still used; only `observed_packets` is
    discarded and replaced by the caller.
    """
    if not copy.get("gap_event"):
        return None
    from controller.sublink_feedback import GapEvent
    raw_sublink = int(copy["vlink"])
    vlink, context = raw_sublink >> 4, raw_sublink & 0xF
    if not 0 <= vlink < N_VLINKS:
        raise ValueError("gap event sublink is outside the configured fabric")
    return GapEvent(vlink=vlink, context=context, epoch=int(copy["csig"]["epoch"]),
                    gap=int(copy["path_id"]), observed_packets=int(copy["attn"]) + 1)


def audit_receipt_from_copy(copy: Dict[str, Any]) -> Optional[Any]:
    """Convert one validated audit copy into its exact declared-probe receipt."""
    if not copy.get("audit_receipt"):
        return None
    from controller.sublink_feedback import AuditReceipt
    raw_sublink = int(copy["vlink"])
    vlink, context = raw_sublink >> 4, raw_sublink & 0xF
    if not 0 <= vlink < N_VLINKS:
        raise ValueError("audit receipt sublink is outside the configured fabric")
    return AuditReceipt(
        vlink=vlink, context=context, epoch=int(copy["csig"]["epoch"]),
        token=int(copy["udp"]["src_port"]), witness_seq=int(copy["witness"]["seq"]),
        gap=int(copy["path_id"]),
    )


# ----------------------------------------------------------------------------- samples
def _sample_cls() -> Any:
    try:
        from controller.infer import Sample          # lazy: written by another builder
        return Sample
    except ImportError:
        try:
            from controller.types import Sample      # the record type infer re-exports
            return Sample
        except ImportError:
            return _LocalSample


@dataclass(frozen=True)
class _LocalSample:
    """Fallback with the controller.infer.Sample contract (used only if infer is absent)."""
    element: str
    delivered: int
    lost: int
    latency_us: tuple
    t_us: int


@dataclass
class Observation:
    epoch: int
    t_host_us: int
    samples: List[Any] = field(default_factory=list)
    path_to_links: Dict[str, List[str]] = field(default_factory=dict)
    n_copies: int = 0
    n_measured: int = 0
    n_lost: int = 0
    mirror_bytes: int = 0
    t_switch_ns: int = 0                     # latest copy tstamp seen this epoch
    attn: List[List[int]] = field(default_factory=list)    # [slot][pipe]
    clean: List[List[int]] = field(default_factory=list)
    fail_truth: Dict[int, Dict[str, int]] = field(default_factory=dict)   # GROUND TRUTH only
    t_read_us: int = 0                       # copies
    t_sync_us: int = 0                       # counters incl. SyncCounters
    counter_reads: int = 0
    gap_events: List[Any] = field(default_factory=list)
    n_gap_events: int = 0
    audit_receipts: List[Any] = field(default_factory=list)
    n_audit_receipts: int = 0


def aggregate(copies: List[Dict[str, Any]], vlink_deltas: Dict[int, Tuple[int, int]],
              t_us: int) -> Tuple[List[Any], Dict[str, List[str]]]:
    """Copies + per-vlink (pkts, bytes) deltas -> (samples, path_to_links)."""
    sample = _sample_cls()
    samples: List[Any] = []
    for v in sorted(vlink_deltas):
        pkts, _ = vlink_deltas[v]
        samples.append(sample("vlink:%d" % v, int(pkts), 0, (), t_us))
    per_path: Dict[int, Dict[str, Any]] = {}
    for c in copies:
        if c["gap_event"] or c["audit_receipt"]:
            continue
        p = per_path.setdefault(c["path_id"], {"d": 0, "l": 0, "lat": [], "links": set()})
        if c["dropped"] or c["corrupted"]:
            p["l"] += 1
        elif c["measured"]:
            p["d"] += 1
        if c["worst_tdelta_ns"] is not None:
            p["lat"].append(c["worst_tdelta_ns"] / 1000.0)
        if c["vlink"] < N_VLINKS and c["next_hop"] >= 1:   # vlink is 0 at the delivery pass
            if not (c["vlink"] == 0 and c["inner_etype"] != 0x0800):
                p["links"].add("vlink:%d" % c["vlink"])
    path_to_links: Dict[str, List[str]] = {}
    for pid in sorted(per_path):
        p = per_path[pid]
        el = "path:%d" % pid
        samples.append(sample(el, p["d"], p["l"], tuple(p["lat"]), t_us))
        path_to_links[el] = sorted(p["links"] | set(path_static_links(pid)))
    return samples, path_to_links


# ----------------------------------------------------------------------------- copy sources
def read_pcap(path: str) -> Iterator[Tuple[int, bytes]]:
    """Yield (capture_time_us, frame) from a classic libpcap file (linktype 1)."""
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = struct.unpack("<I", gh[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            end, nano = "<", magic == 0xA1B23C4D
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            end, nano = ">", magic == 0x4D3CB2A1
        else:
            raise ValueError("not a pcap file: magic 0x%08x" % magic)
        rec = struct.Struct(end + "IIII")
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            sec, frac, caplen, _ = rec.unpack(rh)
            t_us = sec * 1_000_000 + (frac // 1000 if nano else frac)
            yield t_us, f.read(caplen)


class PcapSource:
    """Replays copies from a pcap; each poll() returns the copies whose capture time falls
    in the next `epoch_us` window, so the replay keeps the recorded cadence."""

    def __init__(self, path: str, epoch_us: int) -> None:
        self._it = read_pcap(path)
        self._epoch_us = epoch_us
        self._t0: Optional[int] = None
        self._pending: Optional[Tuple[int, bytes]] = None
        self._epoch = 0

    def poll(self) -> List[bytes]:
        out: List[bytes] = []
        self._epoch += 1
        while True:
            item = self._pending or next(self._it, None)
            self._pending = None
            if item is None:
                return out
            t_us, frame = item
            if self._t0 is None:
                self._t0 = t_us
            if t_us - self._t0 >= self._epoch * self._epoch_us:
                self._pending = item
                return out
            out.append(frame)

    def close(self) -> None:
        return None


class LiveSource:
    """Non-blocking AF_PACKET socket on the collector interface, ethertype 0x88F1 only."""

    def __init__(self, iface: str) -> None:
        self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(MIRROR_ETYPE))
        self._sock.bind((iface, 0))
        self._sock.setblocking(False)

    def poll(self) -> List[bytes]:
        out: List[bytes] = []
        while True:
            try:
                out.append(self._sock.recv(65535))
            except BlockingIOError:
                return out

    def close(self) -> None:
        self._sock.close()


def parse_copies(frames: List[bytes]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for fr in frames:
        try:
            out.append(parse_copy(fr))
        except ValueError as e:
            logger.debug("skipping frame: %s", e)
    return out


# ----------------------------------------------------------------------------- bfrt adapter
# Every table BfrtAdapter reads or writes.  All three exist in mcp_fabric, mcp_fabric_cw4
# and mcp_fabric_gate_event, so a program that cannot resolve them is the wrong program.
REQUIRED_TABLES = ("pipe.Ingress.tbl_vlink", "pipe.Ingress.tbl_fail", "pipe.Ingress.reg_attn")


class ProgramMismatch(RuntimeError):
    """The bound bfrt schema is not the P4 program this adapter needs (HURDLES H39b)."""


def verify_program(bfrt: Any, program: str,
                   tables: Tuple[str, ...] = REQUIRED_TABLES) -> None:
    """Resolve every table the adapter uses, immediately after binding.

    Binding the WRONG program name does not fail on its own: bf_switchd serves its schema
    from the JSON named in its conf, so the reply is a schema for a program the chip may
    not be running, and the damage surfaces later as wrong action arity or a silently
    EMPTY table (setup_skeleton.TO_LOOP_PATH_ID; HURDLES H39b).  Fail here instead, naming
    the program and the table that is missing."""
    for name in tables:
        try:
            resolved = bfrt.table_get(name)
        except Exception as e:                     # bfrt raises KeyError; wrappers vary
            resolved, reason = None, "%s: %s" % (type(e).__name__, e)
        else:
            reason = "table_get returned None"
        if resolved is None:
            raise ProgramMismatch(
                "P4 program %r does not provide %s (%s).  The bound bfrt schema is not the "
                "program this adapter needs — pass --program <the loaded binary>."
                % (program, name, reason))
    logger.info("bound P4 program %s: %d required tables resolved", program, len(tables))


class BfrtAdapter:
    """Live adapter against bf_switchd.  UNTESTED on silicon (see module docstring)."""

    def __init__(self, source: Any, client_id: int = CLIENT_ID, program: str = PROG) -> None:
        import bfrt_grpc.client as gc   # type: ignore
        self.gc = gc
        self.program = program
        self.iface = gc.ClientInterface(GRPC_ADDR, client_id=client_id, device_id=DEV)
        self.bfrt = self.iface.bfrt_info_get(program)
        self.iface.bind_pipeline_config(program)   # per-client bind, no warm-init
        verify_program(self.bfrt, program)         # loud and early, never a silent empty table
        self.tgt = gc.Target(device_id=DEV, pipe_id=0xFFFF)
        self.source = source
        self._prev: Dict[int, Tuple[int, int]] = {}
        self._attn_keys: Optional[List[Any]] = None
        self.reg_writes = 0

    @staticmethod
    def _val(d: Dict[str, Any], name: str) -> Any:
        v = d.get(name)
        return v.get("value", v) if isinstance(v, dict) else v

    def _counters(self, table: str, key_field: str, vlink_from_action: bool) -> Dict[int, Dict[str, int]]:
        t = self.bfrt.table_get(table)
        t.operations_execute(self.tgt, "SyncCounters")
        tot: Dict[int, Dict[str, int]] = {}
        # keyless entry_get yields (Data, Key) — setup_skeleton._rows asserts this order
        for data, key in t.entry_get(self.tgt, flags={"from_hw": True}):
            k, d = key.to_dict(), data.to_dict()
            if vlink_from_action:
                v = self._val(d, "vlink_id") if d.get("action_name", "").endswith("to_loop") else None
            else:
                v = self._val(k, key_field)
            if v is None:
                continue
            act = (d.get("action_name") or "").split(".")[-1]
            row = tot.setdefault(int(v), {})
            row["pkts"] = row.get("pkts", 0) + int(self._val(d, "$COUNTER_SPEC_PKTS") or 0)
            row["bytes"] = row.get("bytes", 0) + int(self._val(d, "$COUNTER_SPEC_BYTES") or 0)
            row[act] = row.get(act, 0) + int(self._val(d, "$COUNTER_SPEC_PKTS") or 0)
        return tot

    def read_attn(self) -> Tuple[List[List[int]], List[List[int]]]:
        # A KEYLESS full-table get is measured 13 % faster than passing 256 explicit
        # keys (47.5 ms vs 54.7 ms median on silicon) and returns identical content,
        # still carrying $REGISTER_INDEX in the key, so the indexing below is unchanged.
        t = self.bfrt.table_get("pipe.Ingress.reg_attn")
        attn: List[List[int]] = [[] for _ in range(N_PATHS)]
        clean: List[List[int]] = [[] for _ in range(N_PATHS)]
        for data, key in t.entry_get(self.tgt, flags={"from_hw": True}):
            i = int(self._val(key.to_dict(), "$REGISTER_INDEX"))
            dd = data.to_dict()
            attn[i] = list(dd["Ingress.reg_attn.attn"])      # one value per pipe
            clean[i] = list(dd["Ingress.reg_attn.clean"])
        return attn, clean

    def write_attn(self, vec: List[int]) -> None:
        # The 256 KEY objects are identical every epoch, so build them once: rebuilding
        # them per epoch cost a measured 23.6 ms/epoch against 9.6 ms for the same
        # entry_add with pre-built keys, which is most of the reason tau_slow overran a
        # 100 ms epoch.  Only the DATA changes, so only the data is rebuilt.
        t = self.bfrt.table_get("pipe.Ingress.reg_attn")
        if self._attn_keys is None:
            self._attn_keys = [t.make_key([self.gc.KeyTuple("$REGISTER_INDEX", i)])
                               for i in range(N_PATHS)]
        n = min(len(vec), N_PATHS)
        data = [t.make_data([self.gc.DataTuple("Ingress.reg_attn.attn", int(a)),
                             self.gc.DataTuple("Ingress.reg_attn.clean", 0)])
                for a in vec[:n]]
        t.entry_add(self.tgt, self._attn_keys[:n], data)   # register writes are idempotent adds
        self.reg_writes += n

    def observe(self, epoch: int) -> Observation:
        t_us = int(time.time() * 1e6)
        obs = Observation(epoch=epoch, t_host_us=t_us)
        t0 = time.perf_counter()
        copies = parse_copies(self.source.poll())
        obs.t_read_us = int((time.perf_counter() - t0) * 1e6)
        t0 = time.perf_counter()
        cur = self._counters("pipe.Ingress.tbl_vlink", "", True)
        deltas = {v: (r["pkts"] - self._prev.get(v, (0, 0))[0],
                      r["bytes"] - self._prev.get(v, (0, 0))[1]) for v, r in cur.items()}
        self._prev = {v: (r["pkts"], r["bytes"]) for v, r in cur.items()}
        obs.fail_truth = self._counters("pipe.Ingress.tbl_fail", "md.vlink_id", False)
        obs.attn, obs.clean = self.read_attn()
        obs.t_sync_us = int((time.perf_counter() - t0) * 1e6)
        obs.counter_reads = 2 + N_PATHS
        _fill(obs, copies, deltas, t_us)
        return obs

    def close(self) -> None:
        self.source.close()


def _fill(obs: Observation, copies: List[Dict[str, Any]],
          deltas: Dict[int, Tuple[int, int]], t_us: int) -> None:
    obs.samples, obs.path_to_links = aggregate(copies, deltas, t_us)
    obs.gap_events = [event for event in (gap_event_from_copy(c) for c in copies)
                      if event is not None]
    obs.n_gap_events = len(obs.gap_events)
    obs.audit_receipts = [receipt for receipt in (audit_receipt_from_copy(c) for c in copies)
                          if receipt is not None]
    obs.n_audit_receipts = len(obs.audit_receipts)
    obs.n_copies = len(copies)
    obs.n_measured = sum(1 for c in copies if c["measured"] and not (c["dropped"] or c["corrupted"]))
    obs.n_lost = sum(1 for c in copies if c["dropped"] or c["corrupted"])
    obs.mirror_bytes = sum(c["length"] for c in copies)
    obs.t_switch_ns = max((c["tstamp_ns"] for c in copies), default=0)
