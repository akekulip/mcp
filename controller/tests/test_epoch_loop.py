"""Tests for controller/hw_adapter.py, controller/policies.py, controller/epoch_loop.py.

Run from the repo root:  python3 -m unittest discover -s controller/tests -p "test_epoch_loop.py" -v
No third-party dependencies (struct-based parsing).  If controller.infer is not present yet,
a minimal fake honouring its contract is installed in sys.modules.
"""
import csv
import os
import pathlib
import socket
import struct
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def _install_fake_infer() -> types.ModuleType:
    """Minimal controller.infer honouring the contract (Sample, InferState, update, localize)."""
    m = types.ModuleType("controller.infer")

    @dataclass(frozen=True)
    class Sample:
        element: str
        delivered: int
        lost: int
        latency_us: tuple
        t_us: int

    class InferState(dict):
        pass

    class Localization:
        def __init__(self, anomaly: bool, ranked: List[Any]) -> None:
            self.anomaly, self.ranked = anomaly, ranked
            self.suspects = [e for e, _ in ranked]

    def update(state: Any, samples: Any, path_to_links: Dict[str, List[str]]) -> Any:
        st = InferState(state)
        for s in samples:
            d, l = st.get(s.element, (0, 0))
            st[s.element] = (d + s.delivered, l + s.lost)
        return st

    def localize(state: Any, k: int, h: float) -> Localization:
        r = sorted(((l / (d + l) if d + l else 0.0), e) for e, (d, l) in state.items())
        ranked = [(e, x) for x, e in reversed(r)]
        return Localization(bool(ranked) and ranked[0][1] > h, ranked[:k])

    m.Sample, m.InferState, m.update, m.localize, m.H_DEFAULT = Sample, InferState, update, localize, 0.1
    return m


try:
    import controller.infer as _real_infer  # noqa: F401
    HAVE_REAL_INFER = True
except ImportError:
    sys.modules["controller.infer"] = _install_fake_infer()
    HAVE_REAL_INFER = False

from controller import hw_adapter as hw  # noqa: E402
from controller import policies  # noqa: E402
from controller import epoch_loop  # noqa: E402
from controller.sublink_feedback import AuditReceipt, GapEvent  # noqa: E402

FAKE_INFER = _install_fake_infer()


class TestParseCopy(unittest.TestCase):
    def _mirror(self, next_hop: int, vlink: int, pid: int, attn: int, flags: int, ts: int) -> bytes:
        return (bytes.fromhex("a5a5a5a5a5a5") + bytes.fromhex("020000004d43") + b"\x88\xf1"
                + struct.pack("!HHHHH", next_hop, vlink, pid, attn, flags) + ts.to_bytes(6, "big"))

    def test_sid1_hop0_plain_inner(self) -> None:
        inner = bytes(12) + b"\x08\x00" + bytes(20)
        c = hw.parse_copy(self._mirror(1, 3, 7, 4096, 0x1, 0x0123456789AB) + inner)
        self.assertEqual((c["next_hop"], c["vlink"], c["path_id"], c["attn"]), (1, 3, 7, 4096))
        self.assertEqual(c["tstamp_ns"], 0x0123456789AB)
        self.assertTrue(c["measured"]); self.assertFalse(c["dropped"]); self.assertFalse(c["corrupted"])
        self.assertEqual(c["inner_etype"], 0x0800)
        self.assertIsNone(c["fabric"]); self.assertIsNone(c["csig"]); self.assertIsNone(c["worst_tdelta_ns"])
        self.assertEqual(c["length"], 30 + 14 + 20)

    def test_plain_inner_exposes_exact_ipv4_udp_probe_identity(self) -> None:
        ipv4 = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0,
            socket.inet_aton("10.0.1.1"), socket.inet_aton("10.0.1.3"))
        udp = struct.pack("!HHHH", 41000, 4449, 8, 0)
        inner = bytes(12) + b"\x08\x00" + ipv4 + udp

        copy = hw.parse_copy(self._mirror(1, 1, 5, 4096, 0x1, 100) + inner)

        self.assertEqual(copy["ipv4"], {
            "diffserv": 0, "total_len": 28, "protocol": 17,
            "src": "10.0.1.1", "dst": "10.0.1.3",
        })
        self.assertEqual(copy["udp"], {"src_port": 41000, "dst_port": 4449})

    def test_sid1_spine_copy_fabric_csig(self) -> None:
        fabric = struct.pack("!HHHHBBBB", 2, 1, 1, 5, 0, 1, 1, 0)         # nxt == 1 -> csig follows
        csig = struct.pack("!HHHIHH", 1, 9, 77, 123456, 5, 42)
        inner = bytes(12) + b"\x88\xf0" + fabric + csig + bytes(20)
        c = hw.parse_copy(self._mirror(2, 9, 5, 65535, 0x1, 1000) + inner)
        self.assertEqual(c["inner_etype"], 0x88F0)
        self.assertEqual(c["fabric"]["hop"], 1); self.assertEqual(c["fabric"]["path_id"], 5)
        self.assertEqual(c["csig"]["worst_vlink"], 9); self.assertEqual(c["csig"]["epoch"], 42)
        self.assertEqual(c["worst_tdelta_ns"], 123456)

    def test_spine_copy_without_csig(self) -> None:
        fabric = struct.pack("!HHHHBBBB", 2, 1, 0, 4, 0, 0, 0, 0)         # nxt == 0
        c = hw.parse_copy(self._mirror(2, 8, 4, 4096, 0x1, 1) + bytes(12) + b"\x88\xf0" + fabric + bytes(20))
        self.assertIsNotNone(c["fabric"]); self.assertIsNone(c["csig"])

    def test_sid3_dropped(self) -> None:
        c = hw.parse_copy(self._mirror(1, 0, 2, 4096, 0x2, 5) + bytes(12) + b"\x08\x00" + bytes(20))
        self.assertTrue(c["dropped"]); self.assertFalse(c["measured"]); self.assertFalse(c["corrupted"])

    def test_rejects_non_copy(self) -> None:
        with self.assertRaises(ValueError):
            hw.parse_copy(bytes(12) + b"\x08\x00" + bytes(40))
        with self.assertRaises(ValueError):
            hw.parse_copy(b"\x00" * 10)

    def test_build_copy_roundtrip(self) -> None:
        c = hw.parse_copy(hw.build_copy(3, 5, hw.FLAG_MEASURED, 99, 4096, 2, hw.FABRIC_ETYPE,
                                        {"worst_tdelta": 2500, "worst_vlink": 3}))
        self.assertEqual((c["vlink"], c["path_id"], c["worst_tdelta_ns"]), (3, 5, 2500))

    def test_gap_mirror_decodes_an_attributed_sublink_event(self) -> None:
        sublink = (2 << 4) | 3
        frame = hw.build_copy(
            sublink, 0xFFFB, hw.FLAG_GAP_EVENT, 99, 999, 2, hw.FABRIC_ETYPE,
            {"epoch": 42}, witness={"seq": 17})
        copy = hw.parse_copy(frame)
        self.assertTrue(copy["gap_event"])
        self.assertEqual(copy["witness"], {"seq": 17})
        self.assertEqual(hw.gap_event_from_copy(copy), GapEvent(2, 3, 42, 0xFFFB, 1000))

    def test_gap_mirror_rejects_missing_attribution(self) -> None:
        """The "mismatched attribution" half of this test retired with link_id itself
        (overhead-reduction pass 2026-09-02): mirror_h.vlink is the only surviving source
        of sublink identity in an event copy, so there is nothing left in the same copy to
        cross-check it against. A missing witness is still rejected -- it is still
        required whenever gap_event/audit_receipt is set.

        payload_len=0 here is load-bearing, not incidental: build_copy's default 32-byte
        payload filler always follows the witness slot, so a genuinely absent witness and
        a present-but-zeroed one are indistinguishable by length alone once enough filler
        is appended -- caught by this exact test regressing (silently parsing filler bytes
        as a bogus witness) when the now-removed mismatch check stopped masking it. Real
        truncation happens for a different reason (the switch's mirror session caps
        $max_pkt_len below what CSIG+witness need); payload_len=0 reproduces that shape.
        """
        sublink = (2 << 4) | 3
        no_witness = hw.build_copy(
            sublink, 0xFFFB, hw.FLAG_GAP_EVENT, 99, 1000, 2, hw.FABRIC_ETYPE,
            {"epoch": 42}, payload_len=0)
        with self.assertRaisesRegex(ValueError, "witness"):
            hw.parse_copy(no_witness)

    def test_audit_receipt_decodes_declared_probe_token(self) -> None:
        sublink = (2 << 4) | 3
        frame = hw.build_copy(
            sublink, 0, hw.FLAG_AUDIT_RECEIPT, 99, 7, 2, hw.FABRIC_ETYPE,
            {"epoch": 42}, witness={"seq": 17},
            udp_src_port=40001, udp_dst_port=hw.AUDIT_UDP_DST)
        copy = hw.parse_copy(frame)
        self.assertTrue(copy["audit_receipt"])
        self.assertEqual(copy["udp"], {"src_port": 40001, "dst_port": hw.AUDIT_UDP_DST})
        self.assertEqual(
            hw.audit_receipt_from_copy(copy),
            AuditReceipt(2, 3, 42, 40001, 17, 0),
        )
        self.assertIsNone(hw.gap_event_from_copy(copy))

    def test_combined_audit_gap_is_both_negative_receipt_and_gap_event(self) -> None:
        sublink = (13 << 4) | 7
        frame = hw.build_copy(
            sublink, 0xFFFB, hw.FLAG_AUDIT_RECEIPT | hw.FLAG_GAP_EVENT,
            99, 2, 2, hw.FABRIC_ETYPE, {"epoch": 9},
            witness={"seq": 21},
            udp_src_port=40002, udp_dst_port=hw.AUDIT_UDP_DST)
        copy = hw.parse_copy(frame)
        self.assertEqual(hw.gap_event_from_copy(copy), GapEvent(13, 7, 9, 0xFFFB, 3))
        self.assertEqual(
            hw.audit_receipt_from_copy(copy),
            AuditReceipt(13, 7, 9, 40002, 21, 0xFFFB),
        )

    def test_audit_receipt_requires_reserved_udp_identity(self) -> None:
        sublink = (2 << 4) | 3
        missing_udp = hw.build_copy(
            sublink, 0, hw.FLAG_AUDIT_RECEIPT, 99, 1, 2, hw.FABRIC_ETYPE,
            {"epoch": 42}, witness={"seq": 17})
        with self.assertRaisesRegex(ValueError, "audit UDP"):
            hw.parse_copy(missing_udp)
        wrong_port = hw.build_copy(
            sublink, 0, hw.FLAG_AUDIT_RECEIPT, 99, 1, 2, hw.FABRIC_ETYPE,
            {"epoch": 42}, witness={"seq": 17},
            udp_src_port=40001, udp_dst_port=4791)
        with self.assertRaisesRegex(ValueError, "destination"):
            hw.parse_copy(wrong_port)

    def test_normal_mirror_is_not_a_gap_event(self) -> None:
        copy = hw.parse_copy(hw.build_copy(3, 5, hw.FLAG_MEASURED, 99))
        self.assertIsNone(hw.gap_event_from_copy(copy))


class TestAggregate(unittest.TestCase):
    def test_synthetic_epoch(self) -> None:
        frames = [hw.build_copy(3, 5, hw.FLAG_MEASURED, 10, next_hop=1),
                  hw.build_copy(14, 5, hw.FLAG_MEASURED, 12, next_hop=2, inner_etype=hw.FABRIC_ETYPE,
                                csig={"worst_tdelta": 3000}),
                  hw.build_copy(3, 5, hw.FLAG_DROPPED, 20, next_hop=1),
                  hw.build_copy(0, 0, hw.FLAG_MEASURED, 30, next_hop=1),
                  hw.build_copy(0, 0, hw.FLAG_CORRUPTED, 31, next_hop=1)]
        samples, p2l = hw.aggregate(hw.parse_copies(frames), {3: (100, 150000), 14: (90, 1)}, 777)
        by = {s.element: s for s in samples}
        self.assertEqual((by["vlink:3"].delivered, by["vlink:3"].lost), (100, 0))
        self.assertEqual((by["path:5"].delivered, by["path:5"].lost), (2, 1))
        self.assertEqual(by["path:5"].latency_us, (3.0,))
        self.assertEqual((by["path:0"].delivered, by["path:0"].lost), (1, 1))
        self.assertEqual(by["path:5"].t_us, 777)
        self.assertEqual(p2l["path:5"], ["vlink:14", "vlink:3"])     # downlink 8+1*4+2, learned uplink
        self.assertEqual(p2l["path:0"], ["vlink:0", "vlink:8"])

    def test_fail_truth_not_in_samples(self) -> None:
        obs = hw.Observation(epoch=1, t_host_us=0)
        obs.fail_truth = {0: {"inj_drop": 5}}
        hw._fill(obs, [], {}, 0)
        self.assertEqual(obs.samples, [])

    def test_observation_surfaces_gap_events_separately_from_attention_samples(self) -> None:
        sublink = (13 << 4) | 7
        frame = hw.build_copy(
            sublink, 0xFFF0, hw.FLAG_GAP_EVENT, 99, 1499, 2, hw.FABRIC_ETYPE,
            {"epoch": 9}, witness={"seq": 21})
        obs = hw.Observation(epoch=9, t_host_us=0)
        hw._fill(obs, hw.parse_copies([frame]), {}, 0)
        self.assertEqual(obs.gap_events, [GapEvent(13, 7, 9, 0xFFF0, 1500)])
        self.assertEqual(obs.n_gap_events, 1)

    def test_observation_surfaces_audit_receipts_without_polluting_attention_samples(self) -> None:
        sublink = (13 << 4) | 7
        frame = hw.build_copy(
            sublink, 0, hw.FLAG_AUDIT_RECEIPT, 99, 0, 2, hw.FABRIC_ETYPE,
            {"epoch": 9}, witness={"seq": 21},
            udp_src_port=40003, udp_dst_port=hw.AUDIT_UDP_DST)
        obs = hw.Observation(epoch=9, t_host_us=0)
        hw._fill(obs, hw.parse_copies([frame]), {}, 0)
        self.assertEqual(obs.audit_receipts, [AuditReceipt(13, 7, 9, 40003, 21, 0)])
        self.assertEqual(obs.n_audit_receipts, 1)
        self.assertEqual(obs.samples, [])


class TestPolicies(unittest.TestCase):
    def test_uniform_covers_all_in_256_over_B_epochs(self) -> None:
        for b in (1, 16, 64):
            p = policies.UniformPolicy(b, a_hi=65535, a_lo=256)
            seen: set = set()
            for e in range(256 // b):
                vec = p.choose(e)
                hi = [i for i, a in enumerate(vec) if a == 65535]
                self.assertEqual(len(hi), b)
                self.assertTrue(all(a == 256 for i, a in enumerate(vec) if i not in hi))
                seen.update(hi)
            self.assertEqual(seen, set(range(256)))

    def test_random_seeded_reproducible(self) -> None:
        a = [policies.RandomPolicy(16, seed=7).choose(e) for e in range(5)]
        b = [policies.RandomPolicy(16, seed=7).choose(e) for e in range(5)]
        c = [policies.RandomPolicy(16, seed=8).choose(e) for e in range(5)]
        self.assertEqual(a, b); self.assertNotEqual(a, c)
        self.assertEqual(sum(1 for x in a[0] if x == policies.A_HI_DEFAULT), 16)

    def test_oracle_first_then_fill(self) -> None:
        p = policies.OraclePolicy(4, [5, 200])
        self.assertEqual(p.select(0)[:2], [5, 200]); self.assertEqual(len(p.select(1)), 4)
        self.assertIn("GROUND-TRUTH", p.name)
        self.assertEqual(policies.vlinks_to_paths([14]), [5])
        self.assertEqual(policies.vlinks_to_paths([1]), [1, 3, 5, 7])

    def test_mcp_stub_identity(self) -> None:
        p = policies.McpStubPolicy()
        self.assertIsNone(p.choose(0, [4096] * 256))
        adapter = epoch_loop.SyntheticAdapter()
        loop = epoch_loop.EpochLoop(adapter, FAKE_INFER, p, 10, os.devnull)
        loop.step(1); loop.close()
        self.assertEqual(adapter.written, []); self.assertEqual(adapter.attn, [4096] * 256)


class TestLoop(unittest.TestCase):
    def _run(self, argv: List[str]) -> List[Dict[str, str]]:
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "x.csv")
            self.assertEqual(epoch_loop.main(["--dry-run", "--epochs", "20", "--epoch-ms", "10",
                                              "--out", out] + argv), 0)
            with open(out) as f:
                rows = list(csv.DictReader(f))
        return rows

    def test_dry_run_csv(self) -> None:
        rows = self._run(["--policy", "uniform", "--budget", "16"])
        self.assertEqual(len(rows), 20)
        self.assertEqual(list(rows[0].keys()), epoch_loop.CSV_COLUMNS)
        for r in rows:
            for col in ("t_read_us", "t_sync_us", "t_infer_us", "t_write_us", "tau_slow_us"):
                self.assertGreaterEqual(int(r[col]), 0)
            self.assertGreaterEqual(int(r["tau_slow_us"]), int(r["t_infer_us"]) + int(r["t_write_us"]))
            self.assertIn(r["anomaly"], ("0", "1"))
            self.assertEqual(r["reg_writes"], "256"); self.assertEqual(r["frozen"], "0")
            self.assertGreater(int(r["t_switch_ns"]), 0)
        self.assertEqual([int(r["epoch"]) for r in rows], list(range(1, 21)))

    def test_frozen_never_writes(self) -> None:
        rows = self._run(["--policy", "uniform", "--freeze-controller"])
        self.assertTrue(all(r["reg_writes"] == "0" and r["frozen"] == "1" for r in rows))

    def test_loop_with_fake_infer_localizes_synthetic_fault(self) -> None:
        adapter = epoch_loop.SyntheticAdapter(seed=3, faulty_path=5, loss=0.5, copies_per_epoch=500)
        loop = epoch_loop.EpochLoop(adapter, FAKE_INFER, policies.McpStubPolicy(), 10, os.devnull, k=1, h=0.1)
        row = None
        for e in range(1, 4):
            row = loop.step(e)
        loop.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["suspects"], "path:5"); self.assertEqual(row["anomaly"], 1)


class _StubSource:
    def poll(self) -> List[bytes]:
        return []

    def close(self) -> None:
        return None


class _FakeBfrtInfo:
    """`bfrt_grpc.client._BfRtInfo.table_get` is `self.table_dict[name]` — a KeyError on a
    table the served schema does not carry (SDE 9.13, client.py:3007)."""

    def __init__(self, program: str, tables: Any) -> None:
        self.p4_name, self.table_dict = program, dict(tables)

    def table_get(self, name: str) -> Any:
        return self.table_dict[name]


class _FakeIface:
    def __init__(self, tables_by_program: Dict[str, Any]) -> None:
        self._tables = tables_by_program
        self.info_calls: List[str] = []
        self.bind_calls: List[str] = []

    def bfrt_info_get(self, program: str) -> _FakeBfrtInfo:
        self.info_calls.append(program)
        return _FakeBfrtInfo(program, self._tables.get(program, {}))

    def bind_pipeline_config(self, program: str) -> None:
        self.bind_calls.append(program)


class _FakeGc(types.ModuleType):
    """Stand-in for `bfrt_grpc.client`: only what BfrtAdapter.__init__ touches."""

    def __init__(self, tables_by_program: Dict[str, Any]) -> None:
        types.ModuleType.__init__(self, "bfrt_grpc.client")
        self._tables = tables_by_program
        self.last_iface: Any = None
        self.ClientInterface = self._client_interface
        self.Target = lambda **kw: ("target", kw)
        self.KeyTuple = lambda *a, **kw: ("key", a, kw)
        self.DataTuple = lambda *a, **kw: ("data", a, kw)

    def _client_interface(self, addr: str, client_id: int = 0, device_id: int = 0) -> _FakeIface:
        self.last_iface = _FakeIface(self._tables)
        return self.last_iface


class _fake_bfrt:
    """Install a fake `bfrt_grpc.client` for the duration of a `with` block."""

    def __init__(self, tables_by_program: Dict[str, Any]) -> None:
        self.gc = _FakeGc(tables_by_program)

    def __enter__(self) -> _FakeGc:
        self._saved = {k: sys.modules.get(k) for k in ("bfrt_grpc", "bfrt_grpc.client")}
        pkg = types.ModuleType("bfrt_grpc")
        pkg.client = self.gc            # type: ignore[attr-defined]
        sys.modules["bfrt_grpc"], sys.modules["bfrt_grpc.client"] = pkg, self.gc
        return self.gc

    def __exit__(self, *exc: Any) -> None:
        for k, v in self._saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


ALL_TABLES = {t: object() for t in hw.REQUIRED_TABLES}


class TestBfrtProgramBinding(unittest.TestCase):
    """H39b: the program name is a parameter, and a wrong one fails loudly HERE rather
    than as wrong action arity or a silently empty table later."""

    def test_default_program_is_unchanged(self) -> None:
        self.assertEqual(hw.PROG, "mcp_fabric")
        with _fake_bfrt({"mcp_fabric": ALL_TABLES}) as gc:
            a = hw.BfrtAdapter(_StubSource())
        self.assertEqual(a.program, "mcp_fabric")
        self.assertEqual(gc.last_iface.info_calls, ["mcp_fabric"])
        self.assertEqual(gc.last_iface.bind_calls, ["mcp_fabric"])

    def test_explicit_program_reaches_info_get_and_bind(self) -> None:
        with _fake_bfrt({"mcp_fabric_gate_event": ALL_TABLES}) as gc:
            a = hw.BfrtAdapter(_StubSource(), program="mcp_fabric_gate_event")
        self.assertEqual(a.program, "mcp_fabric_gate_event")
        self.assertEqual(gc.last_iface.info_calls, ["mcp_fabric_gate_event"])
        self.assertEqual(gc.last_iface.bind_calls, ["mcp_fabric_gate_event"])
        self.assertEqual(a.bfrt.p4_name, "mcp_fabric_gate_event")

    def test_missing_table_raises_named_error_not_a_usable_adapter(self) -> None:
        partial = {t: object() for t in hw.REQUIRED_TABLES if t != "pipe.Ingress.reg_attn"}
        with _fake_bfrt({"not_the_loaded_program": partial}):
            with self.assertRaises(hw.ProgramMismatch) as cm:
                hw.BfrtAdapter(_StubSource(), program="not_the_loaded_program")
        msg = str(cm.exception)
        self.assertIn("not_the_loaded_program", msg)
        self.assertIn("pipe.Ingress.reg_attn", msg)

    def test_empty_schema_names_the_first_missing_table(self) -> None:
        with _fake_bfrt({"mcp_fabric": {}}):
            with self.assertRaises(hw.ProgramMismatch) as cm:
                hw.BfrtAdapter(_StubSource())
        self.assertIn(hw.REQUIRED_TABLES[0], str(cm.exception))

    def test_verify_program_accepts_every_required_table(self) -> None:
        self.assertIsNone(hw.verify_program(_FakeBfrtInfo("mcp_fabric_cw4", ALL_TABLES),
                                            "mcp_fabric_cw4"))

    def test_verify_program_rejects_a_table_that_resolves_to_none(self) -> None:
        tables = dict(ALL_TABLES, **{"pipe.Ingress.tbl_fail": None})
        with self.assertRaises(hw.ProgramMismatch):
            hw.verify_program(_FakeBfrtInfo("mcp_fabric", tables), "mcp_fabric")


class TestProgramFlag(unittest.TestCase):
    """The CLI flag must be the one setup_skeleton.py / setup_attention.py already expose."""

    def _setup_scripts(self) -> Any:
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        sys.path.insert(0, os.path.join(root, "p4", "control"))
        import setup_skeleton  # noqa: E402
        import setup_attention  # noqa: E402
        return setup_skeleton, setup_attention

    def test_flag_defaults_to_the_shared_program_name(self) -> None:
        skeleton, attention = self._setup_scripts()
        args = epoch_loop.build_parser().parse_args(["--dry-run"])
        self.assertEqual(args.program, hw.PROG)
        self.assertEqual(hw.PROG, skeleton.PROG)
        self.assertEqual(hw.PROG, attention.PROG)

    def test_flag_parses_the_same_way_as_setup_skeleton(self) -> None:
        skeleton, attention = self._setup_scripts()
        args = epoch_loop.build_parser().parse_args(["--program", "mcp_fabric_gate_event"])
        self.assertEqual(args.program, "mcp_fabric_gate_event")
        self.assertEqual(skeleton.extract_program_arg(["up", "--program", "mcp_fabric_gate_event"]),
                         ("mcp_fabric_gate_event", ["up"]))
        # setup_attention builds its parser inline in main(), so its convention is checked
        # at the source: the same flag spelling, defaulting to the same program.
        src = pathlib.Path(attention.__file__).read_text()
        self.assertIn('ap.add_argument("--program", default=PROG,', src)


if __name__ == "__main__":
    unittest.main()
