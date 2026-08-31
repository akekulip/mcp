#!/usr/bin/env python3
"""Sealed hardware epochs for sequential CLF evidence.

This module is deliberately a thin harness: it verifies the gate-agent identity,
creates one bounded probe epoch, reads exact CLF counts plus injector ground
truth, and hands a sealed EpochRecord to controller.evidence_ledger.
"""

import argparse
from dataclasses import dataclass
import pathlib
import socket
import subprocess
import sys
import time
from typing import Callable, Iterable, List, Optional, Sequence, Tuple


ROOT = pathlib.Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controller.evidence_ledger import (  # noqa: E402
    CensorReason,
    EpochRecord,
    LedgerDecision,
    ReceiptStatus,
    SequentialEvidenceLedger,
)


SWITCH = "10.10.54.81"
PORT = 47100
EXPECTED_ACT_ENTER_ROWS = 4
FRONTIER_SATURATION = 255
DEFAULT_ALTERNATIVES = (0.01, 0.10, 0.50, 0.75, 0.90, 0.97)


class HarnessError(RuntimeError):
    """The harness could not produce a complete, trustworthy epoch."""


@dataclass(frozen=True)
class ProbeRequest:
    packets: int
    pps: int
    contexts: str


@dataclass(frozen=True)
class TrialConfig:
    program: str
    expected_build_id: str
    expected_runtime_id: str
    sublink: int
    epoch: int
    packets: int
    pps: int
    contexts: str
    survival: float
    bank: int = 0
    guard_seconds: float = 2.0
    expected_act_enter_rows: int = EXPECTED_ACT_ENTER_ROWS
    saturation: int = FRONTIER_SATURATION
    alpha: float = 0.05
    healthy_delivery: float = 0.99
    alternatives: Sequence[float] = DEFAULT_ALTERNATIVES
    repair_generation: int = 0
    probe_script: Optional[str] = None

    def __post_init__(self):
        if not self.program:
            raise ValueError("program is required")
        _validate_identity_hash(self.expected_build_id, "expected_build_id")
        _validate_identity_hash(self.expected_runtime_id, "expected_runtime_id")
        if not 0 <= self.sublink < 1024:
            raise ValueError("sublink must lie in 0..1023")
        if not 0 <= self.epoch <= 0xFFFF:
            raise ValueError("epoch must fit the 16-bit hardware field")
        if self.bank not in (0, 1):
            raise ValueError("bank must be 0 or 1")
        if not 0 < self.packets < self.saturation:
            raise ValueError("packet count must be positive and below saturation")
        if self.pps <= 0:
            raise ValueError("pps must be positive")
        if self.contexts not in ("2", "6", "10", "14"):
            raise ValueError("a single-sublink trial requires one single context")
        if not 0.0 <= self.survival <= 1.0:
            raise ValueError("survival must lie in [0, 1]")
        if self.expected_act_enter_rows <= 0:
            raise ValueError("expected_act_enter_rows must be positive")
        if self.saturation <= 1:
            raise ValueError("saturation must exceed one")
        if self.guard_seconds < 0.0:
            raise ValueError("guard_seconds must be non-negative")
        if self.repair_generation < 0:
            raise ValueError("repair_generation must be non-negative")


@dataclass(frozen=True)
class TrialOutcome:
    record: EpochRecord
    decision: LedgerDecision
    sent_frames: int
    measured_drops: Optional[int]
    identity: dict


class TcpGate:
    def __init__(self, host: str = SWITCH, port: int = PORT):
        self.host = host
        self.port = port

    def request(self, command: str, timeout: int = 25) -> str:
        sock = socket.create_connection((self.host, self.port), timeout)
        sock.settimeout(timeout)
        try:
            sock.sendall((command + "\n").encode("ascii"))
            buf = b""
            while len(buf) < 256 * 1024:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
                if _reply_complete(buf):
                    break
            return buf.decode("ascii", errors="replace")
        finally:
            sock.close()


def _reply_complete(buf: bytes) -> bool:
    lines = [line for line in buf.splitlines() if line.strip()]
    if not lines:
        return False
    last = lines[-1]
    return (last.startswith(b"OK ") or last.startswith(b"ERR ") or
            last.startswith(b"IDENTITY "))


def drops_for_survival(packets: int, survival: float) -> int:
    if packets <= 0:
        raise ValueError("packets must be positive")
    if not 0.0 <= survival <= 1.0:
        raise ValueError("survival must lie in [0, 1]")
    return int(round(packets * (1.0 - survival)))


def run_probe(request: ProbeRequest, script: Optional[str] = None) -> int:
    if script is None:
        script = str(pathlib.Path(__file__).resolve().with_name("multicontext_probe.py"))
    command = [
        "python3", script,
        "--count", str(request.packets),
        "--pps", str(request.pps),
        "--contexts", request.contexts,
    ]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    if completed.returncode != 0:
        raise HarnessError("probe exited %d: %s" %
                           (completed.returncode, (completed.stderr or "").strip()[:200]))
    for token in (completed.stdout or "").split():
        if token.isdigit():
            sent = int(token)
            if sent <= 0:
                break
            if sent >= FRONTIER_SATURATION:
                raise HarnessError("probe sent %d frames, at or above count saturation" % sent)
            return sent
    raise HarnessError("probe reported no packet count: %r" % (completed.stdout or "")[:200])


def run_campaign(gate, probe: Callable[[ProbeRequest], int],
                 config: TrialConfig, epochs: int) -> List[TrialOutcome]:
    if epochs <= 0:
        raise ValueError("epochs must be positive")
    ledger = make_ledger(config)
    outcomes = []
    for offset in range(epochs):
        epoch_config = TrialConfig(
            program=config.program,
            expected_build_id=config.expected_build_id,
            expected_runtime_id=config.expected_runtime_id,
            sublink=config.sublink,
            epoch=(config.epoch + offset) & 0xFFFF,
            packets=config.packets,
            pps=config.pps,
            contexts=config.contexts,
            survival=config.survival,
            bank=(config.bank + offset) % 2,
            guard_seconds=config.guard_seconds,
            expected_act_enter_rows=config.expected_act_enter_rows,
            saturation=config.saturation,
            alpha=config.alpha,
            healthy_delivery=config.healthy_delivery,
            alternatives=config.alternatives,
            repair_generation=config.repair_generation,
            probe_script=config.probe_script,
        )
        outcomes.append(run_trial(gate, probe, ledger, epoch_config))
    return outcomes


def run_trial(gate, probe: Callable[[ProbeRequest], int],
              ledger: Optional[SequentialEvidenceLedger],
              config: TrialConfig) -> TrialOutcome:
    if ledger is None:
        ledger = make_ledger(config)
    identity = require_identity(gate, config.program,
                                config.expected_build_id,
                                config.expected_runtime_id)
    cleanup_required = False
    try:
        require_ok_count(gate.request("C"), "C")
        cleanup_required = True
        set_bank(gate, config.bank, config)
        set_epoch(gate, config.epoch, config)
        if config.guard_seconds:
            time.sleep(config.guard_seconds)
        intended_drops = drops_for_survival(config.packets, config.survival)
        zero_frontiers_for_sublink(gate, config)
        if intended_drops:
            if config.survival == 0.0:
                arm_blackhole(gate, config.sublink)
            else:
                arm_injector(gate, config.sublink, intended_drops)

        sent = probe(ProbeRequest(config.packets, config.pps, config.contexts))
        if sent != config.packets:
            raise HarnessError("probe sent %d frames, expected %d" % (sent, config.packets))
        if sent >= config.saturation:
            raise HarnessError("probe sent %d frames, at or above count saturation" % sent)

        freeze_bank = 1 - config.bank
        set_bank(gate, freeze_bank, config)
        set_epoch(gate, (config.epoch + 1) & 0xFFFF, config)
        if config.guard_seconds:
            time.sleep(config.guard_seconds)

        rows = parse_count_rows(gate.request("X"))
        tx, rx, count_reason = extract_sublink_counts(rows, config)
        injector = parse_injector_rows(gate.request("I"))
        measured_drops = injector_drops_for(injector, config.sublink)
        receipt_status = ReceiptStatus.COMPLETE
        censor_reason = count_reason
        if tx != sent and censor_reason is None:
            censor_reason = CensorReason.INCOMPLETE
        if intended_drops and measured_drops is None:
            receipt_status = ReceiptStatus.MISSING
            if censor_reason is None:
                censor_reason = CensorReason.INVALID_RECEIPT
        elif intended_drops and (
                measured_drops != intended_drops or tx - rx != intended_drops):
            receipt_status = ReceiptStatus.INVALID
            if censor_reason is None:
                censor_reason = CensorReason.INVALID_RECEIPT

        record = EpochRecord(
            sublink=config.sublink,
            epoch=config.epoch,
            tx=tx,
            rx=rx,
            receipt_status=receipt_status,
            censor_reason=censor_reason,
            repair_generation=config.repair_generation,
        )
        decision = ledger.ingest(record)
        return TrialOutcome(record, decision, sent, measured_drops, identity)
    finally:
        if cleanup_required:
            require_ok_count(gate.request("C"), "C")


def make_ledger(config: TrialConfig) -> SequentialEvidenceLedger:
    return SequentialEvidenceLedger(
        alpha=config.alpha,
        healthy_delivery=config.healthy_delivery,
        alternatives=config.alternatives,
        saturation=config.saturation,
    )


def _validate_identity_hash(value: str, field: str) -> None:
    hexchars = frozenset("0123456789abcdef")
    if len(value) != 64 or not set(value) <= hexchars:
        raise ValueError("%s must be a 64-character lowercase hex string" % field)


def require_identity(gate, expected_program: str,
                     expected_build_id: str,
                     expected_runtime_id: str) -> dict:
    reply = gate.request("V")
    fields = reply.strip().split()
    if len(fields) != 5 or fields[0] != "IDENTITY":
        raise HarnessError("malformed gate-agent identity: %r" % reply[:120])
    _, program, build_id, runtime_id, switchd_pid = fields
    hexchars = frozenset("0123456789abcdef")
    if (len(build_id) != 64 or len(runtime_id) != 64 or
            not set(build_id) <= hexchars or not set(runtime_id) <= hexchars or
            not switchd_pid.isdigit()):
        raise HarnessError("malformed gate-agent identity: %r" % reply[:120])
    if program != expected_program:
        raise HarnessError("gate agent serves %s, expected %s" %
                           (program, expected_program))
    if build_id != expected_build_id:
        raise HarnessError("gate agent build_id %s, expected %s" %
                           (build_id, expected_build_id))
    if runtime_id != expected_runtime_id:
        raise HarnessError("gate agent runtime_id %s, expected %s" %
                           (runtime_id, expected_runtime_id))
    return {
        "program": program,
        "build_id": build_id,
        "runtime_id": runtime_id,
        "switchd_pid": int(switchd_pid),
    }


def require_ok_count(reply: str, command: str, expected: Optional[int] = None) -> int:
    lines = [line.strip() for line in reply.splitlines() if line.strip()]
    if not lines:
        raise HarnessError("%s reply was empty" % command)
    if any(line.startswith("ERR") for line in lines):
        raise HarnessError("%s failed: %s" % (command, lines[-1]))
    ok = [line for line in lines if line.startswith("OK ")]
    if not ok:
        raise HarnessError("%s reply missing OK terminator" % command)
    parts = ok[-1].split()
    if len(parts) != 2 or not parts[1].isdigit():
        raise HarnessError("%s reply has malformed OK count: %r" % (command, ok[-1]))
    count = int(parts[1])
    if expected is not None and count != expected:
        raise HarnessError("%s modified %d rows, expected %d" % (command, count, expected))
    return count


def set_bank(gate, bank: int, config: TrialConfig) -> None:
    require_ok_count(gate.request("N %d" % bank), "N %d" % bank,
                     expected=config.expected_act_enter_rows)


def set_epoch(gate, epoch: int, config: TrialConfig) -> None:
    require_ok_count(gate.request("E %d" % epoch), "E %d" % epoch,
                     expected=config.expected_act_enter_rows)


def zero_frontiers(gate) -> None:
    require_ok_count(gate.request("Z"), "Z")


def zero_frontiers_for_sublink(gate, config: TrialConfig, attempts: int = 3) -> None:
    residue = []
    for _ in range(attempts):
        zero_frontiers(gate)
        zero_rows = parse_count_rows(gate.request("X"))
        residue = [row for row in zero_rows if row_matches_sublink(row, config)]
        if not residue:
            return
    raise HarnessError("zero did not take, %d rows remain: %s" %
                       (len(residue), residue[:3]))


def arm_injector(gate, sublink: int, ndrop: int) -> None:
    reply = gate.request("A %d %d" % (sublink, ndrop))
    command = "A %d %d" % (sublink, ndrop)
    details = [line.split() for line in reply.splitlines()
               if line.strip() and not line.startswith("OK ")]
    if len(details) != 1:
        raise HarnessError("%s failed: %s" % (command, reply.strip()[:120]))
    fields = details[0]
    if len(fields) < 4 or fields[0] != "ARMED" or fields[1] != str(sublink):
        raise HarnessError("%s failed: %s" % (command, reply.strip()[:120]))
    range_count = require_ok_count(reply, command)
    if range_count <= 0:
        raise HarnessError("%s installed 0 injector ranges" % command)


def arm_blackhole(gate, sublink: int) -> None:
    command = "K %d 0 65535" % sublink
    reply = gate.request(command)
    details = [line.strip() for line in reply.splitlines()
               if line.strip() and not line.startswith("OK ")]
    expected = "BLACKHOLED %d [0..65535]" % sublink
    if details != [expected]:
        raise HarnessError("%s failed: %s" % (command, reply.strip()[:120]))
    require_ok_count(reply, command, expected=1)


def parse_count_rows(reply: str) -> List[Tuple[int, int, int, int, int]]:
    require_ok_count(reply, "X")
    rows = []
    for line in reply.splitlines():
        fields = line.split()
        if not fields or fields[0] == "OK":
            continue
        if len(fields) != 6 or fields[0] != "X":
            raise HarnessError("malformed X row: %r" % line[:120])
        try:
            rows.append(tuple(int(value) for value in fields[1:]))
        except ValueError:
            raise HarnessError("malformed X row: %r" % line[:120])
    return rows


def extract_sublink_counts(rows: Iterable[Tuple[int, int, int, int, int]],
                           config: TrialConfig) -> Tuple[int, int, Optional[CensorReason]]:
    matches = [row for row in rows if row_matches_sublink(row, config)]
    if not matches:
        return 0, 0, None
    if len(matches) != 1:
        raise HarnessError("X returned duplicate rows for sublink %d" % config.sublink)
    _bank, _vlink, _context, tx, rx = matches[0]
    if tx >= config.saturation or rx >= config.saturation:
        return tx, rx, CensorReason.SATURATED
    if rx > tx:
        return tx, rx, CensorReason.IMPOSSIBLE
    return tx, rx, None


def row_matches_sublink(row: Tuple[int, int, int, int, int],
                        config: TrialConfig) -> bool:
    bank, vlink, context, _tx, _rx = row
    return (bank == config.bank and
            vlink == config.sublink >> 4 and
            context == config.sublink & 0xF)


def parse_injector_rows(reply: str) -> List[Tuple[int, int, int, int]]:
    require_ok_count(reply, "I")
    rows = []
    for line in reply.splitlines():
        fields = line.split()
        if not fields or fields[0] == "OK":
            continue
        if len(fields) != 5 or fields[0] != "I":
            raise HarnessError("malformed I row: %r" % line[:120])
        try:
            rows.append(tuple(int(value) for value in fields[1:]))
        except ValueError:
            raise HarnessError("malformed I row: %r" % line[:120])
    return rows


def injector_drops_for(rows: Iterable[Tuple[int, int, int, int]],
                       sublink: int) -> Optional[int]:
    drops = [count for row_sublink, _low, _high, count in rows
             if row_sublink == sublink]
    if not drops:
        return None
    return sum(drops)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--program", default="mcp_fabric_clf_eg")
    parser.add_argument("--expected-build-id", required=True)
    parser.add_argument("--expected-runtime-id", required=True)
    parser.add_argument("--host", default=SWITCH)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--sublink", type=int, default=2)
    parser.add_argument("--epoch", type=int, default=0)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--packets", type=int, default=40)
    parser.add_argument("--pps", type=int, default=200)
    parser.add_argument("--contexts", choices=("2", "6", "10", "14"), default="2")
    parser.add_argument("--survival", type=float, default=0.95)
    parser.add_argument("--guard", type=float, default=2.0)
    parser.add_argument("--probe-script", default=None)
    args = parser.parse_args(argv)

    config = TrialConfig(
        program=args.program,
        expected_build_id=args.expected_build_id,
        expected_runtime_id=args.expected_runtime_id,
        sublink=args.sublink,
        epoch=args.epoch,
        packets=args.packets,
        pps=args.pps,
        contexts=args.contexts,
        survival=args.survival,
        guard_seconds=args.guard,
        probe_script=args.probe_script,
    )
    gate = TcpGate(args.host, args.port)
    outcomes = run_campaign(gate, lambda req: run_probe(req, config.probe_script),
                            config, args.epochs)
    for outcome in outcomes:
        print("epoch=%d sublink=%d tx=%d rx=%d drops=%s verdict=%s e=%.6g reason=%s" %
              (outcome.record.epoch, outcome.record.sublink,
               outcome.record.tx, outcome.record.rx,
               "missing" if outcome.measured_drops is None else outcome.measured_drops,
               outcome.decision.verdict.value, outcome.decision.e_value,
               outcome.decision.reason), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
