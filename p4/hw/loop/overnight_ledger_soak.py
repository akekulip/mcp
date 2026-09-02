"""Extended overnight soak of the proven ledger smoke-test recipe.

Repeats, at large scale, exactly the two checks already validated in
docs/review/artifacts/HW-LEDGER-SMOKE-TEST.md: (1) clean forwarding advances
seq and obs by equal amounts on every sublink, (2) a known injected drop
count is recovered exactly as delta_seq - delta_obs. Does NOT touch the new
statistical decision layer -- this is a hardware stability soak of the P4
program only.

The ledger's registers are cumulative since bring-up and never reset, so
every check here is a DELTA against a maintained baseline, never an absolute
equality on the raw counters (sublink 2 has carried a real, already-explained
5-packet gap since this afternoon's smoke test; checking absolute seq==obs
would misreport that stale, legitimate state as a fresh failure every cycle).

Stops immediately on the first mismatch (never continues blind past a
disagreement) and logs every cycle to a file so state survives a session
restart.
"""

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict

SWITCH_HOST = "decps@10.10.54.81"
GATE_PORT = 47100
VISION_HOST = "decps@10.10.54.166"
PROBE_SCRIPT = "~/mcp_multicontext_probe.py"
IFACE = "enp59s0f0np0"
CONTEXTS = (2, 6, 10, 14)

# gate_agent.py only accepts connections from 127.0.0.1 or Vision
# (ALLOWED_PEERS in gate_agent.py) -- every command is proxied over SSH to
# the switch itself and connects to localhost from there, exactly like every
# prior interactive check in this session. The script is piped over stdin
# (python3 -) rather than passed as a -c argv string, because ssh always
# re-joins trailing argv words into one string for the remote shell to
# re-parse, which mangles a multi-line payload passed as a single argument.
_GATE_PY = (
    "import socket, time\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "s.settimeout(5)\n"
    "s.connect(('127.0.0.1', {port}))\n"
    "s.sendall({command!r})\n"
    "time.sleep(0.2)\n"
    "print(s.recv(16384).decode())\n"
)


def gate_command(command: str, timeout: float = 10.0) -> str:
    payload = _GATE_PY.format(port=GATE_PORT, command=(command + "\n").encode())
    result = subprocess.run(
        ["ssh", SWITCH_HOST, "python3", "-"],
        input=payload, capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gate command {command!r} failed: {result.stderr}")
    return result.stdout


def read_census() -> Dict[int, Dict[str, int]]:
    reply = gate_command("R")
    rows = {}
    for line in reply.splitlines():
        parts = line.split()
        if len(parts) == 6 and parts[0] == "S":
            sublink = int(parts[1])
            rows[sublink] = {
                "vlink": int(parts[2]),
                "context": int(parts[3]),
                "seq": int(parts[4]),
                "obs": int(parts[5]),
            }
    return rows


def send_clean_traffic(count_per_context: int, pps: int) -> None:
    for context in CONTEXTS:
        cmd = (
            f"sudo -S python3 {PROBE_SCRIPT} --iface {IFACE} "
            f"--count {count_per_context} --pps {pps} --contexts {context}"
        )
        result = subprocess.run(
            ["ssh", VISION_HOST, f"source ~/.lab_env 2>/dev/null; echo \"$SSHPASS\" | {cmd}"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(f"probe failed for context {context}: {result.stderr}")


def arm_injector(sublink: int, ndrop: int) -> str:
    return gate_command(f"A {sublink} {ndrop}")


def clear_injector() -> str:
    """gate_agent.py's own 'per-trial reset' -- each `A` call only ADDS a new
    TCAM range entry and never removes the previous one, so repeated arming
    without this eventually exhausts the injector table (RESOURCE_EXHAUSTED,
    observed in this soak's own cycle 28 after 27 unclearred arms)."""
    return gate_command("C")


# hdr.witness.seq and reg_wit_seq are bit<16> (p4/witness/*.p4: `bit<16> seq;`,
# `Register<bit<16>, bit<16>>(64, 0) reg_wit_seq`), so the per-sublink sequence
# wraps every 65536 stamped packets. First seen on silicon at MAIN2 cycle 224
# (2026-09-02 08:31 UTC): sublink 2 read delta_seq = 20 - 65536 = -65516 with
# delta_obs = 20. A cycle moves each sublink by 40 packets, far below the
# modulus, so reducing every delta mod 2^16 is exact for a 16-bit register and
# a no-op for a wider one.
COUNTER_WRAP = 1 << 16


def deltas_since(baseline: Dict[int, Dict[str, int]],
                  current: Dict[int, Dict[str, int]]) -> Dict[int, Dict[str, int]]:
    result = {}
    for sublink, row in current.items():
        base = baseline.get(sublink, {"seq": row["seq"], "obs": row["obs"]})
        result[sublink] = {
            "delta_seq": (row["seq"] - base["seq"]) % COUNTER_WRAP,
            "delta_obs": (row["obs"] - base["obs"]) % COUNTER_WRAP,
        }
    return result


def census_after_settle(settle_s: float) -> Dict[int, Dict[str, int]]:
    """Read the census only after in-flight probe packets have landed.

    gate_agent.py's R command bulk-reads reg_wit_seq first and
    reg_wit_observed second; a packet that lands between those two reads shows
    obs = seq + 1 for its sublink. Seen once in 1345 cycles (2026-09-02 soak,
    sublinks 14 and 142, both equal again on the very next read). Settling
    before the read closes the window; the recheck below catches the rest."""
    time.sleep(settle_s)
    return read_census()


def mismatches_vs(baseline: Dict[int, Dict[str, int]],
                  current: Dict[int, Dict[str, int]], skip: int = -1) -> list:
    return [{"sublink": s, **d} for s, d in deltas_since(baseline, current).items()
            if s != skip and d["delta_seq"] != d["delta_obs"]]


def run_cycle(cycle: int, log_path: Path, baseline: Dict[int, Dict[str, int]],
              count_per_context: int, pps: int, inject_sublink: int,
              inject_ndrop: int, settle_s: float, recheck_s: float) -> dict:
    send_clean_traffic(count_per_context, pps)
    after_clean = census_after_settle(settle_s)
    clean_first = mismatches_vs(baseline, after_clean)
    clean_recheck = None
    if clean_first:
        # A disagreement on the first read is re-read once before it counts:
        # a read-order race resolves, a real drop or phantom does not.
        time.sleep(recheck_s)
        after_clean = read_census()
        clean_recheck = mismatches_vs(baseline, after_clean)
    baseline = after_clean

    arm_reply = arm_injector(inject_sublink, inject_ndrop)
    send_clean_traffic(count_per_context, pps)
    after_inject = census_after_settle(settle_s)
    clear_reply = clear_injector()
    other_first = mismatches_vs(baseline, after_inject, skip=inject_sublink)
    other_recheck = None
    if other_first:
        time.sleep(recheck_s)
        after_inject = read_census()
        other_recheck = mismatches_vs(baseline, after_inject, skip=inject_sublink)
    inject_deltas = deltas_since(baseline, after_inject)
    baseline = after_inject

    target = inject_deltas.get(inject_sublink, {"delta_seq": 0, "delta_obs": 0})
    recovered_loss = target["delta_seq"] - target["delta_obs"]

    record = {
        "cycle": cycle,
        "timestamp": time.time(),
        "clean_mismatches": clean_recheck if clean_recheck is not None else clean_first,
        "clean_mismatches_first_read": clean_first if clean_recheck is not None else None,
        "arm_reply": arm_reply.strip(),
        "clear_reply": clear_reply.strip(),
        "recovered_loss": recovered_loss,
        "expected_loss": inject_ndrop,
        "loss_matches": recovered_loss == inject_ndrop,
        "other_sublink_mismatches": other_recheck if other_recheck is not None else other_first,
        "other_mismatches_first_read": other_first if other_recheck is not None else None,
    }
    with log_path.open("a") as handle:
        handle.write(json.dumps(record) + "\n")
    return record, baseline

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cycles", type=int, default=200)
    parser.add_argument("--count-per-context", type=int, default=20)
    parser.add_argument("--pps", type=int, default=100)
    parser.add_argument("--inject-sublink", type=int, default=2)
    parser.add_argument("--inject-ndrop", type=int, default=5)
    parser.add_argument("--log", type=str,
                        default="docs/review/artifacts/P3-OVERNIGHT-LEDGER-SOAK-2026-09-02.jsonl")
    parser.add_argument("--sleep-s", type=float, default=2.0)
    parser.add_argument("--settle-s", type=float, default=1.0)
    parser.add_argument("--recheck-s", type=float, default=2.0)
    args = parser.parse_args()

    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    baseline = read_census()
    for cycle in range(1, args.cycles + 1):
        record, baseline = run_cycle(cycle, log_path, baseline, args.count_per_context,
                                     args.pps, args.inject_sublink, args.inject_ndrop,
                                     args.settle_s, args.recheck_s)
        ok = (not record["clean_mismatches"] and record["loss_matches"]
              and not record["other_sublink_mismatches"])
        status = "OK" if ok else "MISMATCH"
        print(f"cycle {cycle}/{args.cycles} {status} "
              f"recovered_loss={record['recovered_loss']} "
              f"expected={record['expected_loss']} "
              f"clean_mismatches={len(record['clean_mismatches'])} "
              f"other_mismatches={len(record['other_sublink_mismatches'])} "
              f"transient_first_read={int(record['clean_mismatches_first_read'] is not None or record['other_mismatches_first_read'] is not None)}",
              flush=True)
        if not ok:
            print("STOPPING: first mismatch, not continuing blind", file=sys.stderr)
            return 1
        time.sleep(args.sleep_s)

    print(f"all {args.cycles} cycles clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
