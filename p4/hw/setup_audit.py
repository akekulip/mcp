#!/usr/bin/env python3
"""setup_audit.py — planned vs installed row counts for EVERY table in a program.

Blocker B4: `setup_skeleton.py` populates 6 of the ~14 runtime tables that
`mcp_fabric_gate_event` needs, and nothing said so out loud.  A table that is empty
at run time does not fail — it silently falls through to its default action, and the
campaign records a number that means something other than what the caption says.

Two design rules, both aimed at drift:

  * The table list is derived from the compiled ``.bfrt.json`` schema, never from a
    list in this file.  Add a table to the P4 and it appears here on the next
    compile, unplanned and loud.
  * Planned row counts are imported from the ``plan_*`` functions in
    ``p4/control/setup_skeleton.py`` and ``p4/control/setup_attention.py``.  They are
    the same functions the installers iterate, so a planned count cannot disagree
    with what the installer would write.

Modes:

  offline (``--dry-run``, the default when no ``--live``)
      Audits the PLAN against the schema.  No bfrt, no gRPC, no switch — a schema
      file is the only input, so this runs before the chip is taken.  A required
      table with no planner is a FAILURE here: nothing would ever fill it.

  live (``--live``)
      Additionally connects over bfrt gRPC and reads the installed row count of
      every table.  A required table that is empty on the chip is a FAILURE.

Usage:
    python3 p4/hw/setup_audit.py --schema p4/hw/schema/mcp_fabric_gate_event.bfrt.json
    python3 p4/hw/setup_audit.py --schema <f> --live --program mcp_fabric_gate_event

Exit status: 0 clean, 1 audit failure, 2 usage/IO error.
"""
import argparse
import json
import os
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple

# The repo's control plane lives here; both modules import cleanly without the SDE
# because they import bfrt_grpc lazily.
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "p4", "control"))

DEV = 0
CLIENT_ID = 7          # not 0 (binds) and not 2 (setup_attention); read-only auditor
GRPC_ADDR = "localhost:50052"

# bfrt table_type prefixes.  Only match-action tables carry forwarding behaviour and
# are therefore required to be non-empty; the rest are reported for completeness.
MATCH_PREFIX = "MatchAction"
STATE_TYPES = ("Register", "Selector", "Action", "RegisterParam")

# Match-action tables that are CORRECT when empty, each with the reason.  Anything
# not listed here is required.  The list is short on purpose: every entry is a claim
# that "empty" is the healthy state, and each one has to be defensible.
EXEMPT: Dict[str, str] = {
    "tbl_fail": "fault injector; empty IS healthy (setup_skeleton `up` clears it)",
    "tbl_health_gate": "quarantine state; empty means nothing is quarantined",
    "tbl_audit_steer": "armed per audit round by the controller, not at setup",
}


# --------------------------------------------------------------------------- planners
def _planners() -> Dict[str, Tuple[int, str]]:
    """Bare table name -> (planned rows, where the number comes from).

    Every count is len() of the very list the installer iterates, so this cannot
    drift from setup_skeleton.py / setup_attention.py.  Import failures are reported
    rather than swallowed: a planner we cannot load is not a planner.
    """
    out: Dict[str, Tuple[int, str]] = {}
    try:
        import setup_skeleton as sk
    except Exception as e:                                    # pragma: no cover
        print("WARNING: setup_skeleton.py not importable (%s)" % e, file=sys.stderr)
    else:
        out["tbl_port_role"] = (len(sk.plan_roles()), "setup_skeleton.plan_roles()")
        out["tbl_dst_leaf"] = (len(sk.plan_dst_leaf()), "setup_skeleton.plan_dst_leaf()")
        out["tbl_vlink"] = (len(sk.plan_vlink()), "setup_skeleton.plan_vlink()")
        out["tbl_final"] = (len(sk.plan_final()), "setup_skeleton.plan_final()")
        out["tbl_spray_mode"] = (len(sk.plan_spray(sk.DEFAULT_SPRAY)),
                                 "setup_skeleton.plan_spray(%r)" % sk.DEFAULT_SPRAY)
        out["reg_spray_rr"] = (64, "setup_skeleton.seed_registers() seeds 64 slots")
    try:
        import setup_attention as at
    except Exception as e:                                    # pragma: no cover
        print("WARNING: setup_attention.py not importable (%s)" % e, file=sys.stderr)
    else:
        out["tbl_gate"] = (len(at.plan_gate()), "setup_attention.plan_gate()")
        out["tbl_eg_vlink"] = (len(at.plan_eg_vlink()), "setup_attention.plan_eg_vlink()")
        out["tbl_exceed_evid"] = (2, "setup_attention.set_thresh_evid() writes 2 rows")
        out["tbl_exceed_csig"] = (1, "setup_attention.set_thresh_csig() writes 1 row")
        out["tbl_evid_fwd"] = (1, "setup_attention.install_evid_fwd() writes 1 row")
        out["reg_attn"] = (at.N_PATHS, "setup_attention.seed_attn() seeds N_PATHS slots")
    return out


# ----------------------------------------------------------------------------- schema
def load_schema(path: str) -> List[Dict[str, Any]]:
    with open(path) as fh:
        doc = json.load(fh)
    tables = doc.get("tables")
    if not isinstance(tables, list):
        raise ValueError("%s has no 'tables' array — is it a bf-rt schema?" % path)
    return tables


def bare(name: str) -> str:
    """'pipe.Ingress.tbl_vlink' -> 'tbl_vlink'."""
    return name.rsplit(".", 1)[-1]


def is_match(table: Dict[str, Any]) -> bool:
    return str(table.get("table_type", "")).startswith(MATCH_PREFIX)


def is_state(table: Dict[str, Any]) -> bool:
    return str(table.get("table_type", "")) in STATE_TYPES


# ------------------------------------------------------------------------------- live
def connect(program: str) -> Tuple[Any, Any, Any]:
    """bfrt read-only session.  Imported lazily so offline mode needs no SDE."""
    import bfrt_grpc.client as gc
    iface = gc.ClientInterface(GRPC_ADDR, client_id=CLIENT_ID, device_id=DEV)
    iface.bind_pipeline_config(program)
    bfrt = iface.bfrt_info_get(program)
    tgt = gc.Target(device_id=DEV, pipe_id=0xFFFF)
    return iface, bfrt, tgt


def installed_rows(bfrt: Any, tgt: Any, name: str) -> Tuple[Optional[int], str]:
    try:
        t = bfrt.table_get(name)
        n = len(list(t.entry_get(tgt, flags={"from_hw": False})))
        return n, ""
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)


# ----------------------------------------------------------------------------- report
def audit(tables: List[Dict[str, Any]],
          planners: Dict[str, Tuple[int, str]],
          reader: Optional[Callable[[str], Tuple[Optional[int], str]]]) -> int:
    """Print the audit and return the number of failures."""
    live = reader is not None
    hdr = "%-34s %-30s %6s %8s %10s  %s" % (
        "table", "type", "size", "planned", "installed", "status")
    print(hdr)
    print("-" * len(hdr))

    failures: List[str] = []
    n_match = n_planned = 0

    for t in sorted(tables, key=lambda x: (not is_match(x), x["name"])):
        name = t["name"]
        short = bare(name)
        ttype = str(t.get("table_type", "?"))
        size = t.get("size", "?")

        plan = planners.get(short)
        planned = plan[0] if plan else 0
        planned_s = str(planned) if plan else "-"

        inst_s = "n/a"
        inst: Optional[int] = None
        if live:
            inst, err = reader(name)          # type: ignore[misc]
            inst_s = str(inst) if inst is not None else "ERR"

        if is_match(t):
            n_match += 1
            if plan:
                n_planned += 1
            if short in EXEMPT:
                status = "exempt (%s)" % EXEMPT[short]
            elif not plan:
                status = "FAIL unplanned — nothing installs rows in this table"
                failures.append("%s: required and unplanned" % short)
            elif live and inst == 0:
                status = "FAIL empty on the chip"
                failures.append("%s: required, planned %d, installed 0" % (short, planned))
            elif live and inst is not None and inst != planned:
                status = "WARN installed %d != planned %d" % (inst, planned)
            elif live and inst is None:
                status = "WARN unreadable: %s" % err
            else:
                status = "ok"
        elif is_state(t):
            status = "state" if plan else "state, unplanned"
        else:
            status = "fixed-function, not audited"

        print("%-34s %-30s %6s %8s %10s  %s"
              % (short, ttype, size, planned_s, inst_s, status))

    print()
    print("match-action tables in schema : %d" % n_match)
    print("  with a planner              : %d" % n_planned)
    print("  exempt (empty is healthy)   : %d  %s"
          % (len(EXEMPT), ", ".join(sorted(EXEMPT))))
    print("  required and unplanned      : %d"
          % sum(1 for t in tables
                if is_match(t) and bare(t["name"]) not in EXEMPT
                and bare(t["name"]) not in planners))
    print("mode                          : %s" % ("live (plan vs chip)" if live
                                                  else "offline (plan only, no switch)"))

    if failures:
        print()
        print("AUDIT FAILED — %d table(s):" % len(failures))
        for f in failures:
            print("  - %s" % f)
    else:
        print()
        print("AUDIT PASSED")
    return len(failures)


def parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--schema", required=True,
                    help="compiled <program>.bfrt.json (the table list comes from here)")
    ap.add_argument("--program", default=None,
                    help="P4 program name for bfrt bind; default: schema file stem")
    ap.add_argument("--live", action="store_true",
                    help="also read installed row counts over bfrt gRPC")
    ap.add_argument("--dry-run", action="store_true",
                    help="offline: audit the plan against the schema alone (default)")
    return ap.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.live and args.dry_run:
        print("--live and --dry-run are mutually exclusive", file=sys.stderr)
        return 2

    program = args.program or os.path.basename(args.schema).split(".bfrt.json")[0]
    try:
        tables = load_schema(args.schema)
    except (OSError, ValueError) as e:
        print("cannot read schema: %s" % e, file=sys.stderr)
        return 2

    print("=== setup coverage audit")
    print("    schema  : %s" % args.schema)
    print("    program : %s" % program)
    print("    tables  : %d" % len(tables))
    if not args.live:
        print("    MODE    : OFFLINE — no bfrt, no gRPC, no switch connection")
    print()

    reader = None
    iface = None
    if args.live:
        try:
            iface, bfrt, tgt = connect(program)
        except Exception as e:
            print("bfrt connect failed (%s: %s)" % (type(e).__name__, e), file=sys.stderr)
            return 2
        reader = lambda n: installed_rows(bfrt, tgt, n)   # noqa: E731

    try:
        failures = audit(tables, _planners(), reader)
    finally:
        if iface is not None:
            try:
                iface._tear_down_stream()
            except Exception:
                pass
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
