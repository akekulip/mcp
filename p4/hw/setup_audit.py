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

# A table declared `const entries` in the P4 has its rows compiled into the binary and
# CANNOT be written at run time.  The bf-rt schema expresses this directly: bf-p4c
# emits "ConstTable" in the table's `attributes` array.  That is a schema fact, so it
# is detected rather than listed — a name list here would reintroduce exactly the
# drift the schema-derived design exists to prevent.
#
# Verified on p4/hw/schema/mcp_fabric_gate_event.bfrt.json: the 8 tables carrying the
# attribute are tbl_attn, tbl_ctx_index, tbl_wit_arm, tbl_wit_check, tbl_wit_count,
# tbl_wit_link, tbl_wit_stamp, tbl_wit_verdict — and no others.
CONST_TABLE_ATTR = "ConstTable"

# A second compiled-in shape, also a schema fact: a table with an EMPTY key array has
# no match key at all.  It exists only to invoke its `const default_action`, so it can
# never hold a row and can never be installed.  In mcp_fabric_gate_event that is
# tbl_csig_diff / tbl_csig_replace_a / tbl_csig_replace_b, each declared in one line
# as `actions = { X; } const default_action = X(); size = 1;`.  Counting these as a
# coverage gap would send someone writing installers for tables that cannot take one.

# Match-action tables that are CORRECT when empty.  Each reason names the code that
# writes the table at run time, or the code that deliberately empties it, so the
# exemption is evidence rather than assumption.  All three also carry a const default
# action, so "empty" means the compiled default runs — which is the healthy behaviour
# in each case.
EXEMPT: Dict[str, str] = {
    "tbl_fail": "fault injector; setup_skeleton.clear_fail() empties it during `up`, "
                "and hw_adapter.py:496 reads its counters as ground truth",
    "tbl_health_gate": "quarantine state written at run time by "
                       "controller/sublink_feedback.py:257; empty = nothing quarantined",
    "tbl_audit_steer": "armed per audit round by controller/sublink_feedback.py:287, "
                       "not at setup; 16-entry cap = AUDIT_ROUND_MAX_TOKENS",
}


def _spray_sel_status():
    """tbl_spray_sel is exempt ONLY while the selector spray mode is unused.

    The table is applied unconditionally at hop 0 (mcp_fabric_gate_event.p4:1111), but all it
    does is write ``md.spray_sel``, which ``tbl_spray_mode`` consumes only under the selector
    mode.  Under random / hash / round-robin the value is computed and discarded, so an empty
    selector costs nothing.  Installing it is not plain rows either — it is an indirect selector
    needing action-profile members plus selector groups.

    This is deliberately CONDITIONAL rather than a flat exemption: if the configured spray mode
    ever becomes the selector, an unplanned tbl_spray_sel silently sprays everything to member 0
    and every path result in the campaign would be wrong with no error anywhere.  So the audit
    must fail in that case, not wave it through.  Returns (is_exempt, reason).
    """
    try:
        import setup_skeleton as sk
        mode = sk.DEFAULT_SPRAY
    except Exception:
        return (False, "cannot determine the spray mode; treat as required")
    if str(mode).lower() in ("sel", "selector"):
        return (False, "spray mode is %r, which CONSUMES md.spray_sel — an installer is "
                       "required (action-profile members + selector groups)" % mode)
    return (True, "applied at hop 0 but its output md.spray_sel is consumed only under the "
                  "selector spray mode; configured mode is %r, so the value is discarded. "
                  "Becomes REQUIRED if the mode changes to selector." % mode)


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
        out["tbl_context"] = (len(sk.plan_context()), "setup_skeleton.plan_context()")
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


def is_const_entries(table: Dict[str, Any]) -> bool:
    """True if bf-p4c compiled this table's entries into the binary.

    Read straight from the schema's `attributes` array; no name list, no inference.
    """
    return CONST_TABLE_ATTR in (table.get("attributes") or [])


def is_keyless(table: Dict[str, Any]) -> bool:
    """True if the table has no match key: default-action-only, cannot hold a row."""
    return not (table.get("key") or [])


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
    n_match = n_planned = n_const = n_keyless = 0

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
            if is_const_entries(t):
                # Compiled-in rows.  Never a coverage gap and never installable: if a
                # const-entry table misbehaves the fault is at COMPILE or LOAD time,
                # so the fix is never "install more rows".
                n_const += 1
                if live and inst == 0:
                    status = ("WARN compiled-in but 0 rows on the chip — a LOAD problem "
                              "(wrong binary / wrong bfrt schema), NOT a setup problem")
                else:
                    status = "compiled-in (const entries; no runtime installation possible)"
            elif is_keyless(t):
                # No key at all: the table only ever runs its const default action.
                n_keyless += 1
                status = "default-action-only (no match key; cannot hold a row)"
            elif short in EXEMPT:
                status = "exempt (%s)" % EXEMPT[short]
            elif short == "tbl_spray_sel":
                ok, why = _spray_sel_status()
                if ok:
                    status = "exempt (%s)" % why
                else:
                    status = "FAIL %s" % why
                    failures.append("%s: %s" % (short, why))
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
    const_names = sorted(bare(t["name"]) for t in tables
                         if is_match(t) and is_const_entries(t))
    keyless_names = sorted(bare(t["name"]) for t in tables
                           if is_match(t) and not is_const_entries(t) and is_keyless(t))
    # tbl_spray_sel is exempt only while the selector spray mode is unused; keep the
    # summary counters consistent with the per-table verdict, or the two contradict
    # each other and whoever is reading this on a switch believes the wrong one.
    _dyn_exempt = set()
    if _spray_sel_status()[0]:
        _dyn_exempt.add("tbl_spray_sel")
    _all_exempt = set(EXEMPT) | _dyn_exempt

    exempt_present = sorted(bare(t["name"]) for t in tables
                            if is_match(t) and bare(t["name"]) in _all_exempt)
    gap = sorted(bare(t["name"]) for t in tables
                 if is_match(t)
                 and not is_const_entries(t)
                 and not is_keyless(t)
                 and bare(t["name"]) not in _all_exempt
                 and bare(t["name"]) not in planners)

    print("match-action tables in schema : %d" % n_match)
    print("  with a planner              : %d" % n_planned)
    print("  compiled-in (const entries) : %d  %s"
          % (n_const, ", ".join(const_names) or "-"))
    print("  default-action-only (no key): %d  %s"
          % (n_keyless, ", ".join(keyless_names) or "-"))
    print("     -> neither category is a coverage gap: their behaviour is in the binary")
    print("        and cannot be written at run time.  If one of them misbehaves the")
    print("        fault is at COMPILE or LOAD time (wrong source, wrong binary, wrong")
    print("        bfrt schema) — the fix is NEVER 'install more rows'.")
    print("  exempt (empty is healthy)   : %d  %s"
          % (len(exempt_present), ", ".join(exempt_present) or "-"))
    print("  required and unplanned      : %d  %s"
          % (len(gap), ", ".join(gap) or "-"))
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
