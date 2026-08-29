#!/usr/bin/env python3
"""Run the frozen dynamic-operating-point grid and print the reporting table.

Usage::

    python3 -m sim.dynamic.sweep --quick                     # smoke grid, seconds
    python3 -m sim.dynamic.sweep --scenarios persistent_partial,no_fault --seeds 30
    python3 -m sim.dynamic.sweep --witness-mode both         # both witness semantics, side by side
    python3 -m sim.dynamic.sweep --context-share 0.7,0.1,0.1,0.1   # the grid under a skewed split
    python3 -m sim.dynamic.sweep --json out/dynamic.json     # full records for reanalysis

The grid is the one frozen in `sim/dynamic/PREREG.md`; the flags narrow it, never widen it beyond
the frozen sets.  `tau_write` defaults to `tau_feedback` because both legs run over the same
controller path, and is overridable so the write latency can be isolated.

Two things are deliberately not optional.  The oracle floor (PREREG tripwire 1) is checked before
anything is printed, so a sweep whose upper-bound arm failed to find a fault it was handed aborts
instead of reporting; and the table always carries the realised-parameter columns, so a cell whose
faulty sublink did not actually lose more than its healthy peers is labelled rather than believed.

`--witness-mode both` runs every cell under BOTH compiled witness semantics (the shipped
unconditional resync and the advance-only variant of
`p4/witness/mcp_fabric_gate_event_advonly.p4`).  The mode is part of `CellKey`, so the two never
merge into one cell and every printed row names the silicon it describes -- a table where the
reader has to remember which half is which is how a fix gets credited with a number it did not
produce.

Seeds are derived with `sim.gate.replay.scenario_seed` (CRC-32).  Python's `hash` is salted per
process and would silently change the fault identity between two runs of the same command.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from typing import Dict, List, Sequence, Tuple

from sim.dynamic.fabric import WITNESS_MODES
from sim.dynamic.metrics import RunRecord, format_table, summarize
from sim.dynamic.runner import (
    ARMS,
    SCENARIOS,
    UNIFORM_QUARTER,
    CellKey,
    RunConfig,
    cell_key,
    check_oracle_floor,
    run,
)
from sim.dynamic.transport import TAU_SWEEP_US
from sim.gate.replay import scenario_seed

H_SWEEP: Tuple[float, ...] = (5.0, 6.5, 8.0, 10.0)
RESTORE_K_SWEEP: Tuple[int, ...] = (1, 3)
P_SWEEP: Tuple[float, ...] = (1e-2, 1e-3, 1e-4)
DEFAULT_SEEDS = 30
DEFAULT_EPOCHS = 60

#: A grid small enough to run in seconds that still contains one cell of each kind that matters:
#: a detectable fault, the false-positive control, and the two blackholes (the structural blind
#: spot), at the instantaneous bound and at the measured controller loop.
#:
#: ``reorder_only`` is deliberately NOT in the smoke grid, and the reason is a result rather than a
#: convenience: at a 1e-3 adjacent-swap rate the witness emits three events per swap, so one 2 s
#: run hands the controller ~2e5 events, and the frozen inference layer spends ~14 s of CPU on
#: them — roughly 7000x slower than the evidence arrives.  Run it explicitly with
#: ``--scenarios reorder_only`` and budget for that.
QUICK: Dict[str, object] = {
    "scenarios": ("persistent_partial", "no_fault", "selective_blackhole",
                  "all_context_blackhole"),
    "arms": ARMS,
    "taus": (0, 106600),
    "hs": (6.5,),
    "ks": (3,),
    "ps": (1e-3,),
    "seeds": 3,
    "epochs": 20,
}


def seed_values(count: int) -> Tuple[int, ...]:
    """`count` reproducible seeds; CRC-32 of a fixed stem, never Python's salted `hash`."""
    return tuple(scenario_seed("sim.dynamic.sweep/%d" % i, "seed") % (1 << 31)
                 for i in range(count))


def _csv(value: str, cast) -> Tuple:
    return tuple(cast(part.strip()) for part in value.split(",") if part.strip())


def witness_modes(choice: str) -> Tuple[str, ...]:
    """`--witness-mode` -> the modes to run.  ``both`` is the comparison, not a third semantics."""
    if choice == "both":
        return WITNESS_MODES
    if choice not in WITNESS_MODES:
        raise ValueError("unknown witness mode %r; choose from %s or 'both'"
                         % (choice, ", ".join(WITNESS_MODES)))
    return (choice,)


def build_configs(scenarios: Sequence[str], arms: Sequence[str], taus: Sequence[int],
                  hs: Sequence[float], ks: Sequence[int], ps: Sequence[float],
                  seeds: Sequence[int], epochs: int, tau_write: object = None,
                  onset_epoch: int = 10, audit_tokens: int = 8,
                  modes: Sequence[str] = ("baseline",),
                  context_share: Sequence[float] = UNIFORM_QUARTER) -> List[RunConfig]:
    """Expand the grid in a fixed order, so two invocations enumerate identically.

    ``context_share`` is ONE vector applied to every cell and every seed.  That is the right shape
    for "run the frozen grid under a skewed workload" and the WRONG shape for a collateral-vs-share
    curve: the faulty context is drawn per seed, so a fixed vector puts the swept share on the
    faulty context in only some of the runs.  `sim/dynamic/share_sweep.py` rebuilds the vector per
    seed for exactly that reason and is what any collateral ratio must come from.
    """
    configs: List[RunConfig] = []
    for scenario in scenarios:
        for arm in arms:
            for tau in taus:
                tw = tau if tau_write is None else int(tau_write)
                for h in hs:
                    for k in ks:
                        for p in ps:
                            for mode in modes:
                                for seed in seeds:
                                    configs.append(RunConfig(
                                        scenario=scenario, arm=arm, tau_feedback_us=tau,
                                        tau_write_us=tw, h=h, clean_epochs_to_restore=k,
                                        p_fault=p, epochs=epochs, seed=seed,
                                        audit_tokens=audit_tokens, onset_epoch=onset_epoch,
                                        witness_mode=mode,
                                        n_context=len(context_share),
                                        context_share=tuple(context_share)))
    return configs


def execute(configs: Sequence[RunConfig]) -> Dict[CellKey, List[RunRecord]]:
    """Run every config and group the records by cell, preserving enumeration order."""
    cells: Dict[CellKey, List[RunRecord]] = {}
    for cfg in configs:
        cells.setdefault(cell_key(cfg), []).append(run(cfg))
    return cells


def main(argv: Sequence[str] = ()) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenarios", default=",".join(SCENARIOS))
    parser.add_argument("--arms", default=",".join(ARMS))
    parser.add_argument("--taus", default=",".join(str(t) for t in TAU_SWEEP_US))
    parser.add_argument("--hs", default=",".join(str(h) for h in H_SWEEP))
    parser.add_argument("--restore-k", default=",".join(str(k) for k in RESTORE_K_SWEEP))
    parser.add_argument("--ps", default=",".join(repr(p) for p in P_SWEEP))
    parser.add_argument("--seeds", type=int, default=DEFAULT_SEEDS)
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--onset", type=int, default=10)
    parser.add_argument("--audit-tokens", type=int, default=8)
    parser.add_argument("--tau-write", default=None,
                        help="microseconds; default: the same as tau_feedback")
    parser.add_argument("--witness-mode", default="baseline",
                        choices=list(WITNESS_MODES) + ["both"],
                        help="which compiled witness to emulate; 'both' runs each cell under "
                             "each and prints the mode in every cell key")
    parser.add_argument("--context-share", default=",".join(str(s) for s in UNIFORM_QUARTER),
                        help="one share vector for the whole grid, summing to 1; the collateral "
                             "curve over share lives in sim.dynamic.share_sweep, which places the "
                             "share on each seed's own faulty context")
    parser.add_argument("--json", default=None, help="write cells and per-run records here")
    parser.add_argument("--quick", action="store_true", help="small smoke grid (seconds)")
    args = parser.parse_args(list(argv) if argv else None)

    if args.quick:
        scenarios = QUICK["scenarios"]
        arms = QUICK["arms"]
        taus = QUICK["taus"]
        hs, ks, ps = QUICK["hs"], QUICK["ks"], QUICK["ps"]
        seeds = seed_values(QUICK["seeds"])
        epochs = QUICK["epochs"]
    else:
        scenarios = _csv(args.scenarios, str)
        arms = _csv(args.arms, str)
        taus = _csv(args.taus, int)
        hs = _csv(args.hs, float)
        ks = _csv(args.restore_k, int)
        ps = _csv(args.ps, float)
        seeds = seed_values(args.seeds)
        epochs = args.epochs

    modes = witness_modes(args.witness_mode)
    configs = build_configs(scenarios, arms, taus, hs, ks, ps, seeds, epochs,
                            tau_write=args.tau_write, onset_epoch=args.onset,
                            audit_tokens=args.audit_tokens, modes=modes,
                            context_share=_csv(args.context_share, float))
    started = time.time()
    cells = execute(configs)
    elapsed = time.time() - started

    # Tripwire before reporting: an oracle that missed means the numbers below describe the
    # harness rather than the mechanism (HURDLES H29/H32).
    check_oracle_floor(cells)

    summaries = {key: summarize(records, seed=scenario_seed(str(key), "bootstrap") % (1 << 31))
                 for key, records in cells.items()}
    print(format_table(summaries))
    print()
    rate = len(configs) / elapsed if elapsed > 0 else float("inf")
    print("%d runs in %d cells, %.1f s wall clock (%.1f runs/s)"
          % (len(configs), len(cells), elapsed, rate))
    # Deliberately NOT extrapolated to a single number for the full grid.  Cost per run varies by
    # three orders of magnitude across the grid because it is dominated by the number of events
    # the frozen inference layer has to score: a 60-epoch `reorder_only` run at p=1e-2 measures
    # ~450 s, while `persistent_partial` at the same p measures ~0.15 s (the quarantine silences
    # the sublink).  Multiplying this cell mix out would be a correct number carried outside the
    # regime where it holds, which is the failure mode recorded in docs/review/GATE2-VERDICT.md.
    full = (len(SCENARIOS) * len(ARMS) * len(TAU_SWEEP_US) * len(H_SWEEP)
            * len(RESTORE_K_SWEEP) * len(P_SWEEP) * DEFAULT_SEEDS)
    print("full frozen grid = %d runs at %d epochs. Cost is dominated by reorder_only at "
          "p=1e-2 (~450 s/run measured): ~200 h single-threaded, so shard it by seed."
          % (full, DEFAULT_EPOCHS))

    if args.json:
        payload = {
            "epochs": epochs,
            "seeds": list(seeds),
            "witness_modes": list(modes),
            "cells": [{"key": key._asdict(),
                       "summary": dataclasses.asdict(summaries[key]),
                       "runs": [dataclasses.asdict(r) for r in cells[key]]}
                      for key in cells],
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=1, sort_keys=True)
        print("wrote %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
