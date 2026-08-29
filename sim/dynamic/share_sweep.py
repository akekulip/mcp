#!/usr/bin/env python3
"""Collateral reduction as a CURVE over the faulty context's share, with its arithmetic baseline.

This module exists because of HURDLES H37, and it is a deliberately unflattering instrument.

The P3 headline was "C-W4 diverts 7x less healthy traffic than directed-link quarantine at
identical unsafe exposure". A reviewer decomposes that in ninety seconds. Quarantine one context of
four under a uniform share vector and you divert a quarter of the link's traffic instead of all of
it, so **1/0.25 = 4.00x of the 7x follows from the share vector alone** and says nothing about the
mechanism. What was left over -- a factor of 1.75 -- came from `directed_w4` recording 87
false-quarantine epochs against `cw4_feedback`'s 0, which is itself close to definitional: sweeping
every context on the vlink necessarily quarantines the three healthy ones.

Two consequences, both implemented here rather than argued:

* **A bare multiplier is not reportable.** The output is a curve over the faulty context's share
  ``s``, with the arithmetic baseline ``1/s`` printed on the same axes and the residual
  ``measured / arithmetic`` printed beside it. If the residual is ~1 everywhere, the honest reading
  is "the advantage is the workload split", and that is the result: the table is built so that
  conclusion is as easy to reach as the flattering one.
* **A number that only survives a favourable split is not a result.** The sweep carries an
  ADVERSARIAL point in which the faulty context carries most of the link (``ADVERSARIAL_SHARE``),
  chosen against the mechanism, and prints it in the same table as the favourable ones rather than
  in a footnote.

Definitions, stated because the ratio is meaningless without them:

* ``collateral`` is `RunRecord.collateral_packets`: HEALTHY packets not offered because a gate key
  was installed, summed over healthy sublinks and epochs. `cw4_feedback`'s collateral is not zero
  even though it quarantines only the faulty context -- the P2 gate is path-keyed while C-W4
  evidence is link-keyed, so one installed key partially gates the same context on other vlinks.
* ``measured reduction`` = directed collateral / selective collateral, the headline ratio.
* ``arithmetic baseline`` = ``1/s``: the reduction you get purely from removing a share ``s`` of a
  link's traffic instead of all of it, with no mechanism in it at all.
* ``residual`` = measured / arithmetic. This is the only column that is about C-W4.

Nothing here re-implements a decision: every point is real `sim.dynamic.runner` runs through the
real `controller.sublink_feedback.SublinkFeedback`, differing only in `RunConfig.context_share`.

Usage::

    python3 -m sim.dynamic.share_sweep                       # the frozen curve, seconds
    python3 -m sim.dynamic.share_sweep --seeds 10 --epochs 40
    python3 -m sim.dynamic.share_sweep --json out/share.json
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from sim.dynamic.runner import RunConfig, fault_site, run
from sim.dynamic.sweep import seed_values

#: The faulty context's share of its link's traffic, swept. 0.25 is the frozen uniform quarter
#: every earlier number was measured under; it is one point on this curve, not the axis.
SHARE_SWEEP: Tuple[float, ...] = (0.05, 0.10, 0.25, 0.50, 0.75)

#: The share chosen AGAINST the mechanism: the faulty context carries most of the link, so
#: quarantining it selectively saves almost nothing that quarantining the whole link would not.
ADVERSARIAL_SHARE = 0.85

#: The two arms the ratio is between. Both see identical evidence and identical transport; they
#: differ only in how much of the link a decision removes.
SELECTIVE_ARM = "cw4_feedback"
DIRECTED_ARM = "directed_w4"

DEFAULT_SEEDS = 5
DEFAULT_EPOCHS = 40
DEFAULT_SCENARIO = "persistent_partial"

NAN = float("nan")


def share_vector(faulty_share: float, faulty_context: int, n_context: int = 4) -> Tuple[float, ...]:
    """Share vector putting ``faulty_share`` on ``faulty_context`` and splitting the rest evenly.

    The remainder is spread uniformly rather than shaped, so that the only thing moving along the
    curve is the quantity on its x axis.
    """
    if n_context < 2:
        raise ValueError("a share split needs at least two contexts, got %r" % (n_context,))
    if not 0.0 < faulty_share <= 1.0:
        raise ValueError("faulty_share must be in (0, 1], got %r" % (faulty_share,))
    if not 0 <= faulty_context < n_context:
        raise ValueError("faulty_context %r is outside %d contexts"
                         % (faulty_context, n_context))
    rest = (1.0 - faulty_share) / (n_context - 1)
    return tuple(faulty_share if c == faulty_context else rest for c in range(n_context))


@dataclass(frozen=True)
class SharePoint:
    """One point of the curve: both arms at one share, plus the baseline it must be read against.

    ``equal_exposure`` is not decoration. The headline claims the collateral advantage comes at
    IDENTICAL unsafe exposure; if the two arms stop the bleeding at different times the ratio is
    buying safety with collateral and the comparison is not the one being claimed.
    """

    label: str
    faulty_share: float
    runs: int
    selective_collateral: int
    directed_collateral: int
    selective_false_quarantine_epochs: int
    directed_false_quarantine_epochs: int
    selective_unsafe_packets: int
    directed_unsafe_packets: int
    selective_quarantined_runs: int
    directed_quarantined_runs: int
    reduction: float
    arithmetic: float
    residual: float
    equal_exposure: bool


def measure_point(faulty_share: float, seeds: Sequence[int], label: str = "",
                  scenario: str = DEFAULT_SCENARIO, p_fault: float = 1e-3, h: float = 6.5,
                  clean_epochs_to_restore: int = 3, epochs: int = DEFAULT_EPOCHS,
                  tau_feedback_us: int = 0, tau_write_us: int = 0, onset_epoch: int = 10,
                  n_context: int = 4) -> SharePoint:
    """Run both arms at one share and return the point, pooled over ``seeds``.

    The faulty context is drawn per seed by :func:`sim.dynamic.runner.fault_site`, so the share
    vector is rebuilt per seed to keep ``faulty_share`` on the context that actually fails.
    """
    totals: Dict[str, Dict[str, int]] = {
        arm: {"collateral": 0, "false_q": 0, "unsafe": 0, "quarantined": 0}
        for arm in (SELECTIVE_ARM, DIRECTED_ARM)}
    for seed in seeds:
        _vlink, context = fault_site(scenario, seed, n_context)
        shares = share_vector(faulty_share, context, n_context)
        for arm in (SELECTIVE_ARM, DIRECTED_ARM):
            record = run(RunConfig(
                scenario=scenario, arm=arm, tau_feedback_us=tau_feedback_us,
                tau_write_us=tau_write_us, h=h,
                clean_epochs_to_restore=clean_epochs_to_restore, p_fault=p_fault, epochs=epochs,
                seed=seed, onset_epoch=onset_epoch, n_context=n_context, context_share=shares))
            bucket = totals[arm]
            bucket["collateral"] += record.collateral_packets
            bucket["false_q"] += record.false_quarantine_epochs
            bucket["unsafe"] += record.unsafe_packets
            bucket["quarantined"] += int(record.quarantined_faulty)

    selective, directed = totals[SELECTIVE_ARM], totals[DIRECTED_ARM]
    # A zero denominator is a real outcome (the selective arm diverted nothing at all), so it is
    # reported as an infinite reduction rather than crashing the sweep.
    if selective["collateral"] > 0:
        reduction = directed["collateral"] / selective["collateral"]
    elif directed["collateral"] > 0:
        reduction = float("inf")
    else:
        reduction = NAN
    arithmetic = 1.0 / faulty_share
    return SharePoint(
        label=label or ("s=%.2f" % faulty_share),
        faulty_share=faulty_share,
        runs=len(seeds),
        selective_collateral=selective["collateral"],
        directed_collateral=directed["collateral"],
        selective_false_quarantine_epochs=selective["false_q"],
        directed_false_quarantine_epochs=directed["false_q"],
        selective_unsafe_packets=selective["unsafe"],
        directed_unsafe_packets=directed["unsafe"],
        selective_quarantined_runs=selective["quarantined"],
        directed_quarantined_runs=directed["quarantined"],
        reduction=reduction,
        arithmetic=arithmetic,
        residual=reduction / arithmetic,
        equal_exposure=selective["unsafe"] == directed["unsafe"],
    )


def collateral_curve(seeds: Sequence[int], shares: Sequence[float] = SHARE_SWEEP,
                     adversarial: float = ADVERSARIAL_SHARE, **kwargs) -> List[SharePoint]:
    """The frozen curve plus the adversarial point, in increasing share order.

    The adversarial point is appended to the SAME list rather than returned separately: a caller
    that prints the curve prints the case chosen against us too, without having to remember to.
    """
    points = [measure_point(s, seeds, **kwargs) for s in shares]
    if adversarial is not None:
        points.append(measure_point(adversarial, seeds,
                                    label="ADVERSARIAL s=%.2f" % adversarial, **kwargs))
    return points


_COLUMNS = (
    "case", "faulty share s", "runs",
    "selective collateral", "directed collateral",
    "measured reduction", "arithmetic 1/s", "residual (measured/arithmetic)",
    "false-q epochs sel/dir", "unsafe pkts sel/dir", "equal exposure?",
    "quarantined runs sel/dir",
)


def _fmt_x(value: float) -> str:
    if value != value:                                     # nan
        return "n/a"
    if value == float("inf"):
        return "inf"
    return "%.2fx" % value


def format_share_table(points: Sequence[SharePoint]) -> str:
    """Render the curve, with the arithmetic baseline in the column beside the measured ratio.

    The two are adjacent on purpose, for the same reason the safety and usefulness columns are
    adjacent in `metrics.format_table`: the decomposition has to be unavoidable for anyone reading
    the row, not something a careful reader can reconstruct.
    """
    rows = ["| " + " | ".join(_COLUMNS) + " |",
            "|" + "|".join(["---"] * len(_COLUMNS)) + "|"]
    for p in points:
        rows.append("| " + " | ".join((
            p.label,
            "%.2f" % p.faulty_share,
            str(p.runs),
            str(p.selective_collateral),
            str(p.directed_collateral),
            _fmt_x(p.reduction),
            _fmt_x(p.arithmetic),
            _fmt_x(p.residual),
            "%d/%d" % (p.selective_false_quarantine_epochs,
                       p.directed_false_quarantine_epochs),
            "%d/%d" % (p.selective_unsafe_packets, p.directed_unsafe_packets),
            "yes" if p.equal_exposure else "NO",
            "%d/%d" % (p.selective_quarantined_runs, p.directed_quarantined_runs),
        )) + " |")
    return "\n".join(rows)


def main(argv: Sequence[str] = ()) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scenario", default=DEFAULT_SCENARIO)
    parser.add_argument("--seeds", type=int, default=DEFAULT_SEEDS)
    parser.add_argument("--epochs", type=int, default=DEFAULT_EPOCHS)
    parser.add_argument("--onset", type=int, default=10)
    parser.add_argument("--p", type=float, default=1e-3)
    parser.add_argument("--h", type=float, default=6.5)
    parser.add_argument("--restore-k", type=int, default=3)
    parser.add_argument("--tau", type=int, default=0, help="tau_feedback and tau_write, us")
    parser.add_argument("--shares", default=",".join(str(s) for s in SHARE_SWEEP))
    parser.add_argument("--adversarial", type=float, default=ADVERSARIAL_SHARE)
    parser.add_argument("--json", default=None)
    args = parser.parse_args(list(argv) if argv else None)

    shares = tuple(float(part) for part in args.shares.split(",") if part.strip())
    seeds = seed_values(args.seeds)
    points = collateral_curve(seeds, shares=shares, adversarial=args.adversarial,
                              scenario=args.scenario, p_fault=args.p, h=args.h,
                              clean_epochs_to_restore=args.restore_k, epochs=args.epochs,
                              tau_feedback_us=args.tau, tau_write_us=args.tau,
                              onset_epoch=args.onset)
    print(format_share_table(points))
    print()
    print("scenario=%s p=%g h=%.1f k=%d tau=%d epochs=%d seeds=%d"
          % (args.scenario, args.p, args.h, args.restore_k, args.tau, args.epochs, args.seeds))
    print("measured reduction = directed collateral / selective collateral; arithmetic = 1/s is "
          "what quarantining a share s instead of the whole link gives with no mechanism in it; "
          "residual = measured / arithmetic is the only column that is about C-W4.")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"seeds": list(seeds),
                       "points": [dataclasses.asdict(p) for p in points]},
                      fh, indent=1, sort_keys=True)
        print("wrote %s" % args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
