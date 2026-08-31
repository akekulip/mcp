#!/usr/bin/env python3
"""Preregistered survival sweep for the sealed-epoch evidence ledger."""

import argparse
import csv
from dataclasses import dataclass
import random
import statistics
import sys
from typing import Iterable, Optional, Sequence

from controller.evidence_ledger import EpochRecord, SequentialEvidenceLedger, Verdict
from sim.clf.verdict import Verdict as FixedVerdict
from sim.clf.verdict import verdict_counts


DEFAULT_SURVIVAL = (0.0, 0.01, 0.05, 0.10, 0.125, 0.15, 0.25,
                    0.50, 0.75, 0.90, 0.95, 0.97, 0.99, 1.0)
DEFAULT_ALTERNATIVES = (0.01, 0.10, 0.50, 0.75, 0.90, 0.97)


@dataclass(frozen=True)
class CampaignSummary:
    survival: float
    runs: int
    presence_rate: float
    presence_median_epoch: Optional[float]
    fixed_starved_rate: float
    fixed_starved_median_epoch: Optional[float]
    ledger_action_rate: float
    ledger_median_epoch: Optional[float]
    statistical_alarm_rate: float
    statistical_median_epoch: Optional[float]


def _binomial(rng, packets, survival):
    return sum(rng.random() < survival for _ in range(packets))


def _rate_epochs(epochs, runs):
    observed = [epoch for epoch in epochs if epoch is not None]
    return len(observed) / float(runs), (statistics.median(observed) if observed else None)


def run_campaign(survival, runs=2000, packets_per_epoch=32, horizon=50,
                 seed=20260830, alpha=0.05, healthy_delivery=0.99,
                 alternatives: Sequence[float] = DEFAULT_ALTERNATIVES):
    rng = random.Random(seed)
    presence_epochs = []
    starved_epochs = []
    ledger_epochs = []
    statistical_epochs = []
    for _run in range(runs):
        ledger = SequentialEvidenceLedger(
            alpha=alpha,
            healthy_delivery=healthy_delivery,
            alternatives=alternatives,
            saturation=255,
        )
        presence_epoch = starved_epoch = ledger_epoch = statistical_epoch = None
        for epoch in range(horizon):
            rx = _binomial(rng, packets_per_epoch, survival)
            if presence_epoch is None and rx == 0:
                presence_epoch = epoch + 1
            if (starved_epoch is None and
                    verdict_counts(packets_per_epoch, rx) in
                    (FixedVerdict.BLACKHOLE, FixedVerdict.STARVED)):
                starved_epoch = epoch + 1
            result = ledger.ingest(EpochRecord(
                sublink=2,
                epoch=epoch,
                tx=packets_per_epoch,
                rx=rx,
                repair_generation=0,
            ))
            if (ledger_epoch is None and
                    result.verdict in (Verdict.BLACKHOLE, Verdict.GRAYHOLE)):
                ledger_epoch = epoch + 1
            if statistical_epoch is None and result.statistical_alarm:
                statistical_epoch = epoch + 1
        presence_epochs.append(presence_epoch)
        starved_epochs.append(starved_epoch)
        ledger_epochs.append(ledger_epoch)
        statistical_epochs.append(statistical_epoch)

    presence_rate, presence_median = _rate_epochs(presence_epochs, runs)
    starved_rate, starved_median = _rate_epochs(starved_epochs, runs)
    ledger_rate, ledger_median = _rate_epochs(ledger_epochs, runs)
    statistical_rate, statistical_median = _rate_epochs(statistical_epochs, runs)
    return CampaignSummary(
        survival=survival,
        runs=runs,
        presence_rate=presence_rate,
        presence_median_epoch=presence_median,
        fixed_starved_rate=starved_rate,
        fixed_starved_median_epoch=starved_median,
        ledger_action_rate=ledger_rate,
        ledger_median_epoch=ledger_median,
        statistical_alarm_rate=statistical_rate,
        statistical_median_epoch=statistical_median,
    )


def evaluate(survival_points: Iterable[float] = DEFAULT_SURVIVAL, **kwargs):
    return [run_campaign(survival, seed=kwargs.get("seed", 20260830) + index,
                         **{key: value for key, value in kwargs.items() if key != "seed"})
            for index, survival in enumerate(survival_points)]


def write_csv(rows, stream):
    fields = tuple(CampaignSummary.__dataclass_fields__)
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({field: getattr(row, field) for field in fields})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=2000)
    parser.add_argument("--packets-per-epoch", type=int, default=32)
    parser.add_argument("--horizon", type=int, default=50)
    parser.add_argument("--seed", type=int, default=20260830)
    args = parser.parse_args()
    if args.runs <= 0 or args.horizon <= 0 or not 0 < args.packets_per_epoch < 255:
        parser.error("runs/horizon must be positive and packets-per-epoch must lie in 1..254")
    write_csv(evaluate(runs=args.runs, packets_per_epoch=args.packets_per_epoch,
                       horizon=args.horizon, seed=args.seed), sys.stdout)


if __name__ == "__main__":
    main()
