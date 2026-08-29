#!/usr/bin/env python3
"""Aggregation and reporting for the dynamic behavioural-sublink experiment.

This module exists to make one class of mistake impossible to publish. Four times on 2026-08-28 a
dramatic number turned out to be an artifact of the harness, and the sharpest of them was a
"0 % unsafe restorations" scored by an arm that never certified anything: perfectly safe because
perfectly useless (repo CLAUDE.md, "Cross-check before concluding", item 4). So the reporting layer
here is not free-form. Two invariants are wired into ``format_table`` rather than left to the
person writing the paragraph:

1. **Safety and usefulness share a row.** The false-quarantine rate is printed immediately beside
   the quarantine rate, and a cell that never quarantined anything is labelled ``INERT`` in its own
   column. A rule that never fires is reported as inert, never as safe.
2. **Realised parameters are printed, not assumed.** Every row carries the packets actually
   offered, the faulty sublink's MEASURED loss rate, the healthy mean, and their ratio. A ratio at
   or below 1 means the fault never reached the data the arm saw, so the cell is labelled
   ``NO-FAULT-INJECTED`` and its other numbers are about the harness, not about the mechanism
   (HURDLES H29/H32).

Uncertainty is reported everywhere it exists, and **the estimator is chosen per metric by what the
independent unit actually is**. That choice is a third invariant, added after the first two because
getting it wrong understates every safety interval in the paper:

* ``wilson()`` assumes independent Bernoulli trials. That holds when the trial is a whole RUN --
  "did this run quarantine the fault", "did this run restore it" -- because runs are drawn on
  independent seeds. It is used for exactly those.
* ``cluster_bootstrap_rate_ci()`` resamples whole RUNS with replacement. It is used for every rate
  pooled over observations *inside* a run, of which the false-quarantine rate is the one that
  matters: quarantine state is autocorrelated **by construction**, because one decision holds a
  sublink out for many consecutive epochs. Treating those sublink-epochs as independent Bernoulli
  trials inflates the effective sample size by roughly the length of a quarantine and returns an
  interval far narrower than the data supports. Both are printed for the false-quarantine rate so
  the size of that error is visible rather than asserted.

Latencies are percentile-bootstrap intervals around the median (the latency distributions here are
skewed and small-sample, so a mean +- s.e. would be a fiction). All three are deterministic given a
seed; stdlib only, no numpy or scipy in this repository.
"""

import math
import random
import statistics
from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Sequence, Tuple

NAN = float("nan")


def wilson(successes: int, trials: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score interval for a binomial proportion (default z = 1.96, i.e. 95%).

    Chosen over the normal approximation because most cells here sit at or near 0/n and n/n, where
    the normal interval has zero width and is simply wrong. The interval is exact at the edges by
    construction: ``wilson(0, n)`` has a lower bound of exactly 0.0, ``wilson(n, n)`` an upper bound
    of exactly 1.0, and ``wilson(x, 0)`` is the vacuous ``(0.0, 1.0)`` rather than a division by
    zero -- a cell with no trials is unknown, not zero.
    """
    if trials < 0:
        raise ValueError("trials must be non-negative, got %r" % (trials,))
    if not 0 <= successes <= max(trials, 0):
        raise ValueError("successes must be in [0, trials], got %r of %r" % (successes, trials))
    if trials == 0:
        return (0.0, 1.0)

    phat = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (phat + z * z / (2.0 * trials)) / denominator
    half = (z / denominator) * math.sqrt(phat * (1.0 - phat) / trials
                                         + z * z / (4.0 * trials * trials))
    low = 0.0 if successes == 0 else max(0.0, centre - half)
    high = 1.0 if successes == trials else min(1.0, centre + half)
    return (low, high)


def _percentile(sorted_values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile of an already-sorted sequence; ``q`` in [0, 1]."""
    if not sorted_values:
        return NAN
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    position = q * (len(sorted_values) - 1)
    lower = int(math.floor(position))
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = position - lower
    return float(sorted_values[lower]) * (1.0 - weight) + float(sorted_values[upper]) * weight


def bootstrap_median_ci(values: Sequence[float], seed: int, iters: int = 2000,
                        alpha: float = 0.05) -> Tuple[float, float]:
    """Percentile bootstrap interval for the median, deterministic given ``seed``.

    Empty input returns ``(nan, nan)`` rather than raising: a cell where the mechanism never fired
    has no latency to report, and that has to survive into the table as "no observations" instead
    of killing the run that would have exposed it.
    """
    if iters <= 0:
        raise ValueError("iters must be positive, got %r" % (iters,))
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1), got %r" % (alpha,))
    if not values:
        return (NAN, NAN)

    rng = random.Random(seed)
    sample = [float(v) for v in values]
    size = len(sample)
    medians: List[float] = []
    for _ in range(iters):
        medians.append(statistics.median(sample[rng.randrange(size)] for _ in range(size)))
    medians.sort()
    return (_percentile(medians, alpha / 2.0), _percentile(medians, 1.0 - alpha / 2.0))


def cluster_bootstrap_rate_ci(clusters: Sequence[Tuple[int, int]], seed: int,
                              iters: int = 2000, alpha: float = 0.05) -> Tuple[float, float]:
    """Percentile interval for a pooled rate whose observations cluster inside runs.

    ``clusters`` is one ``(successes, trials)`` pair per INDEPENDENT unit -- here, per run. Whole
    runs are resampled with replacement and the rate recomputed as ``sum(successes)/sum(trials)``,
    so the interval inherits the between-run variance instead of assuming the within-run
    observations were independent draws.

    This exists because the metrics it serves are autocorrelated by construction. A quarantine
    decision holds a sublink out of service for many consecutive epochs, so 60 sublink-epochs from
    one run carry nowhere near 60 epochs' worth of information about the false-quarantine rate;
    ``wilson()`` on the pooled counts would treat them as if they did. The bootstrap makes no such
    assumption, and on all-or-nothing runs it is several times wider -- which is the point.

    Two properties of the percentile bootstrap are handled explicitly rather than left to bite:

    * **At the 0/n and n/n boundaries it cannot move.** Every resample of all-zero clusters is
      all-zero, so the raw interval would be the point ``[0, 0]`` -- a cell that never
      false-quarantined would be reported as known to be exactly zero. Those two cases fall back to
      a Wilson interval over the CLUSTERS: with equal-sized runs, the fraction of runs carrying any
      success upper-bounds the pooled rate, so ``wilson(0, n_runs)`` is a conservative bound at the
      right unit of independence. It is much wider than the same Wilson computed on the pooled
      epochs, which is the whole point.
    * **Identical clusters give a point interval, and that is a real statement.** If every run
      returns the same rate, the between-run variance observed is zero and the bootstrap reports
      it as such. A zero-width interval therefore means "n runs, no observed between-run
      variation", not "no uncertainty"; the naive Wilson column printed beside it in
      ``format_table`` keeps that visible.

    Deterministic given ``seed``. Degenerate inputs are vacuous rather than fatal, matching
    ``wilson``: no clusters, or no trials at all, is "unknown", not zero.
    """
    if iters <= 0:
        raise ValueError("iters must be positive, got %r" % (iters,))
    if not 0.0 < alpha < 1.0:
        raise ValueError("alpha must be in (0, 1), got %r" % (alpha,))
    pairs = [(int(successes), int(trials)) for successes, trials in clusters]
    for successes, trials in pairs:
        if trials < 0:
            raise ValueError("trials must be non-negative, got %r" % (trials,))
        if not 0 <= successes <= max(trials, 0):
            raise ValueError("successes must be in [0, trials], got %r of %r"
                             % (successes, trials))
    if not pairs or sum(trials for _, trials in pairs) == 0:
        return (0.0, 1.0)

    rng = random.Random(seed)
    size = len(pairs)
    rates: List[float] = []
    for _ in range(iters):
        resample = rng.choices(pairs, k=size)
        total_trials = sum(trials for _, trials in resample)
        if total_trials == 0:
            # Every cluster drawn happened to have no trials; that resample carries no rate at
            # all. Dropping it is the only honest option -- substituting 0.0 would invent
            # observations the resample does not contain.
            continue
        rates.append(sum(successes for successes, _ in resample) / total_trials)
    if not rates:
        return (0.0, 1.0)

    # Boundary correction, for the same reason ``wilson`` exists at all. When EVERY cluster sits at
    # 0 successes (or at all successes), every resample reproduces that rate and the percentile
    # interval collapses to a point -- it would report a cell that never false-quarantined as known
    # to be exactly zero, which is the "perfectly safe because perfectly useless" failure this
    # module was written to prevent (repo CLAUDE.md, cross-check item 4). At those two boundaries
    # the interval is taken at the level of the independent unit instead: n RUNS, none of which (or
    # all of which) carried a success. That is far wider than the same Wilson interval computed on
    # the pooled epochs, which is the correct direction -- there are n runs of information here,
    # not sum(trials).
    if all(successes == 0 for successes, _ in pairs):
        return (0.0, wilson(0, len(pairs))[1])
    if all(successes == trials for successes, trials in pairs):
        return (wilson(len(pairs), len(pairs))[0], 1.0)

    rates.sort()
    return (_percentile(rates, alpha / 2.0), _percentile(rates, 1.0 - alpha / 2.0))


@dataclass
class RunRecord:
    """One run: a single (scenario, arm, tau, h, restore_k, p, seed) point.

    Counters are per run; ``*_epochs`` are epoch counts, ``*_packets`` are packet counts, and the
    ``offered_*``/``lost_*`` pairs are the realised-parameter dump the tripwire in PREREG.md
    requires -- they are what the fabric model actually did, not what the flags asked for.
    """

    quarantined_faulty: bool
    unsafe_packets: int
    detect_us: Optional[int]
    healthy_epochs: int
    false_quarantine_epochs: int
    collateral_packets: int
    restored: bool
    restore_us: Optional[int]
    unsafe_restorations: int
    flaps: int
    installs: int
    coalesced: int
    stale_dropped: int
    offered_faulty: int
    lost_faulty: int
    offered_healthy: int
    lost_healthy: int
    evidence_epochs: int
    epochs: int
    # Probation-round outcomes, defaulted so that a caller which does not run probation (and the
    # metrics tests, which predate them) constructs a record unchanged. They exist because
    # ``AuditRound.finish`` has four ways of not restoring and a restore-rate column cannot tell
    # them apart: STALE means the feedback path was slower than an epoch and the round was
    # discarded unread, which is a statement about the transport, while INCOMPLETE and LOSS are
    # statements about the link.
    audit_clean: int = 0
    audit_loss: int = 0
    audit_incomplete: int = 0
    audit_stale: int = 0


@dataclass(frozen=True)
class CellSummary:
    """Aggregate of the runs sharing one cell of the frozen sweep.

    Every field here is printed by ``format_table``; nothing is computed at print time, so the
    numbers in the table and the numbers a caller reads programmatically cannot diverge.
    """

    runs: int
    # usefulness and safety, deliberately adjacent
    quarantined_runs: int
    quarantine_rate: float
    #: WILSON. Unit of independence = the RUN: one Bernoulli trial per run, independent seeds.
    quarantine_ci: Tuple[float, float]
    healthy_epochs: int
    false_quarantine_epochs: int
    false_quarantine_rate: float
    #: CLUSTER BOOTSTRAP over runs. Unit of independence = the RUN, NOT the sublink-epoch: one
    #: decision holds a sublink out for many consecutive epochs, so the epochs inside a run are
    #: autocorrelated by construction and a binomial interval on the pooled counts is too narrow.
    #: This is the interval to quote.
    false_quarantine_ci: Tuple[float, float]
    inert: bool
    # exposure and timing
    unsafe_packets: int
    collateral_packets: int
    detect_us_median: float
    detect_us_ci: Tuple[float, float]
    # restoration
    restored_runs: int
    restore_rate: float
    #: WILSON. Unit of independence = the RUN: "of the runs that quarantined, how many restored".
    restore_ci: Tuple[float, float]
    restore_us_median: float
    restore_us_ci: Tuple[float, float]
    unsafe_restorations: int
    flaps: int
    # probation-round outcomes; ``audit_stale`` is the transport verdict, not a link verdict
    audit_clean: int
    audit_loss: int
    audit_incomplete: int
    audit_stale: int
    # SublinkFeedback.summary() verbatim
    installs: int
    coalesced: int
    stale_dropped: int
    # realised parameters (harness tripwire 2)
    offered_packets: int
    faulty_loss_rate: float
    healthy_loss_rate: float
    loss_ratio: float
    fault_injected: bool
    evidence_epoch_fraction: float
    #: The SAME false-quarantine rate under Wilson, i.e. pretending the sublink-epochs inside a run
    #: were independent. Kept and printed only so the size of that error is visible in the table
    #: instead of being a claim in a paragraph; it is not the interval to quote. Defaulted because
    #: it was added after the field list was in use, and a caller that has not been updated must
    #: get the vacuous "unknown" rather than a fabricated interval.
    false_quarantine_ci_wilson: Tuple[float, float] = (0.0, 1.0)


def _rate(successes: int, trials: int) -> float:
    return successes / trials if trials > 0 else NAN


def summarize(records: Sequence[RunRecord], seed: int) -> CellSummary:
    """Aggregate one cell. ``seed`` drives the bootstrap and nothing else."""
    if not records:
        raise ValueError("cannot summarize an empty cell; a cell with no runs is a harness bug")

    runs = len(records)
    quarantined_runs = sum(1 for r in records if r.quarantined_faulty)
    healthy_epochs = sum(r.healthy_epochs for r in records)
    false_quarantine_epochs = sum(r.false_quarantine_epochs for r in records)
    # Only a run that quarantined the faulty sublink can restore it, so that is the denominator:
    # "of the runs that acted, how many gave the sublink back". Counting restorations from runs
    # that never quarantined the faulty sublink would let a false quarantine inflate the rate.
    restored_runs = sum(1 for r in records if r.restored and r.quarantined_faulty)

    detect = [float(r.detect_us) for r in records if r.detect_us is not None]
    restore = [float(r.restore_us) for r in records if r.restore_us is not None]

    offered_faulty = sum(r.offered_faulty for r in records)
    lost_faulty = sum(r.lost_faulty for r in records)
    offered_healthy = sum(r.offered_healthy for r in records)
    lost_healthy = sum(r.lost_healthy for r in records)
    faulty_loss_rate = _rate(lost_faulty, offered_faulty)
    healthy_loss_rate = _rate(lost_healthy, offered_healthy)

    # The ratio is the headline, but the comparison is done on the rates so that the degenerate
    # cases stay honest: no healthy traffic, or a faulty rate of exactly zero, is NOT evidence that
    # a fault was injected, and a nan ratio must not sneak past a "<= 1" test.
    if healthy_loss_rate > 0.0:
        loss_ratio = faulty_loss_rate / healthy_loss_rate
    elif faulty_loss_rate > 0.0:
        loss_ratio = float("inf")
    else:
        loss_ratio = NAN
    fault_injected = (not math.isnan(faulty_loss_rate)
                      and (math.isnan(healthy_loss_rate) or faulty_loss_rate > healthy_loss_rate)
                      and faulty_loss_rate > 0.0)

    epochs = sum(r.epochs for r in records)
    detect_ci = bootstrap_median_ci(detect, seed)
    restore_ci = bootstrap_median_ci(restore, seed + 1)
    return CellSummary(
        runs=runs,
        quarantined_runs=quarantined_runs,
        quarantine_rate=_rate(quarantined_runs, runs),
        quarantine_ci=wilson(quarantined_runs, runs),
        healthy_epochs=healthy_epochs,
        false_quarantine_epochs=false_quarantine_epochs,
        false_quarantine_rate=_rate(false_quarantine_epochs, healthy_epochs),
        # The run is the cluster: `false_quarantine_epochs` inside one run are consecutive epochs
        # of the same held-out sublink, not independent trials (see the module docstring).
        false_quarantine_ci=cluster_bootstrap_rate_ci(
            [(r.false_quarantine_epochs, r.healthy_epochs) for r in records], seed + 2),
        false_quarantine_ci_wilson=wilson(false_quarantine_epochs, healthy_epochs),
        # "Never fired" means never quarantined ANYTHING -- not merely never quarantined the
        # faulty sublink. A cell that only ever false-quarantines did act, badly, and saying INERT
        # there would be as misleading as saying "safe" about a rule that never fires.
        inert=quarantined_runs == 0 and false_quarantine_epochs == 0,
        unsafe_packets=sum(r.unsafe_packets for r in records),
        collateral_packets=sum(r.collateral_packets for r in records),
        detect_us_median=statistics.median(detect) if detect else NAN,
        detect_us_ci=detect_ci,
        restored_runs=restored_runs,
        restore_rate=_rate(restored_runs, quarantined_runs),
        restore_ci=wilson(restored_runs, quarantined_runs),
        restore_us_median=statistics.median(restore) if restore else NAN,
        restore_us_ci=restore_ci,
        unsafe_restorations=sum(r.unsafe_restorations for r in records),
        flaps=sum(r.flaps for r in records),
        audit_clean=sum(r.audit_clean for r in records),
        audit_loss=sum(r.audit_loss for r in records),
        audit_incomplete=sum(r.audit_incomplete for r in records),
        audit_stale=sum(r.audit_stale for r in records),
        installs=sum(r.installs for r in records),
        coalesced=sum(r.coalesced for r in records),
        stale_dropped=sum(r.stale_dropped for r in records),
        offered_packets=offered_faulty + offered_healthy,
        faulty_loss_rate=faulty_loss_rate,
        healthy_loss_rate=healthy_loss_rate,
        loss_ratio=loss_ratio,
        fault_injected=fault_injected,
        evidence_epoch_fraction=_rate(sum(r.evidence_epochs for r in records), epochs),
    )


INERT_LABEL = "INERT"
NO_FAULT_LABEL = "NO-FAULT-INJECTED"

_COLUMNS = (
    "cell", "runs", "quarantine rate (95%)", "false-quarantine rate (95%)", "acts?",
    # The naive interval for the SAME rate, printed beside the honest one. It is not there to be
    # quoted; it is there so that "Wilson would have said this" cannot be left out of the
    # comparison when someone argues the intervals are too wide.
    "false-q naive Wilson (95%)",
    "unsafe pkts", "detect us (95%)", "collateral pkts",
    "restore rate (95%)", "restore us (95%)", "unsafe restores", "flaps",
    "audit c/l/i/s",
    "installs", "coalesced", "stale",
    "offered pkts", "faulty loss", "healthy loss", "ratio", "fault check",
    "evidence epochs",
)


def _fmt_rate(rate: float, ci: Tuple[float, float]) -> str:
    if math.isnan(rate):
        return "n/a"
    return "%.4f [%.4f, %.4f]" % (rate, ci[0], ci[1])


def _fmt_us(median: float, ci: Tuple[float, float]) -> str:
    if math.isnan(median):
        return "n/a"
    if math.isnan(ci[0]) or math.isnan(ci[1]):
        return "%.0f" % median
    return "%.0f [%.0f, %.0f]" % (median, ci[0], ci[1])


def _fmt_ratio(ratio: float) -> str:
    if math.isnan(ratio):
        return "n/a"
    if math.isinf(ratio):
        return "inf"
    return "%.2f" % ratio


def _fmt_p(rate: float) -> str:
    return "n/a" if math.isnan(rate) else "%.3e" % rate


def _fmt_frac(value: float) -> str:
    return "n/a" if math.isnan(value) else "%.3f" % value


def format_table(cells: Mapping[Any, CellSummary]) -> str:
    """Render cells as a markdown table with the two reporting invariants enforced.

    The quarantine rate and the false-quarantine rate are adjacent columns, followed immediately by
    ``acts?``, which reads ``INERT`` whenever the cell never quarantined anything -- so a
    zero-false-positive claim cannot be read without seeing that the mechanism never fired. The
    realised-parameter columns end the row, and ``fault check`` reads ``NO-FAULT-INJECTED`` unless
    the faulty sublink's measured loss rate genuinely exceeds the healthy mean.

    The false-quarantine rate carries its CLUSTER-BOOTSTRAP interval, and the naive Wilson interval
    for the same rate is printed in the next column but one. Printing both is the point: the gap
    between them is the size of the independence assumption that was being made silently.
    """
    rows = ["| " + " | ".join(_COLUMNS) + " |",
            "|" + "|".join(["---"] * len(_COLUMNS)) + "|"]
    for key, cell in cells.items():
        rows.append("| " + " | ".join((
            str(key),
            str(cell.runs),
            _fmt_rate(cell.quarantine_rate, cell.quarantine_ci),
            _fmt_rate(cell.false_quarantine_rate, cell.false_quarantine_ci),
            INERT_LABEL if cell.inert else "acts",
            "[%.4f, %.4f]" % cell.false_quarantine_ci_wilson,
            str(cell.unsafe_packets),
            _fmt_us(cell.detect_us_median, cell.detect_us_ci),
            str(cell.collateral_packets),
            _fmt_rate(cell.restore_rate, cell.restore_ci),
            _fmt_us(cell.restore_us_median, cell.restore_us_ci),
            str(cell.unsafe_restorations),
            str(cell.flaps),
            # clean / loss / incomplete / stale: a run that never restored because every round
            # arrived after its epoch had turned must not read like one whose link stayed lossy.
            "%d/%d/%d/%d" % (cell.audit_clean, cell.audit_loss,
                             cell.audit_incomplete, cell.audit_stale),
            str(cell.installs),
            str(cell.coalesced),
            str(cell.stale_dropped),
            str(cell.offered_packets),
            _fmt_p(cell.faulty_loss_rate),
            _fmt_p(cell.healthy_loss_rate),
            _fmt_ratio(cell.loss_ratio),
            "ok" if cell.fault_injected else NO_FAULT_LABEL,
            _fmt_frac(cell.evidence_epoch_fraction),
        )) + " |")
    return "\n".join(rows)
