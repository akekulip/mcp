#!/usr/bin/env python3
"""healing.py -- the RESULT-GATE for the counterfactual-observability healing lifecycle.

This settles the plan's Section 11 stop condition BEFORE any P4 is written:

    "the lifecycle does not improve certified restoration or stranded capacity at
     equal probe cost"  ->  STOP.

The question is NOT detection/localization (that is `replay.py`). It is the HEALING
decision: a directed link has been quarantined (rerouted off, so it carries no passive
traffic); it physically recovers at an unknown time; when should the policy certify it
and restore it? The proposed lifecycle is evidence-lease -> capped AUDIT probe on the
starved link -> PROBATION -> confidence-qualified RESTORATION, with an explicit
INCONCLUSIVE state that forbids restoration under insufficient evidence.

The decisive modelling choices, chosen to be maximally GENEROUS to the novel arm and to
isolate the one thing Section 11 asks about (does the lifecycle's structure beat a
trivial matched-cost baseline?):

  * An audit of a link at an epoch reveals that link's true state that epoch with
    CERTAINTY (recovered iff now >= t_recover). This removes the per-audit statistics
    entirely -- it makes every audit arm as good as its schedule allows. If the lifecycle
    cannot win even when a single audit is a perfect oracle-for-that-link, it never will.
  * "Equal probe cost" is enforced by giving every audit arm the SAME per-epoch audit
    budget B, shared across all currently-quarantined links. Arms differ ONLY in which
    links they spend B on. This is the matched-cost comparison Section 11 demands.
  * The recovery time t_recover is UNKNOWN to every arm except the oracle. The spec's
    Section 10 lists "a learned scheduler as a headline contribution" as a NON-GOAL, so no
    arm may predict which link is about to recover.

Cross-check discipline (repo CLAUDE.md): every arm reports SAFETY and USEFULNESS
together -- unsafe-restoration count AND the fraction of links it ever restores
(act-rate) AND stranded capacity. An arm that never restores is perfectly safe and
perfectly useless; it is scored as such, never as "0% unsafe" alone.

Determinism: all randomness is `random.Random(scenario_seed(...))`, never Python hash().
"""
from __future__ import annotations

import argparse
import math
import random
import statistics
import zlib
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple


def scenario_seed(stem: str, role: str) -> int:
    """Stable per-seed scenario seed (CRC-32); Python's str hash is salted per process."""
    return zlib.crc32(f"{stem}/{role}".encode())


# ---------------------------------------------------------------------------
# Scenario: K concurrently-quarantined directed links over a horizon.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Link:
    link_id: int
    t_recover: float           # epoch at which the link becomes truly healthy; inf = permanent
    capacity_gbps: float       # heterogeneous link capacity, used for stranded-CAPACITY metric


@dataclass(frozen=True)
class Scenario:
    horizon_epochs: int
    links: Tuple[Link, ...]
    audit_budget: int          # audits per epoch, shared across all quarantined links

    @property
    def n_links(self) -> int:
        return len(self.links)


def make_scenario(
    seed: int,
    n_links: int,
    horizon_epochs: int,
    audit_budget: int,
    mean_recovery_epochs: float,
    frac_permanent: float,
    capacity_choices: Tuple[float, ...] = (100.0,),
) -> Scenario:
    """K links, all quarantined at epoch 0, each recovering at a random epoch (or never).

    Recovery time ~ geometric-ish (memoryless-like) with the given mean; this is the
    honest "we do not know when the repair completes" prior. `frac_permanent` links never
    recover (failed repair) -- these are what make an un-audited fixed timer UNSAFE.
    """
    rng = random.Random(scenario_seed(f"seed{seed}", "scenario"))
    links: List[Link] = []
    for i in range(n_links):
        cap = rng.choice(capacity_choices)
        if rng.random() < frac_permanent:
            t_rec = math.inf
        else:
            # geometric recovery time, mean ~ mean_recovery_epochs, at least 1 epoch
            p = 1.0 / max(mean_recovery_epochs, 1.0)
            t_rec = 1.0
            while rng.random() > p:
                t_rec += 1.0
        links.append(Link(link_id=i, t_recover=t_rec, capacity_gbps=cap))
    return Scenario(horizon_epochs=horizon_epochs, links=tuple(links), audit_budget=audit_budget)


# ---------------------------------------------------------------------------
# Per-run metrics.
# ---------------------------------------------------------------------------
@dataclass
class RunMetrics:
    policy: str
    n_links: int
    restored: int = 0                     # links ever restored (act-rate numerator)
    unsafe_restores: int = 0              # restored while link still bad (now < t_recover)
    # stranded time = epochs a truly-healthy link stayed un-restored (summed over links)
    stranded_epochs: float = 0.0
    stranded_capacity_gbps_epochs: float = 0.0
    audit_reads: int = 0
    # certified-restore delay per (recoverable, correctly restored) link, in epochs after recovery
    restore_delays: List[float] = field(default_factory=list)

    @property
    def act_rate(self) -> float:
        return self.restored / self.n_links if self.n_links else 0.0

    @property
    def median_restore_delay(self) -> float:
        return statistics.median(self.restore_delays) if self.restore_delays else float("nan")


# ---------------------------------------------------------------------------
# Policies.  A policy is a function of (link states seen so far) -> which links to audit
# this epoch (bounded by budget) and which to restore.  It NEVER sees t_recover except
# the oracle.  All arms share one driver so the accounting is identical.
# ---------------------------------------------------------------------------
class Policy:
    name = "base"

    def __init__(self, scenario: Scenario, seed: int):
        self.sc = scenario
        self.rng = random.Random(scenario_seed(f"seed{seed}", self.name))
        self.budget = scenario.audit_budget
        # per-link controller-visible state
        self.quarantined = {l.link_id for l in scenario.links}
        self.last_audit_epoch: Dict[int, int] = {l.link_id: -1 for l in scenario.links}
        self.restored: set = set()

    def choose_audits(self, epoch: int) -> List[int]:
        """Return up to self.budget quarantined link_ids to audit this epoch."""
        raise NotImplementedError

    def on_audit_result(self, epoch: int, link_id: int, healthy: bool) -> bool:
        """Given an audit verdict, return True to RESTORE the link now."""
        raise NotImplementedError

    def maybe_untimed_restore(self, epoch: int) -> List[int]:
        """Arms that restore WITHOUT auditing (fixed timer) return link_ids here."""
        return []


class Oracle(Policy):
    """Upper bound: restore each link exactly at its true recovery epoch. 0 unsafe, 0 audit."""
    name = "oracle"

    def choose_audits(self, epoch):
        return []

    def on_audit_result(self, epoch, link_id, healthy):
        return False

    def maybe_untimed_restore(self, epoch):
        out = []
        for l in self.sc.links:
            if l.link_id in self.quarantined and epoch >= l.t_recover:
                out.append(l.link_id)
        return out


class PermanentQuarantine(Policy):
    """Never restores. Perfectly SAFE, perfectly USELESS (act-rate 0). The always-INCONCLUSIVE arm.
    Included precisely so a '0 unsafe' column is never read without its 0 act-rate beside it."""
    name = "permanent_quarantine"

    def choose_audits(self, epoch):
        return []

    def on_audit_result(self, epoch, link_id, healthy):
        return False


class FixedTimer(Policy):
    """Trivial baseline that spends NO probe budget: restore every link at t_q + T, blind.
    Its whole point is to show that WITHOUT evidence you must trade unsafe against stranded."""
    name = "fixed_timer"

    def __init__(self, scenario, seed, fire_epoch: int):
        super().__init__(scenario, seed)
        self.fire_epoch = fire_epoch

    def choose_audits(self, epoch):
        return []

    def on_audit_result(self, epoch, link_id, healthy):
        return False

    def maybe_untimed_restore(self, epoch):
        if epoch == self.fire_epoch:
            return list(self.quarantined)
        return []


class RoundRobin(Policy):
    """Matched-cost baseline: audit the stalest quarantined links first (round-robin), restore
    on a healthy verdict. With no recovery predictor, 'audit the stalest' IS the evidence-lease
    earliest-deadline schedule -- see EarliestDeadline below."""
    name = "round_robin"

    def choose_audits(self, epoch):
        cand = sorted(self.quarantined, key=lambda k: (self.last_audit_epoch[k], k))
        return cand[: self.budget]

    def on_audit_result(self, epoch, link_id, healthy):
        return healthy


class EarliestDeadline(Policy):
    """THE LIFECYCLE ARM. Evidence-lease: each link carries a lease that expires `lease` epochs
    after its last audit; audit the links whose lease expired earliest (the stalest) first.
    Absent any predictor of which link will recover next, 'stalest first' == round-robin. This
    equivalence is the crux of the vacuity finding and is asserted in the tests."""
    name = "earliest_deadline"

    def __init__(self, scenario, seed, lease: int = 1):
        super().__init__(scenario, seed)
        self.lease = lease

    def choose_audits(self, epoch):
        # lease deadline = last_audit_epoch + lease; earliest deadline first == stalest first
        cand = sorted(self.quarantined, key=lambda k: (self.last_audit_epoch[k] + self.lease, k))
        return cand[: self.budget]

    def on_audit_result(self, epoch, link_id, healthy):
        return healthy


class CapacityWeighted(Policy):
    """The lifecycle arm's best shot at a NON-vacuous edge: among stale links, audit the
    HIGHEST-CAPACITY links first, to reduce stranded CAPACITY rather than stranded time. This
    is 'capacity_weight' from the plan. It is itself a trivial weighted-round-robin baseline."""
    name = "capacity_weighted"

    def choose_audits(self, epoch):
        cap = {l.link_id: l.capacity_gbps for l in self.sc.links}
        cand = sorted(
            self.quarantined,
            key=lambda k: (self.last_audit_epoch[k], -cap[k], k),
        )
        return cand[: self.budget]

    def on_audit_result(self, epoch, link_id, healthy):
        return healthy


class ContinuousProbe(Policy):
    """Audit EVERY quarantined link EVERY epoch (ignores budget). The 'what if probing were
    free' reference. Detects recovery within one epoch. If the honest-budget arms tie this, the
    budget does not bind -- which is exactly the vacuity claim."""
    name = "continuous_probe"

    def choose_audits(self, epoch):
        return list(self.quarantined)

    def on_audit_result(self, epoch, link_id, healthy):
        return healthy


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------
def run_policy(scenario: Scenario, policy: Policy) -> RunMetrics:
    m = RunMetrics(policy=policy.name, n_links=scenario.n_links)
    truth = {l.link_id: l for l in scenario.links}

    for epoch in range(scenario.horizon_epochs):
        # 1) untimed (blind) restores, e.g. fixed timer / oracle
        for lid in policy.maybe_untimed_restore(epoch):
            if lid in policy.quarantined:
                _do_restore(m, policy, truth[lid], epoch)

        # 2) audits under budget
        chosen = policy.choose_audits(epoch)
        assert len(chosen) <= policy.budget or policy.name == "continuous_probe", (
            f"{policy.name} exceeded audit budget {policy.budget}: {len(chosen)}"
        )
        for lid in chosen:
            if lid not in policy.quarantined:
                continue
            policy.last_audit_epoch[lid] = epoch
            m.audit_reads += 1
            healthy = epoch >= truth[lid].t_recover
            if policy.on_audit_result(epoch, lid, healthy):
                _do_restore(m, policy, truth[lid], epoch)

    # 3) end-of-horizon accounting: any link that recovered but was never restored strands
    for l in scenario.links:
        if l.link_id in policy.quarantined and math.isfinite(l.t_recover):
            stranded = max(scenario.horizon_epochs - l.t_recover, 0.0)
            m.stranded_epochs += stranded
            m.stranded_capacity_gbps_epochs += stranded * l.capacity_gbps
    return m


def _do_restore(m: RunMetrics, policy: Policy, link: Link, epoch: int) -> None:
    policy.quarantined.discard(link.link_id)
    policy.restored.add(link.link_id)
    m.restored += 1
    if epoch < link.t_recover:            # restored while still bad (or permanent) -> UNSAFE
        m.unsafe_restores += 1
    else:
        # stranded = time the healthy link waited between recovery and restore
        stranded = max(epoch - link.t_recover, 0.0)
        m.stranded_epochs += stranded
        m.stranded_capacity_gbps_epochs += stranded * link.capacity_gbps
        m.restore_delays.append(stranded)


# ---------------------------------------------------------------------------
# Arm factory.
# ---------------------------------------------------------------------------
def make_policy(name: str, scenario: Scenario, seed: int, *, fire_epoch: int = 0,
                lease: int = 1) -> Policy:
    if name == "oracle":
        return Oracle(scenario, seed)
    if name == "permanent_quarantine":
        return PermanentQuarantine(scenario, seed)
    if name == "fixed_timer":
        return FixedTimer(scenario, seed, fire_epoch=fire_epoch)
    if name == "round_robin":
        return RoundRobin(scenario, seed)
    if name == "earliest_deadline":
        return EarliestDeadline(scenario, seed, lease=lease)
    if name == "capacity_weighted":
        return CapacityWeighted(scenario, seed)
    if name == "continuous_probe":
        return ContinuousProbe(scenario, seed)
    raise ValueError(f"unknown policy {name!r}")


ALL_POLICIES = (
    "oracle", "continuous_probe", "earliest_deadline", "round_robin",
    "capacity_weighted", "fixed_timer", "permanent_quarantine",
)
