"""Tests for the application-impact CCT gate (sim/gate/cct_model.py + app_impact_gate.py).

These lock the model invariants the gate verdict rests on:
  * ORACLE is the best possible and DO-NOTHING the worst -- every real arm is bracketed by them
    (with the default reroute_cap_cost=0, where mitigating never hurts).
  * the overhead e is monotone in p, lam and tau, and vanishes as any of them -> 0 (the masking
    limit that makes Q1 a NULL), and a fully loss-stalled path is at most ~2x slower (batched).
  * a MISS arm is byte-identical to DO-NOTHING; an EXACT arm with 0 detect delay is the ORACLE.
  * faster detection never yields a worse CCT (the detection-limited monotonicity Q2 depends on).
  * with a positive reroute_cap_cost, exact < ambiguous < miss, AND the mitigation-net-negative
    regime exists (oracle loses to do-nothing) -- the finding the sensitivity pass reports.
  * the recorded near-idle fault produces a negligible do-nothing slowdown (H27 corner).
"""
import math

import pytest

from sim.gate.cct_model import (
    Arm, Fabric, Localize, RECOVERY_MODES, ORACLE, DO_NOTHING, cct_ratio, cct_seconds,
)
from sim.gate.app_impact_gate import MEASURED, ARM_ORDER, scenario_seed


# --- determinism -----------------------------------------------------------------------------
def test_scenario_seed_stable_and_role_separated():
    assert scenario_seed("seed3", "onset") == scenario_seed("seed3", "onset")
    assert scenario_seed("seed3", "a") != scenario_seed("seed3", "b")


# --- bounds (default reroute cost 0) ---------------------------------------------------------
@pytest.mark.parametrize("mode", RECOVERY_MODES)
@pytest.mark.parametrize("p", sorted(MEASURED))
def test_oracle_lower_donothing_upper_bracket_every_arm(mode, p):
    fab = Fabric(p=p, lam_pkts_s=1e5, tau_s=10e-3)
    orc = cct_ratio(fab, ORACLE, mode)
    don = cct_ratio(fab, DO_NOTHING, mode)
    assert orc <= don + 1e-12
    for name in ARM_ORDER:
        r = cct_ratio(fab, MEASURED[p][name], mode)
        assert orc - 1e-9 <= r <= don + 1e-9, f"{name} {r} outside [{orc},{don}]"


def test_oracle_ratio_is_essentially_one():
    fab = Fabric(p=1.5e-2, lam_pkts_s=1e6, tau_s=50e-3)
    assert cct_ratio(fab, ORACLE, "batched") == pytest.approx(1.0, abs=5e-3)


def test_batched_overhead_caps_at_double():
    # a fully loss-stalled critical path is at most ~2x slower under the batched model
    fab = Fabric(p=1.5e-2, lam_pkts_s=1e7, tau_s=100e-3)
    assert fab.overhead("batched") <= 1.0 + 1e-9
    # do-nothing over the whole degraded window approaches, but never exceeds, ~2x
    assert cct_ratio(fab, DO_NOTHING, "batched") < 2.0


# --- overhead monotonicity + masking limit ---------------------------------------------------
@pytest.mark.parametrize("mode", RECOVERY_MODES)
def test_overhead_monotone_in_p_lam_tau(mode):
    lo = Fabric(p=1e-4, lam_pkts_s=1e4, tau_s=1e-3)
    for bump in ("p", "lam_pkts_s", "tau_s"):
        hi = Fabric(**{**lo.__dict__, bump: getattr(lo, bump) * 10})
        assert hi.overhead(mode) >= lo.overhead(mode) - 1e-15


@pytest.mark.parametrize("mode", RECOVERY_MODES)
def test_overhead_vanishes_in_masking_limit(mode):
    fab = Fabric(p=0.0, lam_pkts_s=1e6, tau_s=50e-3)
    assert fab.overhead(mode) == pytest.approx(0.0, abs=1e-12)
    assert cct_ratio(fab, DO_NOTHING, mode) == pytest.approx(cct_ratio(fab, ORACLE, mode), abs=5e-3)


# --- arm equivalences ------------------------------------------------------------------------
@pytest.mark.parametrize("mode", RECOVERY_MODES)
def test_miss_arm_equals_do_nothing(mode):
    fab = Fabric(p=1e-3, lam_pkts_s=1e5, tau_s=10e-3)
    miss = Arm("m", detect_pkts=None, localize=Localize.MISS)
    assert cct_seconds(fab, miss, mode) == pytest.approx(cct_seconds(fab, DO_NOTHING, mode))


@pytest.mark.parametrize("mode", RECOVERY_MODES)
def test_zero_delay_exact_equals_oracle(mode):
    fab = Fabric(p=1e-3, lam_pkts_s=1e5, tau_s=10e-3)
    instant = Arm("i", detect_pkts=0.0, localize=Localize.EXACT)
    assert cct_seconds(fab, instant, mode) == pytest.approx(cct_seconds(fab, ORACLE, mode))


# --- the detection-limited monotonicity Q2 depends on ----------------------------------------
@pytest.mark.parametrize("mode", RECOVERY_MODES)
def test_faster_detection_never_worse(mode):
    fab = Fabric(p=1e-3, lam_pkts_s=1e5, tau_s=10e-3)
    fast = Arm("fast", detect_pkts=22e6, localize=Localize.EXACT)
    slow = Arm("slow", detect_pkts=114e6, localize=Localize.EXACT)
    assert cct_seconds(fab, fast, mode) <= cct_seconds(fab, slow, mode) + 1e-12


@pytest.mark.parametrize("mode", ("batched", "serial"))  # overhead-dominated modes;
# under fast_rtt the overhead is below the reroute cost and the ordering inverts (that inversion
# is the mitigation-net-negative finding, covered by test_mitigation_can_be_net_negative_*).
def test_exact_beats_ambiguous_beats_miss_when_reroute_costs(mode):
    # with a positive reroute cost, localization QUALITY separates the arms: exact<ambiguous<miss
    fab = Fabric(p=1e-3, lam_pkts_s=1e5, tau_s=10e-3, reroute_cap_cost=1.0 / 8)
    ex = Arm("e", 30e6, Localize.EXACT)
    am = Arm("a", 30e6, Localize.AMBIGUOUS, set_size=2.0)
    ms = Arm("m", 30e6, Localize.MISS)
    assert cct_seconds(fab, ex, mode) <= cct_seconds(fab, am, mode) + 1e-12
    assert cct_seconds(fab, am, mode) <= cct_seconds(fab, ms, mode) + 1e-12


def test_mitigation_can_be_net_negative_when_bandwidth_bound():
    # the reported finding: when the loss overhead is smaller than the reroute capacity cost,
    # even the ORACLE loses to DO-NOTHING (mitigating a masked fault costs more than the fault).
    fab = Fabric(p=1e-4, lam_pkts_s=2e3, tau_s=1e-3, reroute_cap_cost=1.0 / 8)
    assert cct_ratio(fab, ORACLE, "batched") > cct_ratio(fab, DO_NOTHING, "batched")


def test_fault_after_collective_finishes_is_no_op():
    fab = Fabric(cct_clean_s=1.0, onset_s=2.0, p=1.5e-2, lam_pkts_s=1e6, tau_s=50e-3)
    assert cct_seconds(fab, DO_NOTHING, "serial") == pytest.approx(1.0)


# --- H27 corner: recorded near-idle fault is negligible --------------------------------------
def test_recorded_near_idle_fault_is_negligible():
    fab = Fabric(p=1e-4, lam_pkts_s=2.0e3, tau_s=10e-3)   # the near-idle 2k pkt/s measured link
    assert cct_ratio(fab, DO_NOTHING, "batched") < 1.02
    assert cct_ratio(fab, DO_NOTHING, "serial") < 1.02
