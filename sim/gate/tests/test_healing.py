"""Tests for the healing result-gate simulator (sim/gate/healing.py).

These lock the accounting invariants and the load-bearing finding: absent a recovery
predictor, the evidence-lease earliest-deadline schedule is byte-identical to round-robin.
"""
import math

from sim.gate.healing import (
    Scenario, Link, make_scenario, make_policy, run_policy, scenario_seed, ALL_POLICIES,
)


def _single_link_scenario(t_recover, horizon=50, budget=1, cap=100.0):
    return Scenario(horizon_epochs=horizon,
                    links=(Link(link_id=0, t_recover=t_recover, capacity_gbps=cap),),
                    audit_budget=budget)


def test_scenario_seed_is_stable_across_processes():
    # CRC-32 based, not salted hash()
    assert scenario_seed("seed7", "scenario") == scenario_seed("seed7", "scenario")
    assert scenario_seed("seed7", "a") != scenario_seed("seed7", "b")


def test_oracle_restores_exactly_at_recovery_zero_unsafe_zero_stranded():
    sc = _single_link_scenario(t_recover=10)
    m = run_policy(sc, make_policy("oracle", sc, seed=1))
    assert m.unsafe_restores == 0
    assert m.restored == 1
    assert m.stranded_epochs == 0.0
    assert m.audit_reads == 0


def test_permanent_quarantine_is_safe_but_never_acts():
    sc = _single_link_scenario(t_recover=10)
    m = run_policy(sc, make_policy("permanent_quarantine", sc, seed=1))
    assert m.unsafe_restores == 0
    assert m.restored == 0            # act-rate 0: safe AND useless, reported together
    assert m.act_rate == 0.0
    # a healthy link left un-restored strands for the rest of the horizon
    assert m.stranded_epochs == sc.horizon_epochs - 10


def test_fixed_timer_too_early_is_unsafe():
    sc = _single_link_scenario(t_recover=20)
    m = run_policy(sc, make_policy("fixed_timer", sc, seed=1, fire_epoch=5))
    assert m.unsafe_restores == 1     # restored at 5 while link recovers at 20
    assert m.restored == 1


def test_fixed_timer_too_late_strands():
    sc = _single_link_scenario(t_recover=5)
    m = run_policy(sc, make_policy("fixed_timer", sc, seed=1, fire_epoch=30))
    assert m.unsafe_restores == 0
    assert m.stranded_epochs == 25    # recovered at 5, restored at 30


def test_fixed_timer_restores_permanent_link_unsafe():
    sc = _single_link_scenario(t_recover=math.inf)
    m = run_policy(sc, make_policy("fixed_timer", sc, seed=1, fire_epoch=10))
    assert m.unsafe_restores == 1     # a permanent fault restored blind is unsafe


def test_audit_arm_never_restores_permanent_link():
    sc = _single_link_scenario(t_recover=math.inf)
    for name in ("round_robin", "earliest_deadline", "continuous_probe", "capacity_weighted"):
        m = run_policy(sc, make_policy(name, sc, seed=1))
        assert m.unsafe_restores == 0, name
        assert m.restored == 0, name  # correct: never certifies a permanently-bad link


def test_audit_arm_restores_within_budget_of_recovery():
    sc = _single_link_scenario(t_recover=10, budget=1)
    m = run_policy(sc, make_policy("continuous_probe", sc, seed=1))
    assert m.unsafe_restores == 0
    assert m.restored == 1
    assert m.stranded_epochs == 0     # audited every epoch -> detects recovery at epoch 10


def test_no_audit_arm_exceeds_its_budget():
    sc = make_scenario(seed=1, n_links=40, horizon_epochs=60, audit_budget=5,
                       mean_recovery_epochs=15, frac_permanent=0.1)
    for name in ("round_robin", "earliest_deadline", "capacity_weighted"):
        pol = make_policy(name, sc, seed=1)
        # driver asserts budget internally; also check directly
        for epoch in range(sc.horizon_epochs):
            assert len(pol.choose_audits(epoch)) <= sc.audit_budget, name
            # advance staleness so choose_audits keeps moving
            for lid in pol.choose_audits(epoch):
                pol.last_audit_epoch[lid] = epoch


def test_earliest_deadline_equals_round_robin_without_a_predictor():
    """THE CRUX. With no side-information about which link recovers next, the evidence-lease
    earliest-deadline schedule and round-robin choose the SAME links every epoch, so they
    produce identical metrics on every seed and budget. The lifecycle's scheduling therefore
    cannot beat the trivial round-robin baseline."""
    for seed in range(30):
        for budget in (1, 3, 7, 20):
            sc = make_scenario(seed=seed, n_links=32, horizon_epochs=80, audit_budget=budget,
                               mean_recovery_epochs=20, frac_permanent=0.15,
                               capacity_choices=(100.0,))  # uniform capacity so tie-break matches
            rr = run_policy(sc, make_policy("round_robin", sc, seed=seed))
            ed = run_policy(sc, make_policy("earliest_deadline", sc, seed=seed, lease=1))
            assert (rr.stranded_epochs, rr.unsafe_restores, rr.restored, rr.audit_reads) == \
                   (ed.stranded_epochs, ed.unsafe_restores, ed.restored, ed.audit_reads), \
                   f"seed={seed} budget={budget}: lease != RR"


def test_determinism_same_seed_same_metrics():
    sc = make_scenario(seed=3, n_links=16, horizon_epochs=50, audit_budget=4,
                       mean_recovery_epochs=12, frac_permanent=0.1)
    a = run_policy(sc, make_policy("earliest_deadline", sc, seed=3))
    b = run_policy(sc, make_policy("earliest_deadline", sc, seed=3))
    assert (a.stranded_epochs, a.unsafe_restores, a.restored) == \
           (b.stranded_epochs, b.unsafe_restores, b.restored)


def test_all_policies_run():
    sc = make_scenario(seed=5, n_links=20, horizon_epochs=60, audit_budget=5,
                       mean_recovery_epochs=15, frac_permanent=0.1)
    for name in ALL_POLICIES:
        m = run_policy(sc, make_policy(name, sc, seed=5, fire_epoch=15))
        assert 0 <= m.restored <= sc.n_links
