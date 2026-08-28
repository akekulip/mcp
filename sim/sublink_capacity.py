#!/usr/bin/env python3
"""Post-localization value gate for C-W4 behavioral sublinks.

The simulator asks a narrow question: after a conditional fault is known, how much byte-demand
can each quarantine granularity serve safely? It does not model detection, feedback, or application
completion time; those are deliberately reserved for the trace-driven experiment described in
``sim/sublink/PREREG.md``.
"""

import argparse
import json
import statistics
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Callable, Dict, Iterable, Tuple


class Policy(str, Enum):
    PHYSICAL = "physical"
    DIRECTED_W4 = "directed_w4"
    WITNESS_STOP = "witness_stop"
    CW4_SIZE = "cw4_size"
    CAPSULE = "capsule"
    ORACLE = "oracle"


POLICIES = tuple(Policy)


@dataclass(frozen=True)
class Demand:
    direction: str
    size_bytes: int
    traffic_class: int
    bytes_demand: float

    def __post_init__(self):
        if self.direction not in ("forward", "reverse"):
            raise ValueError("direction must be 'forward' or 'reverse'")
        if not 0 <= self.size_bytes <= 65535:
            raise ValueError("size_bytes must fit the C-W4 16-bit range key")
        if self.bytes_demand < 0:
            raise ValueError("bytes_demand must be non-negative")


@dataclass(frozen=True)
class Scenario:
    name: str
    demands: Tuple[Demand, ...]
    is_faulty: Callable[[Demand], bool]


@dataclass(frozen=True)
class SizeSchema:
    """The four size strata compiled into ``mcp_fabric_cw4.p4``."""

    boundaries: Tuple[int, int, int] = (256, 1024, 2048)

    def stratum(self, size_bytes: int) -> int:
        if not 0 <= size_bytes <= 65535:
            raise ValueError("size_bytes must be in [0, 65535]")
        for index, upper_exclusive in enumerate(self.boundaries):
            if size_bytes < upper_exclusive:
                return index
        return len(self.boundaries)


@dataclass(frozen=True)
class Result:
    offered_bytes: float
    primary_safe_bytes: float
    alternate_bytes: float
    blocked_bytes: float
    unsafe_primary_bytes: float
    healthy_primary_quarantined_bytes: float
    safe_delivery_fraction: float


def _blocked_predicate(scenario: Scenario, policy: Policy, schema: SizeSchema):
    faulty_demands = tuple(d for d in scenario.demands if scenario.is_faulty(d))
    if policy == Policy.PHYSICAL:
        fault_present = bool(faulty_demands)
        return lambda demand: fault_present
    if policy in (Policy.DIRECTED_W4, Policy.WITNESS_STOP):
        bad_directions = {d.direction for d in faulty_demands}
        return lambda demand: demand.direction in bad_directions
    if policy == Policy.CW4_SIZE:
        bad_sublinks = {(d.direction, schema.stratum(d.size_bytes)) for d in faulty_demands}
        return lambda demand: (demand.direction, schema.stratum(demand.size_bytes)) in bad_sublinks
    if policy == Policy.CAPSULE:
        # The Context Capsule is classified at the SOURCE leaf, where the IPv4 header is still
        # parsed, so its 4-bit id is size stratum x service class rather than size alone. That is
        # the difference that decides the class-selective negative control: C-W4 reads only
        # eg_intr_md.pkt_length and cannot see the class at all.
        bad_sublinks = {(d.direction, schema.stratum(d.size_bytes), d.traffic_class)
                        for d in faulty_demands}
        return lambda demand: (demand.direction, schema.stratum(demand.size_bytes),
                               demand.traffic_class) in bad_sublinks
    if policy == Policy.ORACLE:
        return scenario.is_faulty
    raise ValueError("unknown policy: %s" % policy)


def run_scenario(scenario: Scenario, policy: Policy, schema: SizeSchema,
                 alternate_headroom: float) -> Result:
    """Run one conservative post-localization policy.

    ``alternate_headroom`` is spare healthy detour capacity per direction, expressed as a fraction
    of that direction's offered demand. A quarantined faulty packet is safe on the alternate path
    because the fault belongs to the primary physical link.
    """
    if not 0.0 <= alternate_headroom <= 1.0:
        raise ValueError("alternate_headroom must be in [0, 1]")
    if not scenario.demands:
        raise ValueError("scenario must contain demand")

    blocked_on_primary = _blocked_predicate(scenario, policy, schema)
    offered_by_direction: Dict[str, float] = {"forward": 0.0, "reverse": 0.0}
    denied_by_direction: Dict[str, float] = {"forward": 0.0, "reverse": 0.0}
    offered = primary_safe = unsafe_primary = healthy_quarantined = 0.0

    for demand in scenario.demands:
        amount = demand.bytes_demand
        offered += amount
        offered_by_direction[demand.direction] += amount
        faulty = scenario.is_faulty(demand)
        if blocked_on_primary(demand):
            denied_by_direction[demand.direction] += amount
            if not faulty:
                healthy_quarantined += amount
        elif faulty:
            unsafe_primary += amount
        else:
            primary_safe += amount

    alternate = sum(
        min(denied_by_direction[direction],
            alternate_headroom * offered_by_direction[direction])
        for direction in offered_by_direction
    )
    denied = sum(denied_by_direction.values())
    blocked = denied - alternate
    safe_delivery = (primary_safe + alternate) / offered
    return Result(
        offered_bytes=offered,
        primary_safe_bytes=primary_safe,
        alternate_bytes=alternate,
        blocked_bytes=blocked,
        unsafe_primary_bytes=unsafe_primary,
        healthy_primary_quarantined_bytes=healthy_quarantined,
        safe_delivery_fraction=safe_delivery,
    )


def size_aligned_scenario(affected_forward_fraction: float) -> Scenario:
    if not 0.0 <= affected_forward_fraction <= 1.0:
        raise ValueError("affected_forward_fraction must be in [0, 1]")
    forward_total = reverse_total = 1000.0
    faulty = forward_total * affected_forward_fraction
    safe = forward_total - faulty
    demands = (
        Demand("forward", 512, 0, safe),
        Demand("forward", 4096, 1, faulty),
        Demand("reverse", 512, 0, reverse_total * 0.25),
        Demand("reverse", 4096, 1, reverse_total * 0.75),
    )
    return Scenario(
        name="aligned_direction_x_size_%g" % affected_forward_fraction,
        demands=demands,
        is_faulty=lambda d: d.direction == "forward" and d.size_bytes >= 2048,
    )


def full_direction_scenario() -> Scenario:
    demands = (
        Demand("forward", 512, 0, 250.0),
        Demand("forward", 4096, 1, 750.0),
        Demand("reverse", 512, 0, 250.0),
        Demand("reverse", 4096, 1, 750.0),
    )
    return Scenario("whole_forward_direction", demands,
                    lambda d: d.direction == "forward")


def no_fault_scenario() -> Scenario:
    demands = (
        Demand("forward", 512, 0, 250.0),
        Demand("forward", 4096, 1, 750.0),
        Demand("reverse", 512, 0, 250.0),
        Demand("reverse", 4096, 1, 750.0),
    )
    return Scenario("no_fault", demands, lambda _d: False)


def misaligned_size_scenario() -> Scenario:
    demands = (
        Demand("forward", 1400, 1, 500.0),
        Demand("forward", 1800, 1, 500.0),
        Demand("reverse", 1400, 1, 500.0),
        Demand("reverse", 1800, 1, 500.0),
    )
    return Scenario(
        "misaligned_size_boundary",
        demands,
        lambda d: d.direction == "forward" and d.size_bytes > 1500,
    )


def class_selective_scenario() -> Scenario:
    demands = tuple(
        Demand(direction, size, traffic_class, 250.0)
        for direction in ("forward", "reverse")
        for size, traffic_class in ((512, 0), (512, 1), (4096, 0), (4096, 1))
    )
    return Scenario(
        "class_selective_negative_control",
        demands,
        lambda d: d.direction == "forward" and d.traffic_class == 1,
    )


def _frozen_runs() -> Iterable[Tuple[str, float, float, Scenario]]:
    for affected in (0.10, 0.25, 0.50, 0.75, 0.90):
        for headroom in (0.0, 0.10, 0.25, 0.50):
            yield "aligned", affected, headroom, size_aligned_scenario(affected)
    controls = (
        ("no_fault", no_fault_scenario()),
        ("whole_direction", full_direction_scenario()),
        ("misaligned_size", misaligned_size_scenario()),
        ("class_selective", class_selective_scenario()),
    )
    for label, scenario in controls:
        for headroom in (0.0, 0.10, 0.25, 0.50):
            yield label, -1.0, headroom, scenario


def run_frozen_experiment() -> Dict[str, object]:
    schema = SizeSchema()
    rows = []
    all_safe = True
    for kind, affected, headroom, scenario in _frozen_runs():
        for policy in POLICIES:
            result = run_scenario(scenario, policy, schema, headroom)
            all_safe = all_safe and result.unsafe_primary_bytes == 0
            row = {
                "kind": kind,
                "scenario": scenario.name,
                "affected_forward_fraction": affected,
                "alternate_headroom": headroom,
                "policy": policy.value,
            }
            row.update(asdict(result))
            rows.append(row)

    gains = []
    closures = []
    for affected in (0.10, 0.25, 0.50, 0.75, 0.90):
        scenario = size_aligned_scenario(affected)
        results = {p: run_scenario(scenario, p, schema, 0.0) for p in POLICIES}
        directed = results[Policy.DIRECTED_W4].safe_delivery_fraction
        cw4 = results[Policy.CW4_SIZE].safe_delivery_fraction
        oracle = results[Policy.ORACLE].safe_delivery_fraction
        gains.append(cw4 - directed)
        closures.append((cw4 - directed) / (oracle - directed))

    no_fault = {p: run_scenario(no_fault_scenario(), p, schema, 0.0) for p in POLICIES}
    whole = {p: run_scenario(full_direction_scenario(), p, schema, 0.0) for p in POLICIES}
    misaligned = {p: run_scenario(misaligned_size_scenario(), p, schema, 0.0)
                  for p in POLICIES}
    class_selective = {p: run_scenario(class_selective_scenario(), p, schema, 0.0)
                       for p in POLICIES}

    median_gain = statistics.median(gains)
    aligned_closure = min(closures)
    no_fault_tie = len({r.safe_delivery_fraction for r in no_fault.values()}) == 1
    whole_direction_tie = whole[Policy.CW4_SIZE] == whole[Policy.DIRECTED_W4]
    gate_pass = (all_safe and median_gain >= 0.10 and aligned_closure == 1.0
                 and no_fault_tie and whole_direction_tie)
    gate = {
        "pass": gate_pass,
        "all_policies_zero_unsafe_primary": all_safe,
        "median_aligned_gain_percentage_points": 100.0 * median_gain,
        "minimum_aligned_oracle_gap_closed_percent": 100.0 * aligned_closure,
        "no_fault_tie": no_fault_tie,
        "whole_direction_cw4_equals_w4": whole_direction_tie,
        "misaligned_oracle_gap_percentage_points": 100.0 * (
            misaligned[Policy.ORACLE].safe_delivery_fraction
            - misaligned[Policy.CW4_SIZE].safe_delivery_fraction
        ),
        "class_selective_oracle_gap_percentage_points": 100.0 * (
            class_selective[Policy.ORACLE].safe_delivery_fraction
            - class_selective[Policy.CW4_SIZE].safe_delivery_fraction
        ),
    }
    return {"gate": gate, "rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", action="store_true",
                        help="include every frozen policy/scenario row instead of only the gate")
    args = parser.parse_args()
    experiment = run_frozen_experiment()
    output = experiment if args.rows else experiment["gate"]
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
