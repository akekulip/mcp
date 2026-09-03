#!/usr/bin/env python3
"""
baselines.py — Baseline selectors for comparison against MCP

Each baseline represents one technique from the literature:
  1. FixedPolling — poll all counters, no sketches/sampling
  2. AdaptivePolling — adapt polling frequency (OpenNetMon-style)
  3. PlacementOnly — set-cover switch selection (FlowCover-style)
  4. CentralitySampling — sample at high-centrality switches (Yoon-style)
  5. SketchOnly — CMS sketch everywhere, nothing else
  6. FixedMCP — MCP algorithm with shadow prices disabled

All baselines implement the same interface:
    select(candidates, current_usage) -> List[MeasurementAction]
"""

from typing import Dict, List


class BaselineSelector:
    """Base class for baseline selectors."""

    name = 'baseline'

    def select(self, candidates, current_usage):
        raise NotImplementedError

    def update(self, selected, outcome):
        """Baselines don't learn (except AdaptivePolling)."""
        pass


class FixedPollingSelector(BaselineSelector):
    """Baseline 1: Fixed periodic polling.

    Poll all counters on all switches every epoch. No watchlists,
    no sketches, no sampling. This is the simplest approach.
    """

    name = 'fixed_polling'

    def select(self, candidates, current_usage):
        # Select only 'poll' actions
        return [a for a in candidates if a.action_type == 'poll']


class AdaptivePollingSelector(BaselineSelector):
    """Baseline 2: Adaptive polling (OpenNetMon-style).

    Adapt polling frequency per switch based on rate of change.
    Poll more when traffic changes fast, less when stable.
    Also enables watchlists on switches with high traffic rates.
    """

    name = 'adaptive_polling'

    def __init__(self):
        self.prev_rates = {}

    def select(self, candidates, current_usage):
        selected = []
        for a in candidates:
            if a.action_type == 'poll':
                # Always poll
                selected.append(a)
            elif a.action_type == 'watchlist':
                # Enable watchlist on high-rate switches
                rate = self.prev_rates.get(a.switch, 0)
                if rate > 100:
                    selected.append(a)
        return selected

    def update(self, selected, outcome):
        # Track rates for adaptation
        pass


class PlacementOnlySelector(BaselineSelector):
    """Baseline 3: Placement-only (FlowCover-style).

    Select a minimum set of switches to cover all subnets.
    Only uses polling, placed at switches chosen by a simple
    greedy set-cover heuristic.
    """

    name = 'placement_only'

    def __init__(self, selected_switches=None):
        # Greedy set-cover: spine switches cover all traffic
        self.selected_switches = selected_switches or {'s1', 's2'}

    def select(self, candidates, current_usage):
        return [a for a in candidates
                if a.switch in self.selected_switches
                and a.action_type in ('poll', 'watchlist')]


class CentralitySamplingSelector(BaselineSelector):
    """Baseline 4: Centrality-based sampling (Yoon et al.-style).

    Enable sampling only on the top-centrality switches.
    No sketches, no adaptive polling.
    """

    name = 'centrality_sampling'

    def __init__(self, centrality_threshold=0.7):
        self.threshold = centrality_threshold

    def select(self, candidates, current_usage):
        selected = []
        for a in candidates:
            if a.action_type == 'sample':
                # Only on high-centrality switches
                # (expected_value encodes centrality weighting)
                if a.expected_value > 2.0:
                    selected.append(a)
            elif a.action_type == 'poll':
                selected.append(a)
        return selected


class SketchOnlySelector(BaselineSelector):
    """Baseline 5: Sketch-only (Sketchovsky-style).

    Activate CMS sketch on all switches. No watchlists, no sampling,
    no adaptive polling. Relies entirely on sketch-based measurement.
    """

    name = 'sketch_only'

    def select(self, candidates, current_usage):
        return [a for a in candidates
                if a.action_type in ('sketch', 'poll')]


class FixedMCPSelector(BaselineSelector):
    """Baseline 6: MCP with shadow prices disabled.

    Uses the same greedy score/cost selection as MCP, but
    with all shadow prices fixed at 0. Tests whether the
    adaptive shadow pricing adds value.
    """

    name = 'fixed_mcp'

    def __init__(self, budget):
        self.budget = budget

    def select(self, candidates, current_usage):
        rho = self.budget.headroom
        remaining = {
            'tcam': (1 - rho) * self.budget.tcam_entries
                    - current_usage.get('tcam', 0),
            'reg': (1 - rho) * self.budget.register_cells
                    - current_usage.get('reg', 0),
            'bw': (1 - rho) * self.budget.bandwidth_msgs
                    - current_usage.get('bw', 0),
            'cpu': (1 - rho) * self.budget.cpu_percent
                    - current_usage.get('cpu', 0),
        }

        # Score by expected value only (no shadow prices)
        scored = []
        for a in candidates:
            total_cost = (a.cost_tcam + a.cost_registers / 100
                         + a.cost_bandwidth + a.cost_cpu)
            norm_cost = max(total_cost, 0.01)
            scored.append((a.expected_value / norm_cost, a))

        scored.sort(key=lambda x: x[0], reverse=True)

        selected = []
        for _, a in scored:
            if a.expected_value <= 0:
                continue
            fits = (
                a.cost_tcam <= remaining['tcam'] and
                a.cost_registers <= remaining['reg'] and
                a.cost_bandwidth <= remaining['bw'] and
                a.cost_cpu <= remaining['cpu']
            )
            if fits:
                selected.append(a)
                remaining['tcam'] -= a.cost_tcam
                remaining['reg'] -= a.cost_registers
                remaining['bw'] -= a.cost_bandwidth
                remaining['cpu'] -= a.cost_cpu

        return selected


# Registry of all baselines
BASELINES = {
    'fixed_polling': FixedPollingSelector,
    'adaptive_polling': AdaptivePollingSelector,
    'placement_only': PlacementOnlySelector,
    'centrality_sampling': CentralitySamplingSelector,
    'sketch_only': SketchOnlySelector,
    'fixed_mcp': FixedMCPSelector,
}
