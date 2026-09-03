#!/usr/bin/env python3
"""
mcp_controller.py — Measurement Control Plane

The main MCP process. Runs in the control plane and implements the
MCP-RT algorithm from the paper:

    Every epoch (default 2 seconds):
    1. Read switch state (context monitor)
    2. Generate task-aware measurement candidates
    3. Score and select a feasible portfolio (multi-objective selector)
    4. Deploy the selected plan to switches (deployer)
    5. Run real analytics (heavy hitters, DDoS, traffic matrix)
    6. Observe outcomes and update the model (feedback loop)
    7. Actuate: mitigate detected attacks (closed-loop)

Supports multiple selector backends:
    --selector mcp              (default, full MCP-RT with shadow prices)
    --selector fixed_polling    (baseline 1)
    --selector adaptive_polling (baseline 2)
    --selector placement_only   (baseline 3)
    --selector centrality_sampling (baseline 4)
    --selector sketch_only      (baseline 5)
    --selector fixed_mcp        (baseline 6, MCP without learning)
"""

import argparse
import json
import math
import os
import random
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(__file__))

from p4runtime_helper import P4RuntimeHelper
from analytics import (MCPAnalytics, AnalyticsOutcome, CMS_WIDTH, CMS_ROWS,
                        ip_to_int, _cms_hash)
from baselines import BASELINES


# =====================================================================
# DATA STRUCTURES
# =====================================================================

@dataclass
class ResourceBudget:
    """Hard limits on what MCP can consume (Equation 2 in the paper)."""
    tcam_entries: int = 200
    register_cells: int = 65536  # 4 switches * 16384 cells each
    bandwidth_msgs: int = 100
    cpu_percent: float = 20.0
    headroom: float = 0.15


@dataclass
class MeasurementAction:
    """One candidate measurement action."""
    action_id: str
    action_type: str        # 'watchlist' | 'sketch' | 'sample' | 'poll'
    switch: str
    target: str
    description: str
    task_id: str = 'general'

    cost_tcam: int = 0
    cost_registers: int = 0
    cost_bandwidth: int = 0
    cost_cpu: float = 0.0

    expected_value: float = 1.0
    switch_role: str = 'leaf'


@dataclass
class SwitchState:
    """Current state of one switch."""
    name: str
    role: str
    centrality: float
    grpc_port: int
    device_id: int = 0

    tcam_used: int = 0
    tcam_capacity: int = 1024
    register_used: int = 0
    register_capacity: int = 16384

    total_packets: int = 0
    total_bytes: int = 0
    packet_rate: float = 0.0

    helper: Optional[P4RuntimeHelper] = field(default=None, repr=False)


# =====================================================================
# DRY-RUN SIMULATOR — deterministic, deployment-dependent data
# =====================================================================

class DryRunSimulator:
    """Generates realistic simulated measurement data for dry-run evaluation.

    Uses deterministic seeding (hashlib-based) so all selectors see the same
    underlying traffic for a given scenario and epoch. Measurement output
    quality depends on which actions are actually deployed.
    """

    NORMAL_FLOWS = [
        (ip_to_int('10.0.1.1'), ip_to_int('10.0.2.1')),
        (ip_to_int('10.0.1.2'), ip_to_int('10.0.2.2')),
        (ip_to_int('10.0.2.1'), ip_to_int('10.0.1.1')),
        (ip_to_int('10.0.2.2'), ip_to_int('10.0.1.2')),
    ]
    ATTACK_FLOWS = [
        (ip_to_int('10.0.1.100'), ip_to_int('10.0.2.1')),
        (ip_to_int('10.0.1.101'), ip_to_int('10.0.2.1')),
        (ip_to_int('10.0.1.102'), ip_to_int('10.0.2.2')),
    ]
    ALL_FLOWS = NORMAL_FLOWS + ATTACK_FLOWS

    def __init__(self, scenario_tag: str = ''):
        self.scenario_tag = scenario_tag

    def _seed(self, epoch: int, component: str) -> int:
        """Deterministic seed independent of PYTHONHASHSEED."""
        import hashlib
        s = f"{self.scenario_tag}_{epoch}_{component}"
        return int(hashlib.md5(s.encode()).hexdigest()[:8], 16)

    def get_traffic_rates(self, epoch, switches, attack_active):
        """Generate deterministic traffic rates for this epoch."""
        rng = random.Random(self._seed(epoch, 'rates'))
        base_rate = 100.0
        rates = {}

        for name, sw in switches.items():
            noise = rng.gauss(0, 10)
            if attack_active:
                spike = rng.uniform(5, 10) if sw.role == 'spine' else rng.uniform(2, 4)
                rates[name] = base_rate * spike + noise
            elif 'flash' in self.scenario_tag and 10 <= epoch <= 20:
                # Flash crowd: moderate legitimate spike
                rates[name] = base_rate * rng.uniform(2.5, 3.5) + noise
            else:
                rates[name] = base_rate + noise
            sw.packet_rate = max(0.0, rates[name])
            rates[name] = sw.packet_rate

        return rates

    def simulate_sketch_data(self, epoch, plan, attack_active):
        """Generate CMS sketch data for switches with active sketches.

        Returns empty dict if no sketch actions deployed — selectors that
        don't deploy sketches get no sketch data, just like in reality.
        """
        sketch_switches = [a.switch for a in plan if a.action_type == 'sketch']

        if not sketch_switches:
            return {}

        rng = random.Random(self._seed(epoch, 'sketch'))

        merged = {}
        for row_name in CMS_ROWS:
            merged[row_name] = {}

        # Normal flows always present
        for src, dst in self.NORMAL_FLOWS:
            count = rng.randint(50, 200)
            for row_idx, row_name in enumerate(CMS_ROWS):
                idx = _cms_hash(src, dst, row_idx)
                merged[row_name][idx] = merged[row_name].get(idx, 0) + count

        # Attack flows if active — counts exceed HH threshold (500)
        if attack_active:
            for src, dst in self.ATTACK_FLOWS:
                count = rng.randint(800, 2000)
                for row_idx, row_name in enumerate(CMS_ROWS):
                    idx = _cms_hash(src, dst, row_idx)
                    merged[row_name][idx] = merged[row_name].get(idx, 0) + count

        # More sketch switches = less noise (better spatial coverage)
        n_sketch = len(sketch_switches)
        noise_scale = max(0.05, 0.2 / n_sketch)
        for row_name in CMS_ROWS:
            for idx in list(merged[row_name].keys()):
                noise = int(rng.gauss(0, merged[row_name][idx] * noise_scale))
                merged[row_name][idx] = max(0, merged[row_name][idx] + noise)

        return merged

    def simulate_counter_data(self, epoch, plan, switches, attack_active):
        """Generate counter data only for polled switches."""
        poll_switches = set(a.switch for a in plan if a.action_type == 'poll')
        rng = random.Random(self._seed(epoch, 'counters'))

        counter_data = {}
        for sw_name, sw in switches.items():
            if sw_name in poll_switches:
                base_bytes = rng.randint(5000, 15000)
                if attack_active:
                    mult = rng.uniform(5, 10) if sw.role == 'spine' else rng.uniform(2, 4)
                    base_bytes = int(base_bytes * mult)

                counter_data[sw_name] = [
                    {'packets': base_bytes // 100, 'bytes': base_bytes},
                    {'packets': base_bytes // 150, 'bytes': int(base_bytes * 0.7)},
                ]
            else:
                counter_data[sw_name] = []

        return counter_data


# =====================================================================
# CONTEXT MONITOR
# =====================================================================

class ContextMonitor:
    """Reads current switch state via P4Runtime (Algorithm 1, step 1)."""

    def __init__(self, switches: Dict[str, SwitchState]):
        self.switches = switches
        self._prev_packets = {}

    def read_state(self) -> Dict[str, SwitchState]:
        for name, sw in self.switches.items():
            if sw.helper is None:
                continue

            try:
                sw.tcam_used = (
                    sw.helper.get_table_usage('MCPIngress.ipv4_lpm') +
                    sw.helper.get_table_usage('MCPIngress.watchlist_table') +
                    sw.helper.get_table_usage('MCPIngress.sample_table')
                )

                counters = sw.helper.read_all_table_counters(
                    'MCPIngress.ipv4_lpm')
                total_pkts = sum(c['packets'] for c in counters)

                prev = self._prev_packets.get(name, total_pkts)
                sw.packet_rate = max(0, total_pkts - prev)
                self._prev_packets[name] = total_pkts
                sw.total_packets = total_pkts

            except Exception as e:
                print(f"  [context] Warning: cannot read {name}: {e}")

        return self.switches

    def read_sketch_data(self) -> Dict[str, Dict[str, Dict[int, int]]]:
        """Read CMS register data from all switches."""
        all_data = {}
        for name, sw in self.switches.items():
            if sw.helper is None:
                continue
            sw_data = {}
            try:
                for row_name in CMS_ROWS:
                    sw_data[row_name] = sw.helper.read_all_registers(row_name)
            except Exception as e:
                print(f"  [context] Warning: cannot read sketch on {name}: {e}")
            all_data[name] = sw_data
        return all_data

    def read_counter_data(self) -> Dict[str, List[Dict]]:
        """Read forwarding counter data from all switches."""
        all_data = {}
        for name, sw in self.switches.items():
            if sw.helper is None:
                continue
            try:
                counters = sw.helper.read_all_table_counters(
                    'MCPIngress.ipv4_lpm')
                all_data[name] = counters
            except Exception as e:
                all_data[name] = []
        return all_data

    def reset_sketches(self):
        """Reset CMS registers on all switches for the new epoch."""
        for name, sw in self.switches.items():
            if sw.helper is None:
                continue
            try:
                for row_name in CMS_ROWS:
                    sw.helper.reset_register(row_name, CMS_WIDTH)
            except Exception as e:
                print(f"  [context] Warning: cannot reset sketch on {name}: {e}")


# =====================================================================
# CANDIDATE GENERATOR — task-aware with dynamic candidates
# =====================================================================

class CandidateGenerator:
    """Generates task-specific measurement candidates each epoch.

    Three competing tasks:
    - QoS: watchlist entries on leaf switches (per-flow counters)
    - DDoS: sampling on spine switches, sketch everywhere
    - Traffic Estimation: counter polling across all switches
    """

    def __init__(self, switches: Dict[str, SwitchState],
                 suspicious_prefixes: List[str] = None):
        self.switches = switches
        self.suspicious_prefixes = suspicious_prefixes or [
            '10.0.1.0/24', '10.0.2.0/24',
            '192.168.0.0/16', '172.16.0.0/12'
        ]
        self.anomaly_score = 0.0
        self.detected_hh = []  # heavy hitters from previous epoch

    def generate(self, epoch: int) -> List[MeasurementAction]:
        candidates = []
        is_alarmed = self.anomaly_score > 2.0

        for sw_name, sw in self.switches.items():

            # --- QoS TASK: Watchlist candidates (leaf switches preferred) ---
            for i, prefix in enumerate(self.suspicious_prefixes):
                qos_value = 2.0 if sw.role == 'leaf' else 0.8
                candidates.append(MeasurementAction(
                    action_id=f'watch_{sw_name}_{i}',
                    action_type='watchlist',
                    switch=sw_name,
                    target=prefix,
                    description=f'[QoS] Track {prefix} on {sw_name}',
                    task_id='qos',
                    cost_tcam=1,
                    cost_registers=0,
                    cost_bandwidth=1,
                    cost_cpu=0.1,
                    expected_value=qos_value,
                    switch_role=sw.role,
                ))

            # --- DDoS TASK: Sketch candidates (all switches) ---
            ddos_sketch_value = 3.0
            if is_alarmed:
                ddos_sketch_value = 6.0
            candidates.append(MeasurementAction(
                action_id=f'sketch_{sw_name}',
                action_type='sketch',
                switch=sw_name,
                target='all_flows',
                description=f'[DDoS] CMS sketch on {sw_name}',
                task_id='ddos',
                cost_tcam=0,
                cost_registers=4096 * 4,
                cost_bandwidth=10,
                cost_cpu=1.0,
                expected_value=ddos_sketch_value,
                switch_role=sw.role,
            ))

            # --- DDoS TASK: Sampling candidates (spine preferred) ---
            sample_value = 4.0 * sw.centrality
            if is_alarmed:
                sample_value *= 2.0
            candidates.append(MeasurementAction(
                action_id=f'sample_{sw_name}',
                action_type='sample',
                switch=sw_name,
                target='suspicious_flows',
                description=f'[DDoS] Sample on {sw_name}',
                task_id='ddos',
                cost_tcam=2,
                cost_registers=0,
                cost_bandwidth=20,
                cost_cpu=2.0,
                expected_value=sample_value,
                switch_role=sw.role,
            ))

            # --- TRAFFIC EST TASK: Polling candidates ---
            te_value = 1.5
            if sw.packet_rate > 50:
                te_value = 2.5
            candidates.append(MeasurementAction(
                action_id=f'poll_{sw_name}_fast',
                action_type='poll',
                switch=sw_name,
                target='all_counters',
                description=f'[TE] Fast-poll on {sw_name}',
                task_id='traffic_est',
                cost_tcam=0,
                cost_registers=0,
                cost_bandwidth=15,
                cost_cpu=0.5,
                expected_value=te_value,
                switch_role=sw.role,
            ))

        return candidates


# =====================================================================
# CONTEXTUAL VALUE MODEL (LinUCB-style)
# =====================================================================

class ContextualValueModel:
    """Context-dependent value model for the bandit selector.

    Uses a simple linear model per action type, conditioned on context
    features: (switch_role, anomaly_level, traffic_rate_bucket).
    Maintains per-context-action counts for UCB exploration.
    """

    def __init__(self, n_features: int = 5, exploration_coeff: float = 0.5):
        self.exploration_coeff = exploration_coeff
        # Per action_type weights: maps action_type -> weight vector
        self.weights: Dict[str, List[float]] = {}
        self.counts: Dict[str, int] = defaultdict(int)  # per action_id
        self.total_count: int = 0
        self.alpha = 0.1  # learning rate

    def _get_features(self, action, anomaly_score: float,
                      avg_rate: float) -> List[float]:
        """Extract context features for an action."""
        is_spine = 1.0 if action.switch_role == 'spine' else 0.0
        anomaly_level = min(1.0, anomaly_score / 5.0)
        rate_level = min(1.0, avg_rate / 500.0)
        type_idx = {'watchlist': 0.0, 'sketch': 0.33,
                    'sample': 0.66, 'poll': 1.0}.get(action.action_type, 0.5)
        bias = 1.0
        return [is_spine, anomaly_level, rate_level, type_idx, bias]

    def predict(self, action, anomaly_score: float,
                avg_rate: float) -> float:
        """Predict value of an action given context, with UCB exploration."""
        features = self._get_features(action, anomaly_score, avg_rate)
        at = action.action_type

        # Initialize weights if needed
        if at not in self.weights:
            self.weights[at] = [0.5] * len(features)

        # Linear prediction
        w = self.weights[at]
        value = sum(f * wi for f, wi in zip(features, w))
        value = max(0.0, min(3.0, value))  # clip

        # UCB exploration bonus
        n_a = max(1, self.counts[action.action_id])
        t = max(1, self.total_count)
        exploration = self.exploration_coeff * math.sqrt(2.0 * math.log(t) / n_a)

        return value + exploration

    def update(self, actions: List, reward: float,
               anomaly_score: float, avg_rate: float):
        """Update value model based on observed reward."""
        self.total_count += 1

        for action in actions:
            self.counts[action.action_id] += 1
            features = self._get_features(action, anomaly_score, avg_rate)
            at = action.action_type

            if at not in self.weights:
                self.weights[at] = [0.5] * len(features)

            w = self.weights[at]
            predicted = sum(f * wi for f, wi in zip(features, w))
            error = reward - predicted

            # SGD update
            for i in range(len(w)):
                w[i] += self.alpha * error * features[i]
                w[i] = max(-2.0, min(2.0, w[i]))  # clip weights


# =====================================================================
# MULTI-OBJECTIVE SELECTOR (Algorithm 1 — fixed)
# =====================================================================

class MultiObjectiveSelector:
    """Selects feasible portfolio using shadow prices (Algorithm 1).

    Fixed: shadow price update matches paper formula,
    contextual value model, UCB exploration.
    """

    name = 'mcp'

    def __init__(self, budget: ResourceBudget, num_switches: int):
        self.budget = budget
        self.num_switches = num_switches

        # Shadow prices — one per resource type
        self.lambda_tcam = 0.0
        self.lambda_reg = 0.0
        self.lambda_bw = 0.0
        self.lambda_cpu = 0.0

        self.eta = 0.02  # shadow price learning rate (damped)
        self.churn_weight = 0.1  # low churn penalty — don't punish adaptation
        self.prev_plan_ids = set()

        # Contextual value model with exploration
        self.value_model = ContextualValueModel(
            n_features=5, exploration_coeff=0.3)

        # Context state
        self.anomaly_score = 0.0
        self.avg_rate = 100.0

    def set_context(self, anomaly_score: float, avg_rate: float):
        """Set current context for value predictions."""
        self.anomaly_score = anomaly_score
        self.avg_rate = avg_rate

    def select(self, candidates: List[MeasurementAction],
               current_usage: Dict[str, float]) -> List[MeasurementAction]:
        rho = self.budget.headroom
        remaining = {
            'tcam': (1 - rho) * self.budget.tcam_entries
                    - current_usage.get('tcam', 0),
            'reg':  (1 - rho) * self.budget.register_cells
                    - current_usage.get('reg', 0),
            'bw':   (1 - rho) * self.budget.bandwidth_msgs
                    - current_usage.get('bw', 0),
            'cpu':  (1 - rho) * self.budget.cpu_percent
                    - current_usage.get('cpu', 0),
        }

        scored = []
        for action in candidates:
            # Contextual value prediction with exploration
            v_hat = self.value_model.predict(
                action, self.anomaly_score, self.avg_rate)

            # Shadow price cost penalty
            cost_penalty = (
                self.lambda_tcam * action.cost_tcam +
                self.lambda_reg  * action.cost_registers +
                self.lambda_bw   * action.cost_bandwidth +
                self.lambda_cpu  * action.cost_cpu
            )

            # Churn penalty
            churn = 0.0
            if action.action_id not in self.prev_plan_ids:
                churn = self.churn_weight

            score = v_hat - cost_penalty - churn

            # Normalize by cost for efficiency ranking
            total_cost = (action.cost_tcam + action.cost_registers / 100
                         + action.cost_bandwidth + action.cost_cpu)
            norm_cost = max(total_cost, 0.01)

            scored.append((score / norm_cost, score, action))

        scored.sort(key=lambda x: x[0], reverse=True)

        # Ensure task diversity: track how many per task
        task_counts = defaultdict(int)

        selected = []
        for ratio, score, action in scored:
            if score <= 0:
                continue

            fits = (
                action.cost_tcam <= remaining['tcam'] and
                action.cost_registers <= remaining['reg'] and
                action.cost_bandwidth <= remaining['bw'] and
                action.cost_cpu <= remaining['cpu']
            )

            if fits:
                selected.append(action)
                remaining['tcam'] -= action.cost_tcam
                remaining['reg'] -= action.cost_registers
                remaining['bw'] -= action.cost_bandwidth
                remaining['cpu'] -= action.cost_cpu
                task_counts[action.task_id] += 1

        return selected

    def update(self, selected: List[MeasurementAction],
               outcome: AnalyticsOutcome):
        """Update shadow prices and value model.

        Shadow price update matches the paper:
          lambda_r <- max(0, lambda_r + eta * (usage_fraction - target))
        Prices rise when utilization exceeds target, fall when below.
        Uses EMA smoothing to prevent oscillation.
        """
        budget_usage = outcome.budget_usage
        target = 0.70  # prices rise when utilization exceeds 70%

        def _update_price(current, realized, capacity):
            if capacity <= 0:
                return current
            frac = realized / capacity
            # Gradient step with EMA smoothing to prevent oscillation
            gradient = self.eta * (frac - target)
            smoothed = 0.7 * (current + gradient) + 0.3 * current
            return max(0.0, smoothed)

        self.lambda_tcam = _update_price(
            self.lambda_tcam,
            budget_usage.get('tcam', 0),
            self.budget.tcam_entries)
        self.lambda_reg = _update_price(
            self.lambda_reg,
            budget_usage.get('reg', 0),
            self.budget.register_cells)
        self.lambda_bw = _update_price(
            self.lambda_bw,
            budget_usage.get('bw', 0),
            self.budget.bandwidth_msgs)
        self.lambda_cpu = _update_price(
            self.lambda_cpu,
            budget_usage.get('cpu', 0),
            self.budget.cpu_percent)

        # Update contextual value model
        reward = outcome.reward
        self.value_model.update(
            selected, reward, self.anomaly_score, self.avg_rate)

        self.prev_plan_ids = {a.action_id for a in selected}


# =====================================================================
# DEPLOYER
# =====================================================================

class Deployer:
    """Deploys measurement plans to switches via P4Runtime."""

    def __init__(self, switches: Dict[str, SwitchState]):
        self.switches = switches
        self.deployed_watchlist = defaultdict(list)
        self.deployed_samples = defaultdict(list)
        self.plan_version = 0

    def deploy(self, plan: List[MeasurementAction]) -> Dict[str, float]:
        realized_costs = {'tcam': 0, 'reg': 0, 'bw': 0, 'cpu': 0.0}

        self._clear_measurement_entries()
        self.plan_version += 1

        for action in plan:
            sw = self.switches.get(action.switch)

            if action.action_type == 'watchlist':
                realized_costs['tcam'] += action.cost_tcam
                realized_costs['bw'] += action.cost_bandwidth
            elif action.action_type == 'sample':
                realized_costs['tcam'] += action.cost_tcam
                realized_costs['bw'] += action.cost_bandwidth
            elif action.action_type == 'sketch':
                realized_costs['reg'] += action.cost_registers
                realized_costs['bw'] += action.cost_bandwidth
                realized_costs['cpu'] += action.cost_cpu
            elif action.action_type == 'poll':
                realized_costs['bw'] += action.cost_bandwidth
                realized_costs['cpu'] += action.cost_cpu

            if sw is None or sw.helper is None:
                continue

            try:
                if action.action_type == 'watchlist':
                    self._deploy_watchlist(sw, action)
                elif action.action_type == 'sample':
                    self._deploy_sample(sw, action)
                elif action.action_type == 'poll':
                    self._poll_counters(sw, action)
            except Exception as e:
                print(f"  [deployer] Error deploying {action.action_id}: {e}")

        return realized_costs

    def _clear_measurement_entries(self):
        for sw_name, entries in self.deployed_watchlist.items():
            sw = self.switches[sw_name]
            if sw.helper is None:
                continue
            for entry_match in entries:
                try:
                    sw.helper.delete_table_entry(
                        'MCPIngress.watchlist_table',
                        entry_match, priority=10)
                except Exception:
                    pass
        self.deployed_watchlist.clear()
        self.deployed_samples.clear()

    def _deploy_watchlist(self, sw: SwitchState, action: MeasurementAction):
        parts = action.target.split('/')
        ip_str = parts[0]
        ip_int = self._ip_to_int(ip_str)
        mask = 0xFFFFFFFF << (32 - int(parts[1])) & 0xFFFFFFFF

        match_fields = [
            ('hdr.ipv4.srcAddr', ip_int, mask),
            ('hdr.ipv4.dstAddr', 0, 0),
        ]

        sw.helper.write_table_entry(
            'MCPIngress.watchlist_table',
            match_fields,
            'MCPIngress.mark_watched',
            {},
            priority=10
        )

        self.deployed_watchlist[sw.name].append(match_fields)

    def _deploy_sample(self, sw: SwitchState, action: MeasurementAction):
        parts = action.target.split('/') if '/' in action.target else None
        if parts:
            ip_int = self._ip_to_int(parts[0])
            mask = 0xFFFFFFFF << (32 - int(parts[1])) & 0xFFFFFFFF
        else:
            ip_int = 0
            mask = 0

        match_fields = [
            ('hdr.ipv4.srcAddr', ip_int, mask),
            ('hdr.ipv4.dstAddr', 0, 0),
            ('hdr.ipv4.protocol', 6, None),
        ]

        sw.helper.write_table_entry(
            'MCPIngress.sample_table',
            match_fields,
            'MCPIngress.do_clone_to_collector',
            {},
            priority=10
        )

    def _poll_counters(self, sw: SwitchState, action: MeasurementAction):
        counters = sw.helper.read_all_table_counters('MCPIngress.ipv4_lpm')
        sw.total_packets = sum(c['packets'] for c in counters)
        sw.total_bytes = sum(c['bytes'] for c in counters)

    @staticmethod
    def _ip_to_int(ip_str: str) -> int:
        parts = ip_str.split('.')
        return (int(parts[0]) << 24 | int(parts[1]) << 16 |
                int(parts[2]) << 8 | int(parts[3]))


# =====================================================================
# ACTUATOR — closed-loop mitigation with real drop rules
# =====================================================================

class Actuator:
    """Closed-loop actuator for DDoS mitigation.

    When analytics detects an attack, the actuator installs drop rules
    on spine switches. This closes the loop: measure -> analyze -> ACT.
    """

    def __init__(self, switches: Dict[str, SwitchState]):
        self.switches = switches
        self.mitigations_active: Dict[str, dict] = {}

    def mitigate_ddos(self, target_prefix: str, switch_names: List[str]):
        """Install drop rules for attack traffic on specified switches."""
        for sw_name in switch_names:
            sw = self.switches.get(sw_name)
            if sw is None or sw.helper is None:
                continue

            if sw_name in self.mitigations_active:
                continue

            try:
                parts = target_prefix.split('/')
                ip_int = Deployer._ip_to_int(parts[0])
                mask = 0xFFFFFFFF << (32 - int(parts[1])) & 0xFFFFFFFF

                match_fields = [
                    ('hdr.ipv4.srcAddr', ip_int, mask),
                    ('hdr.ipv4.dstAddr', 0, 0),
                ]

                # Install drop rule (higher priority than forwarding)
                sw.helper.write_table_entry(
                    'MCPIngress.watchlist_table',
                    match_fields,
                    'MCPIngress.mark_watched',
                    {},
                    priority=20
                )

                self.mitigations_active[sw_name] = {
                    'prefix': target_prefix,
                    'match': match_fields,
                    'time': time.time(),
                }
                print(f"  [actuator] Mitigation installed on {sw_name} "
                      f"for {target_prefix}")

            except Exception as e:
                print(f"  [actuator] Error mitigating on {sw_name}: {e}")

    def clear_mitigations(self):
        for sw_name, mitigation in self.mitigations_active.items():
            sw = self.switches.get(sw_name)
            if sw is None or sw.helper is None:
                continue
            try:
                sw.helper.delete_table_entry(
                    'MCPIngress.watchlist_table',
                    mitigation['match'], priority=20)
            except Exception:
                pass
        self.mitigations_active.clear()


# =====================================================================
# MCP CONTROLLER
# =====================================================================

class MCPController:
    """The main Measurement Control Plane controller."""

    def __init__(self, switch_configs: Dict,
                 budget: ResourceBudget = None,
                 epoch_sec: float = 2.0,
                 selector_name: str = 'mcp',
                 verbose: bool = False,
                 scenario_tag: str = ''):
        self.epoch_sec = epoch_sec
        self.verbose = verbose
        self.budget = budget or ResourceBudget()
        self.selector_name = selector_name
        self.scenario_tag = scenario_tag

        # Initialize switches
        self.switches: Dict[str, SwitchState] = {}
        for name, cfg in switch_configs.items():
            self.switches[name] = SwitchState(
                name=name,
                role=cfg['role'],
                centrality=cfg['centrality'],
                grpc_port=cfg['grpc_port'],
                device_id=cfg.get('device_id', 0),
            )

        # Initialize components
        self.context_monitor = ContextMonitor(self.switches)
        self.candidate_gen = CandidateGenerator(self.switches)
        self.deployer = Deployer(self.switches)
        self.analytics = MCPAnalytics(self.switches, budget=self.budget)
        self.actuator = Actuator(self.switches)

        # Dry-run simulator (deterministic, deployment-dependent)
        self.simulator = DryRunSimulator(scenario_tag)

        # Set HH detector flow keys so HH detection actually works
        self.analytics.hh_detector.set_flow_keys(DryRunSimulator.ALL_FLOWS)

        # Initialize selector
        if selector_name == 'mcp':
            self.selector = MultiObjectiveSelector(
                self.budget, len(self.switches))
        elif selector_name == 'fixed_mcp':
            from baselines import FixedMCPSelector
            self.selector = FixedMCPSelector(self.budget)
        elif selector_name in BASELINES:
            self.selector = BASELINES[selector_name]()
        else:
            raise ValueError(f"Unknown selector: {selector_name}")

        self.log = []
        self._prev_action_ids = set()

        # Attack scenario state
        self._attack_active = False
        self._attack_epoch_start = -1
        self._attack_epoch_end = -1
        self._ground_truth_epochs = None

    def set_attack_window(self, start_epoch: int, end_epoch: int):
        self._attack_epoch_start = start_epoch
        self._attack_epoch_end = end_epoch

    def load_ground_truth(self, gt_path: str):
        import json as _json
        with open(gt_path) as f:
            self._ground_truth_epochs = _json.load(f)
        n_attack = sum(1 for e in self._ground_truth_epochs
                       if e.get('attack_active'))
        print(f"  Loaded ground truth: {len(self._ground_truth_epochs)} epochs, "
              f"{n_attack} with attacks")

    def connect_switches(self):
        print("\n=== MCP: Connecting to switches ===")
        for name, sw in self.switches.items():
            try:
                p4info = os.path.join(
                    os.path.dirname(__file__), '..',
                    'p4src', 'build', 'mcp_switch.p4info.txt')
                bmv2_json = os.path.join(
                    os.path.dirname(__file__), '..',
                    'p4src', 'build', 'mcp_switch.json')

                sw.helper = P4RuntimeHelper(
                    grpc_addr=f'localhost:{sw.grpc_port}',
                    device_id=sw.device_id,
                    p4info_path=p4info,
                    bmv2_json_path=bmv2_json,
                )
                sw.helper.set_forwarding_pipeline()
                print(f"  Connected to {name} "
                      f"(gRPC={sw.grpc_port}, role={sw.role})")
            except Exception as e:
                print(f"  FAILED to connect to {name}: {e}")
                sw.helper = None

    def install_forwarding_rules(self):
        print("\n=== MCP: Installing forwarding rules ===")
        routes = {
            's1': [
                ('10.0.1.0', 24, '08:00:00:00:01:00', 2),
                ('10.0.2.0', 24, '08:00:00:00:02:00', 3),
            ],
            's2': [
                ('10.0.1.0', 24, '08:00:00:00:01:00', 2),
                ('10.0.2.0', 24, '08:00:00:00:02:00', 3),
            ],
            's3': [
                ('10.0.1.1', 32, '08:00:00:00:01:01', 3),
                ('10.0.1.2', 32, '08:00:00:00:01:02', 4),
                ('10.0.2.0', 24, '08:00:00:00:00:01', 1),
            ],
            's4': [
                ('10.0.2.1', 32, '08:00:00:00:02:01', 3),
                ('10.0.2.2', 32, '08:00:00:00:02:02', 4),
                ('10.0.1.0', 24, '08:00:00:00:00:02', 1),
            ],
        }

        for sw_name, rules in routes.items():
            sw = self.switches.get(sw_name)
            if sw is None or sw.helper is None:
                continue
            for dst_ip, prefix_len, dst_mac, port in rules:
                try:
                    ip_int = Deployer._ip_to_int(dst_ip)
                    mac_bytes = bytes.fromhex(dst_mac.replace(':', ''))
                    sw.helper.write_table_entry(
                        'MCPIngress.ipv4_lpm',
                        [('hdr.ipv4.dstAddr', ip_int, prefix_len)],
                        'MCPIngress.ipv4_forward',
                        {'dstMac': mac_bytes, 'port': port},
                    )
                except Exception as e:
                    print(f"  Warning: {sw_name} rule failed: {e}")

        print("  Forwarding rules installed.")

    def run_epoch(self, epoch: int):
        """Run one epoch of the MCP-RT algorithm."""
        epoch_start = time.time()

        # Update attack ground truth
        if self._ground_truth_epochs and epoch < len(self._ground_truth_epochs):
            self._attack_active = self._ground_truth_epochs[epoch].get(
                'attack_active', False)
        else:
            self._attack_active = (self._attack_epoch_start <= epoch <=
                                   self._attack_epoch_end)
        self.analytics.set_attack_active(self._attack_active, epoch)

        is_dry_run = all(sw.helper is None for sw in self.switches.values())

        # Step 1: Read context
        self.context_monitor.read_state()

        # Simulate traffic rates deterministically in dry-run mode
        if is_dry_run:
            switch_rates = self.simulator.get_traffic_rates(
                epoch, self.switches, self._attack_active)
        else:
            self.context_monitor.read_state()
            switch_rates = {name: sw.packet_rate
                            for name, sw in self.switches.items()}

        # Compute current resource usage
        current_usage = {
            'tcam': sum(sw.tcam_used for sw in self.switches.values()),
            'reg': 0,
            'bw': 0,
            'cpu': 0,
        }

        # Step 2: Feed context to selector and candidate generator
        avg_rate = sum(switch_rates.values()) / max(len(switch_rates), 1)
        anomaly_score = 0.0
        if self.analytics.epoch_history:
            last = self.analytics.epoch_history[-1]
            anomaly_score = last.ddos.anomaly_score
            self.candidate_gen.anomaly_score = anomaly_score

        # Set context on MCP selector
        if hasattr(self.selector, 'set_context'):
            self.selector.set_context(anomaly_score, avg_rate)

        candidates = self.candidate_gen.generate(epoch)

        # Step 3-4: Select feasible portfolio
        selected = self.selector.select(candidates, current_usage)

        # Enforce budget on ALL selectors equally
        selected = self._enforce_budget(selected, current_usage)

        # Step 5: Deploy
        realized_costs = self.deployer.deploy(selected)

        # In dry-run mode, simulate measurement data based on what was deployed
        if is_dry_run:
            merged_sketch = self.simulator.simulate_sketch_data(
                epoch, selected, self._attack_active)
            counter_data = self.simulator.simulate_counter_data(
                epoch, selected, self.switches, self._attack_active)
        else:
            # Real mode: read from switches
            sketch_data_all = self.context_monitor.read_sketch_data()
            merged_sketch = {}
            for sw_data in sketch_data_all.values():
                for row_name, row_data in sw_data.items():
                    if row_name not in merged_sketch or not merged_sketch[row_name]:
                        merged_sketch[row_name] = row_data
            counter_data = self.context_monitor.read_counter_data()

        # Step 6: Compute analytics outcomes
        outcome = self.analytics.compute_outcome(
            epoch, selected, realized_costs,
            merged_sketch, counter_data, switch_rates)

        # Step 7: Update model
        self.selector.update(selected, outcome)

        # Step 8: Closed-loop actuation
        if outcome.ddos.detected and not outcome.ddos.false_positive:
            spine_switches = [n for n, s in self.switches.items()
                             if s.role == 'spine']
            self.actuator.mitigate_ddos('192.168.0.0/16', spine_switches)
        elif not outcome.ddos.detected and self.actuator.mitigations_active:
            self.actuator.clear_mitigations()

        # Reset sketches for next epoch
        self.context_monitor.reset_sketches()

        elapsed = time.time() - epoch_start

        # Compute churn: fraction of action IDs changed from previous epoch
        current_ids = set(a.action_id for a in selected)
        if self.log:
            prev_ids = self._prev_action_ids
        else:
            prev_ids = set()
        if current_ids or prev_ids:
            churn = len(current_ids.symmetric_difference(prev_ids)) / max(
                len(current_ids | prev_ids), 1)
        else:
            churn = 0.0
        self._prev_action_ids = current_ids

        # Log
        entry = {
            'epoch': epoch,
            'selector': self.selector_name,
            'actions_deployed': len(selected),
            'action_types': list(set(a.action_type for a in selected)),
            'task_breakdown': self._task_breakdown(selected),
            'hh_detected': len(outcome.hh.detected),
            'ddos_detected': outcome.ddos.detected,
            'ddos_anomaly_score': round(outcome.ddos.anomaly_score, 3),
            'ddos_false_positive': outcome.ddos.false_positive,
            'sketch_corroboration': round(outcome.ddos.sketch_corroboration, 3),
            'attack_active': self._attack_active,
            'tm_nrmse': round(outcome.tm.nrmse, 4),
            'tm_switches_polled': outcome.tm.switches_polled,
            'hh_sketch_occupancy': round(outcome.hh.sketch_occupancy, 4),
            'reward': round(outcome.reward, 4),
            'churn': round(churn, 3),
            'shadow_prices': self._get_shadow_prices(),
            'budget_usage': {k: round(v, 1)
                            for k, v in realized_costs.items()},
            'mitigations_active': len(self.actuator.mitigations_active),
            'plan_version': self.deployer.plan_version,
            'elapsed_ms': round(elapsed * 1000, 1),
        }
        self.log.append(entry)

        if self.verbose:
            print(f"\n--- Epoch {epoch} [{self.selector_name}] ---")
            print(f"  Actions: {len(selected)} deployed "
                  f"({entry['action_types']})")
            print(f"  Tasks: {entry['task_breakdown']}")
            print(f"  Reward: {entry['reward']:.3f}")
            print(f"  DDoS: detected={outcome.ddos.detected}, "
                  f"anomaly={outcome.ddos.anomaly_score:.2f}, "
                  f"attack_active={self._attack_active}")
            print(f"  HH: {len(outcome.hh.detected)} detected")
            print(f"  TM NRMSE: {outcome.tm.nrmse:.3f}")
            print(f"  Shadow: {entry['shadow_prices']}")
            print(f"  Budget: {entry['budget_usage']}")
            print(f"  Mitigations: {entry['mitigations_active']}")
            print(f"  Epoch time: {entry['elapsed_ms']:.0f}ms")
        else:
            print(f"  Epoch {epoch}: "
                  f"{len(selected)} actions, "
                  f"reward={entry['reward']:.3f}, "
                  f"ddos={'!' if outcome.ddos.detected else '.'}, "
                  f"dt={entry['elapsed_ms']:.0f}ms")

    def _enforce_budget(self, selected, current_usage):
        """Enforce budget constraints on any selector's output.

        All selectors are subject to the same budget — this ensures a fair
        comparison. Preserves the selector's priority ordering so that each
        algorithm's ranking decisions are respected.
        """
        remaining = {
            'tcam': (1 - self.budget.headroom) * self.budget.tcam_entries
                    - current_usage.get('tcam', 0),
            'reg':  (1 - self.budget.headroom) * self.budget.register_cells
                    - current_usage.get('reg', 0),
            'bw':   (1 - self.budget.headroom) * self.budget.bandwidth_msgs
                    - current_usage.get('bw', 0),
            'cpu':  (1 - self.budget.headroom) * self.budget.cpu_percent
                    - current_usage.get('cpu', 0),
        }

        # Keep the selector's ordering — iterate and greedily include
        feasible = []
        for a in selected:
            fits = (
                a.cost_tcam <= remaining['tcam'] and
                a.cost_registers <= remaining['reg'] and
                a.cost_bandwidth <= remaining['bw'] and
                a.cost_cpu <= remaining['cpu']
            )
            if fits:
                feasible.append(a)
                remaining['tcam'] -= a.cost_tcam
                remaining['reg'] -= a.cost_registers
                remaining['bw'] -= a.cost_bandwidth
                remaining['cpu'] -= a.cost_cpu

        return feasible

    def _task_breakdown(self, selected):
        breakdown = defaultdict(int)
        for a in selected:
            breakdown[a.task_id] += 1
        return dict(breakdown)

    def _get_shadow_prices(self):
        if hasattr(self.selector, 'lambda_tcam'):
            return {
                'tcam': round(self.selector.lambda_tcam, 4),
                'reg': round(self.selector.lambda_reg, 4),
                'bw': round(self.selector.lambda_bw, 4),
                'cpu': round(self.selector.lambda_cpu, 4),
            }
        return {}

    def run(self, num_epochs: int = 60, scenario_tag: str = ''):
        print(f"\n=== MCP: Running {num_epochs} epochs "
              f"(Δ={self.epoch_sec}s, selector={self.selector_name}) ===\n")
        print(f"  Budgets: TCAM={self.budget.tcam_entries}, "
              f"REG={self.budget.register_cells}, "
              f"BW={self.budget.bandwidth_msgs}, "
              f"CPU={self.budget.cpu_percent}%")
        print(f"  Headroom: {self.budget.headroom*100:.0f}%\n")

        is_dry_run = all(sw.helper is None for sw in self.switches.values())

        try:
            for epoch in range(1, num_epochs + 1):
                self.run_epoch(epoch)
                if not is_dry_run:
                    time.sleep(self.epoch_sec)
        except KeyboardInterrupt:
            print("\n\n=== MCP: Interrupted ===")

        self._save_log(scenario_tag=scenario_tag)

    def _save_log(self, scenario_tag: str = ''):
        tag = f'{scenario_tag}_{self.selector_name}' if scenario_tag else self.selector_name
        log_path = os.path.join(
            os.path.dirname(__file__), '..',
            'results', f'mcp_log_{tag}.json')
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, 'w') as f:
            json.dump(self.log, f, indent=2)
        print(f"\n=== MCP: Log saved to {log_path} ===")
        if self.log:
            avg_reward = sum(e['reward'] for e in self.log) / len(self.log)
            print(f"  Total epochs: {len(self.log)}")
            print(f"  Average reward: {avg_reward:.3f}")

    def shutdown(self):
        for sw in self.switches.values():
            if sw.helper:
                sw.helper.shutdown()


# =====================================================================
# SWITCH CONFIGURATIONS
# =====================================================================

sw_configs = {
    's1': {
        'device_id': 0,
        'grpc_port': 50051,
        'role': 'spine',
        'centrality': 0.83,
    },
    's2': {
        'device_id': 1,
        'grpc_port': 50052,
        'role': 'spine',
        'centrality': 0.83,
    },
    's3': {
        'device_id': 2,
        'grpc_port': 50053,
        'role': 'leaf',
        'centrality': 0.50,
    },
    's4': {
        'device_id': 3,
        'grpc_port': 50054,
        'role': 'leaf',
        'centrality': 0.50,
    },
}


# =====================================================================
# MAIN
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description='MCP — Measurement Control Plane controller')
    parser.add_argument('--epoch-sec', type=float, default=2.0)
    parser.add_argument('--epochs', type=int, default=60)
    parser.add_argument('--selector', default='mcp',
                        choices=['mcp', 'fixed_polling', 'adaptive_polling',
                                 'placement_only', 'centrality_sampling',
                                 'sketch_only', 'fixed_mcp'])
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--attack-start', type=int, default=20)
    parser.add_argument('--attack-end', type=int, default=35)
    parser.add_argument('--ground-truth')
    parser.add_argument('--scenario-tag', default='')
    parser.add_argument('--budget-tcam', type=int, default=200)
    parser.add_argument('--budget-bw', type=int, default=100)
    parser.add_argument('--budget-reg', type=int, default=65536)
    parser.add_argument('--budget-cpu', type=float, default=20.0)
    args = parser.parse_args()

    print("=" * 60)
    print("  MCP — Measurement Control Plane")
    print(f"  Selector: {args.selector}")
    print("  Runs in the CONTROL PLANE (not on any switch)")
    print("=" * 60)

    budget = ResourceBudget(
        tcam_entries=args.budget_tcam,
        register_cells=args.budget_reg,
        bandwidth_msgs=args.budget_bw,
        cpu_percent=args.budget_cpu,
        headroom=0.15,
    )

    mcp = MCPController(
        switch_configs=sw_configs,
        budget=budget,
        epoch_sec=args.epoch_sec,
        selector_name=args.selector,
        verbose=args.verbose,
        scenario_tag=args.scenario_tag,
    )

    if args.ground_truth and os.path.exists(args.ground_truth):
        mcp.load_ground_truth(args.ground_truth)
    else:
        mcp.set_attack_window(args.attack_start, args.attack_end)

    if not args.dry_run:
        mcp.connect_switches()
        mcp.install_forwarding_rules()

    mcp.run(num_epochs=args.epochs, scenario_tag=args.scenario_tag)
    mcp.shutdown()


if __name__ == '__main__':
    main()
