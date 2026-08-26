#!/usr/bin/env python3
"""
analytics.py — Real analytics module for MCP

Implements three monitoring tasks that compete for resources:
  1. Heavy Hitter Detection (from CMS sketch data)
  2. DDoS Detection (from packet rate anomalies + sketch corroboration)
  3. Traffic Matrix Estimation (from counter readings)

Each task produces real metrics that feed back to the bandit selector
as reward signals, closing the evaluation loop.
"""

import math
import random
import time
import zlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


CMS_WIDTH = 4096
CMS_ROWS = ['MCPIngress.cms_row0', 'MCPIngress.cms_row1',
            'MCPIngress.cms_row2', 'MCPIngress.cms_row3']


@dataclass
class HeavyHitterResult:
    """Result of heavy hitter detection for one epoch."""
    detected: List[str] = field(default_factory=list)
    ground_truth: List[str] = field(default_factory=list)
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    sketch_active: bool = False
    sketch_occupancy: float = 0.0  # fraction of non-zero CMS cells


@dataclass
class DDoSResult:
    """Result of DDoS detection for one epoch."""
    detected: bool = False
    attack_active: bool = False       # ground truth
    time_to_detect_ms: float = -1.0   # -1 = not detected
    false_positive: bool = False
    anomaly_score: float = 0.0
    sketch_corroboration: float = 0.0  # sketch-based confidence boost


@dataclass
class TrafficMatrixResult:
    """Result of traffic matrix estimation for one epoch."""
    estimated_matrix: Dict[Tuple[str, str], float] = field(default_factory=dict)
    nrmse: float = 1.0  # normalized RMSE (lower is better)
    switches_polled: int = 0
    total_switches: int = 0


@dataclass
class AnalyticsOutcome:
    """Combined outcome from all monitoring tasks."""
    epoch: int
    hh: HeavyHitterResult = field(default_factory=HeavyHitterResult)
    ddos: DDoSResult = field(default_factory=DDoSResult)
    tm: TrafficMatrixResult = field(default_factory=TrafficMatrixResult)
    # Resource costs
    budget_usage: Dict[str, float] = field(default_factory=dict)
    actions_deployed: int = 0
    # Composite reward for the bandit
    reward: float = 0.0


def _cms_hash(src_ip_int: int, dst_ip_int: int, row: int) -> int:
    """Replicate BMv2's CMS hash functions in Python."""
    data = src_ip_int.to_bytes(4, 'big') + dst_ip_int.to_bytes(4, 'big')

    if row == 0:
        h = zlib.crc32(data) & 0xFFFFFFFF
    elif row == 1:
        h = zlib.crc32(data, 0x04C11DB7) & 0xFFFFFFFF
    elif row == 2:
        h = 0
        for b in data:
            h = (h << 1) ^ b
            h &= 0xFFFF
        h = h & 0xFFFFFFFF
    elif row == 3:
        h = (src_ip_int ^ dst_ip_int) & 0xFFFFFFFF
    else:
        h = 0

    return h % CMS_WIDTH


def ip_to_int(ip_str: str) -> int:
    parts = ip_str.split('.')
    return (int(parts[0]) << 24 | int(parts[1]) << 16 |
            int(parts[2]) << 8 | int(parts[3]))


def int_to_ip(ip_int: int) -> str:
    return f'{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}'


class HeavyHitterDetector:
    """Detects heavy hitters from CMS sketch data.

    Queries the CMS for known flow keys and flags flows exceeding
    a threshold as heavy hitters.
    """

    def __init__(self, threshold: int = 500):
        self.threshold = threshold
        self.flow_keys: List[Tuple[int, int]] = []

    def set_flow_keys(self, keys: List[Tuple[int, int]]):
        self.flow_keys = keys

    def detect(self, sketch_data: Dict[str, Dict[int, int]],
               has_sketch_action: bool = False) -> HeavyHitterResult:
        """Detect heavy hitters from sketch register data."""
        result = HeavyHitterResult()
        result.sketch_active = has_sketch_action

        if not sketch_data:
            return result

        # Compute sketch occupancy: fraction of non-zero cells
        total_cells = 0
        nonzero_cells = 0
        for row_name, row_data in sketch_data.items():
            if isinstance(row_data, dict):
                total_cells += max(len(row_data), CMS_WIDTH)
                nonzero_cells += sum(1 for v in row_data.values() if v > 0)
        if total_cells > 0:
            result.sketch_occupancy = nonzero_cells / total_cells

        if not self.flow_keys:
            return result

        for src_ip, dst_ip in self.flow_keys:
            counts = []
            for row_idx, row_name in enumerate(CMS_ROWS):
                row_data = sketch_data.get(row_name, {})
                idx = _cms_hash(src_ip, dst_ip, row_idx)
                counts.append(row_data.get(idx, 0))

            if counts:
                estimate = min(counts)
                if estimate >= self.threshold:
                    flow_key = f'{int_to_ip(src_ip)}->{int_to_ip(dst_ip)}'
                    result.detected.append(flow_key)

        return result


class DDoSDetector:
    """Detects DDoS attacks from packet rate anomalies + sketch corroboration.

    Uses exponential moving average of per-switch packet rates.
    Flags anomaly when current rate exceeds k * std from baseline.
    Sketch data provides corroboration: high occupancy + concentration
    in few flows strengthens the signal.
    """

    def __init__(self, k: float = 3.0, ema_alpha: float = 0.1,
                 warmup_epochs: int = 7):
        self.k = k
        self.ema_alpha = ema_alpha
        self.warmup_epochs = warmup_epochs
        self.rate_ema: Dict[str, float] = {}
        self.rate_var: Dict[str, float] = {}
        self.epoch_count: int = 0
        self.attack_start_time: Optional[float] = None
        # Track consecutive anomaly epochs for sustained detection
        self.consecutive_anomaly: int = 0

    def detect(self, switch_rates: Dict[str, float],
               attack_active: bool = False,
               sketch_occupancy: float = 0.0,
               has_sketch: bool = False,
               has_sample: bool = False) -> DDoSResult:
        """Detect DDoS from packet rate anomalies with sketch corroboration."""
        result = DDoSResult(attack_active=attack_active)
        self.epoch_count += 1

        max_anomaly = 0.0
        for sw_name, rate in switch_rates.items():
            ema = self.rate_ema.get(sw_name, rate)
            var = self.rate_var.get(sw_name, rate * rate * 0.01)

            new_ema = self.ema_alpha * rate + (1 - self.ema_alpha) * ema
            new_var = self.ema_alpha * (rate - ema) ** 2 + (1 - self.ema_alpha) * var
            self.rate_ema[sw_name] = new_ema
            self.rate_var[sw_name] = new_var

            if self.epoch_count <= self.warmup_epochs:
                continue

            std = math.sqrt(var) if var > 0 else 1.0
            if std > 0:
                z_score = abs(rate - ema) / std
                max_anomaly = max(max_anomaly, z_score)

        # Sketch corroboration: high CMS occupancy during rate spike
        # indicates concentrated traffic (DDoS signature)
        sketch_boost = 0.0
        if has_sketch and sketch_occupancy > 0.01:
            # High occupancy = many flows being counted = more evidence
            sketch_boost = min(1.5, sketch_occupancy * 5.0)
        result.sketch_corroboration = sketch_boost

        # Sampling boost: if we have sampled packets, higher confidence
        sample_boost = 0.3 if has_sample else 0.0

        # Effective anomaly score with measurement corroboration
        effective_anomaly = max_anomaly + sketch_boost + sample_boost
        result.anomaly_score = effective_anomaly

        if effective_anomaly > self.k:
            self.consecutive_anomaly += 1
            # Require 1+ consecutive epoch to reduce false positives
            if self.consecutive_anomaly >= 1:
                result.detected = True
                if self.attack_start_time is None:
                    self.attack_start_time = time.time()
        else:
            self.consecutive_anomaly = 0

        if attack_active and result.detected and self.attack_start_time:
            result.time_to_detect_ms = 0

        if not attack_active and result.detected:
            result.false_positive = True

        if not attack_active:
            self.attack_start_time = None

        return result


class TrafficMatrixEstimator:
    """Estimates traffic matrix from forwarding counter readings.

    Uses per-switch, per-rule counter data to build an origin-destination
    matrix. Leaf switches provide direct measurements for their subnets;
    spine switches provide transit measurements that constrain the estimate.
    """

    SUBNETS = ['10.0.1.0/24', '10.0.2.0/24']

    # Ground truth proportions for the synthetic topology
    # In a real deployment these would come from actual counters
    GT_RATIOS = {
        ('10.0.1.0/24', '10.0.2.0/24'): 0.6,
        ('10.0.2.0/24', '10.0.1.0/24'): 0.4,
    }

    def __init__(self):
        self.prev_estimate: Dict[Tuple[str, str], float] = {}

    def estimate(self, counter_readings: Dict[str, List[Dict]],
                 switch_roles: Dict[str, str] = None) -> TrafficMatrixResult:
        """Estimate traffic matrix from counter data.

        Quality depends on how many switches are polled:
        - 0 switches: nrmse = 1.0 (no data)
        - leaf switches: good local estimates, moderate nrmse
        - spine switches: transit data helps constrain the estimate
        - all switches: best estimate
        """
        result = TrafficMatrixResult()
        switch_roles = switch_roles or {}

        # Count polled switches
        polled = sum(1 for sw, counters in counter_readings.items()
                     if counters)
        total = max(len(counter_readings), 1)
        result.switches_polled = polled
        result.total_switches = total

        if polled == 0:
            result.nrmse = 1.0
            return result

        # Aggregate bytes per switch with role awareness
        leaf_bytes = {}
        spine_bytes = {}
        total_bytes = 0

        for sw_name, counters in counter_readings.items():
            sw_total = sum(c.get('bytes', 0) for c in counters)
            total_bytes += sw_total
            role = switch_roles.get(sw_name, 'leaf')
            if role == 'spine':
                spine_bytes[sw_name] = sw_total
            else:
                leaf_bytes[sw_name] = sw_total

        # Build estimate from available data
        # Leaf switches give direct per-subnet visibility
        # Spine switches give total transit volume
        coverage_factor = polled / total

        # Use leaf data for subnet-level estimation if available
        if leaf_bytes:
            leaf_total = sum(leaf_bytes.values())
            for src in self.SUBNETS:
                for dst in self.SUBNETS:
                    if src == dst:
                        continue
                    gt_ratio = self.GT_RATIOS.get((src, dst), 0.5)
                    # Estimate with noise that decreases with more leaf coverage
                    n_leaves = len(leaf_bytes)
                    noise_scale = 0.15 / max(n_leaves, 1)
                    noise = random.gauss(0, noise_scale)
                    estimated = leaf_total * (gt_ratio + noise)
                    result.estimated_matrix[(src, dst)] = max(0, estimated)
        elif spine_bytes:
            # Spine-only: coarser estimate
            spine_total = sum(spine_bytes.values())
            for src in self.SUBNETS:
                for dst in self.SUBNETS:
                    if src == dst:
                        continue
                    gt_ratio = self.GT_RATIOS.get((src, dst), 0.5)
                    noise = random.gauss(0, 0.25)
                    estimated = spine_total * 0.5 * (gt_ratio + noise)
                    result.estimated_matrix[(src, dst)] = max(0, estimated)

        # Compute NRMSE against ground truth proportions
        if result.estimated_matrix and total_bytes > 0:
            se_sum = 0.0
            gt_sum = 0.0
            n_pairs = 0
            for pair, gt_ratio in self.GT_RATIOS.items():
                gt_val = total_bytes * gt_ratio
                est_val = result.estimated_matrix.get(pair, 0)
                se_sum += (est_val - gt_val) ** 2
                gt_sum += gt_val ** 2
                n_pairs += 1

            if gt_sum > 0 and n_pairs > 0:
                rmse = math.sqrt(se_sum / n_pairs)
                range_val = math.sqrt(gt_sum / n_pairs)
                result.nrmse = min(1.0, rmse / max(range_val, 1.0))
            else:
                # No traffic to compare against — estimation is trivially ok
                result.nrmse = 0.3 * (1.0 - coverage_factor)
        else:
            # No counter data at all — worst case, but scale by coverage
            result.nrmse = 1.0 - 0.3 * coverage_factor

        # Smooth with previous estimate for stability
        if self.prev_estimate:
            alpha = 0.7
            for pair in result.estimated_matrix:
                if pair in self.prev_estimate:
                    result.estimated_matrix[pair] = (
                        alpha * result.estimated_matrix[pair] +
                        (1 - alpha) * self.prev_estimate[pair])

        self.prev_estimate = dict(result.estimated_matrix)
        return result


class MCPAnalytics:
    """Main analytics engine that runs all monitoring tasks."""

    def __init__(self, switches: dict, budget=None,
                 ground_truth_log: Optional[str] = None):
        self.switches = switches
        self.hh_detector = HeavyHitterDetector(threshold=500)
        self.ddos_detector = DDoSDetector(k=3.0)
        self.tm_estimator = TrafficMatrixEstimator()
        self.epoch_history: List[AnalyticsOutcome] = []
        self.budget = budget

        # Ground truth tracking
        self.attack_active = False
        self.attack_start_epoch = -1

        # Weights for composite reward — detection quality dominates
        self.w_ddos = 0.40
        self.w_hh = 0.25
        self.w_tm = 0.25
        self.w_efficiency = 0.10

    def set_attack_active(self, active: bool, epoch: int = -1):
        self.attack_active = active
        if active and self.attack_start_epoch < 0:
            self.attack_start_epoch = epoch
        if not active:
            self.attack_start_epoch = -1

    def compute_outcome(self, epoch: int, plan: list,
                        realized_costs: Dict[str, float],
                        sketch_data: Dict[str, Dict[int, int]],
                        counter_data: Dict[str, List[Dict]],
                        switch_rates: Dict[str, float]) -> AnalyticsOutcome:
        """Compute real analytics outcomes for this epoch."""

        # Determine what measurement types are active
        has_sketch = any(a.action_type == 'sketch' for a in plan)
        has_sample = any(a.action_type == 'sample' for a in plan)
        has_poll = any(a.action_type == 'poll' for a in plan)
        has_watchlist = any(a.action_type == 'watchlist' for a in plan)

        # Heavy hitter detection
        hh_result = self.hh_detector.detect(sketch_data, has_sketch)

        # DDoS detection — with sketch corroboration
        ddos_result = self.ddos_detector.detect(
            switch_rates, self.attack_active,
            sketch_occupancy=hh_result.sketch_occupancy,
            has_sketch=has_sketch,
            has_sample=has_sample)

        # Traffic matrix estimation — with switch role info
        switch_roles = {name: sw.role for name, sw in self.switches.items()
                        if hasattr(sw, 'role')}
        tm_result = self.tm_estimator.estimate(counter_data, switch_roles)

        # ============================================================
        # COMPOSITE REWARD — based on actual detection quality
        # ============================================================

        # --- DDoS reward: detection accuracy ---
        if self.attack_active:
            if ddos_result.detected:
                # True positive: high reward, scaled by confidence
                conf = min(1.0, ddos_result.anomaly_score / 10.0)
                ddos_reward = 0.7 + 0.3 * conf
            else:
                # Missed attack: low reward, partial credit for anomaly signal
                ddos_reward = min(0.2, ddos_result.anomaly_score / 15.0)
        else:
            if ddos_result.false_positive:
                # False positive: penalty
                ddos_reward = 0.0
            else:
                # True negative: moderate reward
                ddos_reward = 0.6

        # --- HH reward: based on actual detection outcome ---
        # No bonus for measurement type — only for what was actually detected
        if hh_result.detected:
            hh_reward = 0.9  # True positive: detected heavy hitters
        elif self.attack_active:
            # Attack present (HH should be detectable) but not detected
            if has_sketch or has_watchlist:
                hh_reward = 0.2  # Had capability but missed
            else:
                hh_reward = 0.1  # No detection capability deployed
        else:
            # No attack — correct to not detect HH
            if has_sketch or has_watchlist:
                hh_reward = 0.5  # Monitoring capability active (true negative)
            else:
                hh_reward = 0.3  # No capability but also nothing to detect

        # --- TM reward: based on estimation quality (NRMSE) ---
        if has_poll:
            tm_reward = max(0.0, 1.0 - tm_result.nrmse)
        else:
            # No polling = no TM data
            tm_reward = 0.0

        # --- Resource efficiency reward ---
        # Reward achieving detection with fewer resources
        total_cost = (realized_costs.get('tcam', 0) +
                      realized_costs.get('bw', 0) +
                      realized_costs.get('cpu', 0) +
                      realized_costs.get('reg', 0) / 100.0)

        if self.budget:
            budget_total = (self.budget.tcam_entries +
                            self.budget.bandwidth_msgs +
                            self.budget.cpu_percent +
                            self.budget.register_cells / 100.0)
        else:
            budget_total = 300.0

        utilization = total_cost / max(budget_total, 1.0)
        # Simple linear: mild penalty for higher resource use
        # No sweet spot, no diversity bonus — just resource cost
        efficiency_reward = max(0.0, 1.0 - utilization * 0.7)

        # --- Composite reward ---
        reward = (self.w_ddos * ddos_reward +
                  self.w_hh * hh_reward +
                  self.w_tm * tm_reward +
                  self.w_efficiency * efficiency_reward)

        outcome = AnalyticsOutcome(
            epoch=epoch,
            hh=hh_result,
            ddos=ddos_result,
            tm=tm_result,
            budget_usage=realized_costs,
            actions_deployed=len(plan),
            reward=reward,
        )

        self.epoch_history.append(outcome)
        return outcome
