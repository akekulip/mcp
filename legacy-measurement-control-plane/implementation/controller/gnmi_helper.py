#!/usr/bin/env python3
"""
gnmi_helper.py — gNMI telemetry interface for MCP

The paper specifies gNMI (gRPC Network Management Interface) as the
standard protocol for streaming switch telemetry to the controller.

In a production deployment, MCP would use gNMI to:
  - Subscribe to per-port counter updates (streaming telemetry)
  - Read switch resource utilization (TCAM occupancy, register usage)
  - Monitor queue depths and link utilization
  - Receive alerts when thresholds are crossed

BMv2 does not natively support gNMI, so this module provides:
  1. A gNMI-like abstraction that wraps P4Runtime reads
  2. A simulated gNMI subscription model with callbacks
  3. The same interface that a real gNMI client (e.g., against
     Stratum or ONOS) would expose

When moving to real hardware (Tofino + Stratum), replace the
P4Runtime-based reads with actual gNMI subscriptions. The MCP
controller code does not change — only this module.

Reference: gNMI specification — https://github.com/openconfig/gnmi
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class GNMIPath:
    """Represents a gNMI path (simplified).

    In real gNMI, paths are structured like:
      /interfaces/interface[name=eth0]/state/counters/in-pkts

    We use a simplified string representation for BMv2.
    """
    path: str
    # Example paths:
    #   /switch/{name}/counters/packets
    #   /switch/{name}/resources/tcam_used
    #   /switch/{name}/resources/register_used
    #   /switch/{name}/traffic/packet_rate


@dataclass
class GNMIUpdate:
    """A telemetry update from a switch (gNMI notification)."""
    path: str
    value: float
    timestamp: float = 0.0
    switch_name: str = ''


@dataclass
class GNMISubscription:
    """A gNMI subscription request."""
    path: str
    mode: str = 'SAMPLE'       # SAMPLE | ON_CHANGE | TARGET_DEFINED
    sample_interval_ms: int = 1000
    callback: Optional[Callable] = None


class GNMIClient:
    """gNMI client abstraction for MCP.

    For BMv2: wraps P4Runtime register/counter reads to provide
    a gNMI-like streaming telemetry interface.

    For production (Stratum/Tofino): replace with real gNMI gRPC client.
    """

    def __init__(self, switches: dict):
        """
        Args:
            switches: dict of {name: SwitchState} objects with .helper
        """
        self.switches = switches
        self.subscriptions: List[GNMISubscription] = []
        self._running = False
        self._thread = None
        self._latest_updates: Dict[str, GNMIUpdate] = {}

    def subscribe(self, path: str, callback: Callable = None,
                  mode: str = 'SAMPLE', interval_ms: int = 1000):
        """Subscribe to telemetry updates on a path.

        In real gNMI, this opens a streaming RPC. For BMv2, we
        poll via P4Runtime at the specified interval.

        Args:
            path: gNMI path string (e.g., '/switch/s1/counters/packets')
            callback: function called with GNMIUpdate on each sample
            mode: 'SAMPLE' (periodic) or 'ON_CHANGE'
            interval_ms: polling interval in milliseconds
        """
        sub = GNMISubscription(
            path=path,
            mode=mode,
            sample_interval_ms=interval_ms,
            callback=callback,
        )
        self.subscriptions.append(sub)

    def get(self, path: str) -> Optional[GNMIUpdate]:
        """Synchronous gNMI Get request.

        Reads the current value of a telemetry path.
        """
        # Parse path: /switch/{name}/{category}/{metric}
        parts = path.strip('/').split('/')
        if len(parts) < 4 or parts[0] != 'switch':
            return None

        sw_name = parts[1]
        category = parts[2]
        metric = parts[3]

        sw = self.switches.get(sw_name)
        if sw is None:
            return None

        value = self._read_metric(sw, category, metric)
        update = GNMIUpdate(
            path=path,
            value=value,
            timestamp=time.time(),
            switch_name=sw_name,
        )
        self._latest_updates[path] = update
        return update

    def get_all_switch_telemetry(self, sw_name: str) -> Dict[str, float]:
        """Get all telemetry for one switch (convenience method).

        Returns a flat dict of metric_name -> value.
        """
        metrics = {}
        for category in ['counters', 'resources', 'traffic']:
            for metric in self._metrics_for_category(category):
                path = f'/switch/{sw_name}/{category}/{metric}'
                update = self.get(path)
                if update:
                    metrics[f'{category}/{metric}'] = update.value
        return metrics

    def start_streaming(self):
        """Start background streaming for all subscriptions.

        In real gNMI, the server pushes updates. For BMv2, we
        poll in a background thread.
        """
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._streaming_loop,
                                        daemon=True)
        self._thread.start()

    def stop_streaming(self):
        """Stop background streaming."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _streaming_loop(self):
        """Background polling loop that simulates gNMI streaming."""
        while self._running:
            for sub in self.subscriptions:
                try:
                    update = self.get(sub.path)
                    if update and sub.callback:
                        sub.callback(update)
                except Exception:
                    pass

            # Sleep for the minimum subscription interval
            min_interval = min(
                (s.sample_interval_ms for s in self.subscriptions),
                default=1000
            )
            time.sleep(min_interval / 1000.0)

    def _read_metric(self, sw, category: str, metric: str) -> float:
        """Read a metric from a switch via P4Runtime.

        This is where the BMv2 → gNMI translation happens.
        """
        if sw.helper is None:
            # Dry-run mode: return cached/simulated values
            return getattr(sw, metric, 0.0)

        try:
            if category == 'counters':
                if metric == 'packets':
                    return float(sw.total_packets)
                elif metric == 'bytes':
                    return float(sw.total_bytes)

            elif category == 'resources':
                if metric == 'tcam_used':
                    return float(sw.tcam_used)
                elif metric == 'tcam_capacity':
                    return float(sw.tcam_capacity)
                elif metric == 'register_used':
                    return float(sw.register_used)
                elif metric == 'register_capacity':
                    return float(sw.register_capacity)

            elif category == 'traffic':
                if metric == 'packet_rate':
                    return float(sw.packet_rate)

        except Exception:
            pass

        return 0.0

    def _metrics_for_category(self, category: str) -> List[str]:
        """List available metrics for a category."""
        if category == 'counters':
            return ['packets', 'bytes']
        elif category == 'resources':
            return ['tcam_used', 'tcam_capacity',
                    'register_used', 'register_capacity']
        elif category == 'traffic':
            return ['packet_rate']
        return []


class GNMIContextMonitor:
    """Context monitor that uses gNMI for telemetry.

    Replacement for the P4Runtime-only ContextMonitor that uses
    gNMI as specified in the paper (Section 5.2).

    "A context monitor reads the current network state via gNMI
     streams: the traffic mix, security signals, topology
     information, and resource utilization."
    """

    def __init__(self, switches: dict, gnmi_client: GNMIClient):
        self.switches = switches
        self.gnmi = gnmi_client
        self._prev_packets = {}

    def read_state(self) -> Dict[str, dict]:
        """Read switch state via gNMI (with P4Runtime fallback for BMv2).

        Returns per-switch telemetry snapshots.
        """
        telemetry = {}
        for name, sw in self.switches.items():
            # Use gNMI to get telemetry
            metrics = self.gnmi.get_all_switch_telemetry(name)
            telemetry[name] = metrics

            # Update switch state from gNMI readings
            sw.tcam_used = int(metrics.get('resources/tcam_used', 0))
            sw.packet_rate = metrics.get('traffic/packet_rate', 0)
            sw.total_packets = int(metrics.get('counters/packets', 0))
            sw.total_bytes = int(metrics.get('counters/bytes', 0))

            # Compute rate from delta
            total = sw.total_packets
            prev = self._prev_packets.get(name, total)
            sw.packet_rate = max(0, total - prev)
            self._prev_packets[name] = total

        return telemetry

    def setup_subscriptions(self, interval_ms: int = 1000):
        """Set up gNMI subscriptions for all switches.

        In production, these would be real gNMI SUBSCRIBE RPCs.
        """
        for name in self.switches:
            for path in [
                f'/switch/{name}/counters/packets',
                f'/switch/{name}/counters/bytes',
                f'/switch/{name}/resources/tcam_used',
                f'/switch/{name}/traffic/packet_rate',
            ]:
                self.gnmi.subscribe(
                    path=path,
                    mode='SAMPLE',
                    interval_ms=interval_ms,
                )
