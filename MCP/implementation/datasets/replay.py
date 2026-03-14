#!/usr/bin/env python3
"""
replay.py — Replay CICIDS2017/InSDN dataset flows into Mininet topology

Takes parsed flow records from the dataset CSV and generates real
packets that flow through the BMv2 switches, so MCP can detect
them with its actual measurement primitives (CMS sketch, watchlist,
sampling).

Two replay modes:
  1. FLOW REPLAY (default) — reads CSV flow labels, generates
     synthetic packets matching each flow's characteristics
     (src/dst IP, ports, protocol, packet count, byte count).
     Fast, no PCAP needed.

  2. PCAP REPLAY — uses tcpreplay to replay actual PCAP files
     with IP address rewriting to match our topology.

Usage:
    # Flow-based replay from CSV
    python3 datasets/replay.py --csv data/cicids2017/Friday-DDos.csv \\
        --iface s3-eth3 --speed 10 --duration 120

    # PCAP replay (requires PCAP file)
    python3 datasets/replay.py --pcap data/cicids2017/Friday.pcap \\
        --iface s3-eth3 --speed 1

    # Integrated with MCP experiment runner
    python3 datasets/replay.py --csv data/cicids2017/Wednesday.csv \\
        --iface eth0 --epochs 60 --epoch-sec 2
"""

import argparse
import csv
import json
import os
import random
import subprocess
import sys
import time
import threading
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(__file__))

try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Ether, Raw, sendp, conf
    )
    conf.verb = 0
except ImportError:
    print("ERROR: scapy not found. Install with: pip install scapy")
    sys.exit(1)

from dataset_manager import (
    parse_cicids2017_csv, compute_stats, build_ip_mapping,
    extract_ground_truth, FlowRecord
)


# =====================================================================
# FLOW-BASED REPLAY
# =====================================================================

class FlowReplay:
    """Replays dataset flows as synthetic packets via Scapy.

    Generates packets matching each flow's characteristics:
    - Source/destination IP (remapped to topology)
    - Ports and protocol
    - Number of packets (scaled by speed factor)
    - Payload size (derived from total bytes / total packets)

    This is faster than PCAP replay and doesn't require the raw
    PCAP files — only the CSV flow labels.
    """

    def __init__(self, flows: List[FlowRecord],
                 ip_mapping: Dict[str, str],
                 interface: str = 'eth0',
                 speed: float = 10.0,
                 log_path: Optional[str] = None):
        """
        Args:
            flows: parsed flow records from dataset
            ip_mapping: {original_ip: topology_ip}
            interface: network interface to send packets on
            speed: speedup factor (10 = replay 10x faster)
            log_path: path for ground truth CSV log
        """
        self.flows = flows
        self.ip_mapping = ip_mapping
        self.interface = interface
        self.speed = speed
        self.stats = {'sent': 0, 'benign': 0, 'attack': 0, 'errors': 0}
        self._stop = False

        # Ground truth logging
        self.log_file = None
        self.log_writer = None
        if log_path:
            self.log_file = open(log_path, 'w', newline='')
            self.log_writer = csv.writer(self.log_file)
            self.log_writer.writerow([
                'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'protocol', 'size', 'label', 'original_src', 'original_dst'
            ])

    def replay(self, max_flows: int = 0, duration: float = 0):
        """Replay flows as packets.

        Args:
            max_flows: max number of flows to replay (0 = all)
            duration: max replay duration in seconds (0 = unlimited)
        """
        start_time = time.time()
        flow_count = 0

        print(f"\n=== Flow Replay ===")
        print(f"  Flows: {len(self.flows)}")
        print(f"  Speed: {self.speed}x")
        print(f"  Interface: {self.interface}")
        if max_flows:
            print(f"  Max flows: {max_flows}")
        if duration:
            print(f"  Duration: {duration}s")
        print()

        for flow in self.flows:
            if self._stop:
                break
            if max_flows and flow_count >= max_flows:
                break
            if duration and (time.time() - start_time) >= duration:
                break

            self._replay_flow(flow)
            flow_count += 1

            # Progress every 1000 flows
            if flow_count % 1000 == 0:
                elapsed = time.time() - start_time
                print(f"  [{elapsed:.1f}s] {flow_count} flows, "
                      f"{self.stats['sent']} pkts "
                      f"({self.stats['attack']} attack)")

        elapsed = time.time() - start_time
        print(f"\n=== Replay complete ===")
        print(f"  Flows replayed: {flow_count}")
        print(f"  Packets sent:   {self.stats['sent']}")
        print(f"  Benign packets: {self.stats['benign']}")
        print(f"  Attack packets: {self.stats['attack']}")
        print(f"  Errors:         {self.stats['errors']}")
        print(f"  Duration:       {elapsed:.1f}s")

        if self.log_file:
            self.log_file.close()

    def _replay_flow(self, flow: FlowRecord):
        """Generate packets for one flow."""
        # Map IPs to topology
        src_ip = self.ip_mapping.get(flow.src_ip, flow.src_ip)
        dst_ip = self.ip_mapping.get(flow.dst_ip, flow.dst_ip)

        # Scale packet count by speed (fewer packets = faster replay)
        n_packets = max(1, flow.total_fwd_packets // max(int(self.speed), 1))
        n_packets = min(n_packets, 50)  # cap per flow

        # Compute payload size
        if flow.total_packets > 0:
            avg_pkt_size = flow.total_bytes // flow.total_packets
        else:
            avg_pkt_size = 128
        payload_size = max(0, min(avg_pkt_size - 54, 1400))  # subtract headers

        # Build packet
        for i in range(n_packets):
            if self._stop:
                return

            try:
                if flow.protocol == 6:  # TCP
                    flags = 'S' if i == 0 else 'A'
                    pkt = (Ether() /
                           IP(src=src_ip, dst=dst_ip, ttl=64) /
                           TCP(sport=flow.src_port or random.randint(1024, 65535),
                               dport=flow.dst_port or 80,
                               flags=flags) /
                           Raw(b'X' * payload_size))
                elif flow.protocol == 17:  # UDP
                    pkt = (Ether() /
                           IP(src=src_ip, dst=dst_ip, ttl=64) /
                           UDP(sport=flow.src_port or random.randint(1024, 65535),
                               dport=flow.dst_port or 53) /
                           Raw(b'X' * payload_size))
                else:  # ICMP or other
                    pkt = (Ether() /
                           IP(src=src_ip, dst=dst_ip, ttl=64) /
                           ICMP() /
                           Raw(b'X' * payload_size))

                sendp(pkt, iface=self.interface, verbose=False)
                self.stats['sent'] += 1

                if flow.is_attack:
                    self.stats['attack'] += 1
                else:
                    self.stats['benign'] += 1

                # Log ground truth
                if self.log_writer:
                    self.log_writer.writerow([
                        f'{time.time():.6f}', src_ip, dst_ip,
                        flow.src_port, flow.dst_port,
                        flow.protocol, payload_size,
                        flow.label, flow.src_ip, flow.dst_ip
                    ])

            except Exception:
                self.stats['errors'] += 1

            # Pacing: inter-packet delay
            time.sleep(0.001 / self.speed)

    def stop(self):
        """Signal the replay to stop."""
        self._stop = True


# =====================================================================
# PCAP REPLAY (using tcpreplay)
# =====================================================================

class PCAPReplay:
    """Replays PCAP files using tcpreplay with IP rewriting.

    For CICIDS2017 PCAPs, rewrites source/destination IPs to match
    our Mininet topology using tcpreplay-edit's --srcipmap and
    --dstipmap options.
    """

    def __init__(self, pcap_path: str, interface: str = 'eth0',
                 speed: float = 1.0,
                 src_ip_map: str = '',
                 dst_ip_map: str = ''):
        self.pcap_path = pcap_path
        self.interface = interface
        self.speed = speed
        self.src_ip_map = src_ip_map
        self.dst_ip_map = dst_ip_map
        self.process = None

    def replay(self, duration: float = 0):
        """Replay PCAP using tcpreplay."""
        if not os.path.exists(self.pcap_path):
            print(f"ERROR: PCAP not found: {self.pcap_path}")
            return

        cmd = [
            'tcpreplay',
            f'--intf1={self.interface}',
            f'--multiplier={self.speed}',
        ]

        if duration > 0:
            cmd.append(f'--duration={int(duration)}')

        # IP rewriting requires tcpreplay-edit
        if self.src_ip_map or self.dst_ip_map:
            cmd[0] = 'tcpreplay-edit'
            if self.src_ip_map:
                cmd.append(f'--srcipmap={self.src_ip_map}')
            if self.dst_ip_map:
                cmd.append(f'--dstipmap={self.dst_ip_map}')

        cmd.append(self.pcap_path)

        print(f"\n=== PCAP Replay ===")
        print(f"  PCAP: {self.pcap_path}")
        print(f"  Speed: {self.speed}x")
        print(f"  Interface: {self.interface}")
        print(f"  Command: {' '.join(cmd)}")

        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = self.process.communicate()

            print(f"\n  tcpreplay output:")
            if stdout:
                print(f"  {stdout.decode()}")
            if stderr:
                print(f"  {stderr.decode()}")

        except FileNotFoundError:
            print("  ERROR: tcpreplay not found. Install with:")
            print("    sudo apt install tcpreplay")

    def stop(self):
        if self.process:
            self.process.terminate()


# =====================================================================
# EPOCH-ALIGNED REPLAY
# =====================================================================

class EpochReplay:
    """Replays dataset flows aligned with MCP epochs.

    Groups flows into time windows matching the epoch duration,
    then replays each window's flows during the corresponding epoch.
    This ensures the MCP controller sees attack traffic at the
    right epoch boundaries for proper evaluation.
    """

    def __init__(self, flows: List[FlowRecord],
                 ip_mapping: Dict[str, str],
                 interface: str = 'eth0',
                 epoch_sec: float = 2.0,
                 speed: float = 10.0):
        self.flows = flows
        self.ip_mapping = ip_mapping
        self.interface = interface
        self.epoch_sec = epoch_sec
        self.speed = speed
        self._stop = False

    def replay(self, num_epochs: int = 60):
        """Replay flows epoch by epoch."""
        # Extract ground truth
        gt = extract_ground_truth(self.flows, self.epoch_sec)

        # Group flows by epoch
        epoch_flows = defaultdict(list)
        from datetime import datetime

        def parse_ts(ts_str):
            ts_str = ts_str.strip()
            for fmt in ['%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M',
                         '%Y-%m-%d %H:%M:%S', '%m/%d/%Y %H:%M']:
                try:
                    return datetime.strptime(ts_str, fmt)
                except ValueError:
                    continue
            return None

        timed = [(parse_ts(f.timestamp), f) for f in self.flows]
        timed = [(ts, f) for ts, f in timed if ts]
        if not timed:
            print("  ERROR: No parseable timestamps")
            return

        timed.sort(key=lambda x: x[0])
        t0 = timed[0][0]

        for ts, flow in timed:
            epoch = int((ts - t0).total_seconds() / self.epoch_sec)
            if epoch < num_epochs:
                epoch_flows[epoch].append(flow)

        print(f"\n=== Epoch-Aligned Replay ===")
        print(f"  Epochs: {num_epochs}")
        print(f"  Epoch duration: {self.epoch_sec}s")
        print(f"  Speed: {self.speed}x")
        print(f"  Attack epochs: {sum(1 for e in gt[:num_epochs] if e.get('attack_active'))}")
        print()

        # Save ground truth for MCP controller
        gt_path = os.path.join(os.path.dirname(__file__), '..', 'results',
                               'dataset_ground_truth.json')
        os.makedirs(os.path.dirname(gt_path), exist_ok=True)
        with open(gt_path, 'w') as f:
            json.dump(gt[:num_epochs], f, indent=2)
        print(f"  Ground truth: {gt_path}")

        # Replay epoch by epoch
        for epoch in range(num_epochs):
            if self._stop:
                break

            flows_this_epoch = epoch_flows.get(epoch, [])
            n_attack = sum(1 for f in flows_this_epoch if f.is_attack)
            n_benign = len(flows_this_epoch) - n_attack

            if flows_this_epoch:
                # Generate packets for this epoch's flows
                replayer = FlowReplay(
                    flows_this_epoch, self.ip_mapping,
                    self.interface, self.speed)
                # Run replay in background, limited to epoch duration
                replay_thread = threading.Thread(
                    target=replayer.replay,
                    kwargs={'duration': self.epoch_sec * 0.8})
                replay_thread.daemon = True
                replay_thread.start()

                marker = ' [ATTACK]' if n_attack > 0 else ''
                print(f"  Epoch {epoch}: {len(flows_this_epoch)} flows "
                      f"({n_attack} attack, {n_benign} benign){marker}")

            time.sleep(self.epoch_sec)

        print(f"\n=== Epoch replay complete ===")

    def stop(self):
        self._stop = True


# =====================================================================
# MAIN
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Replay CICIDS2017/InSDN dataset into Mininet')
    parser.add_argument('--csv', help='Path to CICIDS2017 CSV file')
    parser.add_argument('--pcap', help='Path to PCAP file')
    parser.add_argument('--iface', default='eth0',
                        help='Network interface for replay')
    parser.add_argument('--speed', type=float, default=10.0,
                        help='Replay speed multiplier (default: 10x)')
    parser.add_argument('--duration', type=float, default=0,
                        help='Max replay duration in seconds')
    parser.add_argument('--max-flows', type=int, default=0,
                        help='Max flows to replay (0 = all)')
    parser.add_argument('--epochs', type=int, default=0,
                        help='Epoch-aligned replay (number of epochs)')
    parser.add_argument('--epoch-sec', type=float, default=2.0,
                        help='Epoch duration for aligned replay')
    parser.add_argument('--stats-only', action='store_true',
                        help='Show dataset stats without replaying')
    parser.add_argument('--log-dir', default=None,
                        help='Directory for ground truth logs')
    args = parser.parse_args()

    if args.csv:
        print(f"\n=== Loading CSV: {args.csv} ===\n")
        flows = parse_cicids2017_csv(args.csv, args.max_flows)
        stats = compute_stats(flows)

        print(f"  Total flows:    {stats.total_flows:,}")
        print(f"  Benign flows:   {stats.benign_flows:,}")
        print(f"  Attack flows:   {stats.attack_flows:,}")
        if stats.attack_types:
            for attack, count in sorted(stats.attack_types.items(),
                                        key=lambda x: -x[1]):
                print(f"    {attack:30s} {count:>8,}")

        if args.stats_only:
            return

        # Build IP mapping
        ip_mapping = build_ip_mapping(flows)
        print(f"\n  IP mappings: {len(ip_mapping)} addresses")

        # Log directory
        log_dir = args.log_dir or os.path.join(
            os.path.dirname(__file__), '..', 'results')
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, 'dataset_replay.csv')

        if args.epochs > 0:
            # Epoch-aligned replay
            replayer = EpochReplay(
                flows, ip_mapping, args.iface,
                args.epoch_sec, args.speed)
            replayer.replay(args.epochs)
        else:
            # Continuous replay
            replayer = FlowReplay(
                flows, ip_mapping, args.iface,
                args.speed, log_path)
            replayer.replay(args.max_flows, args.duration)

    elif args.pcap:
        replayer = PCAPReplay(
            args.pcap, args.iface, args.speed,
            src_ip_map='192.168.10.0/24:10.0.1.0/24',
            dst_ip_map='192.168.10.0/24:10.0.2.0/24')
        replayer.replay(args.duration)

    else:
        parser.print_help()
        print("\nExample:")
        print("  # Download dataset first:")
        print("  python3 datasets/dataset_manager.py --download cicids2017")
        print()
        print("  # Then replay:")
        print("  python3 datasets/replay.py --csv data/cicids2017/Friday-DDos.csv \\")
        print("      --iface s3-eth3 --speed 10 --duration 120")


if __name__ == '__main__':
    main()
