#!/usr/bin/env python3
"""
dataset_manager.py — Download and manage CICIDS2017 + InSDN datasets

CICIDS2017:
  - Source: Canadian Institute for Cybersecurity, UNB
  - URL: https://www.unb.ca/cic/datasets/ids-2017.html
  - Contains: 5 days of labeled network traffic (PCAPs + CSV flow labels)
  - Days: Monday (benign), Tuesday-Friday (various attacks)
  - Attacks: Brute Force, DDoS, DoS, Web Attack, Infiltration, Botnet, PortScan
  - CSV labels: Flow ID, Src IP, Src Port, Dst IP, Dst Port, Protocol, Timestamp, Label

InSDN:
  - Source: SDN-specific intrusion detection dataset
  - URL: https://github.com/Taha-Adeel/InSDN-dataset (or Kaggle)
  - Contains: Normal + attack traffic in SDN environment
  - Attacks: DDoS, Probe, R2L, U2R, Web Attack

This module handles:
  1. Downloading dataset files (PCAPs + CSVs)
  2. Parsing flow labels for ground truth
  3. Splitting PCAPs into attack/benign segments
  4. Preparing dataset for replay into Mininet topology

Usage:
    python3 datasets/dataset_manager.py --download cicids2017
    python3 datasets/dataset_manager.py --download insdn
    python3 datasets/dataset_manager.py --prepare cicids2017 --day tuesday
"""

import argparse
import csv
import gzip
import hashlib
import os
import subprocess
import sys
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


# =====================================================================
# DATASET DEFINITIONS
# =====================================================================

DATASET_DIR = os.path.join(os.path.dirname(__file__), 'data')

# CICIDS2017 CSV flow labels (from the CIC Flow Meter tool)
# These are the processed CSVs, not raw PCAPs — much smaller and
# contain ground truth labels for every flow.
CICIDS2017_CSVS = {
    'monday': {
        'url': 'https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/TrafficLabelling/Monday-WorkingHours.pcap_ISCX.csv',
        'filename': 'Monday-WorkingHours.pcap_ISCX.csv',
        'description': 'Monday — benign traffic only',
        'attacks': [],
    },
    'tuesday': {
        'url': 'https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/TrafficLabelling/Tuesday-WorkingHours.pcap_ISCX.csv',
        'filename': 'Tuesday-WorkingHours.pcap_ISCX.csv',
        'description': 'Tuesday — FTP-Patator, SSH-Patator',
        'attacks': ['FTP-Patator', 'SSH-Patator'],
    },
    'wednesday': {
        'url': 'https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/TrafficLabelling/Wednesday-workingHours.pcap_ISCX.csv',
        'filename': 'Wednesday-workingHours.pcap_ISCX.csv',
        'description': 'Wednesday — DoS slowloris, DoS Slowhttptest, DoS Hulk, DoS GoldenEye, Heartbleed',
        'attacks': ['DoS slowloris', 'DoS Slowhttptest', 'DoS Hulk', 'DoS GoldenEye', 'Heartbleed'],
    },
    'thursday': {
        'url': 'https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/TrafficLabelling/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        'filename': 'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
        'description': 'Thursday AM — Web Attack (Brute Force, XSS, SQL Injection)',
        'attacks': ['Web Attack - Brute Force', 'Web Attack - XSS', 'Web Attack - Sql Injection'],
    },
    'thursday_afternoon': {
        'url': 'https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/TrafficLabelling/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
        'filename': 'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
        'description': 'Thursday PM — Infiltration',
        'attacks': ['Infiltration'],
    },
    'friday': {
        'url': 'https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/TrafficLabelling/Friday-WorkingHours-Morning.pcap_ISCX.csv',
        'filename': 'Friday-WorkingHours-Morning.pcap_ISCX.csv',
        'description': 'Friday AM — Botnet',
        'attacks': ['Bot'],
    },
    'friday_afternoon': {
        'url': 'https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/TrafficLabelling/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
        'filename': 'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
        'description': 'Friday PM — PortScan, DDoS',
        'attacks': ['PortScan', 'DDoS'],
    },
    'friday_ddos': {
        'url': 'https://iscxdownloads.cs.unb.ca/iscxdownloads/CIC-IDS-2017/TrafficLabelling/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
        'filename': 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
        'description': 'Friday PM — DDoS (LOIT)',
        'attacks': ['DDoS'],
    },
}

# Best days for MCP evaluation (contain DDoS/DoS attacks)
CICIDS2017_RECOMMENDED = ['wednesday', 'friday_ddos', 'friday_afternoon']


@dataclass
class FlowRecord:
    """One flow from the CICIDS2017/InSDN dataset."""
    flow_id: str = ''
    src_ip: str = ''
    src_port: int = 0
    dst_ip: str = ''
    dst_port: int = 0
    protocol: int = 0
    timestamp: str = ''
    duration: float = 0.0
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_length_fwd: int = 0
    total_length_bwd: int = 0
    flow_bytes_per_sec: float = 0.0
    flow_packets_per_sec: float = 0.0
    label: str = 'BENIGN'

    @property
    def is_attack(self) -> bool:
        return self.label.strip().upper() != 'BENIGN'

    @property
    def total_packets(self) -> int:
        return self.total_fwd_packets + self.total_bwd_packets

    @property
    def total_bytes(self) -> int:
        return self.total_length_fwd + self.total_length_bwd


@dataclass
class DatasetStats:
    """Statistics about a loaded dataset."""
    total_flows: int = 0
    benign_flows: int = 0
    attack_flows: int = 0
    attack_types: Dict[str, int] = field(default_factory=dict)
    unique_src_ips: int = 0
    unique_dst_ips: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    duration_sec: float = 0.0


# =====================================================================
# DOWNLOADER
# =====================================================================

def download_file(url: str, dest_path: str, description: str = ''):
    """Download a file with progress indication."""
    if os.path.exists(dest_path):
        print(f"  [skip] Already exists: {os.path.basename(dest_path)}")
        return True

    print(f"  Downloading: {description or url}")
    print(f"  -> {dest_path}")

    try:
        def reporthook(block_num, block_size, total_size):
            downloaded = block_num * block_size
            if total_size > 0:
                pct = min(100, downloaded * 100 // total_size)
                mb = downloaded / (1024 * 1024)
                total_mb = total_size / (1024 * 1024)
                print(f'\r  Progress: {pct}% ({mb:.1f}/{total_mb:.1f} MB)',
                      end='', flush=True)

        urllib.request.urlretrieve(url, dest_path, reporthook)
        print()  # newline after progress
        return True

    except Exception as e:
        print(f"\n  ERROR downloading: {e}")
        if os.path.exists(dest_path):
            os.remove(dest_path)
        return False


def download_cicids2017(days: List[str] = None):
    """Download CICIDS2017 CSV flow label files.

    Args:
        days: list of day names to download (default: recommended subset)
    """
    os.makedirs(os.path.join(DATASET_DIR, 'cicids2017'), exist_ok=True)

    if days is None:
        days = CICIDS2017_RECOMMENDED

    print(f"\n=== Downloading CICIDS2017 ({len(days)} files) ===\n")

    for day in days:
        if day not in CICIDS2017_CSVS:
            print(f"  WARNING: Unknown day '{day}', skipping")
            continue

        info = CICIDS2017_CSVS[day]
        dest = os.path.join(DATASET_DIR, 'cicids2017', info['filename'])
        download_file(info['url'], dest, info['description'])

    print(f"\n=== CICIDS2017 download complete ===")
    print(f"  Location: {os.path.join(DATASET_DIR, 'cicids2017')}")


# =====================================================================
# PARSER
# =====================================================================

def parse_cicids2017_csv(csv_path: str,
                         max_flows: int = 0) -> List[FlowRecord]:
    """Parse a CICIDS2017 CSV file into FlowRecord objects.

    The CICIDS2017 CSVs have inconsistent column naming (spaces,
    capitalization). This parser handles known variants.
    """
    flows = []

    with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
        # Read header and normalize column names
        reader = csv.reader(f)
        header = next(reader)
        # Strip whitespace and lowercase
        header = [col.strip().lower().replace(' ', '_') for col in header]

        # Map known column name variants
        col_map = {}
        for i, col in enumerate(header):
            if 'flow_id' in col:
                col_map['flow_id'] = i
            elif col in ('source_ip', 'src_ip'):
                col_map['src_ip'] = i
            elif col in ('source_port', 'src_port'):
                col_map['src_port'] = i
            elif col in ('destination_ip', 'dst_ip', 'dest_ip'):
                col_map['dst_ip'] = i
            elif col in ('destination_port', 'dst_port', 'dest_port'):
                col_map['dst_port'] = i
            elif col == 'protocol':
                col_map['protocol'] = i
            elif col == 'timestamp':
                col_map['timestamp'] = i
            elif col in ('flow_duration', 'duration'):
                col_map['duration'] = i
            elif col in ('total_fwd_packets', 'total_fwd_packet'):
                col_map['total_fwd_packets'] = i
            elif col in ('total_backward_packets', 'total_bwd_packets',
                          'total_backward_packets'):
                col_map['total_bwd_packets'] = i
            elif col in ('total_length_of_fwd_packets',
                          'total_length_of_fwd_packet'):
                col_map['total_length_fwd'] = i
            elif col in ('total_length_of_bwd_packets',
                          'total_length_of_bwd_packet'):
                col_map['total_length_bwd'] = i
            elif col in ('flow_bytes/s', 'flow_bytes_per_sec',
                          'flow_bytes/s'):
                col_map['flow_bytes_per_sec'] = i
            elif col in ('flow_packets/s', 'flow_packets_per_sec',
                          'flow_packets/s'):
                col_map['flow_packets_per_sec'] = i
            elif col == 'label':
                col_map['label'] = i

        if 'label' not in col_map:
            print(f"  WARNING: No 'label' column found in {csv_path}")
            print(f"  Columns: {header}")
            return flows

        for row in reader:
            if max_flows > 0 and len(flows) >= max_flows:
                break

            try:
                flow = FlowRecord()

                def _get(key, default=''):
                    idx = col_map.get(key)
                    if idx is not None and idx < len(row):
                        return row[idx].strip()
                    return default

                flow.flow_id = _get('flow_id')
                flow.src_ip = _get('src_ip')
                flow.dst_ip = _get('dst_ip')
                flow.label = _get('label', 'BENIGN')

                # Numeric fields (handle NaN, Infinity)
                def _int(key, default=0):
                    val = _get(key, '')
                    try:
                        return int(float(val))
                    except (ValueError, OverflowError):
                        return default

                def _float(key, default=0.0):
                    val = _get(key, '')
                    try:
                        v = float(val)
                        if v != v or abs(v) == float('inf'):  # NaN or Inf
                            return default
                        return v
                    except (ValueError, OverflowError):
                        return default

                flow.src_port = _int('src_port')
                flow.dst_port = _int('dst_port')
                flow.protocol = _int('protocol')
                flow.timestamp = _get('timestamp')
                flow.duration = _float('duration')
                flow.total_fwd_packets = _int('total_fwd_packets')
                flow.total_bwd_packets = _int('total_bwd_packets')
                flow.total_length_fwd = _int('total_length_fwd')
                flow.total_length_bwd = _int('total_length_bwd')
                flow.flow_bytes_per_sec = _float('flow_bytes_per_sec')
                flow.flow_packets_per_sec = _float('flow_packets_per_sec')

                flows.append(flow)

            except Exception:
                continue  # skip malformed rows

    return flows


def compute_stats(flows: List[FlowRecord]) -> DatasetStats:
    """Compute statistics from a list of flow records."""
    stats = DatasetStats(total_flows=len(flows))

    src_ips = set()
    dst_ips = set()

    for flow in flows:
        if flow.is_attack:
            stats.attack_flows += 1
            label = flow.label.strip()
            stats.attack_types[label] = stats.attack_types.get(label, 0) + 1
        else:
            stats.benign_flows += 1

        src_ips.add(flow.src_ip)
        dst_ips.add(flow.dst_ip)
        stats.total_packets += flow.total_packets
        stats.total_bytes += flow.total_bytes

    stats.unique_src_ips = len(src_ips)
    stats.unique_dst_ips = len(dst_ips)

    return stats


# =====================================================================
# IP ADDRESS MAPPING
# =====================================================================

def build_ip_mapping(flows: List[FlowRecord],
                     topology_subnets: dict = None) -> Dict[str, str]:
    """Map dataset IPs to our Mininet topology IPs.

    CICIDS2017 uses IPs like 192.168.10.x (victims) and various
    attacker IPs. We map these to our topology:
      - Victim/server IPs -> 10.0.2.x (right rack, behind leaf2)
      - Client/benign IPs -> 10.0.1.x (left rack, behind leaf1)
      - Attacker IPs -> 192.168.x.x (spoofed, external)

    This mapping preserves the traffic patterns while fitting
    them into our leaf-spine topology.
    """
    if topology_subnets is None:
        topology_subnets = {
            'victim': ['10.0.2.1', '10.0.2.2', '10.0.2.3', '10.0.2.4'],
            'client': ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4'],
        }

    # Collect unique IPs
    all_ips = set()
    ip_roles = {}  # ip -> 'victim' | 'client' | 'attacker'

    for flow in flows:
        all_ips.add(flow.src_ip)
        all_ips.add(flow.dst_ip)
        if flow.is_attack:
            ip_roles[flow.src_ip] = 'attacker'
            ip_roles.setdefault(flow.dst_ip, 'victim')
        else:
            ip_roles.setdefault(flow.src_ip, 'client')
            ip_roles.setdefault(flow.dst_ip, 'client')

    # Build mapping
    mapping = {}
    victim_idx = 0
    client_idx = 0

    for ip in sorted(all_ips):
        role = ip_roles.get(ip, 'client')

        if role == 'victim':
            mapped = topology_subnets['victim'][
                victim_idx % len(topology_subnets['victim'])]
            victim_idx += 1
        elif role == 'client':
            mapped = topology_subnets['client'][
                client_idx % len(topology_subnets['client'])]
            client_idx += 1
        else:
            # Attacker IPs stay as-is (spoofed)
            mapped = ip

        mapping[ip] = mapped

    return mapping


# =====================================================================
# GROUND TRUTH EXTRACTION
# =====================================================================

def extract_ground_truth(flows: List[FlowRecord],
                         time_window_sec: float = 2.0,
                         num_epochs: int = 0) -> List[dict]:
    """Extract per-epoch ground truth from dataset flows.

    Groups flows into time windows matching MCP's epoch duration
    and labels each window with attack presence and type.

    For CSVs without timestamps (ML-CSV format), flows are
    distributed evenly across num_epochs epochs by row index.

    Returns list of:
      {'epoch': N, 'attack_active': bool, 'attack_types': [...],
       'attack_flows': N, 'benign_flows': N, 'total_packets': N}
    """
    # Sort flows by timestamp
    # CICIDS2017 timestamps are in format: "DD/MM/YYYY HH:MM:SS" or "DD/MM/YYYY HH:MM"
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

    # Try to parse timestamps
    timed_flows = []
    for flow in flows:
        ts = parse_ts(flow.timestamp)
        if ts:
            timed_flows.append((ts, flow))

    # Group into epochs
    epochs = defaultdict(lambda: {
        'attack_active': False, 'attack_types': set(),
        'attack_flows': 0, 'benign_flows': 0,
        'total_packets': 0, 'total_bytes': 0
    })

    if timed_flows:
        # Timestamp-based grouping
        timed_flows.sort(key=lambda x: x[0])
        t0 = timed_flows[0][0]
        indexed_flows = []
        for ts, flow in timed_flows:
            elapsed = (ts - t0).total_seconds()
            epoch = int(elapsed / time_window_sec)
            indexed_flows.append((epoch, flow))
    else:
        # No timestamps (ML-CSV format) — distribute flows evenly
        # across epochs based on row index. The CSV preserves
        # chronological ordering from the original capture.
        n_epochs = max(1, num_epochs) if num_epochs > 0 else 60
        flows_per_epoch = max(1, len(flows) // n_epochs)
        indexed_flows = []
        for i, flow in enumerate(flows):
            epoch = min(i // flows_per_epoch, n_epochs - 1)
            indexed_flows.append((epoch, flow))

    for epoch, flow in indexed_flows:

        if flow.is_attack:
            epochs[epoch]['attack_active'] = True
            epochs[epoch]['attack_types'].add(flow.label.strip())
            epochs[epoch]['attack_flows'] += 1
        else:
            epochs[epoch]['benign_flows'] += 1

        epochs[epoch]['total_packets'] += flow.total_packets
        epochs[epoch]['total_bytes'] += flow.total_bytes

    # Convert to sorted list
    max_epoch = max(epochs.keys()) if epochs else 0
    result = []
    for e in range(max_epoch + 1):
        ep = epochs.get(e, {
            'attack_active': False, 'attack_types': set(),
            'attack_flows': 0, 'benign_flows': 0,
            'total_packets': 0, 'total_bytes': 0
        })
        result.append({
            'epoch': e,
            'attack_active': ep['attack_active'],
            'attack_types': list(ep['attack_types']),
            'attack_flows': ep['attack_flows'],
            'benign_flows': ep['benign_flows'],
            'total_packets': ep['total_packets'],
            'total_bytes': ep['total_bytes'],
        })

    return result


# =====================================================================
# MAIN
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description='CICIDS2017 / InSDN dataset manager')
    parser.add_argument('--download', choices=['cicids2017', 'insdn', 'all'],
                        help='Download dataset files')
    parser.add_argument('--days', nargs='+',
                        default=CICIDS2017_RECOMMENDED,
                        help='CICIDS2017 days to download')
    parser.add_argument('--parse', help='Parse a CSV file and show stats')
    parser.add_argument('--max-flows', type=int, default=0,
                        help='Max flows to parse (0 = all)')
    parser.add_argument('--list', action='store_true',
                        help='List available datasets')
    args = parser.parse_args()

    if args.list:
        print("\n=== CICIDS2017 Dataset Files ===\n")
        for day, info in CICIDS2017_CSVS.items():
            marker = ' [RECOMMENDED]' if day in CICIDS2017_RECOMMENDED else ''
            print(f"  {day:25s} {info['description']}{marker}")
        print(f"\n  Download with: python3 {sys.argv[0]} --download cicids2017")
        return

    if args.download:
        if args.download in ('cicids2017', 'all'):
            download_cicids2017(args.days)

        if args.download in ('insdn', 'all'):
            print("\n=== InSDN ===")
            print("  InSDN dataset must be downloaded manually from:")
            print("  https://github.com/Taha-Adeel/InSDN-dataset")
            print("  or from Kaggle.")
            print(f"  Place CSV files in: {os.path.join(DATASET_DIR, 'insdn')}/")

    if args.parse:
        print(f"\n=== Parsing: {args.parse} ===\n")
        flows = parse_cicids2017_csv(args.parse, args.max_flows)
        stats = compute_stats(flows)

        print(f"  Total flows:    {stats.total_flows:,}")
        print(f"  Benign flows:   {stats.benign_flows:,}")
        print(f"  Attack flows:   {stats.attack_flows:,}")
        print(f"  Unique src IPs: {stats.unique_src_ips}")
        print(f"  Unique dst IPs: {stats.unique_dst_ips}")
        print(f"  Total packets:  {stats.total_packets:,}")
        print(f"  Total bytes:    {stats.total_bytes:,}")

        if stats.attack_types:
            print(f"\n  Attack types:")
            for attack, count in sorted(stats.attack_types.items(),
                                        key=lambda x: -x[1]):
                print(f"    {attack:30s} {count:>8,}")

        # Extract ground truth epochs
        gt = extract_ground_truth(flows)
        attack_epochs = [e for e in gt if e['attack_active']]
        print(f"\n  Ground truth epochs: {len(gt)} total, "
              f"{len(attack_epochs)} with attacks")
        if attack_epochs:
            first = attack_epochs[0]['epoch']
            last = attack_epochs[-1]['epoch']
            print(f"  Attack window: epoch {first} - {last}")


if __name__ == '__main__':
    main()
