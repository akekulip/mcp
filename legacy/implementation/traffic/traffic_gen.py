#!/usr/bin/env python3
"""
traffic_gen.py — Traffic generator for MCP experiments

Generates traffic with ground-truth logging for evaluation:

Scenarios:
  1. steady     — constant normal traffic (120s)
  2. flash      — normal then 3x rate increase (80s)
  3. single_ddos — normal + one SYN flood (60s)
  4. multi_attack — two overlapping DDoS from different sources (90s)
  5. resource_pressure — normal + attack under tight budgets (60s)
  6. mixed      — the original: normal -> attack -> recovery (60s)

Each run produces a ground-truth CSV log for evaluation.

Usage:
    python3 traffic/traffic_gen.py --scenario single_ddos --iface eth0
    python3 traffic/traffic_gen.py --scenario mixed --duration 60
"""

import argparse
import csv
import os
import random
import sys
import time
import threading

try:
    from scapy.all import (
        IP, TCP, UDP, Ether, Raw,
        sendp, conf
    )
    conf.verb = 0
except ImportError:
    print("ERROR: scapy not found. Install with: pip install scapy")
    sys.exit(1)


class GroundTruthLogger:
    """Logs all sent packets with labels for evaluation."""

    def __init__(self, log_path):
        self.log_path = log_path
        self._lock = threading.Lock()
        self._file = open(log_path, 'w', newline='')
        self._writer = csv.writer(self._file)
        self._writer.writerow([
            'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'size', 'label'
        ])

    def log(self, src_ip, dst_ip, src_port, dst_port, proto, size, label):
        with self._lock:
            self._writer.writerow([
                f'{time.time():.6f}', src_ip, dst_ip,
                src_port, dst_port, proto, size, label
            ])

    def close(self):
        self._file.close()


class AttackTimeline:
    """Tracks attack start/end times for ground truth."""

    def __init__(self):
        self.events = []

    def record(self, event_type, epoch, source, target):
        self.events.append({
            'time': time.time(),
            'type': event_type,  # 'attack_start' | 'attack_end'
            'epoch': epoch,
            'source': source,
            'target': target,
        })

    def save(self, path):
        import json
        with open(path, 'w') as f:
            json.dump(self.events, f, indent=2)


def generate_normal_traffic(src_ip, dst_ip, interface='eth0',
                            duration=30, rate_pps=100,
                            logger=None):
    """Generate normal data center traffic (mice + elephant flows)."""
    print(f"[normal] {src_ip} -> {dst_ip}, {rate_pps} pps, "
          f"{duration}s on {interface}")

    end_time = time.time() + duration
    pkt_count = 0
    interval = 1.0 / rate_pps

    while time.time() < end_time:
        if random.random() < 0.8:
            n_pkts = random.randint(1, 5)
            payload_size = random.randint(64, 256)
        else:
            n_pkts = random.randint(10, 50)
            payload_size = random.randint(512, 1400)

        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 8080, 3306, 6379])

        for i in range(n_pkts):
            if time.time() >= end_time:
                break

            pkt = (Ether() /
                   IP(src=src_ip, dst=dst_ip, ttl=64) /
                   TCP(sport=sport, dport=dport,
                       flags='A' if i > 0 else 'S') /
                   Raw(b'X' * payload_size))

            try:
                sendp(pkt, iface=interface, verbose=False)
                pkt_count += 1
                if logger:
                    logger.log(src_ip, dst_ip, sport, dport,
                              'TCP', payload_size, 'normal')
            except Exception:
                pass

            time.sleep(interval)

    print(f"[normal] Done. Sent {pkt_count} packets.")


def generate_attack_traffic(src_ip, dst_ip, interface='eth0',
                            duration=10, rate_pps=1000,
                            spoofed_prefix='192.168',
                            logger=None, timeline=None):
    """Generate DDoS-like SYN flood traffic."""
    print(f"[ATTACK] SYN flood -> {dst_ip}, {rate_pps} pps, "
          f"{duration}s on {interface}")

    if timeline:
        timeline.record('attack_start', -1, spoofed_prefix, dst_ip)

    end_time = time.time() + duration
    pkt_count = 0
    interval = 1.0 / rate_pps

    while time.time() < end_time:
        spoofed_src = (f"{spoofed_prefix}."
                       f"{random.randint(1,254)}.{random.randint(1,254)}")
        sport = random.randint(1024, 65535)

        pkt = (Ether() /
               IP(src=spoofed_src, dst=dst_ip, ttl=64) /
               TCP(sport=sport, dport=80, flags='S') /
               Raw(b'\x00' * 64))

        try:
            sendp(pkt, iface=interface, verbose=False)
            pkt_count += 1
            if logger:
                logger.log(spoofed_src, dst_ip, sport, 80,
                          'TCP', 64, 'attack')
        except Exception:
            pass

        time.sleep(interval)

    if timeline:
        timeline.record('attack_end', -1, spoofed_prefix, dst_ip)

    print(f"[ATTACK] Done. Sent {pkt_count} attack packets.")


# =====================================================================
# SCENARIOS
# =====================================================================

def scenario_steady(interface, duration, logger, timeline):
    """Scenario 1: Constant normal traffic."""
    print(f"\n=== SCENARIO: steady (normal traffic, {duration}s) ===")
    generate_normal_traffic('10.0.1.1', '10.0.2.1', interface,
                           duration, 100, logger)


def scenario_flash(interface, duration, logger, timeline):
    """Scenario 2: Normal then 3x rate spike."""
    print(f"\n=== SCENARIO: flash crowd ({duration}s) ===")
    half = duration // 2

    # Phase 1: normal rate
    print(f"  Phase 1: normal rate (0-{half}s)")
    generate_normal_traffic('10.0.1.1', '10.0.2.1', interface,
                           half, 100, logger)

    # Phase 2: 3x rate
    print(f"  Phase 2: flash crowd ({half}-{duration}s)")
    generate_normal_traffic('10.0.1.1', '10.0.2.1', interface,
                           half, 300, logger)


def scenario_single_ddos(interface, duration, logger, timeline):
    """Scenario 3: Normal + one DDoS attack."""
    print(f"\n=== SCENARIO: single_ddos ({duration}s) ===")
    print("  0-20s: normal, 20-30s: normal + attack, 30-60s: recovery")

    normal_thread = threading.Thread(
        target=generate_normal_traffic,
        args=('10.0.1.1', '10.0.2.1', interface, duration, 50, logger))
    normal_thread.daemon = True
    normal_thread.start()

    time.sleep(20)
    print("\n*** ATTACK PHASE ***")
    attack_thread = threading.Thread(
        target=generate_attack_traffic,
        args=('10.0.1.3', '10.0.2.1', interface, 10, 500,
              '192.168', logger, timeline))
    attack_thread.start()
    attack_thread.join()
    print("*** ATTACK ENDED ***\n")

    normal_thread.join()


def scenario_multi_attack(interface, duration, logger, timeline):
    """Scenario 4: Two overlapping DDoS attacks."""
    print(f"\n=== SCENARIO: multi_attack ({duration}s) ===")
    print("  0-20s: normal, 20-40s: attack1, 30-50s: attack2, 50-90s: recovery")

    normal_thread = threading.Thread(
        target=generate_normal_traffic,
        args=('10.0.1.1', '10.0.2.1', interface, duration, 50, logger))
    normal_thread.daemon = True
    normal_thread.start()

    # Attack 1: from 192.168.x.x -> 10.0.2.1
    time.sleep(20)
    print("\n*** ATTACK 1 ***")
    a1 = threading.Thread(
        target=generate_attack_traffic,
        args=('10.0.1.3', '10.0.2.1', interface, 20, 500,
              '192.168', logger, timeline))
    a1.start()

    # Attack 2: from 172.16.x.x -> 10.0.2.2 (different target)
    time.sleep(10)
    print("\n*** ATTACK 2 ***")
    a2 = threading.Thread(
        target=generate_attack_traffic,
        args=('10.0.1.4', '10.0.2.2', interface, 20, 300,
              '172.16', logger, timeline))
    a2.start()

    a1.join()
    a2.join()
    print("*** ALL ATTACKS ENDED ***\n")

    normal_thread.join()


def scenario_resource_pressure(interface, duration, logger, timeline):
    """Scenario 5: Normal + attack with tight budgets."""
    print(f"\n=== SCENARIO: resource_pressure ({duration}s) ===")
    # Same as single_ddos but controller should be run with tight budgets
    scenario_single_ddos(interface, duration, logger, timeline)


def scenario_mixed(interface, duration, logger, timeline):
    """Scenario 6: Original mixed scenario."""
    print(f"\n=== SCENARIO: mixed ({duration}s) ===")
    scenario_single_ddos(interface, duration, logger, timeline)


SCENARIOS = {
    'steady': scenario_steady,
    'flash': scenario_flash,
    'single_ddos': scenario_single_ddos,
    'multi_attack': scenario_multi_attack,
    'resource_pressure': scenario_resource_pressure,
    'mixed': scenario_mixed,
}


def main():
    parser = argparse.ArgumentParser(
        description='Traffic generator for MCP experiments')
    parser.add_argument('--scenario', choices=list(SCENARIOS.keys()),
                        default='single_ddos',
                        help='Traffic scenario to run')
    parser.add_argument('--iface', default='eth0')
    parser.add_argument('--duration', type=int, default=60)
    parser.add_argument('--log-dir', default=None,
                        help='Directory for ground truth logs')
    args = parser.parse_args()

    # Setup logging
    log_dir = args.log_dir or os.path.join(
        os.path.dirname(__file__), '..', 'results')
    os.makedirs(log_dir, exist_ok=True)

    log_path = os.path.join(log_dir,
                            f'traffic_{args.scenario}.csv')
    timeline_path = os.path.join(log_dir,
                                  f'timeline_{args.scenario}.json')

    logger = GroundTruthLogger(log_path)
    timeline = AttackTimeline()

    print(f"Ground truth log: {log_path}")

    try:
        SCENARIOS[args.scenario](args.iface, args.duration,
                                 logger, timeline)
    finally:
        logger.close()
        timeline.save(timeline_path)
        print(f"\nGround truth saved to {log_path}")
        print(f"Timeline saved to {timeline_path}")


if __name__ == '__main__':
    main()
