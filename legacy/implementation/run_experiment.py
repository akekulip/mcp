#!/usr/bin/env python3
"""
run_experiment.py — Automated experiment runner for MCP evaluation

Runs the MCP controller (or a baseline) against a traffic scenario
and collects all metrics into structured JSON logs.

Usage:
    # Single experiment
    python3 run_experiment.py --scenario single_ddos --selector mcp

    # Compare all selectors on one scenario
    python3 run_experiment.py --scenario single_ddos --selector all

    # Full evaluation matrix
    python3 run_experiment.py --all

The topology must be running separately (make run-topo).
"""

import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'controller'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'datasets'))


SELECTORS = ['mcp', 'fixed_polling', 'adaptive_polling',
             'placement_only', 'centrality_sampling',
             'sketch_only', 'fixed_mcp']

SCENARIOS = {
    'steady': {
        'duration': 60, 'epochs': 30, 'attack_start': 999, 'attack_end': 999,
        'description': 'Constant normal traffic',
    },
    'flash': {
        'duration': 60, 'epochs': 30, 'attack_start': 999, 'attack_end': 999,
        'description': 'Normal then 3x rate spike',
    },
    'single_ddos': {
        'duration': 60, 'epochs': 30, 'attack_start': 10, 'attack_end': 15,
        'description': 'Normal + one SYN flood',
    },
    'multi_attack': {
        'duration': 90, 'epochs': 45, 'attack_start': 10, 'attack_end': 25,
        'description': 'Two overlapping DDoS attacks',
    },
    'resource_pressure': {
        'duration': 60, 'epochs': 30, 'attack_start': 10, 'attack_end': 15,
        'description': 'Attack with tight resource budgets',
        'extra_args': ['--budget-tcam', '50', '--budget-bw', '30',
                       '--budget-reg', '32768'],
    },
    # --- CICIDS2017 dataset-driven scenarios ---
    'cicids_wednesday': {
        'duration': 120, 'epochs': 60, 'attack_start': 0, 'attack_end': 0,
        'description': 'CICIDS2017 Wednesday — DoS attacks (dataset-driven)',
        'dataset': 'wednesday',
        'use_ground_truth': True,
    },
    'cicids_friday_ddos': {
        'duration': 120, 'epochs': 60, 'attack_start': 0, 'attack_end': 0,
        'description': 'CICIDS2017 Friday — DDoS LOIT (dataset-driven)',
        'dataset': 'friday_ddos',
        'use_ground_truth': True,
    },
    'cicids_friday_portscan': {
        'duration': 120, 'epochs': 60, 'attack_start': 0, 'attack_end': 0,
        'description': 'CICIDS2017 Friday — PortScan + DDoS (dataset-driven)',
        'dataset': 'friday_afternoon',
        'use_ground_truth': True,
    },
    'cicids_friday_botnet': {
        'duration': 120, 'epochs': 60, 'attack_start': 0, 'attack_end': 0,
        'description': 'CICIDS2017 Friday AM — Botnet (dataset-driven)',
        'dataset': 'friday',
        'use_ground_truth': True,
    },
}


def prepare_dataset_ground_truth(scenario, results_dir):
    """Generate ground truth JSON from a CICIDS2017 dataset CSV.

    Downloads the dataset if not present, parses flows, extracts
    per-epoch ground truth, and saves it for the MCP controller.

    Returns the path to the ground truth JSON, or None on failure.
    """
    from dataset_manager import (
        CICIDS2017_CSVS, DATASET_DIR,
        download_cicids2017, parse_cicids2017_csv,
        extract_ground_truth
    )

    day = scenario['dataset']
    if day not in CICIDS2017_CSVS:
        print(f"  ERROR: Unknown dataset day '{day}'")
        return None

    info = CICIDS2017_CSVS[day]
    csv_path = os.path.join(DATASET_DIR, 'cicids2017', info['filename'])

    # Download if missing
    if not os.path.exists(csv_path):
        print(f"  Dataset not found, downloading {day}...")
        download_cicids2017([day])

    if not os.path.exists(csv_path):
        print(f"  WARNING: Dataset not available, generating simulated ground truth")
        return _generate_simulated_gt(scenario, results_dir, day)

    # Parse and extract ground truth
    print(f"  Parsing dataset: {info['filename']}...")
    flows = parse_cicids2017_csv(csv_path, max_flows=100000)
    if not flows:
        print(f"  ERROR: No flows parsed from {csv_path}")
        return None

    epoch_sec = 2.0
    gt = extract_ground_truth(flows, epoch_sec, num_epochs=scenario['epochs'])
    n_epochs = min(scenario['epochs'], len(gt))
    gt = gt[:n_epochs]

    gt_path = os.path.join(results_dir, f'gt_{day}.json')
    with open(gt_path, 'w') as f:
        json.dump(gt, f, indent=2)

    n_attack = sum(1 for e in gt if e.get('attack_active'))
    print(f"  Ground truth: {len(gt)} epochs, {n_attack} with attacks")
    return gt_path


# Simulated attack windows matching CICIDS2017 day profiles
_SIMULATED_ATTACK_PROFILES = {
    'wednesday': [
        (15, 25, 'DoS Hulk'),
        (35, 45, 'DoS GoldenEye'),
    ],
    'friday_ddos': [
        (10, 30, 'DDoS'),
    ],
    'friday_afternoon': [
        (8, 18, 'PortScan'),
        (30, 45, 'DDoS'),
    ],
}


def _generate_simulated_gt(scenario, results_dir, day):
    """Generate simulated ground truth when dataset CSV is unavailable."""
    n_epochs = scenario['epochs']
    attacks = _SIMULATED_ATTACK_PROFILES.get(day, [(15, 25, 'Attack')])

    gt = []
    for e in range(n_epochs):
        active_types = [a[2] for a in attacks if a[0] <= e <= a[1]]
        attack = len(active_types) > 0
        gt.append({
            'epoch': e,
            'attack_active': attack,
            'attack_types': active_types,
            'attack_flows': 500 if attack else 0,
            'benign_flows': 100,
            'total_packets': 1000 if attack else 200,
            'total_bytes': 50000 if attack else 10000,
        })

    gt_path = os.path.join(results_dir, f'gt_{day}.json')
    with open(gt_path, 'w') as f:
        json.dump(gt, f, indent=2)

    n_attack = sum(1 for e in gt if e['attack_active'])
    print(f"  Simulated ground truth: {n_epochs} epochs, {n_attack} with attacks")
    return gt_path


def run_single_experiment(scenario_name, selector_name, dry_run=False,
                          verbose=False, results_dir='results'):
    """Run one (scenario, selector) experiment."""
    scenario = SCENARIOS[scenario_name]
    print(f"\n{'='*60}")
    print(f"  Experiment: {scenario_name} x {selector_name}")
    print(f"  {scenario['description']}")
    print(f"{'='*60}")

    os.makedirs(results_dir, exist_ok=True)

    # For dataset scenarios, prepare ground truth
    gt_path = None
    if scenario.get('use_ground_truth'):
        gt_path = prepare_dataset_ground_truth(scenario, results_dir)
        if not gt_path:
            print("  ERROR: Could not prepare dataset ground truth")
            return None

    # Build controller command
    cmd = [
        sys.executable,
        os.path.join(os.path.dirname(__file__), 'controller', 'mcp_controller.py'),
        '--selector', selector_name,
        '--epochs', str(scenario['epochs']),
        '--epoch-sec', '2.0',
        '--attack-start', str(scenario['attack_start']),
        '--attack-end', str(scenario['attack_end']),
        '--scenario-tag', scenario_name,
    ]

    # Use dataset ground truth if available
    if gt_path:
        cmd.extend(['--ground-truth', gt_path])

    if dry_run:
        cmd.append('--dry-run')
    if verbose:
        cmd.append('--verbose')

    # Add scenario-specific budget overrides
    if 'extra_args' in scenario:
        cmd.extend(scenario['extra_args'])

    # Run
    print(f"  Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=not verbose,
                           text=True, cwd=os.path.dirname(__file__))

    if result.returncode != 0:
        print(f"  ERROR: experiment failed (exit code {result.returncode})")
        if result.stderr:
            print(f"  stderr: {result.stderr[:500]}")
        return None

    # Load results — log file uses scenario_tag prefix
    log_path = os.path.join(results_dir,
                            f'mcp_log_{scenario_name}_{selector_name}.json')
    if os.path.exists(log_path):
        with open(log_path) as f:
            log = json.load(f)

        # Compute summary metrics
        summary = compute_summary(log, scenario_name, selector_name)

        # Save summary
        summary_path = os.path.join(
            results_dir, f'summary_{scenario_name}_{selector_name}.json')
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"\n  Results: {summary_path}")
        print(f"  Avg reward: {summary['avg_reward']:.3f}")
        print(f"  DDoS detections: {summary['ddos_true_positives']}")
        print(f"  False positives: {summary['ddos_false_positives']}")
        return summary

    return None


def compute_summary(log, scenario_name, selector_name):
    """Compute summary metrics from an experiment log.

    Covers all metrics required by the paper (Section 6, Requirement 1):
    - Per-task accuracy: DDoS (P/R/F1), HH detection rate, TM NRMSE
    - Detection latency: time-to-detect in epochs
    - Resource utilization: TCAM, BW, register, CPU
    - Reconfiguration churn
    - Composite reward
    """
    n = len(log)
    if n == 0:
        return {}

    avg_reward = sum(e['reward'] for e in log) / n
    avg_actions = sum(e['actions_deployed'] for e in log) / n

    # --- DDoS detection metrics ---
    tp = sum(1 for e in log if e.get('ddos_detected') and e.get('attack_active'))
    fp = sum(1 for e in log if e.get('ddos_detected') and not e.get('attack_active'))
    fn = sum(1 for e in log if not e.get('ddos_detected') and e.get('attack_active'))
    tn = sum(1 for e in log if not e.get('ddos_detected') and not e.get('attack_active'))

    ddos_prec = tp / max(tp + fp, 1)
    ddos_rec = tp / max(tp + fn, 1)
    ddos_f1 = (2 * ddos_prec * ddos_rec / max(ddos_prec + ddos_rec, 1e-9)
               if (ddos_prec + ddos_rec) > 0 else 0.0)

    # Time to detect: epochs from attack start to first detection
    attack_start_epoch = -1
    first_detect_epoch = -1
    for e in log:
        if e.get('attack_active') and attack_start_epoch < 0:
            attack_start_epoch = e['epoch']
        if e.get('attack_active') and e.get('ddos_detected') and first_detect_epoch < 0:
            first_detect_epoch = e['epoch']
    ttd = (first_detect_epoch - attack_start_epoch
           if attack_start_epoch >= 0 and first_detect_epoch >= 0 else -1)

    # --- Heavy hitter detection metrics ---
    attack_epochs = [e for e in log if e.get('attack_active')]
    n_attack = len(attack_epochs)
    hh_tp = sum(1 for e in attack_epochs if e.get('hh_detected', 0) > 0)
    hh_fp = sum(1 for e in log
                if not e.get('attack_active') and e.get('hh_detected', 0) > 0)
    hh_detection_rate = hh_tp / max(n_attack, 1)

    # --- Traffic matrix estimation ---
    poll_epochs = [e for e in log if e.get('tm_nrmse', 1.0) < 1.0]
    avg_nrmse = (sum(e['tm_nrmse'] for e in poll_epochs) / len(poll_epochs)
                 if poll_epochs else 1.0)
    tm_accuracy = 1.0 - avg_nrmse  # higher is better

    # --- Resource utilization ---
    avg_tcam = sum(e['budget_usage'].get('tcam', 0) for e in log) / n
    avg_bw = sum(e['budget_usage'].get('bw', 0) for e in log) / n
    avg_reg = sum(e['budget_usage'].get('reg', 0) for e in log) / n
    avg_cpu = sum(e['budget_usage'].get('cpu', 0) for e in log) / n

    # --- Churn ---
    avg_churn = (sum(e.get('churn', 0) for e in log) / n
                 if any('churn' in e for e in log) else 0.0)

    # --- HH detection latency ---
    hh_first_detect = -1
    for e in log:
        if (e['epoch'] >= attack_start_epoch >= 0
                and e.get('hh_detected', 0) > 0):
            hh_first_detect = e['epoch']
            break
    hh_ttd = (hh_first_detect - attack_start_epoch
              if attack_start_epoch >= 0 and hh_first_detect >= 0 else -1)

    # --- Adaptation latency: epochs from attack start to first plan change ---
    pre_attack_types = set()
    for e in log:
        if attack_start_epoch >= 0 and e['epoch'] < attack_start_epoch:
            pre_attack_types = set(e.get('action_types', []))
    adapt_ttd = -1
    for e in log:
        if attack_start_epoch >= 0 and e['epoch'] >= attack_start_epoch:
            current_types = set(e.get('action_types', []))
            if current_types != pre_attack_types:
                adapt_ttd = e['epoch'] - attack_start_epoch
                break

    # --- Control-plane overhead ---
    avg_latency = sum(e.get('elapsed_ms', 0) for e in log) / n

    # Estimated real-world overhead: per-action gRPC cost
    # watchlist/sample: ~1ms table write, sketch: ~0.5ms reg write, poll: ~2ms read
    grpc_cost = {'watchlist': 1.0, 'sketch': 0.5, 'sample': 1.0, 'poll': 2.0}
    est_overhead_ms = 0.0
    for e in log:
        for at in e.get('action_types', []):
            # Count actions of each type from task_breakdown is approximate
            est_overhead_ms += grpc_cost.get(at, 1.0)
    est_overhead_ms = est_overhead_ms / n

    # Shadow price evolution (MCP only)
    shadow_prices = [e.get('shadow_prices', {}) for e in log
                     if e.get('shadow_prices')]

    return {
        'scenario': scenario_name,
        'selector': selector_name,
        'epochs': n,
        'avg_reward': round(avg_reward, 4),
        'avg_actions': round(avg_actions, 1),
        # DDoS detection
        'ddos_true_positives': tp,
        'ddos_false_positives': fp,
        'ddos_false_negatives': fn,
        'ddos_true_negatives': tn,
        'ddos_precision': round(ddos_prec, 3),
        'ddos_recall': round(ddos_rec, 3),
        'ddos_f1': round(ddos_f1, 3),
        'time_to_detect_epochs': ttd,
        # HH detection
        'hh_detection_rate': round(hh_detection_rate, 3),
        'hh_false_positives': hh_fp,
        'hh_detection_latency': hh_ttd,
        # TM estimation
        'tm_accuracy': round(tm_accuracy, 3),
        'avg_tm_nrmse': round(avg_nrmse, 3),
        # Latency
        'adaptation_latency': adapt_ttd,
        'avg_latency_ms': round(avg_latency, 2),
        'est_overhead_ms': round(est_overhead_ms, 1),
        # Resource usage
        'avg_tcam_usage': round(avg_tcam, 1),
        'avg_bw_usage': round(avg_bw, 1),
        'avg_reg_usage': round(avg_reg, 1),
        'avg_cpu_usage': round(avg_cpu, 1),
        # Churn and latency
        'avg_churn': round(avg_churn, 3),
        'shadow_price_samples': len(shadow_prices),
    }


def run_all_experiments(dry_run=False, verbose=False):
    """Run the full evaluation matrix: all scenarios x all selectors."""
    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(results_dir, exist_ok=True)

    all_summaries = []
    for scenario in SCENARIOS:
        for selector in SELECTORS:
            summary = run_single_experiment(
                scenario, selector, dry_run, verbose, results_dir)
            if summary:
                all_summaries.append(summary)

    # Save combined results
    combined_path = os.path.join(results_dir, 'all_results.json')
    with open(combined_path, 'w') as f:
        json.dump(all_summaries, f, indent=2)
    print(f"\n\n=== All results saved to {combined_path} ===")
    print(f"  Total experiments: {len(all_summaries)}")


def main():
    parser = argparse.ArgumentParser(
        description='MCP experiment runner')
    parser.add_argument('--scenario', choices=list(SCENARIOS.keys()),
                        help='Scenario to run')
    parser.add_argument('--selector', default='mcp',
                        help='Selector (or "all" for all baselines)')
    parser.add_argument('--all', action='store_true',
                        help='Run full evaluation matrix')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()

    results_dir = os.path.join(os.path.dirname(__file__), 'results')
    os.makedirs(results_dir, exist_ok=True)

    if args.all:
        run_all_experiments(args.dry_run, args.verbose)
    elif args.scenario:
        if args.selector == 'all':
            for sel in SELECTORS:
                run_single_experiment(
                    args.scenario, sel, args.dry_run, args.verbose, results_dir)
        else:
            run_single_experiment(
                args.scenario, args.selector, args.dry_run,
                args.verbose, results_dir)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
