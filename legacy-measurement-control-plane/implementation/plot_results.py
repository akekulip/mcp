#!/usr/bin/env python3
"""
plot_results.py — Publication-quality plots for MCP evaluation

Generates 4 focused figures matching the paper's evaluation metrics
(Section 6, Requirement 1):
  Fig 1: Multi-metric comparison (DDoS F1, HH detection, TM accuracy,
         resource usage, churn, reward) — the main result figure
  Fig 2: Scenario × Selector heatmap — overview of all results
  Fig 3: Detection timeline — temporal behavior under attack
  Fig 4: Shadow price convergence — MCP's adaptive mechanism

Usage:
    python3 plot_results.py
    python3 plot_results.py --results-dir DIR
"""

import argparse
import glob
import json
import os
import sys

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:
    print("ERROR: matplotlib/numpy required. Install with:")
    print("  pip install matplotlib numpy")
    sys.exit(1)


# =====================================================================
# STYLE
# =====================================================================

plt.rcParams.update({
    'font.family': 'serif',
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'legend.fontsize': 9,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.05,
    'axes.grid': True,
    'grid.alpha': 0.25,
    'grid.linestyle': '--',
    'axes.spines.top': False,
    'axes.spines.right': False,
    'lines.linewidth': 1.8,
    'lines.markersize': 6,
    'legend.framealpha': 0.9,
    'legend.edgecolor': '0.8',
})

DPI = 300

COLORS = {
    'mcp':                  '#1f77b4',
    'fixed_polling':        '#7f7f7f',
    'adaptive_polling':     '#ff7f0e',
    'placement_only':       '#2ca02c',
    'centrality_sampling':  '#d62728',
    'sketch_only':          '#9467bd',
    'fixed_mcp':            '#17becf',
}

LABELS = {
    'mcp':                  'MCP',
    'fixed_polling':        'Fixed Poll',
    'adaptive_polling':     'Adapt. Poll',
    'placement_only':       'Placement',
    'centrality_sampling':  'Centrality',
    'sketch_only':          'Sketch Only',
    'fixed_mcp':            'Fixed MCP',
}

SCENARIO_LABELS = {
    'steady':               'Steady',
    'flash':                'Flash Crowd',
    'single_ddos':          'Single DDoS',
    'multi_attack':         'Multi-Attack',
    'resource_pressure':    'Resource Press.',
    'cicids_wednesday':     'CICIDS Wed',
    'cicids_friday_ddos':   'CICIDS Fri DDoS',
    'cicids_friday_portscan': 'CICIDS Fri Scan',
    'cicids_friday_botnet': 'CICIDS Fri Bot',
}

SELECTOR_ORDER = [
    'mcp', 'fixed_mcp', 'sketch_only', 'centrality_sampling',
    'adaptive_polling', 'fixed_polling', 'placement_only',
]


# =====================================================================
# DATA LOADING
# =====================================================================

def load_results(results_dir):
    """Load all summary JSON files."""
    combined_path = os.path.join(results_dir, 'all_results.json')
    if os.path.exists(combined_path):
        with open(combined_path) as f:
            return json.load(f)

    results = []
    for fname in sorted(os.listdir(results_dir)):
        if fname.startswith('summary_') and fname.endswith('.json'):
            with open(os.path.join(results_dir, fname)) as f:
                results.append(json.load(f))
    return results


def load_all_logs(results_dir):
    """Load all per-experiment log files."""
    logs = {}
    for fpath in sorted(glob.glob(os.path.join(results_dir, 'mcp_log_*.json'))):
        fname = os.path.basename(fpath)
        key = fname.replace('mcp_log_', '').replace('.json', '')
        with open(fpath) as f:
            logs[key] = json.load(f)
    return logs


def extract_selector(key):
    """Extract selector name from log key."""
    for sel in SELECTOR_ORDER:
        if key.endswith('_' + sel):
            return sel
    return key


def aggregate_by_selector(results, scenarios=None):
    """Average metrics across scenarios for each selector."""
    from collections import defaultdict
    agg = defaultdict(lambda: defaultdict(list))
    for r in results:
        if scenarios and r['scenario'] not in scenarios:
            continue
        sel = r['selector']
        for k, v in r.items():
            if isinstance(v, (int, float)):
                agg[sel][k].append(v)

    out = {}
    for sel, metrics in agg.items():
        out[sel] = {k: np.mean(v) for k, v in metrics.items()}
    return out


# =====================================================================
# FIGURE 1: MULTI-METRIC COMPARISON (main result)
# =====================================================================

def plot_multimetric(results, output_dir):
    """2×3 grid of bar charts showing all paper-required metrics.

    Metrics averaged across attack scenarios (where detection matters).
    """
    attack_scenarios = [
        'single_ddos', 'multi_attack', 'cicids_wednesday',
        'cicids_friday_ddos', 'cicids_friday_botnet',
    ]
    agg = aggregate_by_selector(results, scenarios=attack_scenarios)
    if not agg:
        return

    selectors = [s for s in SELECTOR_ORDER if s in agg]
    x = np.arange(len(selectors))
    w = 0.6

    metrics = [
        ('ddos_f1',           'DDoS F1 Score',        (0, 1.05)),
        ('hh_detection_rate', 'HH Detection Rate',    (0, 1.05)),
        ('tm_accuracy',       'TM Accuracy (1-NRMSE)', (0, 1.05)),
        ('avg_bw_usage',      'Avg BW Usage',          None),
        ('avg_churn',         'Avg Plan Churn',        (0, 0.2)),
        ('avg_reward',        'Avg Reward',            (0, 0.7)),
    ]

    fig, axes = plt.subplots(2, 3, figsize=(14, 7))
    axes = axes.flatten()

    for idx, (key, title, ylim) in enumerate(metrics):
        ax = axes[idx]
        vals = [agg[s].get(key, 0) for s in selectors]

        # For TTD, -1 means no detection — show as max
        if key == 'time_to_detect_epochs':
            vals = [v if v >= 0 else max(15, max(v2 for v2 in vals if v2 >= 0) * 1.2)
                    for v in vals]

        bars = ax.bar(x, vals, w, color=[COLORS[s] for s in selectors],
                      edgecolor='white', linewidth=0.5)

        # Highlight MCP bar
        if 'mcp' in selectors:
            mcp_idx = selectors.index('mcp')
            bars[mcp_idx].set_edgecolor('black')
            bars[mcp_idx].set_linewidth(1.5)

        # Value labels
        for bar, v in zip(bars, vals):
            h = bar.get_height()
            fmt = f'{v:.2f}' if isinstance(v, float) and v < 10 else f'{v:.0f}'
            ax.text(bar.get_x() + w / 2, h + 0.01 * (ylim[1] if ylim else max(vals) * 1.1),
                    fmt, ha='center', va='bottom', fontsize=7)

        ax.set_xticks(x)
        ax.set_xticklabels([LABELS[s] for s in selectors],
                           rotation=40, ha='right', fontsize=8)
        ax.set_title(title, fontsize=11)
        if ylim:
            ax.set_ylim(ylim)

    fig.suptitle('Fig. 1: Multi-Metric Comparison (averaged over attack scenarios)',
                 fontsize=13, y=1.02)
    plt.tight_layout()
    path = os.path.join(output_dir, 'fig1_multimetric.png')
    plt.savefig(path, dpi=DPI)
    plt.close()
    print(f"  Saved: {path}")


# =====================================================================
# FIGURE 2: HEATMAP — scenario × selector reward
# =====================================================================

def plot_heatmap(results, output_dir):
    """Heatmap of avg reward across all (scenario, selector) pairs."""
    scenarios = sorted(set(r['scenario'] for r in results),
                       key=lambda s: list(SCENARIO_LABELS.keys()).index(s)
                       if s in SCENARIO_LABELS else 99)
    selectors = [s for s in SELECTOR_ORDER
                 if s in set(r['selector'] for r in results)]

    if len(scenarios) < 2 or len(selectors) < 2:
        return

    matrix = np.zeros((len(scenarios), len(selectors)))
    for r in results:
        i = scenarios.index(r['scenario'])
        j = selectors.index(r['selector'])
        matrix[i, j] = r['avg_reward']

    fig, ax = plt.subplots(figsize=(max(8, len(selectors) * 1.1),
                                     max(4, len(scenarios) * 0.55)))

    vmin = max(0.0, matrix.min() - 0.03)
    vmax = min(1.0, matrix.max() + 0.03)
    im = ax.imshow(matrix, cmap='RdYlGn', aspect='auto',
                    vmin=vmin, vmax=vmax)

    # Annotate — bold for best per row
    row_maxes = matrix.max(axis=1)
    for i in range(len(scenarios)):
        for j in range(len(selectors)):
            val = matrix[i, j]
            is_best = abs(val - row_maxes[i]) < 0.001
            mid = (vmin + vmax) / 2
            color = 'white' if val < mid else 'black'
            weight = 'bold' if is_best else 'normal'
            ax.text(j, i, f'{val:.3f}', ha='center', va='center',
                     fontsize=9, color=color, fontweight=weight)

    ax.set_xticks(range(len(selectors)))
    ax.set_xticklabels([LABELS.get(s, s) for s in selectors],
                        rotation=40, ha='right', fontsize=9)
    ax.set_yticks(range(len(scenarios)))
    ax.set_yticklabels([SCENARIO_LABELS.get(s, s) for s in scenarios],
                        fontsize=9)

    fig.colorbar(im, ax=ax, shrink=0.8, label='Avg Reward')
    ax.set_title('Fig. 2: Reward Heatmap — Scenario × Selector',
                 fontsize=12, pad=15)
    plt.tight_layout()
    path = os.path.join(output_dir, 'fig2_heatmap.png')
    plt.savefig(path, dpi=DPI)
    plt.close()
    print(f"  Saved: {path}")


# =====================================================================
# FIGURE 3: DETECTION TIMELINE — all selectors on one scenario
# =====================================================================

def plot_timeline(logs, output_dir, scenario='multi_attack'):
    """Detection timeline: attack window vs detection per selector."""
    # Group logs by selector for this scenario
    sel_logs = {}
    for key, log in logs.items():
        if not key.startswith(scenario + '_'):
            continue
        sel = extract_selector(key)
        sel_logs[sel] = log

    if len(sel_logs) < 2:
        # Try single_ddos as fallback
        for key, log in logs.items():
            if key.startswith('single_ddos_'):
                sel = extract_selector(key)
                sel_logs[sel] = log
        scenario = 'single_ddos'

    if len(sel_logs) < 2:
        return

    ordered = [(s, sel_logs[s]) for s in SELECTOR_ORDER if s in sel_logs]
    n = len(ordered)

    fig, axes = plt.subplots(n, 1, figsize=(10, 1.6 * n + 1), sharex=True)
    if n == 1:
        axes = [axes]

    for idx, (sel, log) in enumerate(ordered):
        ax = axes[idx]
        epochs = [e['epoch'] for e in log]
        attack = [e.get('attack_active', False) for e in log]
        ddos = [e.get('ddos_detected', False) for e in log]
        hh = [e.get('hh_detected', 0) > 0 for e in log]

        # Attack ground truth — red shading
        ax.fill_between(epochs, 0, 1,
                        where=attack, alpha=0.2, color='#d62728',
                        step='mid')

        # DDoS detection — blue markers
        for ep, d, a in zip(epochs, ddos, attack):
            if d:
                color = COLORS['mcp'] if a else '#d62728'
                ax.axvline(ep, color=color, alpha=0.8, linewidth=2.5)

        # HH detection — small green markers on top
        for ep, h, a in zip(epochs, hh, attack):
            if h:
                ax.plot(ep, 0.85, marker='v', color='#2ca02c',
                        markersize=5, zorder=5)

        # Metrics annotation
        tp = sum(1 for e in log if e.get('ddos_detected') and e.get('attack_active'))
        fp = sum(1 for e in log if e.get('ddos_detected') and not e.get('attack_active'))
        reward = sum(e['reward'] for e in log) / len(log)
        n_hh = sum(1 for e in log if e.get('hh_detected', 0) > 0 and e.get('attack_active'))

        ax.text(0.99, 0.5,
                f'R={reward:.3f}  DDoS:{tp}TP/{fp}FP  HH:{n_hh}',
                transform=ax.transAxes, fontsize=8, ha='right', va='center',
                bbox=dict(boxstyle='round,pad=0.3', facecolor='white',
                          alpha=0.85, edgecolor='grey'))

        ax.set_ylabel(LABELS.get(sel, sel), fontsize=9,
                      rotation=0, ha='right', va='center', labelpad=60)
        ax.set_yticks([])
        ax.set_ylim(0, 1)

    axes[-1].set_xlabel('Epoch')
    sc_label = SCENARIO_LABELS.get(scenario, scenario)
    fig.suptitle(f'Fig. 3: Detection Timeline — {sc_label}\n'
                 '(red shading = attack, blue bars = DDoS detection, '
                 'green ▾ = HH detection)',
                 fontsize=11, y=1.03)
    plt.tight_layout()
    path = os.path.join(output_dir, 'fig3_timeline.png')
    plt.savefig(path, dpi=DPI)
    plt.close()
    print(f"  Saved: {path}")


# =====================================================================
# FIGURE 4: SHADOW PRICE + RESOURCE ADAPTATION
# =====================================================================

def plot_shadow_and_resources(logs, output_dir):
    """Shadow price convergence + resource adaptation for MCP.

    Shows how MCP adapts its resource allocation in response to
    changing conditions (attack onset/offset).
    """
    # Find MCP logs with shadow prices
    mcp_logs = {}
    for k, v in logs.items():
        if k.endswith('_mcp') and not k.endswith('_fixed_mcp'):
            if v and any(e.get('shadow_prices') for e in v):
                mcp_logs[k] = v

    if not mcp_logs:
        return

    # Pick scenarios that show interesting behavior
    preferred = ['multi_attack_mcp', 'single_ddos_mcp',
                 'cicids_wednesday_mcp', 'cicids_friday_ddos_mcp']
    keys = [k for k in preferred if k in mcp_logs]
    if not keys:
        keys = list(mcp_logs.keys())[:4]
    keys = keys[:4]

    fig, axes = plt.subplots(2, len(keys), figsize=(4 * len(keys), 6),
                              squeeze=False)

    sp_colors = {'tcam': '#1f77b4', 'bw': '#ff7f0e',
                 'reg': '#2ca02c', 'cpu': '#d62728'}
    sp_labels = {'tcam': 'λ_TCAM', 'bw': 'λ_BW',
                 'reg': 'λ_REG', 'cpu': 'λ_CPU'}

    for col, key in enumerate(keys):
        log = mcp_logs[key]
        epochs = [e['epoch'] for e in log]
        attack = [e.get('attack_active', False) for e in log]

        # Top row: shadow prices
        ax_top = axes[0, col]
        shadow = [e.get('shadow_prices', {}) for e in log]
        plotted = False
        for res_key in ['bw', 'tcam', 'reg', 'cpu']:
            vals = [s.get(res_key, 0) for s in shadow]
            if any(v > 0.001 for v in vals):
                ax_top.plot(epochs, vals, linewidth=1.5,
                           color=sp_colors[res_key],
                           label=sp_labels[res_key])
                plotted = True

        # Attack shading
        ax_top.fill_between(epochs, 0, ax_top.get_ylim()[1] or 0.1,
                           where=attack, alpha=0.1, color='#d62728',
                           step='mid')

        scenario = key.replace('_mcp', '')
        ax_top.set_title(SCENARIO_LABELS.get(scenario, scenario), fontsize=10)
        if col == 0:
            ax_top.set_ylabel('Shadow Price λ')
        if plotted:
            ax_top.legend(fontsize=7, loc='upper right')

        # Bottom row: resource usage
        ax_bot = axes[1, col]
        bw = [e['budget_usage'].get('bw', 0) for e in log]
        tcam = [e['budget_usage'].get('tcam', 0) for e in log]
        ax_bot.plot(epochs, bw, linewidth=1.5, color='#ff7f0e', label='BW')
        ax_bot.plot(epochs, tcam, linewidth=1.5, color='#1f77b4', label='TCAM')

        ax_bot.fill_between(epochs, 0, max(max(bw), max(tcam)) * 1.1,
                           where=attack, alpha=0.1, color='#d62728',
                           step='mid')

        ax_bot.set_xlabel('Epoch')
        if col == 0:
            ax_bot.set_ylabel('Resource Usage')
        ax_bot.legend(fontsize=7, loc='upper right')

    fig.suptitle('Fig. 4: Shadow Price Convergence and Resource Adaptation (MCP)',
                 fontsize=12, y=1.02)
    plt.tight_layout()
    path = os.path.join(output_dir, 'fig4_shadow_resources.png')
    plt.savefig(path, dpi=DPI)
    plt.close()
    print(f"  Saved: {path}")


# =====================================================================
# FIGURE 5: LATENCY COMPARISON
# =====================================================================

def plot_latency(results, logs, output_dir):
    """Latency comparison: adaptation latency, HH detection latency,
    and estimated control-plane overhead.

    These are the metrics the paper's utility function Lat_t captures.
    """
    attack_scenarios = [
        'single_ddos', 'multi_attack', 'cicids_wednesday',
        'cicids_friday_ddos', 'cicids_friday_botnet',
    ]
    agg = aggregate_by_selector(results, scenarios=attack_scenarios)
    if not agg:
        return

    selectors = [s for s in SELECTOR_ORDER if s in agg]
    x = np.arange(len(selectors))
    w = 0.6

    fig, axes = plt.subplots(1, 3, figsize=(14, 4.5))

    # (a) Adaptation latency
    ax = axes[0]
    vals = []
    for s in selectors:
        v = agg[s].get('adaptation_latency', -1)
        vals.append(v if v >= 0 else 20)  # show "never" as high bar
    bars = ax.bar(x, vals, w, color=[COLORS[s] for s in selectors],
                  edgecolor='white', linewidth=0.5)
    # Mark "never adapts" bars
    for i, v in enumerate(vals):
        orig = agg[selectors[i]].get('adaptation_latency', -1)
        label = f'{orig:.0f}' if orig >= 0 else 'never'
        ax.text(x[i], v + 0.3, label, ha='center', va='bottom', fontsize=8)
    if 'mcp' in selectors:
        bars[selectors.index('mcp')].set_edgecolor('black')
        bars[selectors.index('mcp')].set_linewidth(1.5)
    ax.set_xticks(x)
    ax.set_xticklabels([LABELS[s] for s in selectors],
                       rotation=40, ha='right', fontsize=8)
    ax.set_title('(a) Adaptation Latency\n(epochs to first plan change)', fontsize=10)
    ax.set_ylabel('Epochs')

    # (b) HH detection latency
    ax = axes[1]
    vals = []
    for s in selectors:
        v = agg[s].get('hh_detection_latency', -1)
        vals.append(v if v >= 0 else 20)
    bars = ax.bar(x, vals, w, color=[COLORS[s] for s in selectors],
                  edgecolor='white', linewidth=0.5)
    for i, v in enumerate(vals):
        orig = agg[selectors[i]].get('hh_detection_latency', -1)
        label = f'{orig:.0f}' if orig >= 0 else 'never'
        ax.text(x[i], v + 0.3, label, ha='center', va='bottom', fontsize=8)
    if 'mcp' in selectors:
        bars[selectors.index('mcp')].set_edgecolor('black')
        bars[selectors.index('mcp')].set_linewidth(1.5)
    ax.set_xticks(x)
    ax.set_xticklabels([LABELS[s] for s in selectors],
                       rotation=40, ha='right', fontsize=8)
    ax.set_title('(b) HH Detection Latency\n(epochs from attack to first HH)', fontsize=10)
    ax.set_ylabel('Epochs')

    # (c) Estimated control-plane overhead
    ax = axes[2]
    vals = [agg[s].get('est_overhead_ms', 0) for s in selectors]
    bars = ax.bar(x, vals, w, color=[COLORS[s] for s in selectors],
                  edgecolor='white', linewidth=0.5)
    for bar, v in zip(bars, vals):
        ax.text(bar.get_x() + w / 2, v + 0.1, f'{v:.1f}',
                ha='center', va='bottom', fontsize=8)
    if 'mcp' in selectors:
        bars[selectors.index('mcp')].set_edgecolor('black')
        bars[selectors.index('mcp')].set_linewidth(1.5)
    ax.set_xticks(x)
    ax.set_xticklabels([LABELS[s] for s in selectors],
                       rotation=40, ha='right', fontsize=8)
    ax.set_title('(c) Est. Control-Plane Overhead\n(ms per epoch, gRPC cost model)',
                 fontsize=10)
    ax.set_ylabel('Milliseconds')

    fig.suptitle('Fig. 5: Latency Comparison', fontsize=13, y=1.02)
    plt.tight_layout()
    path = os.path.join(output_dir, 'fig5_latency.png')
    plt.savefig(path, dpi=DPI)
    plt.close()
    print(f"  Saved: {path}")


# =====================================================================
# SUMMARY TABLE
# =====================================================================

def print_summary_table(results):
    """Print formatted summary table to stdout."""
    print(f"\n{'='*110}")
    print(f"  {'Scenario':<18} {'Selector':<14} {'Reward':>7} "
          f"{'DDoS F1':>8} {'TTD':>4} {'HH Det':>7} {'TM Acc':>7} "
          f"{'BW':>5} {'TCAM':>5} {'Churn':>6}")
    print(f"{'='*110}")

    for scenario in sorted(set(r['scenario'] for r in results),
                           key=lambda s: list(SCENARIO_LABELS.keys()).index(s)
                           if s in SCENARIO_LABELS else 99):
        sc_results = sorted(
            [r for r in results if r['scenario'] == scenario],
            key=lambda r: -r['avg_reward'])
        for r in sc_results:
            sc = SCENARIO_LABELS.get(r['scenario'], r['scenario'])[:17]
            sel = LABELS.get(r['selector'], r['selector'])[:13]
            marker = '>' if r['selector'] == 'mcp' else ' '
            print(f"{marker} {sc:<17} {sel:<13} {r['avg_reward']:>7.3f} "
                  f"{r.get('ddos_f1', 0):>8.3f} "
                  f"{r.get('time_to_detect_epochs', -1):>4d} "
                  f"{r.get('hh_detection_rate', 0):>7.3f} "
                  f"{r.get('tm_accuracy', 0):>7.3f} "
                  f"{r.get('avg_bw_usage', 0):>5.0f} "
                  f"{r.get('avg_tcam_usage', 0):>5.0f} "
                  f"{r.get('avg_churn', 0):>6.3f}")
        print(f"{'-'*110}")


# =====================================================================
# MAIN
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Generate publication-quality plots for MCP evaluation')
    parser.add_argument('--results-dir',
                        default=os.path.join(os.path.dirname(__file__), 'results'))
    args = parser.parse_args()

    output_dir = os.path.join(args.results_dir, 'plots')
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n=== Generating Publication Plots (300 DPI) ===")
    print(f"  Results: {args.results_dir}")
    print(f"  Output:  {output_dir}\n")

    results = load_results(args.results_dir)
    logs = load_all_logs(args.results_dir)

    if not results and not logs:
        print("  No results found. Run experiments first:")
        print("    make eval-all")
        return

    print(f"  Found {len(results)} summaries, {len(logs)} log files\n")

    if results:
        print_summary_table(results)

    print(f"\n--- Generating 5 figures ---\n")

    if results:
        plot_multimetric(results, output_dir)      # Fig 1
        plot_heatmap(results, output_dir)           # Fig 2

    if logs:
        plot_timeline(logs, output_dir)             # Fig 3
        plot_shadow_and_resources(logs, output_dir)  # Fig 4

    if results and logs:
        plot_latency(results, logs, output_dir)     # Fig 5

    print(f"\n=== All plots saved to {output_dir} ===")
    pngs = sorted(glob.glob(os.path.join(output_dir, '*.png')))
    total_size = sum(os.path.getsize(p) for p in pngs)
    print(f"  Files: {len(pngs)} PNGs ({total_size / 1024 / 1024:.1f} MB total)")
    for p in pngs:
        sz = os.path.getsize(p) / 1024
        print(f"    {os.path.basename(p):45s} {sz:>7.0f} KB")


if __name__ == '__main__':
    main()
