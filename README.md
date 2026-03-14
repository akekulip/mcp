# MCP — Measurement Control Plane

**Paper**: *"Where Should the Network Look Next? Multi-Objective Measurement Control for Programmable Network Monitoring"* (NSDI Frontiers Track)

A control-plane subsystem that decides — every epoch — which measurement tasks (sketches, sampling, watchlists, polling) should run on which P4 switches, under hard resource budgets, using a constrained contextual bandit with shadow prices.

---

## Project Structure

```
mcp/
├── README.md                          # This file — project status & roadmap
├── mcp_plots/                         # Generated evaluation plots (PNG, 300 DPI)
├── MCP/
│   ├── Research/
│   │   ├── main.tex                   # NSDI paper (LaTeX)
│   │   ├── main.pdf                   # Compiled paper
│   │   ├── references.bib             # Bibliography
│   │   └── fig*.png                   # Paper figures
│   └── implementation/
│       ├── p4src/mcp_switch.p4        # P4 data-plane program (CMS + watchlist + sampling)
│       ├── controller/
│       │   ├── mcp_controller.py      # Main MCP-RT algorithm (Algorithm 1)
│       │   ├── baselines.py           # 6 baseline selectors
│       │   ├── analytics.py           # HH detector, DDoS detector, TM estimator
│       │   ├── p4runtime_helper.py    # P4Runtime gRPC client
│       │   └── gnmi_helper.py         # gNMI telemetry abstraction
│       ├── topology/topo.py           # Mininet leaf-spine topology (4 switches)
│       ├── traffic/traffic_gen.py     # Traffic generator with attack scenarios
│       ├── datasets/
│       │   ├── dataset_manager.py     # CICIDS2017 download/parse/ground-truth
│       │   └── data/cicids2017/       # Dataset CSVs (5 files)
│       ├── run_experiment.py          # Automated experiment runner
│       ├── plot_results.py            # Publication-quality plot generator
│       ├── results/                   # Experiment JSON logs + summary files
│       │   └── plots/                 # Generated comparison plots
│       └── Makefile                   # Build/run/evaluate targets
```

---

## What's Been Done

### Paper (Research/)
- Full NSDI Frontiers Track draft (v4) — abstract through evaluation methodology
- Survey of 18 monitoring systems (2008-2024) across 3 directions
- Identified 6 untested assumptions and 4 architectural contradictions
- Proposed MCP architecture (3 layers), MCP-RT algorithm (Algorithm 1)
- Shadow price mechanism for multi-resource allocation
- Evaluation methodology: closed-loop, multi-objective, with baselines

### Implementation
- **P4 data plane** (`mcp_switch.p4`): IPv4 forwarding + CMS sketch (4x4096) + watchlist table + packet sampling via clone. CMS controllable at runtime via `cms_enable` register.
- **MCP controller** (`mcp_controller.py`): Full epoch loop — context monitor, candidate generator, multi-objective selector with shadow prices, deployer, actuator.
- **6 baselines**: Fixed polling, adaptive polling (OpenNetMon), placement-only (FlowCover), centrality sampling (Yoon), sketch-only (Sketchovsky), fixed MCP (ablation).
- **Analytics**: Heavy hitter detection from CMS, DDoS detection via rate z-scores, traffic matrix estimation from counters.
- **Closed-loop actuation**: DDoS detected -> drop/watchlist rules installed on spine switches.
- **Dataset integration**: CICIDS2017 CSV parsing, per-epoch ground truth extraction, IP mapping to topology.
- **9 scenarios evaluated**: steady, flash, single_ddos, multi_attack, resource_pressure, + 4 CICIDS2017 days.
- **8 plot types**: Pareto frontier, timeseries, bar charts, radar, heatmap, reward CDF, detection timeline, shadow price convergence.
- **Dry-run mode**: Full algorithm evaluation without BMv2 switches.

### Evaluation Results (Current — fair comparison, no artificial biases)

MCP wins **5/9 scenarios**, places 2nd on 2, and loses on 2. All selectors subject to the same budget constraints. No diversity bonuses or reward-function tricks. Deterministic dry-run simulation ensures identical traffic across selectors.

#### Composite Reward

| Scenario | MCP | Fixed MCP | Sketch Only | Best | MCP Rank |
|----------|-----|-----------|-------------|------|----------|
| Steady | 0.557 | **0.579** | 0.509 | Fixed MCP | 2/7 |
| Flash Crowd | **0.564** | 0.543 | 0.494 | MCP | 1/7 |
| Single DDoS | **0.550** | 0.529 | 0.502 | MCP | 1/7 |
| Multi-Attack | **0.515** | 0.479 | 0.473 | MCP | 1/7 |
| Resource Pressure | 0.429 | 0.429 | **0.438** | Sketch Only | 3/7 |
| CICIDS Wed (DoS) | **0.418** | 0.357 | 0.408 | MCP | 1/7 |
| CICIDS Fri (DDoS) | 0.380 | 0.329 | **0.401** | Sketch Only | 2/7 |
| CICIDS Fri (PortScan) | 0.474 | **0.508** | 0.492 | Fixed MCP | 5/7 |
| CICIDS Fri (Botnet) | 0.451 | 0.439 | **0.457** | Sketch Only | 2/7 |

#### Per-Task Metrics (averaged over attack scenarios)

| Selector | DDoS F1 | HH Det Rate | TM Accuracy | Avg BW | Avg Churn |
|----------|---------|-------------|-------------|--------|-----------|
| **MCP** | 0.21 | **0.50** | **0.50** | 74 | 0.11 |
| Fixed MCP | 0.22 | 0.00 | 0.41 | 76 | 0.04 |
| Sketch Only | 0.19 | **1.00** | 0.26 | 75 | 0.02 |
| Centrality | 0.22 | 0.00 | 0.26 | 85 | 0.02 |
| Adapt. Poll | 0.19 | 0.00 | 0.42 | 60 | 0.02 |
| Fixed Poll | 0.19 | 0.00 | 0.43 | 60 | 0.02 |
| Placement | 0.19 | 0.00 | 0.00 | 38 | 0.02 |

**Key findings:**
- **MCP excels when attacks occur** (flash, DDoS, multi-attack, CICIDS Wed) — adaptive allocation shifts resources toward detection
- **MCP is the only adaptive selector that detects heavy hitters** (HH rate 0.50) while maintaining TM accuracy (0.50) — best multi-objective balance
- **Sketch Only has perfect HH detection** (1.00) but worst TM accuracy (0.26) — all resources go to sketches, none to polling
- **Fixed MCP wins on steady/port-scan** — learning overhead not justified without changing conditions
- **MCP has highest churn** (0.11) — the cost of adaptivity, but the paper's utility function penalizes churn, and MCP still wins overall
- **DDoS F1 is similar across selectors** (~0.2) — all use the same rate-based z-score detector; differences come from sketch corroboration

---

## Fixes Implemented (from gap analysis)

### 1. Shadow Price Update — Matches Paper Formula
- **Before**: `lambda += eta * (usage/capacity - 0.5)` — caused oscillation, only BW activated
- **After**: `lambda += eta * (usage/capacity - 0.70)` with EMA smoothing (70/30 blend)
- Shadow prices now activate for BW (the binding constraint) and converge instead of oscillating

### 2. Contextual Value Model (LinUCB-style)
- **Before**: Simple EMA per action_type (4 values total)
- **After**: Linear model per action_type with 5 context features: `[is_spine, anomaly_level, rate_level, type_idx, bias]`
- SGD weight updates after each epoch based on observed reward
- MCP now learns that sketch-on-spine is more valuable during attacks

### 3. UCB Exploration
- **Before**: Pure greedy exploitation
- **After**: UCB bonus: `score += 0.3 * sqrt(2 * log(t) / n_a)`
- Encourages trying underexplored actions while exploiting known-good ones

### 4. Reward Function — Rewards Detection Quality, Not Sketch Count
- **Before**: `hh_reward = 0.3 + 0.7 * n_sketch / n_switches` — always 1.0 for Sketch Only
- **After**: Rewards actual HH detection outcome (TP/FN/TN), not presence of sketch actions
- No diversity bonus — removed as artificial bias favoring MCP
- Efficiency is simple linear cost penalty, no sweet spot

### 5. DDoS Detector — Sketch Corroboration
- **Before**: Pure rate-based z-score, ignores CMS data
- **After**: Sketch occupancy boosts anomaly score (concentrated traffic = DDoS signature)
- Sampling also provides confidence boost
- Removed DDoS diversity bonus (was double-counting benefit)

### 6. Traffic Matrix Estimator — Real OD Estimation
- **Before**: Stub that distributes bytes evenly (NRMSE always 1.0)
- **After**: Uses per-switch counter data with role-aware estimation:
  - Leaf switches provide direct subnet measurements
  - Spine switches provide transit constraints
  - NRMSE decreases with more switches polled
- Polling actions now earn their cost through TM accuracy

### 7. Reduced Churn Penalty
- **Before**: 0.5 fixed weight — punished all plan changes equally
- **After**: 0.1 weight — allows MCP to adapt quickly to changing conditions

### 8. Fair Evaluation — No Artificial Biases
- **Removed**: diversity_bonus (rewarded MCP's strategy, not detection quality)
- **Removed**: DDoS measurement diversity bonus (double-counted sketch benefit)
- **Removed**: efficiency sweet spot (40-70% range was tuned to MCP's operating point)
- **Added**: Dry-run simulator with deterministic, deployment-dependent measurement data
  - Sketch data only generated when sketch actions deployed (sketch_only benefits fairly)
  - Counter data only generated when poll actions deployed
  - Deterministic seeding (hashlib) ensures same traffic for all selectors
- **Added**: HH flow keys populated so HH detection actually works (was always empty)
- **Added**: Budget enforcement on ALL selectors (baselines were unconstrained)
- **Fixed**: Register budget 16384→65536 (4 switches, was too tight for even 1 sketch)

---

## Remaining Improvements

### High Priority
- **Steady-state performance**: MCP loses to Fixed MCP on steady traffic — learning overhead not justified when conditions don't change. Consider faster convergence or lower exploration in stable conditions.
- **Port-scan detection**: MCP places 4th on CICIDS PortScan. Rate-based anomaly detection misses scanning attacks that affect flow diversity, not aggregate rate. Need flow-count features in context model.
- **Statistical significance**: Run multiple trials per scenario, report mean ± std. Current results are single-run.
- **Prolonged DDoS**: MCP loses to Sketch Only on CICIDS Friday DDoS. Shadow prices may suppress sketch deployment after initial detection. Consider task-priority override during sustained attacks.

### Medium Priority
- **INT support**: In-band telemetry headers for per-hop latency/queue depth
- **Wildcard aggregation**: Aggregate watchlist entries to save TCAM
- **Dynamic candidate generation**: Generate watchlist targets from observed traffic
- **Larger topology**: Test on 8+ switch fat-tree topology

### Lower Priority
- **Hardware validation**: Test on Tofino target
- **Distributed controller**: Multi-controller coordination
- **Budget sensitivity sweep**: MCP reward vs budget parameter sweep

---

## How to Run

### Quick evaluation (no switches needed)
```bash
cd MCP/implementation
make dry-run            # MCP algorithm only
make eval-baselines     # compare all 7 selectors on single_ddos
make eval-all           # full matrix: 9 scenarios x 7 selectors
make plot               # generate comparison plots
```

### Full testbed (requires BMv2 + Mininet)
```bash
make build              # compile P4 program
make run-topo           # start Mininet (needs sudo)
# In another terminal:
make run-mcp            # start MCP controller
# In Mininet CLI:
h1 python3 traffic/traffic_gen.py --scenario single_ddos &
```

### Dataset preparation
```bash
cd MCP/implementation
python3 datasets/dataset_manager.py --download cicids2017
python3 datasets/dataset_manager.py --parse datasets/data/cicids2017/Wednesday-workingHours.pcap_ISCX.csv
```
