# MCP — Measurement Control Plane

A complete testbed implementation of the Measurement Control Plane (MCP) described
in *"Where Should the Network Look Next? Multi-Objective Measurement Control
for Programmable Network Monitoring"*.

MCP sits in the **control plane** and decides, every epoch, which measurement
tasks should run on which switches — under hard resource budgets — using a
constrained contextual bandit with shadow prices.

## Architecture (3 layers from the paper)

```
┌───────────────────────────────────────────────────────────────┐
│                    LAYER 3: ANALYTICS + ACTUATION              │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ Heavy Hitter │  │    DDoS      │  │ Traffic Matrix       │ │
│  │  Detector    │  │   Detector   │  │  Estimator           │ │
│  │ (from CMS)   │  │ (rate anom.) │  │ (from counters)      │ │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘ │
│         │                 │                      │             │
│  ┌──────┴─────────────────┴──────────────────────┴───────────┐ │
│  │              Actuator (closed-loop mitigation)             │ │
│  │         DDoS: install drop rules on spine switches         │ │
│  │         QoS: reroute heavy flows to alternate paths        │ │
│  └───────────────────────────┬───────────────────────────────┘ │
│                              │ reward signal                   │
├──────────────────────────────┴────────────────────────────────┤
│                    LAYER 2: MCP (the brain)                    │
│                                                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │   Context    │  │  Candidate   │  │  Multi-Objective     │ │
│  │   Monitor    │  │  Generator   │  │  Selector (bandit)   │ │
│  │ (gNMI/P4RT)  │  │ (task-aware) │  │  w/ shadow prices    │ │
│  └──────────────┘  └──────────────┘  └──────────────────────┘ │
│                                                                │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                    Deployer                               │  │
│  │        atomic plan versioning via P4Runtime               │  │
│  └──────────────────────────┬───────────────────────────────┘  │
│                              │ P4Runtime + gNMI                 │
├──────────────────────────────┴────────────────────────────────┤
│                    LAYER 1: DATA PLANE                         │
│                                                                │
│   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐     │
│   │  s1     │───│  s2     │   │  s3     │───│  s4     │     │
│   │ (spine) │   │ (spine) │   │ (leaf)  │   │ (leaf)  │     │
│   │ CMS+WL  │   │ CMS+WL  │   │ CMS+WL  │   │ CMS+WL  │     │
│   │ +sample │   │ +sample │   │  │   │  │   │  │   │  │     │
│   └─────────┘   └─────────┘   └──┘   └──┘   └──┘   └──┘     │
│                                h1-h4          h5-h8           │
└───────────────────────────────────────────────────────────────┘
```

## What MCP Controls

| Action Type   | P4 Resource       | Task          | What It Does                              |
|---------------|-------------------|---------------|-------------------------------------------|
| `watchlist`   | TCAM entries      | QoS           | Track specific flows with per-entry counters |
| `sketch`      | Registers (CMS)   | DDoS/HH      | Estimate flow sizes via Count-Min Sketch   |
| `sample`      | Clone/mirror      | DDoS/IDS      | Copy packets to collector for analysis     |
| `poll`        | Control bandwidth | Traffic Est.  | Read counters at higher frequency          |

## Competing Monitoring Tasks

MCP allocates resources across three simultaneous tasks:

1. **QoS Monitoring** — watchlist entries on leaf switches for per-flow counters
2. **DDoS Detection** — sampling on spine switches + CMS sketches everywhere
3. **Traffic Estimation** — counter polling across all switches

## Closed-Loop Evaluation

Unlike prior work that stops at telemetry quality, MCP closes the loop:

```
Measure → Analyze → Act → Observe Outcome → Update Measurement Policy
```

- **DDoS detected** → actuator installs drop rules on spines
- **Heavy hitter found** → analytics flags flow for QoS action
- **Mitigation success/failure** → feeds back as reward to bandit selector

## Baselines (7 selectors)

| Selector | Based On | Strategy |
|----------|----------|----------|
| `mcp` | MCP-RT (ours) | Shadow prices + bandit learning |
| `fixed_polling` | Traditional | Poll all counters, nothing else |
| `adaptive_polling` | OpenNetMon | Adapt polling rate to traffic changes |
| `placement_only` | FlowCover | Set-cover on spine switches only |
| `centrality_sampling` | Yoon et al. | Sample at high-centrality switches |
| `sketch_only` | Sketchovsky | CMS everywhere, no sampling/watchlist |
| `fixed_mcp` | Ablation | MCP without shadow price learning |

## Prerequisites

- **BMv2** (simple_switch_grpc) — P4 software switch with gRPC
- **p4c** — P4 compiler (p4c-bm2-ss backend)
- **Mininet** — network emulator
- **Python 3.8+** with: `scapy`, `grpcio`, `protobuf`, `p4runtime`, `matplotlib`, `numpy`

## Quick Start

### 1. Build and run topology

```bash
make build          # compile P4 program
make run-topo       # start Mininet with 4 BMv2 switches (needs sudo)
```

### 2. Start MCP controller (new terminal)

```bash
make run-mcp                    # default MCP selector
make run-mcp-fixed_polling      # run a baseline instead
```

### 3. Generate traffic (from Mininet CLI)

```bash
mininet> h1 python3 traffic/traffic_gen.py --scenario single_ddos &
```

### 4. Watch MCP adapt

MCP logs show real-time decisions:
```
Epoch 12: 11 actions, reward=0.782, ddos=., dt=48ms
Epoch 22: 13 actions, reward=0.891, ddos=!, dt=52ms  ← attack detected
Epoch 23: mitigations installed on s1, s2
Epoch 35: 9 actions, reward=0.735, ddos=., dt=41ms   ← recovery
```

## Evaluation

### Dry-run mode (no switches needed)

```bash
make dry-run            # MCP algorithm only
make eval-baselines     # compare all 7 selectors on single_ddos
make eval-all           # full matrix: 5 scenarios × 7 selectors
make plot               # generate comparison plots
```

### Traffic scenarios

| Scenario | Description | Duration |
|----------|-------------|----------|
| `steady` | Constant normal traffic | 60s |
| `flash` | Normal then 3x rate spike | 60s |
| `single_ddos` | Normal + one SYN flood | 60s |
| `multi_attack` | Two overlapping DDoS from different sources | 90s |
| `resource_pressure` | Attack under tight budgets (TCAM=50, BW=30) | 60s |

### Visualization

```bash
make plot
# → results/plots/pareto_frontier.png
# → results/plots/comparison_bars.png
# → results/plots/radar_comparison.png
# → results/plots/timeseries_{selector}.png
```

## File Structure

```
implementation/
├── p4src/
│   └── mcp_switch.p4              # P4 program (forwarding + CMS + watchlist + sampling)
│                                    #   Controllable CMS via cms_enable register
├── controller/
│   ├── mcp_controller.py          # Main MCP controller (Algorithm 1)
│   │                                #   Context monitor, candidate gen, selector, deployer
│   ├── p4runtime_helper.py        # P4Runtime gRPC client (bulk reads, batched writes)
│   ├── gnmi_helper.py             # gNMI telemetry interface (BMv2 wrapper)
│   ├── analytics.py               # Real analytics: HH detector, DDoS detector, TM estimator
│   └── baselines.py               # 6 baseline selectors for comparison
├── topology/
│   └── topo.py                    # Mininet topology with BMv2GrpcSwitch class
├── traffic/
│   └── traffic_gen.py             # Traffic generator with scenarios + ground truth logging
├── run_experiment.py              # Automated experiment runner
├── plot_results.py                # Matplotlib visualization
├── results/                       # Experiment outputs (JSON logs, CSV, plots)
├── Makefile                       # Build, run, evaluate, plot targets
└── README.md
```

## gNMI Integration

The paper specifies gNMI for streaming switch telemetry. The `gnmi_helper.py`
module provides a gNMI-compatible abstraction:

- **For BMv2**: wraps P4Runtime reads to simulate gNMI subscriptions
- **For production (Tofino + Stratum)**: replace with real gNMI gRPC client

The MCP controller code does not change — only the gnmi_helper module.

## Key Design Decisions

- **Epoch duration**: 2 seconds (BMv2 register reads are slow)
- **CMS controllable**: `cms_enable` register lets MCP activate/deactivate sketches
- **Sketch reset per epoch**: CMS registers zeroed at epoch boundaries
- **Reward signal**: composite of HH detection + DDoS detection + TM accuracy + coverage
- **Shadow prices**: auto-adjust per resource type based on utilization
- **Atomic deployment**: batched P4Runtime writes for plan versioning
