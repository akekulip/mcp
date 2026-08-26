# sim/ — Tier-1 simulation toolchain (Chakra → ATLAHS/GOAL → htsim)

Everything under `sim/` was set up on 2026-08-25. Exact versions and commits: `VERSIONS.md`.
Gate-experiment implementation plan with source pointers: `GATE-EXPERIMENT.md`.
Every command below was run from this machine; outputs live under `sim/runs/smoke/`.

## Layout

```
sim/
  htsim/            spcl/HTSIM  (UEC htsim fork; -goal input, oblivious/REPS spraying)  <- CHOSEN
  htsim-broadcom/   Broadcom/csg-htsim (upstream; EQDS/NDP/Swift; no GOAL input)       <- reference
  atlahs/           spcl/atlahs  (GOAL generators, LogGOPSim, demo scripts)
  chakra/           mlcommons/chakra (ET schema + converter/generator/jsonizer CLIs)
  .venv/            uv venv, Python 3.12.13, chakra installed
  traces/           downloaded ATLAHS sample traces (lulesh_8 GOAL+bin, llama7b_n2 bin)
  runs/smoke/       build logs + smoke-run outputs
```

## Which htsim, and why

Two candidates were cloned and both were built:

| | Broadcom/csg-htsim (`sim/htsim-broadcom`) | spcl/HTSIM (`sim/htsim`) |
|---|---|---|
| Transports | TCP, NDP, RoCE, Swift, HPCC, **EQDS** | all of those **plus UEC** (`main_uec.cpp`, `uec.cpp`, `uec_mp.cpp`) |
| Spraying / multipath | per-transport `-strat ecmp_host / rr_ecmp / ecmp_ar …` | same switch strategies **plus** `-load_balancing_algo bitmap\|reps\|reps_legacy\|freezing\|oblivious\|mixed\|ecmp` (per-packet entropy choice at the UEC source) |
| Workload input | connection matrix (`-tm`) only | connection matrix **or GOAL binary (`-goal`)** via `logsim-interface.cpp` (the ATLAHS htsim backend) |
| Topologies | fat tree (+ leaf-spine) | fat tree, dragonfly, slimfly; many `.topo` files incl. `fat_tree_128_1os.topo`, `fat_tree_1024_1os.topo` |
| Build | `make` | CMake |

**Chosen: spcl/HTSIM.** It is the only one of the two that (a) has the UEC transport, (b) has
per-packet oblivious spraying as a first-class option, and (c) consumes ATLAHS GOAL traces
directly. It is also what `atlahs/demo/*/0?_run_htsim.sh` invokes (`htsim_uec -goal …`).
The Broadcom tree is kept as the clean upstream reference for EQDS and for diffing the
queue/pipe core, which the spcl fork inherits almost unchanged.

## Build

```bash
# spcl/HTSIM (chosen)
cd /home/philip/Projects/mcp/sim/htsim/htsim/sim
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel 24
# -> build/datacenter/htsim_uec, htsim_uec_df, htsim_uec_sf, build/parse_output
#    (CMake also symlinks datacenter/htsim_uec -> build/datacenter/htsim_uec)

# Broadcom csg-htsim (reference)
cd /home/philip/Projects/mcp/sim/htsim-broadcom/sim && make -j16
cd datacenter && make -j16
# -> datacenter/htsim_{tcp,ndp,roce,swift,hpcc,eqds}
```

Both built with 0 errors (logs: `runs/smoke/build-spcl-cmake.log`, `runs/smoke/build-spcl.log`,
`runs/smoke/build-broadcom.log`). Compiler: g++ 9.4.0.

## Python environment

```bash
cd /home/philip/Projects/mcp/sim
uv venv --python 3.12 .venv
VIRTUAL_ENV=$PWD/.venv uv pip install ./chakra          # NON-editable; -e fails, see VERSIONS.md
VIRTUAL_ENV=$PWD/.venv uv pip install matplotlib pandas seaborn   # htsim/requirements.txt pins
                                                        # pandas 1.4.1, which will not build on 3.12
```

Installed CLIs: `.venv/bin/chakra_converter`, `chakra_generator`, `chakra_jsonizer`,
`chakra_trace_link`, `chakra_timeline_visualizer`, `chakra_visualizer`.

## Smoke runs (all under `runs/smoke/`)

### 1. UEC on a 128-node 3-tier fat tree with oblivious packet spraying (connection matrix)

```bash
cd /home/philip/Projects/mcp/sim/runs/smoke/uec_fattree128_oblivious
H=/home/philip/Projects/mcp/sim/htsim/htsim/sim/datacenter
$H/htsim_uec -topo $H/topologies/fat_tree_128_1os.topo \
  -tm $H/connection_matrices/perm_128n_128c_2MB.cm -nodes 128 \
  -linkspeed 100000 -mtu 4096 -paths 128 -strat ecmp_host \
  -load_balancing_algo oblivious -seed 1 -end 2000 > stdout.log
```
Result: exit 0, 0.30 s wall, 16 MB RSS. `stdout.log` confirms `Load balancing algorithm set to
oblivious`; final line `New: 63616 Rtx: 52 … ACKs: 23902 NACKs: 52`. Per-flow completion
records in `output_metrics/flowsInfo.csv` (128 flows, FCT ≈ 178 µs for 2 MB at 100 Gbps).

### 2. EQDS (Broadcom tree) — leaf-spine 32 nodes and 1024-node fat tree

```bash
cd /home/philip/Projects/mcp/sim/runs/smoke/eqds_fattree_broadcom
H=/home/philip/Projects/mcp/sim/htsim-broadcom/sim/datacenter
$H/htsim_eqds -topo $H/topologies/leaf_spine_tiny.topo -tm $H/connection_matrices/perm_32n_32c_2MB.cm \
  -nodes 32 -linkspeed 100000 -mtu 4096 -paths 128 -strat ecmp_host -seed 1 -end 2000 -o logout.dat > stdout.log
cd ../eqds_fattree1024_broadcom
$H/htsim_eqds -topo $H/topologies/fat_tree_1024.topo -tm $H/connection_matrices/perm_1024n_1024c_0u_2000000b.cm \
  -nodes 1024 -linkspeed 100000 -mtu 4096 -paths 128 -strat ecmp_host -seed 1 -end 2000 -o logout.dat > stdout.log
```
Both exit 0 (0.29 s and 8.7 s wall). EQDS sprays per packet by design (`-paths 128`).

### 3. GOAL chain: GOAL text → `txt2bin` → `htsim_uec -goal` (the ATLAHS htsim backend)

```bash
S=/home/philip/Projects/mcp/sim/htsim/htsim/sim; H=$S/datacenter
# (a) bundled 8-rank incast GOAL shipped with the fork
cd /home/philip/Projects/mcp/sim/runs/smoke/goal_incast8
$S/lgs/txt2bin -i $S/lgs/incast_8_1_2MiB.goal -o incast_8_1_2MiB.bin
$H/htsim_uec -topo $H/topologies/fat_tree_128_1os.topo -goal incast_8_1_2MiB.bin -nodes 128 \
  -linkspeed 100000 -mtu 4096 -paths 128 -strat ecmp_host -load_balancing_algo oblivious \
  -q 1000000 -seed 4 > var_3.log            # exit 0, ends with "Finished all"

# (b) downloaded LULESH 8-rank trace (40 MB GOAL text)
cd /home/philip/Projects/mcp/sim/runs/smoke/goal_lulesh8
$S/lgs/txt2bin -i /home/philip/Projects/mcp/sim/traces/lulesh_8/lulesh_8.goal -o lulesh_8.local.bin
md5sum lulesh_8.local.bin /home/philip/Projects/mcp/sim/traces/lulesh_8/lulesh_8.bin   # identical
$H/htsim_uec -topo $H/topologies/fat_tree_128_1os.topo -goal lulesh_8.local.bin -nodes 128 \
  -linkspeed 100000 -mtu 4096 -paths 128 -strat ecmp_host -load_balancing_algo oblivious \
  -q 1000000 -seed 4 > stdout.log

# (c) downloaded Llama-2 7B, 2 nodes x 4 GPUs, DP8 (95 MB bin, pre-converted by SPCL)
cd /home/philip/Projects/mcp/sim/runs/smoke/goal_llama7b_n2
$H/htsim_uec -topo $H/topologies/fat_tree_128_1os.topo \
  -goal /home/philip/Projects/mcp/sim/traces/llama7b_n2/llama2_7b_2n8g.bin -nodes 128 \
  -linkspeed 200000 -mtu 4096 -paths 128 -strat ecmp_host -load_balancing_algo oblivious \
  -q 1000000 -seed 4 > stdout.log
```
Results: see the table below (filled from `runs/smoke/goal_*/time.log` and `stdout.log`).

RESULTS_TABLE_PLACEHOLDER

Two things learned the hard way, both recorded in `runs/smoke/goal_incast8/`:

* `-lgs_flow_stats`, used by the ATLAHS demo scripts, is **not** an option in this fork's
  `main_uec.cpp` (it prints usage and exits 1). Drop it.
* `htsim_uec -goal` **segfaults on the 2-tier `leaf_spine_tiny.topo`** (the topology the ATLAHS
  demo scripts use) — variants 1 and 6 in `runs/smoke/goal_incast8/var_*.log`. gdb backtrace:
  `UecSink::receivePacket` at `htsim/htsim/sim/uec.cpp:3042` ← `Pipe::doNextEvent`
  (`pipe.cpp:66`) ← `LogSimInterface::htsim_simulate_until` (`logsim-interface.cpp:240`)
  ← `start_lgs` (`logsim-interface.cpp:992`) ← `main_uec.cpp:866`. The same binary and the same
  `.bin` run fine on 3-tier fat trees (`fat_tree_128_1os.topo`, `fat_tree_1024_1os.topo`), with
  and without oblivious spraying. Not investigated further because the gate experiment uses a
  3-tier fat tree; flagged as an upstream bug to report.

### 4. Chakra side

```bash
cd /home/philip/Projects/mcp/sim/runs/smoke/chakra_gen
../../../.venv/bin/chakra_generator --num_npus 8 --default_runtime 1000 \
  --default_tensor_size 4096 --default_comm_size 65536      # writes ALL_GATHER.{0..7}.et, ALL_REDUCE.*.et, ...
../../../.venv/bin/chakra_jsonizer --input_filename ALL_GATHER.0.et --output_filename ALL_GATHER.0.json
```
Both exit 0; the `.et` files decode with `chakra.schema.protobuf.et_def_pb2` (1 COMM_COLL node
each for the synthetic collectives).

## What is missing in the "Chakra → ATLAHS → htsim" chain

The **Chakra → GOAL** arrow does not exist anywhere in the cloned code:

* `mlcommons/chakra` has converters *into* Chakra ET (PyTorch ET, text) and a jsonizer/visualizer,
  but no writer for GOAL / LogGOPSim (`grep -rli goal chakra/src chakra/schema` → nothing).
* `spcl/atlahs` produces GOAL from **nsys SQLite exports (NCCL, via `goal_gen/ai/nccl_generator_v2`)
  and PMPI text traces (via `goal_gen/hpc/Schedgen`)**. Its only Chakra usage is
  `scripts/et_to_chakra.py` (PyTorch ET → Chakra ET) and `scripts/run_simulator.py:178`
  (`ASTRA_SIM_WORKLOAD=<dir>/chakra`) — i.e. Chakra feeds the *astra-sim* baseline in the paper,
  not the ATLAHS/htsim path.
* Therefore the working, verified chain today is **GOAL (text or bin) → `txt2bin` → `htsim_uec -goal`**,
  with GOAL produced either by ATLAHS's own tracers or downloaded from the SPCL trace collection.

To close the gap one needs a `chakra_et_to_goal` converter (Python, in `sim/.venv`): walk each
rank's ET (`Node` protobufs; types `COMP_NODE`, `COMM_SEND_NODE`, `COMM_RECV_NODE`,
`COMM_COLL_NODE`, with `comm_size`, `comm_src`/`comm_dst`, `comm_tag`, `duration_micros`, and
`data_deps`/`ctrl_deps`) and emit GOAL statements (`calc <ns>`, `send <bytes>b to <rank> tag <t>`,
`recv <bytes>b from <rank> tag <t>`, `lN requires lM`), expanding each `COMM_COLL_NODE` into
point-to-point sends/recvs with a chosen algorithm (ring / recursive-doubling) the way
`nccl_generator_v2` does for NCCL. GOAL grammar reference: `sim/htsim/htsim/sim/lgs/txt2bin.re`
and the bundled examples `sim/htsim/htsim/sim/lgs/*.goal`. This is an estimated few-hundred-line
script and is **not implemented here**.

## Reproducing from scratch

```bash
cd /home/philip/Projects/mcp/sim
git clone https://github.com/spcl/HTSIM htsim && git -C htsim checkout d42b1574
git clone https://github.com/Broadcom/csg-htsim htsim-broadcom && git -C htsim-broadcom checkout 841d9e7b
git clone https://github.com/spcl/atlahs atlahs && git -C atlahs checkout fb51a99f
git clone https://github.com/mlcommons/chakra chakra && git -C chakra checkout 9ff3e3e2
# then the Build / Python / Smoke sections above
mkdir -p traces/lulesh_8 traces/llama7b_n2
curl -o traces/lulesh_8/lulesh_8.goal http://storage2.spcl.ethz.ch/traces/hpc/lulesh/lulesh_8/lulesh_8.goal
curl -o traces/lulesh_8/lulesh_8.bin  http://storage2.spcl.ethz.ch/traces/hpc/lulesh/lulesh_8/lulesh_8.bin
curl -o traces/llama7b_n2/llama2_7b_2n8g.bin \
  "http://storage2.spcl.ethz.ch/traces/ai/llama/Llama7B_N2_GPU8_TP1_PP1_DP8_BS32/llama2_7b_2n8g.bin"
```
