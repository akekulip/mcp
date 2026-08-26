# sim/ toolchain versions (recorded 2026-08-25)

All clones are plain `git clone` of the default branch; no local patches applied.

| Component | Path | Origin | Commit | Commit date |
|---|---|---|---|---|
| htsim (SPCL/UEC fork, **chosen**) | `sim/htsim` | https://github.com/spcl/HTSIM | `d42b1574bfe8feef412b03aab842f02738d52def` | 2026-05-25 |
| htsim (Broadcom upstream, reference only) | `sim/htsim-broadcom` | https://github.com/Broadcom/csg-htsim | `841d9e7be46bb968eece766aa4b6c044c7799f67` | 2026-03-23 |
| ATLAHS | `sim/atlahs` | https://github.com/spcl/atlahs | `fb51a99f908e550318056ebb3e084f3d2fff55bd` | 2026-05-12 |
| Chakra | `sim/chakra` | https://github.com/mlcommons/chakra | `9ff3e3e2f276b4c0554a83f8747bf00b2786fa85` | 2026-07-27 |

ATLAHS submodules (apps/*, goal_gen/ai/nccl_generator_v2, nccl_versions, DirectDriveSim) were
**not** initialised (they pull Megatron-LM, vLLM, LAMMPS, etc. and are not needed for the
htsim backend). `sim/atlahs/sim/htsim-backend` is an older vendored htsim snapshot; it was not
built — `sim/htsim` (spcl/HTSIM) is the maintained successor and is what the ATLAHS demo
scripts' `-goal` command line targets.

## Prebuilt binaries shipped inside spcl/HTSIM (used as-is)

| Binary | Path | Size | Note |
|---|---|---|---|
| `txt2bin` (GOAL text -> LogGOPSim binary) | `sim/htsim/htsim/sim/lgs/txt2bin` | 457352 B | checked into git (commit `896cc76`); x86-64 ELF, links against system glibc 2.31 and runs here. Rebuilding needs `re2c` + `gengetopt` (see `lgs/Makefile`). |
| `LogGOPSim` | `sim/htsim/htsim/sim/lgs/LogGOPSim` | 1554880 B | checked in; not used in the smoke tests |

`txt2bin` correctness check: converting the downloaded `lulesh_8.goal` locally produced a file
byte-identical (md5 `a360f63bf0ff92089f81a5a6b72e01b1`) to the `lulesh_8.bin` published on the
SPCL trace server.

## Built artefacts

| Target | Build system | Output |
|---|---|---|
| spcl/HTSIM: `libhtsim.a`, `htsim_uec`, `htsim_uec_df`, `htsim_uec_sf`, `parse_output` | CMake (`cmake -S . -B build -DCMAKE_BUILD_TYPE=Release; cmake --build build --parallel 24`) in `sim/htsim/htsim/sim` | `sim/htsim/htsim/sim/build/datacenter/htsim_uec` (+ symlink `sim/htsim/htsim/sim/datacenter/htsim_uec`) |
| Broadcom csg-htsim: `libhtsim.a`, `htsim_tcp/ndp/roce/swift/hpcc/eqds` | GNU make (`make -j16` in `sim/htsim-broadcom/sim`, then in `sim/htsim-broadcom/sim/datacenter`) | `sim/htsim-broadcom/sim/datacenter/htsim_*` |

Build logs: `sim/runs/smoke/build-spcl-cmake.log`, `build-spcl.log` (0 errors, 13 warnings),
`build-broadcom.log` (0 errors).

## Host toolchain

| Tool | Version |
|---|---|
| OS / kernel | Ubuntu 20.04, Linux 5.15.0-139-generic, glibc 2.31 |
| g++ | 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.2) |
| cmake | 3.16.3 |
| GNU make | 4.2.1 |
| git | 2.25.1 |
| uv | 0.11.4 |
| gdb | present (used for the segfault backtrace) |

## Python environment (`sim/.venv`, created with `uv venv --python 3.12`)

Python 3.12.13 (uv-managed CPython).

| Package | Version | Note |
|---|---|---|
| chakra | 1.0.0 | installed **non-editable** from `sim/chakra` (`uv pip install ./chakra`). `uv pip install -e ./chakra` FAILS: setuptools' editable-wheel path rejects the custom `build_grpc` sub-command (`error in setup.cfg: command 'build_grpc' has no such option`). Log: `sim/runs/smoke/venv.log`. |
| protobuf | 7.36.0 | |
| networkx | 3.6.1 | |
| pydot | 4.0.1 | |
| graphviz | 0.21 | |
| holistictraceanalysis | 0.2.0 | pinned git rev from chakra's pyproject |
| numpy | 2.5.2 | |
| pandas | 3.0.5 | htsim's `requirements.txt` pins `pandas==1.4.1` / `matplotlib==3.5.1`, which do not build on Python 3.12; installed unpinned instead. |
| matplotlib | 3.11.1 | |
| seaborn | 0.13.2 | |

## Sample traces (SPCL ATLAHS Trace Collection, http://storage2.spcl.ethz.ch/traces/)

| File | Local path | Size | md5 |
|---|---|---|---|
| `hpc/lulesh/lulesh_8/lulesh_8.goal` | `sim/traces/lulesh_8/lulesh_8.goal` | 41952746 B | `e79fa78936353fa2c2002688adb617ae` |
| `hpc/lulesh/lulesh_8/lulesh_8.bin` | `sim/traces/lulesh_8/lulesh_8.bin` | 33995064 B | `a360f63bf0ff92089f81a5a6b72e01b1` |
| `ai/llama/Llama7B_N2_GPU8_TP1_PP1_DP8_BS32/llama2_7b_2n8g.bin` | `sim/traces/llama7b_n2/llama2_7b_2n8g.bin` | 99161260 B | `286cb884f18de738b2fd43f72227d5f6` |

Total downloaded: ~171 MB (cap was ~500 MB). The Zenodo NeMo Mixtral record was not used;
the SPCL server already hosts ready-made GOAL/bin traces that are the native ATLAHS input.
