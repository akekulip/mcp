# WORKING_NOTES — MCP: "The Data Plane Decides What to Measure"

Plan of record: ~/.claude/plans/we-have-to-do-spicy-patterson.md (approved 2026-08-25).

## Status (2026-08-25) — Phase S-DOWN started (Tofino down)
- Repo cloned from akekulip/mcp; legacy tree moved to `legacy/` (frozen, read-only — the audit
  found its simulator placement-insensitive, sketch actuation inert, "LinUCB" = SGD+UCB1, unseeded
  RNG in reward). New layout: sim/ p4/ nic/ controller/ paper/ docs/.
- Switch mgmt now decps@10.10.54.81 (not .15); both unreachable today. Vision (.166) and Hulk (.158) up.
- DEADLINES (verified 2026-08-25): NSDI'27 spring passed (Apr 2026); NSDI'27 fall = 17 Sep 2026
  (infeasible). Realistic: SIGCOMM'27 (~late Jan 2027, verify) or NSDI'28 spring (~Apr 2027).
- Running: literature-reviewer → docs/NOVELTY-MATRIX.md + Zotero collection "MCP-sprayed-fabrics".

## Status (2026-08-26, later) — gate RERUN with RTO fix: 105/105, 0 stalls
- Added `-rto_min_us` to htsim main_uec.cpp; run_gate.sh sets RTO_MIN_US=300. Seeds 11/26 now
  recover the single drop via RTO (finish 13.2435 ms vs 13.2367 loss-free). 18/105 runs saw a
  silent drop; all completed. Old dead-RTO results archived in sim/gate/results_2026-08-26_deadRTO/.
- analyze.py: incast TOO HARD (uniform censored 93%, all TTL=132 = horizon; trace too short at
  EPOCH_US=100), lulesh OK (uniform median TTL 52193 epochs, censored 40%; oracle 52182, random 52267
  — policies indistinguishable at n=5).

## (superseded) Status (2026-08-26) — first gate run, dead RTO, verdict TOO HARD
- `sim/gate/run_gate.sh` finished: 133 result csv (incast 28/28/28, lulesh oracle 5 / random 17 / uniform 27).
  `analyze.py` verdict for BOTH traces: TOO HARD — uniform censored >50% (incast 100%, lulesh 67%)
  → PREREG says loosen the operating point one step before proceeding.
- incast runs last only ~13 ms sim time = 132 epochs at EPOCH_US=100; that horizon is far too short
  for localization (all policies censored at 132). Consider longer trace or smaller epoch.
- incast seeds 11 and 26 STALL under every policy: a flow never completes before `-end 1000` ms
  and the htsim GOAL loop then spins forever printing `progress:` (6.5 GB log / 5 min; this is what
  killed the 08-25 batch too). Guard added to run_gate.sh (timeout + ulimit -f 512MiB +
  `seed<N>.STALLED` marker); their `.csv.tmp` measurement logs (10000 epochs) are kept but excluded
  by analyze.py. Root cause is in htsim `logsim-interface.cpp:1005` (no exit when htsim time hits end);
  ROOT CAUSE (2026-08-26, seed 11 bisected): one silent DATA drop (flow 1000000001, psn 433, 148 us)
  is never retransmitted because the UEC RTO is effectively disabled: main_uec.cpp:751 sets
  min_rto = 15us + queuesize*6*8/linkspeed with queuesize in BYTES; our `-q 1000000` packets
  (=4.096 GB) gives min RTO = 1.97 s > sim end, so every startRTO() is rejected as "too late"
  (uec.cpp startRTO null-handle branch). Silent loss has no trim/NACK path, sleek is off, so the
  hole persists; after 16384 packets the receiver's ModularVector<1<<14> rx bitmap wraps and
  aliases psn 433+16384 onto the hole (the "Spurious" burst at 5.73 ms). Fix options: add a
  -rto_min_us CLI (recommended, ~200-500 us) or use a realistic -q; then rerun the WHOLE gate.
  Temporary instrumentation left in sim/htsim (uncommitted): pipe.cpp MCP_DROP print,
  main_uec.cpp UEC_DEBUG_FLOWID env hook, uec.cpp timer debug prints widened to _debug_flowid.
- NOTE: LULESH runs take ~1 min each; script comment corrected.

## 2026-08-26 (afternoon) — real gate (PREREG §10) started: trace + cost probing
- ATLAHS trace collection (http://storage2.spcl.ethz.ch/traces/) has Mixtral-class MoE traces, no
  "NeMo Mixtral"/Zenodo item: MoE8x8B GPU64 (bin 523 MB), MoE8x13B GPU128 (bin 10.05 GB),
  MoE8x70B GPU256 (bin 31.9 GB); Chakra ET twins under astra-sim-traces/. Downloaded 64 and 128
  to sim/traces/moe8x8b_n16, moe8x13b_n32 (SHA256 + SOURCE files alongside). PREREG §10 must be
  amended to name the actual trace.
- Topology fat_tree_1024_1os: 200G links, 16 pods x 8 agg x 8 core = 1024 agg->core uplinks;
  budget 2% = 20 links.
- H18 cost probe on 1024 fat tree (sim/gate/probe/): MoE-128 advances ~0.5 ms sim per wall-second
  (105 ms after 8 min) -> a 120 s horizon is ~3 days/seed: infeasible. MoE-64 probe running.
- Prebuilt lgs/LogGOPSim needs glibc >= 2.38 (host has 2.31); source build needs libgraphviz-dev.
- Vision (.166) and Hulk (.158) idle, 72 cores, glibc 2.39 (prebuilt LogGOPSim runs there). Staged
  to both: ~/mcp/sim/{htsim binary, topologies, traces/moe8x8b_n16, gate/run_gate_real.sh, analyze.py}.
  Login: `source ~/.lab_env; sshpass -e ssh decps@<ip>` (Tooling/README.md).
- sim/gate/run_gate_real.sh = PREREG §10 fan-out (policies x seeds 1000-1029, budget 20/1024,
  loss AGG:0:0:1e-4, RTO 300 us, per-run 12 h timeout + 4 GB log cap + STALLED marker, logs
  stripped of LGS chatter on success). Split seeds across hosts via SEEDS/JOBS env.
- MoE-64 full seed-1000 run (local, epoch 100 ms): ~1 ms sim per wall-second, 2-4 GB RSS.
  LogGOPSim on Vision measuring the trace's intrinsic duration (= usable horizon per run).
- PREREG §10 amendments needed before freezing (Philip to approve): trace = ATLAHS
  MoE8x8B_N16_GPU64 (SHA256 in sim/traces/moe8x8b_n16/SHA256), not "NeMo Mixtral/Zenodo";
  horizon = one training iteration (trace length), not 120 s; epoch 100 ms not 1 s; loss onset
  t=0 not U[10,30] s (hook has no onset knob yet — add `-mcp_loss_onset_ms` if the iteration is
  long enough to afford one).
- LAUNCHED 2026-08-26 ~12:45: real gate on Vision (seeds 1000-1014, 45-wide) + Hulk (1015-1029,
  25-wide), MoE-64 on fat_tree_1024_1os, epoch 100 ms, budget 20, onset U[300,900] ms per seed
  (`seed<N>.onset`), htsim sha256 ec4578cf… (quiet LGS prints + -mcp_loss_onset_ms; LGS_PRINT_EVENTS=1
  restores the per-event log). MoE-64 iteration = 3.517 s (LogGOPSim, Vision gate/lgs/).
  Quiet prints made LULESH 60 s -> 4 s wall with identical csv.
  Coverage arithmetic: uniform sweeps 20/1024 links per epoch -> 52 epochs = 5.2 s > 3.5 s
  horizon, so uniform is expected to censor at 100 ms epochs; if §10 says TOO HARD the loosening
  step is a shorter epoch (50 or 20 ms), not a higher loss rate. analyze_real.py = onset-aware
  TTL, KM, CV(log TTL), rho(uniform,random), verdict.
- ~13:20 memory trim: workers reach ~5 GB RSS and grow (probe: 4.1 GB @1.4 s); Hulk hit 4 GB free.
  Killed newest workers -> Vision 32, Hulk 16 (Hulk xargs killed so it stops refilling). Killed runs
  carry `.STALLED` markers written by one_run: WAVE 2 = delete those markers + rerun with
  JOBS<=32/16 (also covers Hulk's 11 never-started random/oracle jobs). Size rule: <=5 workers
  per 32 GB until RSS at end of a 3.5 s run is measured (`seed<N>.time` maxrss_kb).
- ~13:55: RSS grows with sim time: local seed1000 = 18.5 GB at 3.4 s (fleet workers 7.5 GB @1.6 s).
  Peak ~20 GB/run => fleet width by memory: Hulk 5, Vision 10 (trimmed to that). 90 runs at 15-wide
  x ~1.5 h => ~9 h for the gate. Growth is per-flow state in htsim (MoE creates ~1e5 UEC flows by
  1.4 s; flow ids 1000094663+), not the MCP hooks (mcp.cpp holds only small vectors). -> HURDLES H26.
- ~14:40 RESULTS (2 % budget, 100 ms epoch): 5/5 Hulk uniform runs + local seed1000 finished:
  wall 62 min (fleet) / 31 min (alone), maxrss 21.3 GB, 36 epochs (3.585 s), 19-29 silent drops,
  uniform correct=0 in ALL (100 % censored) -> §10 TOO HARD by construction (52-epoch sweep > horizon).
  CONFOUND: faulty link US0->CS0 is the FIRST link in uniform's sweep order -> probed in epoch 1
  (before onset), next visit epoch 53. PREREG must randomize the faulty uplink per seed (or offset
  the uniform order) — otherwise uniform TTL is an ordering artifact. Detection per probe ~48 %
  (0.65 expected drops per 100 ms epoch on a ~4 %-utilized link); shorter epochs make per-probe
  detection worse, so the loosening lever is budget (or loss), not epoch.
- DECISION TAKEN (pending Philip's confirmation): stop wave 2 at 2 %; let Vision's 10 uniform runs
  finish (n=15 for the verdict); Hulk runs the "loosen one step" pilot BUDGET=41 (4 %) on seeds
  1000-1004 x 3 policies (results_real_b41/). Expected: uniform TTL ~17-23 epochs, oracle ~2,
  random ~50 % censored.
- ~16:10 §10 VERDICT at the pre-registered point (2 %, 100 ms epoch, loss 1e-4, MoE-64, n=15
  uniform): median TTL 30 epochs [28,31] from onset, censored 100 % -> TOO HARD; loosen one step.
  Pilot at 4 % (BUDGET=41) now n=15 x 3 policies: Hulk seeds 1000-1004, Vision 1005-1014
  (results_real_b41/ on each host; pull with the rsync in the notes above).
- ~20:30 4 % PILOT (35/45 in, Hulk complete): §10 verdict OK — uniform median 20 [19,21] 0 % cens.,
  random 27 [17,29] 33 % cens., oracle 12 [12,14]; CV(log TTL) uniform 0.03 / random 0.11 / oracle 0.04;
  rho(uniform,random)=0.20 (n=10). BUT drops are traffic-phased (H27): the faulty link only carries
  traffic in epochs 15-19 and 33-35, oracle's first_correct == first drop epoch in 5/5 seeds. TTL is
  the trace schedule, not the policy. Needs a PREREG metric/placement decision before freezing:
  (a) TTL from first observable drop, (b) randomize faulty uplink per seed, (c) onset inside a
  traffic window or multi-iteration horizon. Vision's last 10 oracle runs pending.
- Hook semantics to state in PREREG §2.1: a probe's evidence window is "since this link was last
  probed" (mcp.cpp `_seen_tx/_seen_drop` deltas), not the epoch; verdict = argmax drop/tx over the
  chosen set if > thresh 1e-5. Counters file (`-mcp_counters`, now in run_gate_real.sh) holds
  cumulative tx/rx/drop per link per epoch; local run real/moe64_b41_counters/ collects it for
  US0->CS0 utilization per epoch (H27 evidence).
- COUNTERS EVIDENCE (real/moe64_b41_counters/seed1000, 31 min, 21.5 GB): US0->CS0 tx per 100 ms
  epoch: 27k,24k (ep 1-2), ~0 (3-15), 33k,41k,28k,29k,22k (16-20), ~0 (21-33), 37k,40k (34-35);
  drops 6,3,3,2 in ep 17-20 and 1,1 in 34-35 (6/40964 = 1.5e-4 ~ injected 1e-4). Fabric-wide:
  896/1024 uplinks idle in epoch 10, 0/1024 idle in epoch 16 -> the MoE-64 iteration is
  compute-dominated with three communication bursts; busy-epoch link load ~6-7 % of 200G.
  Any policy is blind outside bursts. Options for §10: TTL from first observable drop; or add
  a background traffic matrix (PREREG F0 background-loss block already needs one); or choose a
  trace with continuous communication (e.g. Llama DP128) for the gate.
- ~23:30 4 % PILOT COMPLETE, 45/45, 0 stalls (mean wall 62 min, max RSS 21.5 GB): oracle 11 [10,12]
  0 % cens. CV 0.06; random 27 [17,29] 33 % cens. CV 0.11; uniform 20 [19,21] 0 % cens. CV 0.03;
  rho(uniform,random) = 0.20 (n=10). §10 verdict OK mechanically, but H27/H-order caveats stand:
  do NOT freeze §14 until Philip decides TTL definition + faulty-link randomization.
  Summaries: sim/gate/results_real_summary.txt (2 %), results_real_b41_summary.txt (4 %).

## Next action
1. Vision/Hulk: check Netronome SDK, rxe, kernel, perftest, DPDK availability (M4 prep).
2. Simulator tier: clone/build htsim (csg-htsim), ATLAHS, Chakra; gate experiment.
3. Brainstorm fast-loop design → docs/DESIGN-ALTERNATIVES.md; then P4 spec.
4. ~~PREREG.md~~ DONE (paper/PREREG.md, 2026-08-25); reviewer pre-review (ieee-journal-reviewer) after matrix lands.

## Server inventory (2026-08-25)
- Vision: Agilio CX present (pci af:00.0, `nfp` loaded), lanes enp175s0np0s0-3 / np1s0-3; **np1s0 UP = direct link to Hulk enp59s0f1np1 (UP)**. No Netronome SDK → XDP route. docker present. 67 GB free.
- Hulk: XXV710 enp59s0f0np0 (→switch, DOWN with switch), enp59s0f1np1 UP (→Vision). 75 GB free.
- Both: kernel 6.8.0-138, libibverbs 50.0, ib_core loaded, NO rdma_rxe / perftest / dpdk; gcc, cmake, bpftool, Python 3.12.

## 2026-08-25 (later) — decisions + host prep
- Philip: target **SIGCOMM'27**; sudo on servers approved.
- Soft-RoCE up on both hosts (rxe0 ACTIVE), perftest installed, direct link 192.168.100.1↔.2.
  First calibration: 2.3 Gb/s single-QP, 57 µs avg write latency (nic/CALIBRATION.md).
- Zotero collection MCP-sprayed-fabrics (AT2STS8I) is the reference library.

## 2026-08-25 (evening) — S-DOWN deliverables landed, commit 4e2a6c6
- docs/NOVELTY-MATRIX.md (34 systems; closest: SprayCheck, OmniPath Ping, ChameleMon; new finds FANT, INTaaS, OpenAI MRC/SRv6). Zotero: 39 items in MCP-sprayed-fabrics.
- paper/PREREG.md (567 lines; 12 baselines, F0–F9 fault catalogue, power calc, reward-integrity tests).
- docs/P4-DESIGN-SPACE.md (1246 lines). KEY: local /home/philip/bf-sde-9.13.1 has bf-p4c + tofino-model + PTF → full offline loop.
- sim/: spcl/HTSIM built; UEC oblivious spraying + GOAL chain verified (incast, LULESH). Llama-7B >10 min/seed (H18).
- Running: builder → htsim gate hooks (sim/htsim branch mcp-hooks, sim/gate/); p4-dataplane-engineer → p4/mcp_fabric.p4 steps 1–4 compiled locally.
- OPEN for Philip (from P4 design §12): which host is on dp9 (map says Vision, testbed.md says Hulk); is dp65 still the Agilio leg; fabric shape 2 leaves×4 spines (recommended) vs 4×2; docker group for SDE-container check; bf_switchd restart window (defense4_caseA loaded).
