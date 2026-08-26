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
