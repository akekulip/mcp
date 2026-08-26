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
