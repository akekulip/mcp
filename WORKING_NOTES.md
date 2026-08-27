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
- 2026-08-27 ~00:15 "go": decisions taken = TTL_obs (from first observable drop, via counters) as the
  §10 rule metric + from-onset reported; faulty uplink randomized per seed (seed<N>.fault);
  point frozen at 4 %, loss 1e-4, 100 ms. PREREG §14 amendment v1.2 appended. v1.2 GATE LAUNCHED:
  Vision seeds 1000-1019 (10-wide), Hulk 1020-1029 (5-wide), OUT=results_real_v12 (~6.5 h).
- 2026-08-26 ~21:30 SWITCH REACHABLE (decps@10.10.54.81, up since ~17:15): chip FREE — no
  bf_switchd, gc-switchd inactive+masked (defense4_caseA NOT loaded). SDE 9.13.2 at
  /home/decps/Downloads/bf-sde-9.13.2 (also /opt/bf-sde-9.13.2). mcp_fabric.p4 (sha c40dbfbe)
  compiled there: 0 errors, same stages/tables/bin size as local 9.13.1 -> H17 closed for step 4.
  Build at ~/mcp/p4/mcp_fabric.tofino on the switch. Starting bf_switchd = gated on Philip.
- Philip 2026-08-26: bf_switchd NOT YET (chip stays idle; prepared: ~/mcp/p4/mcp_fabric_abs.conf +
  launch_mcp_switchd.sh on the switch, run with sudo when approved). FABRIC SHAPE DECIDED:
  **4 leaves x 2 spines** (P4 design §12 Q5) -> update P4-DESIGN-SPACE §5/§12 and the vlink map.
  Q4: decps is NOT in the docker group on the switch (needs sudo usermod). Q1/Q2 (dp9 host, dp65
  Agilio leg) still need a live bf_switchd to read link state.
- 2026-08-26 ~21:45 Philip: sudo on switch OK, never REBOOT the switch; bf_switchd/controllers fine.
  bf_kdrv was not loaded after the reboot -> `sudo bf_kdrv_mod_load $SDE_INSTALL`; bf_switchd now runs
  mcp_fabric (launch_mcp_switchd.sh, /tmp/mcp_switchd.log). bfshell usage: feed stdin with sleeps
  (`ucli` lands in pm context; bfshell only flushes on exit). Docker NOT installed on switch (Q4).
  WIRING (10G sweep of all 132 lanes, 2026-08-26): UP = 15/1 (dp9, 25G RS AN) = **Vision
  enp59s0f0np0** (carrier flips with 15/1 -> Q1 = Vision); 33/2+33/3 (dp66/67, 10G, symmetric RX)
  ; 5/0-3 + 6/0-3 (dp164-167, 172-175, 10G, 0 frames) -> patched DAC between cages 5 and 6.
  DOWN with module present (RDY): 15/0, 15/2, 15/3 (4x25G breakout, other legs unplugged).
  **Hulk enp59s0f0np0 is NOT connected to the switch** (no link at 25G or 10G on any lane; its
  i40e now reports 10GbaseT-only link modes, AN off). dp65 (33/1) RDY=NO -> Agilio leg gone (Q2);
  Vision Agilio np0 cage EMPTY (no module), np1 = direct 10G link to Hulk enp59s0f1np1.
  PAIR TEST: dis 6/0,6/2 -> 5/0,5/2 drop => cages 5<->6 are one 4-lane DAC, lane-for-lane
  (5/k <-> 6/k, k=0..3): 4 physical loopback links available to mcp_fabric. dis 33/3 leaves 33/2 UP
  => 33/2 and 33/3 go to separate external devices (probably the DNP3 rig; leave alone).
  5/0-3 <-> 6/0-3 link at **25G RS-FEC** (dp164-167 <-> dp172-175): 4 x 25G loops = 100 Gb/s for
  the 4-leaf x 2-spine virtual fabric (§5.4 bandwidth table: recompute with these, not dp65).
  Ports left configured on the chip: 15/0 (10G, no link), 15/1 25G (Vision), 5/x+6/x 25G, 33/x 10G,
  and ~120 sweep-added RDY=NO lanes (harmless; port-del if `show` gets noisy).
  HUMAN ACTION NEEDED: plug Hulk enp59s0f0np0's DAC into the switch (cage 15 lanes 0/2/3 have the
  breakout legs; today no lane links) — until then Hulk reaches the fabric only via Vision's
  direct 10G link (enp59s0f1np1 <-> enp175s0np1s0).
- 2026-08-26 ~22:30 Philip: "P4 and the switch is yours". Fabric mapping for 4x2 on the real
  loops: leaf l <-> pair 5/l<->6/l; uplink out 5/l qid s (re-enters 6/l = spine pass), downlink
  out 6/l qid s (re-enters 5/l = dest-leaf pass); all leaves deliver to dp9 until Hulk is cabled.
  p4-dataplane-engineer agent: setup_skeleton.py rewrite + silicon smoke of steps 1-4 (running).
  STEP 5 DONE (me): attention register + §7.4 rule + TCAM gate; 0 errors both SDEs, 8 stages;
  PREREG v1.3 freezes §7.4; H22 closed; 3 new bf-p4c constraint classes (9-11) in the tofino-p4
  skill. Next: step 6 (mirror on inj_drop -> collector dp9), control-plane additions for step 5.
- ~23:45 STEPS 6 + 7 DONE: mirrors (sid 3 on injected faults, sid 1 on gated samples, OR-composed;
  collector = dp9 for now) and the CSIG tag (inserted/zeroed in ingress act_enter with path_id +
  epoch, compare-and-replaced in egress via diff = worst |-| this, gate diff == 0). fabric_h is 8 B
  (+path_id), csig_h 14 B. Ingress 9 stages (at the §8.1 limit), egress 3. Both SDEs 0 errors,
  bin 1461583 B, sha a0dee21f. Constraint classes 12-13 added to the tofino-p4 skill (mid-word
  intrinsic slices; egress one-source-per-container). Not yet loaded on the chip: the switch still
  runs the step-4 build while the agent smoke-tests it; reload after that.
- ~00:20 (08-27) ALL 8 §9.2 STEPS COMPILED: final sha 1a8fc6104b03bcdf, bin 1461583 B on both SDEs
  (also built at ~/mcp/p4 on the switch, not loaded). p4/control/setup_attention.py = steps 5-7
  control plane (client_id 2, no bind): params k_up/a_min/n_clean_m1, reg_attn seed, 255 tbl_gate
  rows, tbl_eg_vlink 16 rows, exceed thresholds, mirror sids 1/3 -> dp9. Rule shipped = saturating
  bump (no bump_cap); PREREG v1.3 corrected same day. Commits 575f1ee..381c4e4.
  TO DO once the step-4 silicon smoke finishes: pkill bf_switchd, relaunch (same launch script,
  build already at ~/mcp/p4/mcp_fabric.tofino), setup_skeleton up + setup_attention up, then
  silicon tests: (a) counters + hairpin delivery as in step 4; (b) mirrors: tcpdump on Vision for
  ether 0x88F0 copies while `fail <vlink> 50 drop`; (c) attention: `attn` dump before/after sending
  evidence packets (UDP dst 0xE5E5, evid_h path_id/loss_q) — attn[path] += 1024 per packet;
  (d) CSIG: captured mirrored samples carry csig_h with worst_qdepth/worst_vlink set.
- 08-27 ~00:45 DEPLOYED: step-4 silicon smoke PASSED (agent; p4/reports/step4-silicon.md) and found
  the parser cast aliasing (md.hop == vsw_id<<8|hop) -> fixed by widening fabric_h to 16-bit fields
  (12 B; ingress back to 8 stages; sha 232b7355). bf_switchd restarted on the final build;
  setup_skeleton up + setup_attention up succeeded (bind_pipeline_config needed per client).
  Agent now validating steps 5-7 on silicon (gate sampling, fault mirrors, evidence bump, decay,
  CSIG). Skill testbed.md updated with the deployment landmines.
- 08-27 ~00:55 STEPS 5-7 SILICON (agent, p4/reports/step5-7-silicon.md): gate 508/4000 copies at
  attn=4096 (6.25 % x 2 passes), seed 0 -> 0, seed 65535 -> 2/pkt; evidence +1024/pkt exact; decay
  exact; fault mirrors == inj_drop count exactly; CSIG under a 50 Mb/s shaper: worst_vlink correct
  92.5 %, qdepth up to 11306 cells, attn saturated 65535 -> ~100 % sampling: THE FAST LOOP CLOSED
  END-TO-END ON SILICON (H7 mechanism demonstrated; timing measurement still to do).
  Defects -> P4 v2 (sha 789b5b27, deployed 23:11): mirror_h prepended to copies (Mirror.emit copies
  the packet as arrived), egress skips copies, evidence forwarded host-pipe -> loop-pipe (reg_attn is
  PER PIPE: dp9 = pipe 0, loops = another pipe), attention only on fabric passes. Class 14 added to
  the skill. Agent re-validating v2 now.
- 08-27 ~01:15 V2 VERIFIED ON SILICON (p4/reports/step5-7-silicon-v2.md): all exact — 487/487 copies
  0x88F1 with flags bit0, fault copies 246 == inj_drop 246, evidence +10240 in BOTH pipes, decay
  symmetric [4095,4095]/[904,904], inner CSIG worst_vlink 269/269, loop closes (attn trajectory
  visible in mirror_h.attn: 843 @4096, one per +1024 step, 8675 @65535). Notes: mirror_h.hop is
  next_hop (renamed); CSIG exceedance only in the loop pipe by construction (design errata 8).
  H4, H5 closed. Chip state: build 789b5b27 loaded, both control planes up, attn seeded 4096.
  NEXT on hardware: H7 timing (tau_fast vs tau_slow), rxe pre-test (H20) needs Hulk cabled.
- 08-27 ~01:30 H7 (F6) TIMING RUN STARTED: build f0b66793 (mirror_h + 48-bit ingress_mac_tstamp,
  30 B) loaded 23:23 switch time; agent measuring tau_fast = first attn>4096 copy - first
  csig.worst_qdepth>=4096 copy (switch clock), tau_slow = full 256-slot reg read + counter sync +
  256-slot write from the switch's control plane, >=10 reps, specificity across healthy paths.
  F1 (loss) cannot be timed until the NIC evidence producer (nic/) exists -> needs Hulk + rxe.
- 08-27 ~02:00 H7 (F6) RESULT (p4/reports/h7-timing-F6.md, 12 reps): tau_fast as PREREG defines it
  is 0 by construction (ingress order exceed -> attn -> gate: the evidence packet is gated under
  the attention it just raised; t_react - t_evid <= 0 in 12/12). Back-extrapolated tau_fast
  median 97.4 us (BCa CI 68-215 us); ramp to saturation 1.21 ms; tau_slow full-sweep epoch 88.8
  ms (read 48.5 + counter sync 29.8 + write 9.6) -> ratio median 907, CI 452-1143 (sign test
  12/12, p=2.4e-4); but vs a minimal 1-slot epoch (2.2 ms) ratio 22, CI 6-27 (< 100).
  Specificity 0/13 healthy path-instances reacted. F1 not run (no NIC evidence producer).
  DECISIONS FOR PHILIP (PREREG, post-hoc-flagged): (i) tau_fast definition — first gated sample
  after the first *exceeding* packet is degenerate; candidates: ramp back-extrapolation, or
  time from fault ARM (shaper on) to first raised-attention copy, or from first over-threshold
  queue sample to attn crossing a fixed level (e.g. 2x baseline); (ii) tau_slow scope — the
  claimed 100x must name the epoch (full sweep vs minimal); (iii) H7 needs F1 -> nic/ producer.
  Anomalies: 0.15-0.22 % collector-side frame drops at saturation; `shape` unit is Gb/s (fixed
  usage text). Chip idle, attn 4096, PID 26316.
- 08-27 Philip: tau_fast = ramp back-extrapolation; tau_slow = full-sweep epoch -> PREREG amendment
  v1.4 appended (F6 post-hoc, F1 pre-registered). Agent building nic/evidence_probe.py then H7-F1.
- 08-27 ~02:30 CONTROLLER WORKSTREAM STARTED (two builders in parallel): controller/infer.py = the
  frozen common inference layer (§3.3: Beta-Binomial + Normal-Gamma posteriors, uniform-prior
  de-aggregation path->links, two-sided CUSUM, ranking; conf/infer/frozen.yaml + freeze.py hash;
  tests i-v) + controller/reward.py (§7.2) with test_reward_no_leakage (§7.3);
  controller/epoch_loop.py + hw_adapter.py (mirror_h/fabric_h/csig_h parser, tbl_vlink deltas,
  reg_attn snapshot; tbl_fail = ground truth, never a sample) + policies.py (uniform/random/
  oracle/mcp_stub = A6). Shared Sample(element, delivered, lost, latency_us, t_us) contract.
  Later: point sim/gate analysis at infer.localize too (§3.3 says every arm uses it).
- 08-27 ~03:10 nic/evidence_probe.py DONE (agent): spray recovery = zlib.crc32(src|dst|sport)&1,
  4983/4983 vs silicon; 1 % drop -> loss on the right path only, reg_attn -> 65535 both pipes.
  H7-F1 (12 reps, v1.4): tau_fast 10.115 ms (CI 10.10-10.13), sid-3 check 10.47 ms, ratio 8.8
  (CI 8.6-9.1) -> H7 FAILS for F1, structurally (no in-band loss evidence; floor = RTT tail of the
  probe path, 1.8 ms; 2 ms window gives 2.0 ms/ratio 44 with specificity breaking). Recorded in
  PREREG §14. Defect: evidence-packet copies had path_id 0 -> P4 emits md.mir_path (MAU copy of
  attn_idx) now. NOTE for the paper: "fast where the data plane can see, host-bound where it
  cannot" is the honest H7 story.
- 08-27 ~03:45 CONTROLLER LANDED (5a1892f) + CO-SIM BRIDGE: htsim `-mcp_policy extern:obs:act`
  (sim/htsim ef6d591) <-> controller/sim_bridge.py; extern-uniform reproduces C++ uniform
  IDENTICALLY (LULESH-128 seed 1). cusum arm (MCP v0 = localizer suspects + round-robin explore):
  budget 32 -> anomaly at epoch 49, locks on US0->CS0; budget 4 -> blind (per-element 10-obs
  warm-up needs 320 epochs). Builder adding baseline_mode=pooled. PREREG §14 row for the
  candidate localizer constants (not frozen yet). Remaining MCP pieces: shadow-price budgeted
  bandit (H3) + context vector (H4) on top of the bridge; the hardware epoch loop is code-complete
  but untested on silicon.
- 08-27 ~04:30 MCP v0 LEARNER (controller/mcp_policy.py) + co-sim mini-gate (run_cosim.sh): on
  LULESH-128 mcp v0 is WORSE than uniform; root cause = localizer false alarms (anomaly on in
  46/55 epochs every run: two-sided loss CUSUM trips on healthy links in pooled mode). Fix: loss
  CUSUM upper-sided only (builder). Learner untuned; results interim, not for the paper.
  + explore_floor=0.25 (coverage guarantee) -> b32: mcp median 8 vs uniform 9, 0 censored (no
  more collapse); b4: still 4/5 censored (floor = 1 slot). Awaiting the upper-sided CUSUM fix
  before any tuning; then the §3.2 tuning block, not ad-hoc knob turning.
- 08-27 ~05:00 Localizer: upper-sided loss CUSUM landed (29fc176) but alarms unchanged (46/55):
  the real source is IDLE links — a probe returning (0,0) leaves the Beta(1,1) prior mean 0.5
  and the CUSUM explodes (~2000/epoch). Builder making zero-count samples no-ops. Hardware loop
  now has --policy mcp (McpLearnedPolicy, ed81082/0b59db6). Pending: zero-count fix -> rerun
  run_cosim.sh; slow-loop silicon report; v1.2 gate.
- 08-27 ~05:30 zero-count fix landed (af5e858) but alarms still 46/55: third source = prior mass
  on light probes (500 clean packets -> Beta mean 2e-3 -> stat 6.96 > h). Fix in progress:
  loss CUSUM increment = binomial LLR (x log(p1/p0) + (n-x) log((1-p1)/(1-p0)), delta_loss 1e-3,
  h 5 nats) — count-aware, clean probes give negative increments. Lesson for §3.3: "CUSUM on the
  posterior mean" is the wrong statistic for counts; PREREG text to be amended when frozen.
- 08-27 ~06:15 LOCALIZER CLEAN (361a729, hash 116ffc9f, h=6.5 nats): co-sim alarms now ALL on the
  faulty link, 0 false alarms in 50 runs. cusum == uniform TTL (first post-onset probe decides);
  mcp v0 untuned: b32 median 11 vs 9, b4 4/5 censored. Next per PREREG = §3.2 tuning block on the
  tuning split (seeds 6-10, LULESH-128): sim/gate/run_tuning.sh (64 mcp configs, 9 cusum).
- 08-27 ~07:15 TUNING + EVAL DONE (730 + 40 runs, 0 failures): all arms tie at equal budget on
  LULESH-128 single-fault (b32 medians 9/8/9/9; b4 31/22/31/34). Learner selects coverage-like
  configs (floor 0.75). sim/gate/COSIM-RESULTS.md. Conclusion: pipeline validated; H1 on this
  rehearsal trace would be falsified; the Tier-1 environment (MoE bursty load = context, multi-
  fault, background loss, non-stationarity) is where MCP must show its 30 %. Next research
  moves for Philip: (a) co-sim on MoE-64 @1024 (1 h/run, on Vision/Hulk after the gate);
  (b) hook flags for background loss (-mcp_bg_loss p) and multi-fault; (c) load context is
  already in the learner's features.
- 08-27 ~07:30 `-mcp_bg_loss <p>` added to the hook (sim/htsim 4a9ad8b): F0 background loss on all
  uplinks, per-link RNG, fault spec overrides its link (verified: 34/128 uplinks dropped at 1e-4).
  Multi-fault already works (repeatable -mcp_loss). run_cosim/run_tuning need a BG_LOSS knob.
- 08-27 ~05:45 SLOW LOOP ON SILICON (p4/reports/slow-loop-silicon.md): adapter correct first try;
  copies 117/epoch (attn decays to <4096 -> 5.86 %), counters exact, frozen mode 0 writes, uniform
  policy rotates exactly (bfrt readback), fault -> vlink 0/9 top (identifiable only as a pair with
  one host). tau_slow 96.2 ms observe / 116.6 ms with writes -> epoch default 200 ms. No-fault
  false alarms 90/100 before af5e858, 0/100 after. GRPC_ADDR localhost-only: copies captured on
  Vision and replayed on the switch.

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
