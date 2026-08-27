**Numbers I recomputed and confirmed exact (kept as written).**
- Frozen-localizer TTL: MCP 19.0 (2/30 censored) vs cusum 19.5 (6/30), paired 11 faster / 19 slower, sign p = 0.2005; sim-rule 18 vs 15, p = 0.0052. Verified against `results_tier1_cosim/**/seed*.bridge.csv` using `analyze_real.py`'s own `onset_epoch = floor(onset/epoch)` convention.
- Busy uplinks at the first-drop epoch: median 1024, ≥768 in 21/30, <512 in 2/30 (values 128, 192), over 30 seeds.
- τ_fast F6 97.4 µs (CI 67.9–215.1), ramp 1.209 ms, specificity 0/13, ratio 907 (452–1143); τ_fast F1 10.115 ms (10.101–10.127), ratio 8.8; τ_slow 88.8 ms raw, 96.2/116.6 ms Python, t_sync 94.7 ms, 30/30 epochs over when writing; single-slot read 1.37 ms, minimal path 2.20 ms.
- Silicon counts: 487 gate copies, 246/246 fault mirrors, 269/269 `worst_vlink`, +1024/pkt evidence; 9 ingress + 3 egress stages; 36 tests pass (I ran them).
- Hardware "F6" is a 50 Mb/s TM shaper = PREREG §5.2's **F5**, not F6.
- DE-CuSum is IEEE T-IT 2012, and its abstract explicitly contrasts itself with coin-toss fractional sampling — the refutation is sourced, not asserted.
- LinkGuardian is SIGCOMM'23 (DOI 10.1145/3603269.3604853); the 2022 hit is the APNet precursor.

**Errors I fixed in place.**
1. **τ_slow/τ_fast against the minimal controller path was "0.2"; it is 22 (CI 6–27).** The report contradicted itself — §3 correctly said 22, §4.2 said 0.2. Fixed everywhere.
2. **"None of LinkGuardian/FANcY/LossRadar/RFC 9341 is in NOVELTY-MATRIX.md — a citation gap that would have been fatal."** False. FANcY has its own row (#23) calling itself the precedent for data-plane attention; LossRadar is cited inside the ChameleMon row. Only LinkGuardian, RFC 9341/8321, dDrops and WJH are absent. Corrected, and M7 rewritten so it does not tell the author to "add" a paper already in the matrix.
3. **"frozen.yaml records hash be12e7b2 while the pilot ran hash 116ffc9f."** `be12e7b2…` matches HEAD exactly (verified by calling `infer.module_hash()`). The real defects are the `baseline_mode: per_element` vs `--baseline-mode pooled` mismatch, and the fact that the LULESH rehearsal's `116ffc9f` is no longer reproducible from HEAD. Rewritten.
4. **"18k runs = 14 baselines × F0–F9 × 30 seeds."** That product is 4,200. `PREREG §11` puts the main block at 5,100 and the whole matrix at ≈18,400 (tuning alone is 4,480). Fixed, and I added the sharper point: §11 estimated 2–6 min per run; the measured median is 3863 s (64 min), a 10–30× error already flagged by `H18`.
5. **Identifiability numbers were swapped.** `vlink:9` = 41.44 and `vlink:0` = 40.92, and `vlink:0` is the genuinely faulty uplink — the wrong link is consistently ahead, which is a stronger point than the draft made.
6. **"~95 ms of the 907× denominator is bfrt I/O plus Python decoding."** The 88.8 ms denominator is *entirely* raw bfrt I/O (48.5 + 29.8 + 9.6); the ~16 ms of `to_dict()` decoding is on top, in the 96–117 ms Python figure. Fixed.
7. **"a 24-B mirror header."** `mcp_fabric.p4:149-163` declares 30 B (14 B Ethernet + 16 B metadata). `HURDLES H5` says 24 B. I flagged the inconsistency rather than picking silently, and added reconciling it to M0.
8. **"amendments v1.2–v1.5."** Only v1.2, v1.3, v1.4 exist.
9. **"1024 uplinks logged."** 2048 links are logged (1024 up + 1024 down); 1024 uplinks are the candidate set.
10. **`mcp.cpp` line ranges** corrected to 120-125 (counter dump) and 133-152 (probe deltas + ratio verdict).
11. **"41/41 never-probed in 22 of the first 27 epochs"** → 21 of 27 (recounted).
12. **The 100 µs refutation assumed 300 kpps without saying so.** The F6 session ran ~75 kpps on the shaped vlink; 300 kpps is the peak blast from a different report. Both rates now stated, with the 4× consequence spelled out. M2's kill condition was rescaled the same way.
13. **Unverifiable specifics removed or attributed**: SprayCheck "≥0.4 % on Tofino" and "7e3–6e4 packets per spine" (not in the matrix; replaced with its published 1.5 %/1 iteration, 0.5 %/5 iterations, <2 KB per 32 spines); "Flare/EROICA (NSDI'26)" (absent from the matrix, and REPS/Themis are EuroSys'26 there, not NSDI); "Meta RoCE SIGCOMM'24 §6.3.1" subsection; "Alibaba HPN 0.057 %/month"; UEC CSIG 0.50 / IEEE 802.1 Nov 2025 / Cumulus 5.14–5.15 (flagged inline as unverified). The Llama-3 figure is corrected to 466 interruptions of which 419 unexpected, over 54 days.
14. **PLAN "H28/H29"** collided with the `HURDLES` H1–H27 namespace. Renamed to H8/H9 in the PREREG hypothesis namespace, which is free.
15. **`csig_h.epoch` verified to exist** (`mcp_fabric.p4:108`) — M2's field-reuse suggestion is sound as written.

**New evidence I generated, now load-bearing in both documents.**
- **Counter files are byte-identical across all five arms, 120/120 arm-seed pairs.** This proves replay is exact rather than approximate, proves β_probe = β_tag = 0 for every Tier-1 arm, and is the strongest single argument for deleting the 18,400-run matrix. It replaces the draft's unverifiable "the red team already reproduced this bit-exact".
- **A full budget sweep by independent replay** (oracle / uniform / load-gated / greedy / random at 1, 2, 4, 8, 19.5 %), plus the **TTL_obs decomposition** (oracle 1, uniform 13, gated 11 at B = 41). The draft's replay numbers (19.5 / 19.5 / 17–19) are close but were not reproducible as stated; mine are in the report with their provenance.

**The counter-argument that forced a rewrite.**
The draft's headline — "the localization floor is the fault's own evidence rate, not the measurement schedule" — is refuted by the repo's own oracle: 10 epochs vs round-robin's 19 at B = 41 is a 47 % reduction, *above* H1's 30 % bar. Schedule demonstrably matters; what fails is computing a good one from counters. A reviewer would find this in ten minutes and the paper would be dead. I also killed two weaker versions of the claim: "spraying makes gray loss self-localizing" (the per-link sequence check is topology-agnostic and works identically on ECMP, so spraying is not what makes it work), and "at zero probe bytes" (the shim is 2 B/packet). The rewritten contribution is a three-part claim — the decomposition, the *computability* negative result with its informational reason, and the priced link-local alternative at 0.049 % of capacity, which makes the equal-budget comparison legitimate instead of a straw man. M1's goal and gate were rewritten to match, and I added semi-synthetic multi-fault and moving-fault replay, which is free and closes the single biggest hole in the negative result.

**CRITICAL, not fixed.**
1. **The negative result is currently single-fault, single-trace, single-operating-point.** Multi-fault and non-stationary replay (new M1 step 3) is the only thing standing between it and a desk reject; until it runs, the scope sentence in C2 must stay in the paper.
2. **`sim/htsim/htsim/sim/pipe.h` implements only Bernoulli silent loss.** F2–F9 do not exist in the simulator. Any claim spanning the fault catalogue is unsupported today, and I removed implementing them from the plan rather than pretending a month absorbs it.
3. **The panel's literature sweep is not in the repo**, so roughly a dozen claims about CSIG standardization, packet-trimming product versions, WJH, dDrops and venue years for Flare/EROICA could not be checked against anything. I removed or flagged them; they need a source pass before drafting.
4. **The 62 min / 21.5 GB figure everyone quotes is 64 min** (median 3863 s over 90 runs). Minor, but it appears in every cost calculation in the repo.
