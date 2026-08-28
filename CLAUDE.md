# MCP — repository instructions

Gray-failure localization on packet-sprayed AI training fabrics. Target venue SIGCOMM'27
(~Jan 2027) or NSDI'28. The canonical schedule is `docs/review/PLAN.md` (tracked) with the full
RALPLAN-DR record in `.omx/plans/high-novelty-telemetry-plan.md`; the pre-registration is
`paper/PREREG.md` (amendments in §14) and every hurdle hit so far is in `HURDLES.md`.

## Standing rules

- **Commits are authored as Philip alone.** `akekulip <akekulip@gmail.com>`, no `Co-Authored-By`,
  no Claude trailer, no `🤖 Generated with` line. This overrides the global commit convention.
- **Never reboot the switch.** `bf_switchd`, the bfrt controller and `bfshell` may be restarted;
  the machine may not.
- **Check who owns the chip before any port or table write.** One Tofino is shared with other
  projects. `pgrep -x bf_switchd` then `sudo tr '\0' ' ' < /proc/<pid>/cmdline` names the loaded
  program. As of 2026-08-28 the chip is running `defense4_rrc_bor_unified12` (pid 36630) — a
  sibling project's program, not MCP. Reconfiguring its ports broke it once; restore via bfrt.
- **`pkill -f <pattern>` from an SSH session kills that session** (the pattern matches the ssh
  command line). Use `pkill -x <exact-name>`.
- **Monitor long runs.** Never start a multi-hour batch without a check that catches an error in
  the first minutes; verify the flags actually reached the run log before walking away.
- Simulation blocks are memory-bound: one htsim gate run is ~62 min and ~21.5 GB (H26).

## Cross-check before concluding — a standing role, not a nicety

Four times on 2026-08-28 a dramatic result turned out to be an artifact of the harness rather than
a finding, and every one of them would have been published if it had not been checked. They share
a shape, so the check is mechanical:

1. **An upper-bound arm that fails is a bug until proven otherwise.** The oracle losing to a
   baseline (H29) meant the oracle was not handed the synthetic faults. Every arm censored
   including the oracle (H32) meant the fault injector had *overwritten* the background rate
   instead of composing with it, so there was no fault to find. If the arm that is handed the
   answer cannot find it, stop and audit the harness.
2. **Verify the injected quantity in the DATA, not in the flags.** `-mcp_loss` was on the command
   line and the run log said so. The faulty link's measured rate was 0.72x the healthy mean, and
   that is what settled it. Read out what the experiment actually did.
3. **Print each arm's realised parameters before believing any row.** In the audit gate, twins were
   modelled as carrying production's load onto a link that by definition carries no production,
   and separately a clone ratio of 0.02 was normalised to induce *full* load. Both flattered the
   arm being argued for. A three-line dump of packets sent, mean load, and the fraction of each
   stratum covered exposed both instantly.
4. **Report safety AND usefulness together.** "0 % unsafe restorations" was scored by an arm that
   could never certify anything at that budget — it always returned INCONCLUSIVE and so was
   perfectly safe and perfectly useless. A rule that never fires is not a safe rule. Any
   false-positive metric must be reported next to the rate at which the mechanism actually acts.
5. **Cheap, clean and decisive is the suspicious combination.** Real measurements of a hard problem
   are rarely all-or-nothing. A column of 0.0 % and 100.0 % is a hypothesis about the harness
   before it is a result about the system.

The same discipline applies to arguments, not just experiments: the first-pass gate-2 verdict took
a cost calculation that was valid only for IID loss under the audit's own packet distribution and
generalised it into "recovery evidence is cheap". The correction is recorded in
`docs/review/GATE2-VERDICT.md` rather than edited away, because the failure mode — a correct number
carried outside the regime where it holds — is worth keeping visible.

## Testbed (verified 2026-08-28)

| host | mgmt | access |
|---|---|---|
| switch (Tofino 1, SDE 9.13.2, hostname `ufispace`) | `decps@10.10.54.81` | key-based SSH, passwordless sudo |
| Vision | `decps@10.10.54.166` | `source ~/.lab_env; sshpass -e ssh decps@10.10.54.166` |
| Hulk | `decps@10.10.54.158` | same, `$SSHPASS` from `~/.lab_env` — never inline on a command line |

Laptop SDE is 9.13.1 (reference only); compile and run on the switch's 9.13.2.

Cabling and addressing:

| link | endpoints | speed | note |
|---|---|---|---|
| Vision ↔ switch | `enp59s0f0np0` (10.0.1.1/24, 192.168.10.1/24) ↔ front port 15/1 = **dp9** | 25G | the MCP fabric's host port and the mirror collector |
| Hulk ↔ switch | `enp59s0f1np1` (10.0.1.2/24) ↔ front port 15/2 = **dp10** | 25G | second source leaf (M3); links only when 15/2 is out of MAC-near loopback |
| Vision Agilio ↔ Hulk | `enp175s0np1s0` (192.168.100.1/24) ↔ `enp59s0f0np0` (192.168.100.2/24) | 10G | direct NIC-to-NIC, carries Soft-RoCE (rxe) |

- The virtual fabric (4 leaves × 2 spines) is emulated on the cage 5↔6 4-lane 25G DAC loopback,
  one TM queue per virtual link (`p4/control/setup_skeleton.py`, `LEAF_HOST_DP=[9,10,9,9]`).
- `nic/lab_link_setup.sh` (deployed at `/home/decps/lab_link_setup.sh` on both hosts) restores
  link state, addressing and RoCE after a reboot — NetworkManager strips runtime `ip addr add`
  on a link flap.
- Soft-RoCE GID follows the interface's **primary** address; Hulk's stale `10.0.2.10/16` on
  `enp59s0f0np0` silently broke `ib_write_bw` (0 bytes). Omit `-x <gid>` from perftest.
- The Vision Agilio CX (Netronome NFP-4000) runs **eBPF/XDP offloaded to the NIC**
  (`nic/xdp_count.c`, `nic/README-xdp.md`). P4 on it needs the native SDK (`nfp4build`/`nfp4c`),
  which is not publicly downloadable — a request is out (`docs/NETRONOME-SDK.md`).

## The frozen localizer

`controller/infer.py` is the ONE inference layer every arm uses (PREREG §3.3). Any edit requires
`python3 controller/freeze.py` to refresh `conf/infer/frozen.yaml:module_sha256`, a §14 amendment
recording why, and a re-run of every affected result. Warm-up is counted in **observed packets**,
never in update calls (v1.6) — counting calls penalised low-cadence schedules and made the in-band
arm blind. Run `python3 -m pytest controller/tests -q` (37 tests) after any change.

## Simulation

`sim/gate/replay.py` replays any read schedule over recorded per-link counters in seconds instead
of the hours htsim needs; it is exact because the counter logs are byte-identical across arms
(the measurement policy never perturbs the fabric). Prefer it to a new htsim block. Scenario
randomness uses `scenario_seed()` (CRC-32), never Python's salted `hash()`.
