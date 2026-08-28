# W4 order witness: model validation (M2 step (b)) — 11/11 PASS, one real defect found

Ran 2026-08-28 on the laptop's SDE 9.13.1 software model. **The shared Tofino was never
touched**: no chip access, no `bf_switchd` on the switch, no ports written. The switch stayed
on `defense4_rrc_bor_unified12` (pid 36630) throughout.

Suite: `p4/ptf/test_w4_witness.py` (11 tests). Harness: `p4/ptf/model/`.

## Result

| # | Semantics (PLAN M2 (b)) | Verdict |
|---|---|---|
| 01 | initialization — a fresh link starts at expected 0, first packet is contiguous | PASS |
| 02 | contiguous run of 10 leaves expected = last+1, no events | PASS |
| 03 | a single loss re-synchronises on the next survivor and does not desynchronise later packets | PASS |
| 04 | a burst of 5 behaves as one discontinuity; the loss count is recoverable as 2^16 − gap | PASS |
| 05 | a duplicate re-synchronises to observed+1 (and is indistinguishable from loss by the verdict) | PASS |
| 06 | reorder re-synchronises (out of scope on a FIFO link; pinned so it cannot regress silently) | PASS |
| 07 | modulo wrap 65535 → 0 costs nothing and raises nothing | PASS |
| 08 | controller re-seed: the next packet at the seeded value is contiguous | PASS |
| 09 | per-link independence — interleaved links keep separate state (the multi-queue prerequisite) | PASS |
| 10 | canary for the arming defect below | PASS (asserts the defect) |

The state machine is correct. The model's own per-packet trace confirms the arithmetic
directly: `md.wit_gap` came out `0xffff` for one lost packet, `0xfffb` for a five-packet burst,
and `0x1` for a duplicate — so a loss reads as a large value and a duplicate or reorder as a
small one, and the two are separable by magnitude if a later design needs it.

## The defect: a sequence gap does not arm the attention machinery

`mcp_fabric_w4.p4:731` claims *"A gap sets md.exceed, so the existing tbl_attn/tbl_gate
machinery treats a post-TM sequence discontinuity as path evidence with no new gate."* **That is
false on this build**, and the trace says why:

```
Output Destination Field: md.wit_gap = 0xffff          <- the gap IS computed
Ingress : Gateway table condition () not matched.
Ingress : Table Ingress.tbl_wit_verdict is inhibited by a gateway condition
Ingress : Table Ingress.tbl_attn is hit
Execute Action: Ingress.act_attn_clean                 <- clean, not exceed
```

bf-p4c folds `tbl_wit_verdict` — one `const` entry plus a `const default_action` — into a
**gateway**. On `gap == 0` the gateway supplies the `wit_ok` payload; on a miss it *skips the
table*, so `const default_action = wit_loss()` never executes and `md.exceed` is never set.
The gap is computed and then silently dropped. `act_attn_exceed` executes **zero** times in a
full run of the suite.

Arming from the measurement instead (`p4/witness/mcp_fabric_w4_arm2.p4`: `md.exceed = 1` in
`wit_measure`, cleared in `wit_ok`) compiles cleanly but does **not** fix it either — still zero
`act_attn_exceed`. So the arming needs a design decision, not a one-line patch, and it is now a
precise reproducible question rather than a surprise waiting on the chip.

Two consequences worth carrying into M6:
1. A const-entry + const-default table is not a reliable way to express "everything else" on
   this compiler. Anything that must run on the miss path needs a shape the gateway cannot
   swallow.
2. `wit_ok` clearing a shared `md.exceed` would also cancel a CSIG/NIC exceedance raised
   earlier in the pipeline. A production integration needs a separate `md.wit_bad` flag OR-ed
   into `md.exceed`, not a shared write. This is noted in `mcp_fabric_w4_arm2.p4`.

**This is what a model gate is for**: the defect is invisible to the compile gate (all variants
compile at 8 ingress / 3 egress) and would have cost a silicon session to find.

## Reproducing

```
sudo $SDE/install/bin/veth_setup.sh          # once; the only step needing root
p4/ptf/model/run_stack_host.sh p4/ptf/model/run_ptf.sh
```

`run_stack_host.sh` starts `tofino-model` + `bf_switchd` on the laptop SDE and runs the suite
against them. Three environment problems it works around, recorded so they are not re-debugged:

- The SDE's `run_tofino_model.sh` / `run_switchd.sh` wrappers shell out to `sudo`, and the model
  needs `CAP_NET_RAW` on the veths, so the binaries are invoked directly under sudo. An
  unprivileged user namespace (`unshare -r -n`) hosts veths fine but breaks the DMA emulation —
  bf_switchd asserts in `pipe_mgr_lrt_buf_load`.
- `bf_switchd` loads `libpltfm_mgr.so` and exits looking for a BMC, so the model conf is
  rewritten without the platform agent and with absolute artifact paths (`model_*.conf`).
- PTF runs as root and Debian's `protobuf nspkg.pth` pins the `google` namespace to
  `/usr/lib/python3/dist-packages`, whose protobuf predates `google.protobuf.internal.builder`.
  `p4/ptf/model/pyfix/sitecustomize.py` repoints it at the SDE's protobuf 3.20.3.

**A model PASS is necessary, not sufficient** — the model accepts control-plane writes the ASIC
rejects. Silicon is still M2 step (c).
