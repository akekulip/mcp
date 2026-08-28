# W4 order witness: model validation (M2 step (b)) — 11/11 PASS, arming defect found AND fixed

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
| 10 | a gap arms the fast loop, and a contiguous packet after it does not re-arm | PASS |

The state machine is correct. The model's own per-packet trace confirms the arithmetic
directly: `md.wit_gap` came out `0xffff` for one lost packet, `0xfffb` for a five-packet burst,
and `0x1` for a duplicate — so a loss reads as a large value and a duplicate or reorder as a
small one, and the two are separable by magnitude if a later design needs it.

## The defect, and the fix

`mcp_fabric_w4.p4:731` claims *"A gap sets md.exceed, so the existing tbl_attn/tbl_gate
machinery treats a post-TM sequence discontinuity as path evidence with no new gate."* That was
**false on the original build**, and the model's per-packet trace said why:

```
Output Destination Field: md.wit_gap = 0xffff          <- the gap IS computed
Ingress : Gateway table condition () not matched.
Ingress : Table Ingress.tbl_wit_verdict is inhibited by a gateway condition
Ingress : Table Ingress.tbl_attn is hit
Execute Action: Ingress.act_attn_clean                 <- clean, not exceed
```

bf-p4c folds `tbl_wit_verdict` — one `const` entry plus a `const default_action` — into a
**gateway**. On `gap == 0` the gateway supplies the `wit_ok` payload; on a miss it *skips the
table*, so `const default_action = wit_loss()` never executes and `md.exceed` is never set. The
gap was computed and then silently dropped: `act_attn_exceed` executed **zero** times across a
full run of the suite. Arming from the measurement instead — `md.exceed = 1` in `wit_measure`,
cleared in `wit_ok` (`mcp_fabric_w4_arm2.p4`) — compiles cleanly and fails identically, because
the clear rides the same folded gateway.

**The fix (`mcp_fabric_w4_arm3.p4`)** is to stop relying on a miss path at all and arm from an
explicit control-flow test, which gives the gateway a condition that runs the table exactly when
there is a gap:

```p4
action wit_arm() { md.exceed = 1; }
table tbl_wit_arm {                       // keyed, so it is not a keyless default (Class 11)
    key = { md.role : exact; }
    const entries = { ROLE_LOOP : wit_arm(); }
    const default_action = NoAction();
}
...
if (hdr.witness.isValid()) {
    tbl_wit_check.apply();
    tbl_wit_verdict.apply();              // keeps its counting role
    if (md.wit_gap != 0) { tbl_wit_arm.apply(); }
}
```

Verified two independent ways. The suite's attention assertions were restored and all 11 tests
pass; and the model's own trace counts **8 `act_attn_exceed` executions against exactly 8
nonzero `md.wit_gap` values** — one event per discontinuity, none for the contiguous packets
that follow — with the path `tbl_wit_arm → wit_arm → act_attn_exceed`.

**Placement cost: zero.** On this SDE (9.13.1) the baseline, `w4`, `w4_arm`, `w4_arm2` and
`w4_arm3` all place at 8 ingress / 3 egress, read from each build's `pipe/context.json`. Note
the compile gate measured `w4_arm` at 9 ingress on the switch's 9.13.2 — a different shape on a
different compiler version — so `arm3`'s placement must be re-measured on 9.13.2 before silicon
rather than assumed from this.

Two things to carry into M6:
1. A const-entry + const-default table is not a reliable way to express "everything else" on
   this compiler. Anything that must run on the miss path needs a shape the gateway cannot
   swallow — an explicit control-flow test is the cheapest one that works.
2. `wit_ok` clearing a shared `md.exceed` would also cancel a CSIG or NIC exceedance raised
   earlier in the pipeline. `arm3` avoids this by only ever setting the flag, never clearing it;
   `mcp_fabric_w4_arm2.p4` is kept as the record of the shape that does not work.

**This is what a model gate is for**: the defect is invisible to the compile gate (every variant
compiles and places identically) and would have cost a silicon session to find.

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
