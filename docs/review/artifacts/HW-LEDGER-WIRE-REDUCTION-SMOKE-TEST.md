# Hardware smoke test — wire-reduction ledger on real silicon (2026-09-02)

Real hardware validation of the wire-overhead reduction
(`docs/review/artifacts/LEDGER-WIRE-REDUCTION-2026-09-02.md`): does `mcp_fabric_ledger.p4`, with
`hdr.witness.link_id` dropped and `md.wit_link` reconstructed at ingress from
`(ig_intr_md.ingress_port, hdr.fabric.spray)` plus a freshly re-derived ctx nibble, still forward
and count correctly on the real Tofino — not just in `tofino-model`. Both parts pass, replicating
`HW-LEDGER-SMOKE-TEST.md`'s exact methodology against the new binary.

## Setup

- Chip taken over from `mcp_fabric_ledger` (this program's own PRIOR build, i.e. the
  pre-wire-reduction binary — confirmed via `pgrep`/`cmdline` before touchdown, snapshotted to
  `p4/hw/snapshots/20260902T182651Z-takeover.txt`) via `takeover.sh`. Two-phase recheck (t+0,
  t+30s) both clean — no respawn.
- `deploy.sh mcp_fabric_ledger` shipped the edited source, compiled clean on the switch's 9.13.2
  (0 errors, 5 warnings, 12 ingress / 5 egress stages, 91 SRAM / 16 TCAM blocks — matching the
  9.13.1 laptop gate exactly), then sealed build/setup/runtime provenance manifests.
- `bringup.sh mcp_fabric_ledger` launched a fresh `bf_switchd` (pid 1286684), ran
  `setup_skeleton.py up` then `setup_attention.py up`. The latter printed
  **`tbl_wit_link_recon: 16 rows installed, 0 stale rows removed`** — the new production
  control-plane population (`plan_wit_link_recon()`/`install_wit_link_recon()`, added to
  `setup_attention.py` this session) ran automatically as part of the standard bring-up sequence,
  with no manual step. All four loop pairs and both host ports came up.
- **A real, general infrastructure gap was found and fixed here, not just worked around**:
  `gate_agent.py` refused to start (`RuntimeError: loaded setup does not name the live build
  owner`) because nothing writes the `<PROG>.loaded-setup.sha256` receipt its
  `verify_loaded_setup()` guard requires — that guard was added on the switch in a later session
  (git commit `b1a5ec1`, "pull gate_agent.py/... from the live switch") than `bringup.sh`, and the
  writer-side edit was never made or never pulled back. Fixed by adding step 5c to
  `p4/hw/bringup.sh`: write the receipt (bf_switchd pid + a stable switch identity + the sealed
  setup-manifest hash) right after `setup_attention.py up` succeeds. Verified against the live
  switch by extracting the exact shell logic bringup.sh now runs and confirming it reproduces,
  byte-for-byte, the receipt this session first wrote by hand to unblock itself. This closes the
  gap for every future bring-up, not just this one.
- Traffic generated from Vision with `multicontext_probe.py` (identical file, confirmed by diff
  against the switch's already-deployed copy): UDP `10.0.1.1→10.0.1.3`, `sport 41000 dport 4449`,
  1400 B payload, DSCP selecting contexts 2/6/10/14 — same recipe as the original smoke test.
- Read out with the gate agent's `R` command. One operational note not in the original doc: bare
  `R` (no arguments) reads every populated register index and fails hard on any seq/obs asymmetry;
  bring-up's own port-training traffic left sublink 14 asymmetric (21 stamped, 0 arrived — an
  incomplete round trip from link training, not a real loss). Requesting the exact sublinks under
  test (`R 2 6 10 14 162 166 170 174`) avoids this and is what every read below uses.

## Part 1 — clean forwarding, 80 packets, 4 contexts

20 packets per context (2, 6, 10, 14) sent from Vision. Baseline vs. post-traffic `R`:

| sublink | vlink | ctx | before (seq/obs) | after (seq/obs) | Δseq | Δobs | loss |
|---|---|---|---|---|---|---|---|
| 2 | 0 | 2 | 0/0 | 20/20 | 20 | 20 | 0 |
| 6 | 0 | 6 | 0/0 | 20/20 | 20 | 20 | 0 |
| 10 | 0 | 10 | 0/0 | 20/20 | 20 | 20 | 0 |
| 14 | 0 | 14 | 21/0 | 41/20 | 20 | 20 | 0 |
| 162 | 10 | 2 | 0/0 | 20/20 | 20 | 20 | 0 |
| 166 | 10 | 6 | 0/0 | 20/20 | 20 | 20 | 0 |
| 170 | 10 | 10 | 0/0 | 20/20 | 20 | 20 | 0 |
| 174 | 10 | 14 | 0/0 | 20/20 | 20 | 20 | 0 |

Every sublink shows Δseq == Δobs == 20, zero loss. This is a stronger exercise of the
reconstruction than the model PTF suite: it validates the **two-step composition catch from the
implementation pass** (vlink from `tbl_wit_link_recon`, ctx from a fresh `tbl_context`
classification of each packet's own DSCP, composed by `tbl_wit_ctx_index`) against **four
different real DSCP values on the same physical links**, across **both an uplink pass (vlink 0)
and an independent downlink pass (vlink 10)**, with no cross-hop double-counting. Sublink 14's
nonzero baseline (21/0) is bring-up's own incidental training traffic, not this test's traffic;
its Δ is exactly clean regardless.

## Part 2 — injected loss, exact recovery

Armed the existing one-shot injector for a known 5-packet drop on sublink 2 (`A 2 5` →
`ARMED 2 23 27`, i.e. drop the next 5 stamps in range [23,27) on that sublink), then sent 20 more
context-2 packets from Vision.

| sublink | vlink | ctx | before (seq/obs) | after (seq/obs) | Δseq | Δobs | seq−obs |
|---|---|---|---|---|---|---|---|
| 2 | 0 | 2 | 20/20 | 40/35 | 20 | 15 | **5** |
| 162 | 10 | 2 | 20/20 | 35/35 | 15 | 15 | 0 |
| 6, 10, 14 (vlink 0) | | | unchanged | unchanged | 0 | 0 | 0 |
| 166, 170, 174 (vlink 10) | | | unchanged | unchanged | 0 | 0 | 0 |

Sublink 2 recovers a loss of exactly 5 — matching the armed drop count with no off-by-one, no
saturation artifact, on the reconstructed `md.wit_link` path. Sublink 162 (the downstream vlink-10
pass for the same context) shows only 15 new arrivals, not 20: the 5 packets dropped at the uplink
hop never reached the downlink hop to be stamped there, so its own seq and obs both advance by 15
with zero further loss — the same expected physical cascade `HW-LEDGER-SMOKE-TEST.md` recorded for
the pre-wire-reduction binary. Injector cleared (`C 2`) after the read.

## Conclusion

**Update 2026-09-02, later:** an extended soak run surfaced a real, unresolved anomaly on
unmeasured sublinks — see `HW-LEDGER-WIRE-REDUCTION-SOAK-ANOMALY-2026-09-02.md` for the full
finding and the PI decision. The paragraph below is corrected, not retracted: it is exact for the
mechanism this smoke test actually exercises (loss recovery on the sublink under active
measurement), not exact in the broader, unqualified sense originally written here.

The overhead-reduction pass (`link_id` dropped from the wire, `md.wit_link` reconstructed at
ingress) reproduces the pre-change binary's real-silicon behavior on the sublink under active
detection: `Δseq − Δobs` recovers zero loss and a known 5-packet loss with no discrepancy, across
nine independent sublink counters, two hop directions, and four DSCP-driven contexts, with the
production control-plane population (`tbl_wit_link_recon`) installed automatically by the standard
bring-up sequence rather than by hand. The one real defect found along the way — the missing
`loaded-setup.sha256` writer — is fixed in `bringup.sh`, not merely routed around, so it will not
recur on the next bring-up of any program.

Not exercised here: sustained/soak traffic on the new binary (the original ledger's soak results
in `P3-OVERNIGHT-LEDGER-SOAK-*` predate this wire-reduction pass and are not yet re-run against
it), the reorder/duplicate edge cases (already proven in the model, PTF Tests 63–64, and unaffected
by this change since it touches only how `md.wit_link` is computed, not the ledger arithmetic
itself), and any statistical decision-layer behavior.
