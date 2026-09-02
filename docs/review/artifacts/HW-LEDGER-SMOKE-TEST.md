# Hardware smoke test — receiver ledger on real silicon (2026-09-02)

Step 3 of the post-redesign roadmap: does `mcp_fabric_ledger.p4` forward correctly and count
correctly on the real Tofino, not just in `tofino-model`. Both parts pass.

## Setup

- Chip taken over from `mcp_fabric_clf_eg` (this project's own prior program, confirmed by
  `pgrep`/`cmdline` before touchdown) via `takeover.sh`, snapshotted to
  `p4/hw/snapshots/20260902T010245Z-takeover.txt`.
- `deploy.sh mcp_fabric_ledger` then `bringup.sh mcp_fabric_ledger`, both dry-run then live. New
  `bf_switchd` pid 185642, all ports and loop pairs up.
- Reconciled `gate_agent.py` (git commit `6761571`, carrying both the switch's V2/S/M additions
  and this session's F/X/Z ledger-safety guard) launched bound to `MCP_PROG=mcp_fabric_ledger`,
  pid 187023. The F/X/Z guard self-disabled correctly with a clear log line, since this program has
  no `reg_rx_frontier`.
- Traffic generated from Vision with the existing `multicontext_probe.py` (proven recipe from
  `HW-SUBLINK-PRIMITIVE.md`): UDP `10.0.1.1→10.0.1.3`, `sport 41000 dport 4449`, 1400 B payload,
  DSCP selecting contexts 2/6/10/14.
- Read out with the gate agent's `R` command: `sublink vlink context seq obs`, where `seq` is
  `reg_wit_seq` (egress stamp count for that hop) and `obs` is `reg_wit_observed` (ingress arrival
  count for that hop) — the same `(hi, lo)` pair PTF Test 60 exercised in the model, under the
  names this program's control plane actually uses.

## Part 1 — clean forwarding, 80 packets, 4 contexts

20 packets per context (2, 6, 10, 14) sent from Vision. Baseline vs. post-traffic `R`:

| sublink | vlink | ctx | before | after | Δseq | Δobs | loss |
|---|---|---|---|---|---|---|---|
| 2 | 0 | 2 | 21/21 | 41/41 | 20 | 20 | 0 |
| 6 | 0 | 6 | — | 20/20 | 20 | 20 | 0 |
| 10 | 0 | 10 | — | 20/20 | 20 | 20 | 0 |
| 14 | 0 | 14 | — | 20/20 | 20 | 20 | 0 |
| 130 | 8 | 2 | 15/15 | 15/15 | 0 | 0 | 0 |
| 162 | 10 | 2 | — | 20/20 | 20 | 20 | 0 |
| 166 | 10 | 6 | — | 20/20 | 20 | 20 | 0 |
| 170 | 10 | 10 | — | 20/20 | 20 | 20 | 0 |
| 174 | 10 | 14 | — | 20/20 | 20 | 20 | 0 |

Every sublink shows `seq == obs`. Each context appears on two independent hops — an uplink pass
(vlink 0) and a downlink pass (vlink 10) — with an exact, independent 20/20 count on both, meaning
the per-sublink counters do not double-count across hops that share a context id. Sublink 130
(vlink 8) is unrelated background traffic from bring-up's own port check and correctly did not
move.

## Part 2 — injected loss, exact recovery

Armed the existing one-shot injector for a known 5-packet drop on sublink 2 (`A 2 5` →
`ARMED 2 44 48`, i.e. drop the next 5 stamps in range [44,48) on that sublink), then sent 20 more
context-2 packets from Vision.

| sublink | vlink | ctx | before | after | Δseq | Δobs | seq−obs |
|---|---|---|---|---|---|---|---|
| 2 | 0 | 2 | 41/41 | 61/56 | 20 | 15 | **5** |
| 162 | 10 | 2 | 20/20 | 35/35 | 15 | 15 | 0 |
| 6, 10, 14 (vlink 0) | | | unchanged | unchanged | 0 | 0 | 0 |
| 166, 170, 174 (vlink 10) | | | unchanged | unchanged | 0 | 0 | 0 |
| 14 (vlink 0, ctx 14) | | | 20/20 | 21/21 | 1 | 1 | 0 (background) |
| 142 (vlink 8, ctx 14) | | | — | 1/1 | — | — | 0 (background) |

Sublink 2 recovers a loss of exactly 5 — matching the armed drop count with no off-by-one, no
saturation artifact. Sublink 162 (the downstream vlink-10 pass for the same context) shows only 15
new arrivals, not 20: the 5 packets dropped at the uplink hop never reached the downlink hop to be
stamped there, so its own seq and obs both simply advance by 15 with zero further loss. This is the
expected physical cascade, not a second discrepancy — the injector fires once, upstream, and every
downstream counter correctly reflects only the survivors.

Two small unrelated deltas appear (sublink 14 +1/+1, a new sublink 142 at 1/1) — single stray
background packets, zero loss on either, not caused by this test's traffic and not affecting the
result.

## Conclusion

This is the first real-silicon confirmation of the receiver-ledger's core claim
(`Δseq − Δobs = exact loss count`) — the same claim PTF Test 60 proved in `tofino-model`. Both the
zero-loss and known-loss cases match exactly, across nine independent sublink counters, with no
cross-hop double-counting and no discrepancy on any untouched sublink. Step 3 of the roadmap is
complete.

Not exercised here: sustained/soak traffic, the reorder and duplicate edge cases (already proven in
the model, PTF Tests 63–64), and the statistical decision layer (roadmap step 4, not yet built).
