# Context Liveness Frontier — compile gate — 2026-08-30

The first kill criterion for CLF was that the frontier must fit within 12 ingress stages. It does,
with margin: **the complete primitive costs ZERO ingress stages and ONE egress stage.**

## Result

| program | ingress | egress | errors |
|---|---:|---:|---|
| `mcp_fabric_gate_event.p4` (baseline) | 11 | 4 | 0 |
| `mcp_fabric_clf.p4` (RX frontier in INGRESS) | **12** | 4 | 0 |
| `mcp_fabric_clf_eg.p4` (RX in egress) | **11** | 4 | 0 |
| `mcp_fabric_clf_eg.p4` (RX + TX) | **11** | **5** | 0 |

bf-p4c 9.13.1. Stage counts read from `pipe/logs/table_summary.log`, the COUNT line, never
`context.json` and never a zero-based maximum index.

## The placement finding, which changed the design

Putting the receiver mark in ingress compiles at 12/4 — inside the stated bound — but the extra
stage is **displacement, not resource cost**. `tbl_rx_frontier` landed in ingress stage 5 and cost
2 SRAM blocks, yet pushed `tbl_audit_steer` 4->5, `tbl_attn` 7->8, `tbl_evid_fwd` 8->9,
`tbl_final` 9->10 and the three gap-event tables 10->11, exhausting the last ingress stage. The
mark sits in the dependency chain behind `md.wit_link`, and everything after it inherits the delay.

The receiver's **egress** sees every arrival too and had eight stages free. Moving the mark there
costs nothing: **no ingress table moves at all**, placement is byte-identical to the baseline.

## Placement, and why the order is load-bearing

    egress stage 0   tbl_eg_vlink
    egress stage 1   tbl_ctx_index
    egress stage 2   tbl_wit_stamp, tbl_rx_frontier      <- RX reads link_id here
    egress stage 3   tbl_wit_link, tbl_eg_fail           <- link_id OVERWRITTEN here
    egress stage 4   tbl_tx_frontier

`tbl_wit_link` rewrites `hdr.witness.link_id` with the DOWNSTREAM sublink for the next hop, so the
receiver mark must read it first. Source order expresses that intent; the compiled placement
(stage 2 against stage 3) is what makes it true. A future edit that moves either table must
re-check this ordering.

## Design decisions forced by the target

**A byte per sublink, not a 16-bit mask per link.** The specified per-link mask needs a one-hot
`1 << ctx`, and this compiler cannot shift a runtime value — the same constraint that already
forces the control plane to hand `tbl_eg_vlink` a pre-shifted `vlink << 4`. Producing the one-hot
in the data plane costs a lookup table. Indexing instead by the sublink the witness has ALREADY
computed needs neither. **The control plane packs the per-link mask on read, so the batched record
still crosses the wire, which is where the O(L) rather than O(LK) argument lives.** The register
layout is an implementation detail; the exchanged record is the contribution.

**TX is post-TM by construction.** A packet dropped by our own traffic manager never reaches
egress, so it never marks TX. Congestion inside the switch therefore cannot be misread as the link
going dark. This is the difference between "we sent it" and "we intended to send it", and it is
what makes TX=1, RX=0 a sound blackhole inference rather than an artefact of our own queueing.

**Banking rides `hdr.fabric.flags` bit 3**, which is free (bits 0-2 are measured/dropped/corrupted),
so a reader can compare the INACTIVE bank after a guard interval without racing the epoch boundary,
at no new wire bytes.

**Both frontiers use the same behavioural-sublink identity** the witness stamps, so they are
directly comparable across a link — the "same context identity indexes evidence and forwarding"
property the novelty argument rests on.

## What this gate does NOT establish

- **No behaviour.** This is a compile and placement result only. Nothing has been run on the model
  or on silicon, and no frontier has ever been read.
- **No distributed exchange.** In the 4x2 loopback emulation both frontiers live on the same chip,
  which makes them easy to compare and means the agent-to-agent exchange — the thing the O(L)
  claim depends on — is NOT exercised.
- **No epoch-race analysis.** Double banking is implemented; the guard interval, and whether
  congestion or reordering can produce a false blackhole, are unmeasured.
- **No detection claim.** The TX/RX truth table is not yet evaluated against any fault.
