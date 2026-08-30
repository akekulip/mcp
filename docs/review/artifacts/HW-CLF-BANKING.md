# CLF double-buffering: why the reader must never touch the active bank — 2026-08-30

The frontier's double-buffered banks were specified in the design, indexed in the data plane, and
**inert in practice**: nothing ever stamped the parity bit, so bank 0 was the only bank ever
written. Completing it explains every anomaly in items 2-4.

## The defect

`hdr.fabric.flags` bit 3 carries bank parity. Both references in `mcp_fabric_clf_eg.p4` only READ
it; no action set it. Consequence: one bank, so a reader had to ZERO it to get a clean baseline —
and on a live fabric that is unsound, because zeroing clears TX while packets are in flight, which
then arrive and set RX with no matching TX.

That is the `TX=0, RX=1` IMPOSSIBLE state. It appeared in **50 of 50 trials** once a single-context
probe stopped masking it. With `ctx_pilot`, which marks TX on three contexts, it was invisible.

## The fix

`act_enter` gained a `bank` action-data parameter, stamped into `hdr.fabric.flags` bit 3 at the
SOURCE so every switch on the path agrees which bank a packet belongs to. Compiles at **11 ingress
/ 5 egress — no additional stage cost**. The control plane flips it via the agent's `N` command,
which rewrites the source-side `act_enter` rows. `setup_skeleton`'s existing `OPTIONAL_ACTION_ARGS`
negotiation picked the parameter up automatically and reported `act_enter written as next_hop,
bank, epoch`, so an older binary still loads.

## The measurement that justifies the whole design

After a flip, with no fault armed anywhere:

| bank | TX | RX | TX & ~RX | state |
|---|---|---|---|---|
| 0 (inactive, frozen at the flip) | 0x0006 | 0x0007 | **0x0000** | correct — healthy |
| 1 (active, still being written) | 0x0006 | 0x0001 | **0x0006** | **two false blackholes** |

Bank 1 had never carried state before this run. Bank 0 stopped changing the moment the flip landed.

**Read the inactive bank and you get truth; read the active bank and you manufacture blackholes.**
An active bank is incomplete by construction: TX is marked at the source egress and RX at the
receiver egress, so at any instant there are packets counted in TX whose RX has not yet landed.

## Why this matters beyond the bug

`NOVELTY-GATE-4.md` concluded that CLF's only real advantage over standardised per-class counters
(RFC 6374, Y.1731) is that **a presence bit is monotone within an epoch**, so packets in flight at
an epoch boundary cannot fabricate a blackhole — the obstacle LossRadar §3.4 and FlowRadar §6.2
both name as fundamental to differencing across a link.

That property only holds if the reader observes a bank that is no longer being written. The banking
is not an implementation convenience; it is the mechanism by which the claimed advantage is
realised. Without it the frontier has exactly the epoch-skew problem it is supposed to avoid.

## Corrections to earlier records

- `HW-CLF-RATES.md` reports rule 5 (IMPOSSIBLE == 0) as PASSING on 200 trials. **That reading was
  wrong.** Those zeros came from a probe that marked TX on every context in play, masking the
  condition. Under a single-context probe the same protocol yields IMPOSSIBLE in every trial. Rule 5
  was untested, and it FAILS under a zero-based reset.
- The 0.910 detection rate in the same file is superseded twice over: it was measured with a
  spraying probe whose target-context share varied per trial, AND under a zero-based reset.

## Still to measure

- The guard interval has no number. With flipping it is bounded by fabric traversal time and can be
  swept for the point at which residual IMPOSSIBLE states reach zero.
- Detection and false-blackhole rates must be re-measured under flip-guard-read-inactive. Every rate
  recorded before this change was taken through a reader that could manufacture the states it was
  counting.
