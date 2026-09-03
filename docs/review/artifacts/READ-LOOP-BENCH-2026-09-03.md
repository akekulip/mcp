# Controller read-loop benchmark on the Tofino (2026-09-03)

**Why.** Two referee findings turn on one number the paper never stated: how long the controller
takes to read the ledger. (1) A zero-byte per-link TX/RX counter pair (RFC 6374 style) has the
same information as the witness but reads its two registers on two switches at two instants, so
every packet sent between the two reads looks like loss; the tolerable skew is the paper's actual
justification for spending two bytes. (2) The 16-bit sequence wraps every 65 536 packets per
sublink, so the read cadence bounds the per-sublink rate the two-byte width can serve.

**Method.** Live switch (`ufispace`, Tofino 1, SDE 9.13.2), program `mcp_fabric_ledger` build
`6ace4fb1` (confirmed by the gate agent's `V` identity), `bf_switchd` pid 1359710, chip owned by
this project (`mcp_fabric_ledger_abs.conf`). The gate agent's `R` census reads
`reg_wit_seq` and `reg_wit_observed` for the requested sublinks with one batched `entry_get`
(`from_hw=True`) per register table. Timed from a client on the switch's own host over the
loopback socket (so gRPC to bfrt and the register fetch are included; an off-box controller
would add its network round trip). A full fabric is 1024 sublinks, read in four commands of 256
(the agent caps one command line at 4 KB). Five repetitions.

| read | median | reps |
|---|---|---|
| one sublink, both registers (`R 2`) | 2.6 ms | 5 |
| all 1024 sublinks, both registers (4 × 256) | **347.5 ms** (304–358) | 5 |

**Consequences, stated for the paper.**

- *Counter-pair skew.* The best case for a counter pair is a pairwise read of one link's TX and RX
  registers back to back, about 2.6 ms apart on this switch plus the inter-switch network; the
  worst case is a full-fabric sweep, 350 ms. Against the harness's 100 ms epoch these are skew
  fractions of 2.6e-2 (best) and 3.5 (a sweep longer than the epoch itself, which no epoch of
  that length can absorb). At 250 000 packets per spine per epoch the phantom-loss noise of a
  2.6e-2 skew has a standard deviation near 250 000 × 0.026 / √6 ≈ 2 700 packets, against a true
  signal of 25 packets at p = 10⁻⁴ and 250 at 10⁻³. The harness sweep
  (`BASELINE-COMPARISON-SWEEP-2026-09-03.json`) measures what that does to detection and false
  positives; the witness reads both registers on one switch in one batch and has no such term.
- *Wrap bound for the 16-bit sequence.* At 25 Gb/s with 1400-byte payloads (1438 bytes on the
  wire with preamble and gap) a port carries about 2.17 Mpps; a sublink carrying a whole port wraps
  the 16-bit sequence every 65 536 / 2.17e6 ≈ 30 ms. With a 350 ms census the two-byte witness is
  unambiguous only while a sublink carries under 65 536 / 0.35 s ≈ 187 kpps, about 9 percent of a
  port at that packet size. The silicon cells of this paper ran at 20 kpps (3.3 s per wrap) and
  are unaffected. Above 187 kpps per sublink the read loop must be shortened (the per-sublink read
  is 2.6 ms, so a targeted read of a hot sublink is possible) or the sequence widened to 32 bits,
  which is four bytes of sequence and not the earlier four-byte header, whose extra two bytes were
  a link identifier rather than sequence width.

Raw client output (5 reps): 306.3, 347.5, 357.5, 304.5, 352.0 ms full census; 2.6 ms single.
The switch was left as found: no injector armed, no table written, gate agent healthy.
