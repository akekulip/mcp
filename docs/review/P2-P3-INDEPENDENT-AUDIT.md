# Independent P2/P3 audit — 2026-08-28

## Verdict

- **P2 behavioral health gate: PASS as a mechanism.** The exact P4 sources compile on both available
  SDE versions, fit with two ingress stages free, and the PTF assertions target the essential
  selective-reroute/accounting semantics.
- **P3 topology-realistic feedback: PARTIAL.** The repository now has a tested decision core and
  real BFRT health-gate writer, but no data-plane event producer/transport or restoration audit
  source. The earlier fast-feedback result compared unrelated mechanisms and is retracted.
- **P4 end-to-end value: BLOCKED.** It would currently assume both instantaneous feedback and
  observability of total context blackholes, neither of which the implementation provides.

## Exact sources

| program | SHA-256 |
|---|---|
| `mcp_fabric_w4_arm.p4` | `208f888f6f83080c5ea380096324c2fc04c91d601c9da275e4e1d5fb01610873` |
| `mcp_fabric_cw4.p4` | `deccd483db14bbe376d5b8f9db905a124ebe2eb876253893532004eec98f970e` |
| `mcp_fabric_capsule.p4` | `58c947b301b4bb6254b3427583f21a81c1cb2c102b2b5b5ec7003c1af0927dcd` |
| `mcp_fabric_gate.p4` | `1ab98892082e659149cb03f156f99210b9901a87ead0b9db604f10195dde7eec` |

The same bytes were compiled locally with bf-p4c 9.13.1 and remotely with bf-p4c 9.13.2. The remote
run was compile-only under `/home/decps/mcp_m2_gate`; no pipeline was loaded and no switch state was
changed. The checked-in evidence artifact contains the local compiler identity, source hashes, and
SHA-pinned placement excerpts. The remote resource extraction is retained as an external
cross-check; its raw compiler logs are not in this repository and are therefore not the primary
evidence for the placement claim.

## Placement and resource evidence

Both compiler versions agree on stage placement:

| variant | ingress / egress stages |
|---|---:|
| armed W4 | 9 / 3 |
| C-W4 | 9 / 4 |
| Context Capsule | 9 / 3 |
| Capsule + health gate | 10 / 3 |

The earlier 8/3 W4 number was stale. The appropriate comparator is the armed W4 source above at
9/3. P2 still adds one ingress stage relative to Context Capsule.

Local placement evidence is archived in
[`artifacts/P2-PLACEMENT-9.13.1.md`](artifacts/P2-PLACEMENT-9.13.1.md). Detailed 9.13.2 resource
extraction from `resources.json`, `table_summary.log`, and `phv_allocation_summary_0.log` was also
recorded during the compile-only cross-check:

| variant | SRAM blocks I/E | TCAM blocks I/E | SALUs I/E | PHV containers | PHV bits |
|---|---:|---:|---:|---:|---:|
| armed W4 | 59 / 6 | 10 / 0 | 4 / 1 | 33.0% | 30.3% |
| C-W4 | 59 / 7 | 10 / 1 | 4 / 1 | 33.5% | 31.1% |
| Context Capsule | 60 / 6 | 11 / 0 | 4 / 1 | 35.3% | 31.9% |
| Capsule + health gate | 65 / 6 | 11 / 0 | 4 / 1 | 35.3% | 31.9% |

The health gate consumes five additional ingress SRAM blocks and one ingress stage relative to the
capsule; it does not increase PHV, TCAM, or SALU usage. Ingress stage count, not PHV or stateful ALUs,
is the immediate constraint.

## Fresh software verification

The corrected controller path now has regression coverage for:

- uplink and downlink expansion from one directed sublink to every exact P2 key;
- quarantine of only the named context;
- one decision per sublink epoch, with bounded exact-key expansion;
- earlier-epoch event rejection;
- restoration only after positive probation observations;
- real BFRT key/action schema and add/modify/delete operations;
- propagation of non-BFRT programming failures instead of masking them as duplicate entries;
- disjoint accounting of observed arrivals and inferred missing packets.

The simulation report has a regression test preventing the 97.4 us F6 congestion result from being
relabeled as C-W4 feedback.

## P3 gaps that stop the paper claim

1. **No event source:** no running component reads or receives an attributed C-W4 gap and constructs
   `GapEvent`.
2. **No transport:** no packet/control path carries the downstream event to the source selector.
3. **No restoration evidence:** after P2 reroutes a context, the original sublink is silent. The
   fixed controller refuses to interpret silence as health, but no probation/audit path exists.
4. **No end-to-end latency:** 2.20 ms and 106.6 ms are controller references; the exact
   C-W4-event-to-health-gate latency is unmeasured. The 97.4 us result is a different, same-switch
   congestion mechanism.
5. **Total-blackhole blindness:** a sequence gap appears only when a later packet in the same
   context survives. C-W4 alone cannot detect 100% selective loss or an all-context blackhole.
6. **No dynamic operating point:** specificity, false quarantine, unsafe exposure, restoration, and
   flap behavior have not been replayed through the actual feedback state machine with confidence
   intervals.

## Required next decision

Behavioral Sublinks remains the primary contribution because P1/P2 establish a new controlled
resource and selective mitigation capability. The next implementation must make the observability
contract explicit:

- use ordinary C-W4 for partial conditional loss and add a separately priced liveness/audit path for
  complete blackholes; or
- prototype a cross-context frontier witness behind strict encoding, compiler, false-positive, and
  baseline gates.

The second option is a research candidate, not yet a contribution. It still depends on sibling
traffic, risks conflicts with active header fields, and cannot eliminate the need for a liveness
marker when every context is blackholed.
