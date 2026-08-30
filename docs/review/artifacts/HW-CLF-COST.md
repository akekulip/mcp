# What CLF costs, measured — the claim that survived the dShark narrowing

**Date:** 2026-08-30. `NOVELTY-GATE.md` records the M1 verdict as `NARROW`: detecting and
localizing silent black holes is occupied by dShark (NSDI'19), so the surviving claims are **cost
of evidence acquisition** and **actionability**. The cost claim had no measurement. This is it.

## 1. Price of the primitive on the chip

Same program compiled with and without the frontier. `mcp_fabric_noclf.p4` is generated from
`mcp_fabric_clf_eg.p4` with both registers, both stateful ALUs, both tables and both apply sites
removed and nothing else changed.

| | ingress stages | egress stages | SRAM blocks | map RAM | stateful ALUs |
|---|---:|---:|---:|---:|---:|
| without CLF | 11 | **4** | 80 | 23 | 6 |
| with CLF | 11 | **5** | 92 | 27 | 8 |
| **cost of CLF** | **+0** | **+1** | +12 | +4 | **+2** |

Stage counts are from `pipe/logs/table_summary.log`, the file `deploy.sh` insists on; the MAU
figures are totals from `pipe/logs/mau.resources.log` for the same two builds. The +2 stateful
ALUs are exactly `rx_seen` and `tx_seen`. Wire cost is **zero bytes**: the bank parity rides
`hdr.fabric.clf_bank`, a byte that was already declared and never read.

On-chip state is fixed: two `Register<bit<8>, bit<16>>(512)` arrays = **1024 bytes total**,
independent of traffic.

## 2. Evidence that has to leave the switch

The structural difference from a capture-based framework is not how much state sits on the chip,
it is how much evidence must be shipped off it. dShark's model is to mirror packets to collector
servers; the paper sizes its collectors on "each mirrored packet is 1500 bytes large" and sets its
performance goal at 3.33 Mpps per commodity core.

Measured on this testbed. Frame size is measured, not assumed: the ingress vlink counter recorded
`pkts=400 bytes=578400`, i.e. **1446 bytes per frame**.

| packets sent | CLF readout (bytes) | rows returned | mirroring the same traffic | ratio |
|---:|---:|---:|---:|---:|
| 10 | 58 | 4 | 14,460 | 249x |
| 100 | 37 | 2 | 144,600 | 3,908x |
| 500 | 86 | 6 | 723,000 | 8,407x |

**The CLF readout does not grow with packet count.** It varies between 37 and 86 bytes only
because the number of *active sublinks* varied (2 to 6 rows, from background traffic), and it is
bounded above by the register array: a complete read of every sublink in both banks is ~1 KB
whatever the traffic rate. Mirroring is proportional to packets, so the ratio grows without limit
as load rises — the three rows above are one, two and three orders of magnitude apart for the same
reason.

## What this does and does not establish

**Establishes:** for the specific question *"is this behavioural sublink delivering what its
source committed"*, evidence cost is **O(active sublinks) per epoch** against **O(packets)** for
mirroring, measured, with a fixed 1 KB ceiling on the switch and +1 egress stage to compute it.

**Does not establish:**

* dShark can truncate or sample. The 1500-byte figure is the paper's collector sizing, not a floor;
  mirroring headers only would cut its side of the ratio substantially. This comparison uses full
  frames because that is the deployment the paper describes.
* This is a cost comparison **at equal task, not equal capability**. dShark answers questions CLF
  cannot: path recovery through header transformations, middlebox correctness, ECMP profiling,
  per-packet forensics. Buying one aggregate answer cheaply is not the same as buying all of them.
* Nothing here measures a real mirroring pipeline on this testbed. The mirrored-bytes column is
  arithmetic on a measured frame size and a measured packet count, not a captured trace. A true
  baseline would also carry dShark's own reported capture noise, which the paper states can bury
  real drops in mirrored drops.
