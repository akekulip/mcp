# C-W4 post-localization capacity gate

**Verdict: PASS for direction x coarse-size faults; NARROW for general context faults.**

The frozen design is `sim/sublink/PREREG.md`; the dependency-free implementation is
`sim/sublink_capacity.py`; six invariant tests are in `sim/tests/test_sublink_capacity.py`.

## What this gate asks

After a conditional fault is already known, how much byte-demand can be served safely when the
control unit is a physical link, a directed link, a direction x size sublink, or the exact oracle
predicate? Every conservative arm has the same bound: zero known-unsafe bytes may remain on the
primary link. Every arm receives the same alternate-path headroom.

This isolates the value of behavioral sublinks from detection latency. It does **not** prove the
feedback path, health gate, false-positive behavior, CCT, or performance on a packet trace.

## Aligned conditional fault

Only the forward `>=2048 B` stratum is faulty; reverse traffic and smaller forward traffic are
healthy. With no alternate headroom, safe delivered byte-demand is:

| faulty share of forward demand | physical disable | directed W4 / witness-stop | C-W4 size | oracle |
|---:|---:|---:|---:|---:|
| 10% | 0% | 50% | 95% | 95% |
| 25% | 0% | 50% | 87.5% | 87.5% |
| 50% | 0% | 50% | 75% | 75% |
| 75% | 0% | 50% | 62.5% | 62.5% |
| 90% | 0% | 50% | 55% | 55% |

C-W4's median gain over directed W4 is **25 percentage points**, and it closes **100%** of the
directed-W4-to-oracle gap on every aligned point. All arms admit zero known-unsafe primary bytes.
At a 50% affected forward share, the same 25-point advantage persists throughout the frozen
alternate-headroom sweep because C-W4 avoids detouring the healthy half of the forward direction.

## Controls and failure surfaces

| zero-headroom scenario | directed W4 | size-only C-W4 | oracle | meaning |
|---|---:|---:|---:|---|
| whole forward direction faulty | 50% | 50% | 50% | no invented advantage when no safe sublink exists |
| no fault | 100% | 100% | 100% | no-regression control |
| 1400 B healthy / 1800 B faulty in one size bin | 50% | 50% | 75% | coarse boundary costs 25 points |
| class 0 healthy / class 1 faulty within both size bins | 50% | 50% | 75% | class is not implemented; costs 25 points |

The negative controls are load-bearing. The current C-W4 must not be described as isolating
arbitrary packet contexts or service classes. Its supported capability is direction x the four
compiled size bins.

## Engineering corrections found during independent verification

- Fresh bf-p4c 9.13.1 compilation reports armed W4 at **9 ingress / 3 egress** stages and C-W4 at
  **9 / 4**, not 8/3 and 8/4. The old report used maximum zero-based stage ids as counts. C-W4 still
  fits Tofino 1 and leaves 3 ingress / 8 egress stages.
- The original three PTF tests supplied a composed sublink id directly to the downstream checker.
  New Test23 exercises the actual upstream size classifier, vlink-base composition, wire stamp, and
  two independent sequence spaces. The software-model suite is now **4/4**.
- The production control plane programmed only the old `set_eg_vlink(vlink)` action. Both setup
  programs now accept `--program mcp_fabric_cw4`, and `setup_attention.py` supplies
  `vlink_base = vlink << 4`; five offline control-plane tests cover the contract.

## Decision

The preregistered mechanism-value gate passes. This authorizes the trace-driven and data-plane
enforcement work; it does not authorize a capacity or application claim in a paper.

The next primitive must be a source-switch context label plus behavioral health gate. A four-bit
label can encode size x service class in the existing shim padding and drive both C-W4 indexing and
selective path rerouting without new wire bytes. That design is required to close the two 25-point
negative-control gaps; it must compile, pass end-to-end PTF tests, and then face Ring-AllReduce and
MoE AlltoAll traces at matched unsafe exposure.
