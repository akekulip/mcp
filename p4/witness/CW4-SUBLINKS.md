# C-W4: behavioural sublinks — compiles, fits, and the mechanism holds on the model

A physical link is not simply healthy or faulty. It can be healthy for some packet contexts and
faulty for others, and the evidence for that is production data, not a model: **CorrOpt** measured
corruption present in *both* directions on only 8.2 % of corrupting links yet disabled both,
because its hardware could not express a one-directional decision; **Aegis** hit a fault that
dropped only packets larger than 1 KB while its 64-byte probes saw nothing. So the resource worth
tracking is the **behavioural sublink = (directed link × context stratum)**, and the question stops
being "is this link healthy" and becomes "which parts of it are still usable".

## What changed in the data plane

Less than expected, which is the point.

* **Zero extra wire bytes.** `wit_h.link_id` is already 16 bits and 64 links need 6, so the stratum
  rides in the spare nibble: `link_id[15:4]` = directed vlink, `link_id[3:0]` = stratum. The
  witness header stays 4 bytes and the packet size is identical either way (asserted in the suite).
* **The downstream check is untouched.** It already indexes `reg_wit_expect` by the whole 16-bit
  field it receives, so it becomes per-sublink the moment the upstream composes the id. Every line
  of new logic is upstream.
* **2 KB of state.** Both registers grow 64 → 1024 cells (64 links × 16 strata).
* **One new egress table**, `tbl_stratum`, a range match on `eg_intr_md.pkt_length`.

Ingress on Tofino 1 has **no packet-length intrinsic**, which is why this first variant labels at
upstream egress. Label corruption/forgery is not covered by the current suite and is therefore an
open hostile test, not a detection claim.

## Cost

| variant | ingress / egress stages |
|---|---|
| W4 (witness, no attention arming) | 8 / 3 |
| W4 + attention arming | 9 / 3 |
| **C-W4 (behavioural sublinks + arming)** | **9 / 4** |

One extra egress stage relative to armed W4, on a chip with 12 per gress — 3 ingress and 8 egress
stages remain. The earlier 8/3 and 8/4 report accidentally quoted the maximum zero-based stage
indices rather than the number of occupied stages. A fresh compile from the committed source on
bf-p4c 9.13.1 reports 9/3 and 9/4 in `table_summary.log`; the raw C-W4 evidence is archived under
`p4/witness/artifacts/mcp_fabric_cw4.*`. The fit stop condition still does not fire.

## Three compiler fights, all documented constraint classes

Recorded because each cost a build and each will recur:

1. `wit_next.execute((md.vlink << 4) | md.stratum)` → *"The index is too complex for the primitive
   to be handled."* A SALU index must be a plain PHV field; the id has to be pre-computed into
   metadata a stage earlier.
2. Computing that id in one action → **Class 5**, *"action spanning multiple stages"*: a shift and
   an or on a runtime operand cannot share an action.
3. Splitting it so `set_eg_vlink` did `md.sublink = vlink << 4` → a **silent internal compiler
   error**: "1 error generated" with no error text, the Class 6 signature.

The resolution removes data-plane arithmetic entirely: the control plane supplies `vlink << 4` as a
second action parameter to `set_eg_vlink`, and `set_stratum` does a single OR. The controller
already knows the vlink id, so it costs nothing.

## The claim, tested on the model

`p4/ptf/test_cw4_sublinks.py`, 4/4 passing against the generated `mcp_fabric_cw4`:

| # | what it asserts | result |
|---|---|---|
| 20 | two strata of one physical link keep separate sequence spaces | PASS |
| 21 | **a gap in the large-packet sublink leaves the small-packet sublink contiguous, uncondemned, and still counting cleanly — and raises no further event** | PASS |
| 22 | the stratum rides in the spare bits: header stays 4 B, packet size unchanged across strata | PASS |
| 23 | the upstream egress itself classifies 120 B and 1272 B frames, composes distinct sublink ids, and stamps independently increasing sequences on the wire | PASS |

Test 21 is the whole abstraction. Under ordinary W4 the gap condemns the entire directed link, so
the Aegis fault would strand the small-packet traffic that was never affected. The model's own
per-packet trace confirms `act_attn_exceed` fires **exactly once** for the one injected
discontinuity — the healthy stratum of a faulty link raises nothing.

## What this does not yet show

The post-localization value gate now exists in `sim/sublink_capacity.py` and is recorded in
`docs/review/CW4-CAPACITY-GATE.md`. It passes for faults aligned with the implemented direction x
size strata, but exposes a 25 percentage-point oracle gap for both a within-bin size boundary and a
class-only fault. The current implementation therefore supports a **direction x coarse-size**
claim only. It still lacks the upstream behavioral health gate, downstream-to-upstream feedback,
dynamic false-positive/detection behavior, trace-driven application results, and silicon evidence.
