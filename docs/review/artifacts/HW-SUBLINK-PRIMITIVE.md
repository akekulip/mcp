# The behavioural sublink, demonstrated on silicon — 2026-08-29

The project's core abstraction — a **(directed link x traffic behaviour)** pair as an addressable,
independently witnessed resource computed per packet at line rate — running on a Tofino 1.

## Result

17 behavioural sublinks carrying independent sequence state across **7 distinct directed links**
and **3 behaviour classes**, with `stamped == expected == observed` on **17 of 17**.

| sublink | vlink | ctx | stamped | expected | observed |
|---:|---:|---:|---:|---:|---:|
| 0 | 0 | 0 | 958 | 958 | 958 |
| 1 | 0 | 1 | 2054 | 2054 | 2054 |
| 2 | 0 | 2 | 146 | 146 | 146 |
| 16 | 1 | 0 | 24 | 24 | 24 |
| 17 | 1 | 1 | 31 | 31 | 31 |
| 18 | 1 | 2 | 24 | 24 | 24 |
| 33 | 2 | 1 | 1 | 1 | 1 |
| 34 | 2 | 2 | 1 | 1 | 1 |
| 129 | 8 | 1 | 13 | 13 | 13 |
| 130 | 8 | 2 | 1 | 1 | 1 |
| 160 | 10 | 0 | 26 | 26 | 26 |
| 161 | 10 | 1 | 26 | 26 | 26 |
| 162 | 10 | 2 | 26 | 26 | 26 |
| 193 | 12 | 1 | 7 | 7 | 7 |
| 224 | 14 | 0 | 24 | 24 | 24 |
| 225 | 14 | 1 | 24 | 24 | 24 |
| 226 | 14 | 2 | 24 | 24 | 24 |

vlinks 0-2 are uplinks and 8-14 downlinks, so both directions are exercised. vlink 10 and vlink 14
each carry all three behaviour classes simultaneously with independent counters — one physical
directed link, three separately witnessed behavioural sublinks.

## How it was produced

Three packet sizes from Vision (payload 64 / 600 / 1400 B, so `hdr.ipv4.total_len` = 92 / 628 /
1428) into the emulated 4x2 fabric. `tbl_context` maps total_len to a size bin, the capsule carries
it in the existing shim pad byte at **zero added wire bytes**, and egress composes
`md.sublink = (vlink << 4) | ctx`. Registers read `from_hw` over bfrt.

## Two defects this pilot found, both silent

**`tbl_eg_vlink` was empty.** Before `setup_attention up` ran, `md.vlink` defaulted to 0, so every
sublink id was `(0 << 4) | ctx` — the context half only. An earlier read showed three contexts and
looked like the primitive working; it was not. The link half was never exercised. Reading the table
row count is what distinguished them.

**`setup_attention` decided the contextual form by a hardcoded program name.** Line 348 tested
`a.program == "mcp_fabric_cw4"` while the correct helper `is_contextual_program()` — already used
by the print path in the same file — returns True for `mcp_fabric_gate_event` and
`mcp_fabric_capsule` as well. Against this program it would have installed `tbl_eg_vlink` WITHOUT
the `vlink << 4` shift, giving `sublink = vlink | ctx`: the context nibble colliding with the low
bits of the vlink, wrong sublink ids under every measurement, no error and no failed write. Fixed
to derive from `CONTEXTUAL_PROGRAMS`, the single source of truth.

That is the third defect of this species today, after `eg_qid` versus the raw qid and `vlink_dn`
disagreeing between two files. All three are one fact restated in two places; all three fixes made
one place authoritative.

## What this establishes, and what it does not

**Establishes:** the abstraction is real on hardware. A packet's behaviour class is computed at the
source from its own header, carried at no wire cost, and composed at egress with the directed link
it is actually leaving on, giving a per-pair sequence witness that stays exactly synchronised.

**Does not establish:** any loss, detection, mitigation or latency claim. Every sublink here is
loss-free by construction — `stamped == observed` everywhere. The fault injector `tbl_eg_fail` has
not been armed, no gap has been produced, and `tbl_wit_verdict` still fails to allocate at load
(H42) so its counter is unavailable. Mirror sessions now exist (1/2 at 128 B, 3 at 64 B, to dp9)
but no gap event has yet been observed at a collector.
