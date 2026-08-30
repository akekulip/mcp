# CLF detects a total context blackhole on silicon — 2026-08-30

The Context Liveness Frontier detects the fault class C-W4 structurally cannot see: a behavioural
sublink where **every** packet disappears, leaving no survivor to expose a discontinuity.

## Method

`mcp_fabric_clf_eg` loaded on Tofino 1 via a sealed deploy manifest
(`cc957520a40b62f1...`), 11 ingress / 5 egress. Fabric verified: all four loop pairs and both host
ports up, 400/400 forwarding proof in the same session.

Injector `tbl_eg_fail` armed to cover the **entire 16-bit sequence space** on sublink 2
(vlink 0, ctx 2 = the `>=1024 B` class), so every packet of that context on that directed link is
destroyed AFTER the sequence stamp. 50 packets of each of three size classes sent from Vision.

## Result

    frontier   bank vlink   TX_mask   RX_mask   TX & ~RX
                  0     0    0x0007    0x0003     0x0004
                  0     1    0x0007    0x0007     0x0000

| sublink | TX | RX | verdict |
|---|---|---|---|
| vlink 0, ctx 0 | 1 | 1 | HEALTHY |
| vlink 0, ctx 1 | 1 | 1 | HEALTHY |
| **vlink 0, ctx 2** | **1** | **0** | **BLACKHOLE** |
| vlink 1, ctx 0 | 1 | 1 | HEALTHY |
| vlink 1, ctx 1 | 1 | 1 | HEALTHY |
| vlink 1, ctx 2 | 1 | 1 | HEALTHY |

**Selectivity holds in both directions.** Contexts 0 and 1 share the *link* with the fault and are
healthy. Context 2 on vlink 1 shares the *class* with the fault and is healthy. Only the
(link, context) pair fires — which is the property the abstraction exists to provide.

**C-W4 sees nothing here, by construction.** A discontinuity requires a later packet in the same
context to survive and arrive. With every packet destroyed there is no successor, so the witness
has no evidence and its counters are indistinguishable from an idle context. This blind spot has
been recorded in every P3 result document in this repository; CLF closes it.

The evidence is internally consistent without needing the injector counter: TX says the source
committed context 2 post-TM, RX says it never arrived. Neither half alone would be sufficient —
RX=0 on its own cannot distinguish "everything vanished" from "nothing was sent", which is exactly
why the source frontier exists.

## Baseline that makes this readable

Immediately before, on the same fabric with no fault armed: difference mask **0x0000 across three
directed links and three contexts**, with 400/400 forwarding. A nonzero mask is therefore signal
against a demonstrated zero rather than against an assumption.

## Two defects found getting here, both silent

**The contextual-program list.** `setup_attention` decides whether to install `tbl_eg_vlink` with
the `vlink << 4` shift from a hardcoded `CONTEXTUAL_PROGRAMS` set, and `mcp_fabric_clf_eg` was not
in it. Without the shift `md.sublink = vlink | ctx`, so vlink 2 ctx 1 becomes 3 and reports as
vlink 0: every directed link collapsed onto one. Now DERIVED from the compiled schema — a
contextual program's `set_eg_vlink` action carries a `vlink_base` parameter, so the schema already
knows — with the list kept only as a fallback. This is the third defect of this exact class
(after `eg_qid` and `vlink_dn`): one fact restated in two places.

**A cross-check that could not have worked.** The collapse was invisible when comparing the
frontier against the witness census, because BOTH read `md.sublink`; a fault in that shared input
made them agree while both were wrong. What exposed it was the forwarding proof — 400/400 delivered
to two different leaves, which physically must traverse different vlinks — because it does not
touch `md.sublink` at all. **Two agreeing instruments are not a cross-check if they share an
input.** Independence has to be structural.

## What this does NOT establish

- **One run, one fault.** No false-blackhole rate, no confidence interval, no repetition. PREREG
  decision rule 1 requires >=95% detection across runs; this is n=1.
- **`congestion_no_fault` is untested** — the decisive test of whether the post-TM placement
  argument holds. A traffic-manager drop must never mark TX. Until that is run, the soundness of
  TX=1/RX=0 rests on where the table sits in the pipeline, which is an argument, not a measurement.
- **No epoch-race analysis.** Banking is implemented and bank 0 was used throughout; the guard
  interval and bank-flip behaviour are unmeasured.
- **No distributed exchange.** Both frontiers live on the same chip in this loopback emulation, so
  the agent-to-agent comparison the O(L) claim depends on is not exercised.
- **No mitigation or restoration** driven by a CLF verdict.
