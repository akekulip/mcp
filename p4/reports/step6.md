# Step 6 — Truncated ingress mirrors: fault evidence (sid 3) and gated samples (sid 1)

Design reference: `docs/P4-DESIGN-SPACE.md` §5.4 (truncated mirror), §5.6 (mirror-on-drop
instead of deflect-on-drop). Source hash after this step: `sha256(mcp_fabric.p4) = 2e1a54bef56f289f…`.

## What was added

- `inj_drop` and `inj_corrupt` set `ig_dprsr_md.mirror_type = 3w1` and `md.mirror_sid = 3`
  before dropping/corrupting; the mirror is taken in the ingress deparser, so the collector
  gets a trimmed copy of every injected fault (§5.6; `simple_l3_mirror.p4:456` precedent).
- `set_measure` (the gate hit, §5.4) sets `mirror_type = 3w1` and `md.mirror_sid |= 1`:
  OR-composition means a packet that is both fault-injected and gated keeps sid 3.
- Ingress deparser: `Mirror() mcp_mirror; if (mirror_type == 3w1) mcp_mirror.emit(md.mirror_sid);`
  — no-arg constructor, session id from metadata, single-argument emit (the copy is the
  post-MAU frame, shim included; `$max_pkt_len` truncates it).
- `md.mirror_sid` is now `MirrorId_t` (bit<10>): `emit()` rejects a cast or slice
  (`error: expression md.mirror_sid[9:0] in mirror`).

## Build

Local 9.13.1 and switch 9.13.2: 0 errors, 4 warnings (unchanged). 8 ingress stages, same
stage map as step 5; `tofino.bin` 1 457 755 bytes (step 5: 1 457 311).

## Control-plane contract

`$mirror.cfg` sessions 1 (128 B) and 3 (64 B), `$direction=INGRESS`, `$ucast_egress_port` =
the collector. **Collector today = dp9 (Vision)** — there is no Agilio leg (dp65 is gone); mirrored
copies reach Vision with ether_type 0x88F0 and are told apart from delivered traffic by that.
Budget arithmetic of §5.4 now applies to a 25 G collector port shared with delivered traffic.
