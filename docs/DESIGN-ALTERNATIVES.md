# Fast-loop design: what was built, what was tried, and what the silicon decided

Status 2026-08-27. Companion to `P4-DESIGN-SPACE.md` (the pre-build design space) and its errata
section; this file records the design as it exists in `p4/mcp_fabric.p4` (sha `f0b66793…`,
8 ingress + 3 egress stages) and the alternatives that were eliminated by bf-p4c or by silicon
measurement. Numbers cite `p4/reports/step*-silicon*.md` and `h7-timing-F6.md`.

## 1. The loop as built

```
host pass (dp9, pipe 0)          loop passes (5/l <-> 6/l, loop pipe)
 tbl_port_role                     tbl_port_role
 tbl_dst_leaf, draws               tbl_exceed_csig  <- previous hop's tag
 spray (hash | random | rr | sel)  tbl_vlink -> path_id, (port,qid)
 tbl_vlink -> path_id              tbl_fail (range TCAM; mirror sid 3 on fault)
 tbl_fail                          tbl_attn (SALU: bump | decay)  <- reg_attn[path], per pipe
 tbl_exceed_evid (NIC evidence)    tbl_gate (TCAM attn[15:8] x rnd)  -> mirror sid 1
 tbl_attn, tbl_gate                tbl_final: transit | deliver (strip)
 tbl_final: enter (shim + zeroed tag) egress: (port,qid)->vlink, diff = worst |-| this, replace
 egress: same
```

Per packet, per fabric pass: one SALU update of the path's attention word, one TCAM gate, at
most one mirror. Evidence enters two ways — a NIC evidence packet (updates the host pipe's
register, is forwarded to loop 5/0, updates the loop pipe's register, is dropped) and the
previous hop's CSIG tag (loop pipe only). The controller sets three RegisterParams and seeds
the register; everything else moves per packet.

## 2. Alternatives considered and why they lost

| Decision | Chosen | Rejected | Decided by |
|---|---|---|---|
| Gate primitive | 256-row TCAM on `attn[15:8]` × `rnd` range | gateway `rnd < attn` (§5.3) | bf-p4c: a gateway magnitude compare needs a constant operand (Class 9) |
| Attention word | `{attn16, clean16}` in one 32-bit SALU register, 2 RegisterActions, saturating bump | separate `a_max` param; two registers | 4 parameter slots per register (Class 10); one SALU access per packet |
| a_max | 65535 fixed (saturating `|+|`) | `bump_cap` parameter | slot limit; PREREG v1.3 corrected same day |
| Exceedance signal in ingress | previous hop's CSIG `worst_qdepth` + NIC evidence | ingress queue depth | Tofino 1 has no ingress queue depth |
| Tag insertion | ingress `act_enter` inserts + zeroes the tag; egress only replaces `worst_*` | egress insertion with bridged metadata (§5.5) | egress header writes: one source per packed container (Class 13); `(path_id|epoch)` unwritable in egress |
| Tag compare | `diff = worst |-| this`, gateway `diff == 0` | `this > worst` | Class 9 |
| Queue depth field | `deq_qdepth[15:0]` (1-cell units) | `[18:3]` (8-cell) | mid-word intrinsic slice does not allocate (Class 12) |
| Shim field widths | 16-bit `vsw_id/hop/spray/path_id` (12 B shim) | 8-bit fields, 6 B | silicon: parser casts do not zero-extend (`md.hop == vsw_id<<8|hop`); also saved one stage |
| Mirror content | 30-B `mirror_h` (fake Ethernet 0x88F1 + hop/vlink/path/attn/flags/tstamp) + frame as arrived | rely on the copied frame's shim/flags | silicon: `Mirror.emit` copies the packet as it arrived (flags tracked the previous pass) |
| Mirror header sources | shim fields + MAU-written metadata; constants set in the parser | literals; `md.hop`/`md.attn_idx` | literals forbidden in the field list; parser-written key metadata breaks stage-1 RNG placement (Class 14) |
| Fault evidence | mirror-on-drop (sid 3 armed before `drop_ctl`) | deflect-on-drop trimming (§5.6) | no local precedent; mirror gives the same observable |
| Update cadence | fabric passes only (2 per packet) + evidence packets | every pass (3) | delivery pass is not a sample; silicon showed asymmetric decay |
| Evidence and pipes | update host pipe, forward to loop, update loop pipe, drop | drop at host pass | `reg_attn` is per pipe; dp9 and the loops are in different pipes |
| Physical fabric | 4 leaves × 2 spines on the cage 5↔6 4-lane 25 G DAC, one queue per vlink | recirc dp68 + MAC-near loopback dp8, dp65 Agilio collector | live wiring sweep: dp65 gone, 15/0 unlinked, 5↔6 DAC found |
| Collector | dp9 (Vision), shared with delivered traffic | dp65 Agilio at 10 G | Agilio cage empty |

## 3. What the silicon measured (v2 build, 2026-08-27)

- Gate: 487 copies of 4000 packets at attn = 4096 (expected 500); `seed 0` → 0; `seed 65535` →
  2 per packet. Flags/attn/vlink/path in every copy correct.
- Fault mirrors: copies == `inj_drop` count exactly (246/246), including 19 both-dropped-and-gated.
- NIC evidence: +1024 per packet in both pipes, exact; `loss_q = 0` does not bump.
- Decay: 5000 packets per pass → attn 4095, clean 904, symmetric across pipes.
- CSIG: `worst_vlink` correct in 269/269 copies; under a 50 Mb/s shaper, queue depth up to
  11 306 cells; attention saturates at 65535 and sampling goes from 6.25 % to ~100 % with no
  controller involvement — the loop closes end to end.
- H7 (F6, 12 reps, PREREG v1.4 definitions): τ_fast 97.4 µs (BCa 67.9–215.1), ramp to saturation
  1.21 ms, τ_slow full-sweep epoch 88.8 ms (read 48.5 + counter sync 29.8 + write 9.6), ratio
  median 907 (452–1143), sign test 12/12; specificity 0/13 healthy path-instances reacted.

## 4. Open design items

1. CSIG exceedance is single-pipe by construction (the source leaf never sees a tag). The host
   pipe's register reacts to NIC evidence and re-pricing only. Option: mirror the loop pipe's
   exceedance to the host pipe via the same forward-and-drop trick used for evidence packets.
2. Collector bandwidth: at saturation the faulty path emits ~2 copies per packet into dp9, which
   also carries delivered traffic; 0.15–0.22 % interface drops were observed at 25 G. A second
   collector port (Hulk, once cabled) or per-session `$max_pkt_len` tightening is the lever.
3. Attention semantics differ per pipe; the epoch controller must read and reconcile both
   (`controller/epoch_loop.py`).
4. Latency inflation (§7.4 L1/L2) and black-hole-with-reroute (§7.5, ActionSelector group edit)
   are implemented in the control plane but not yet exercised on silicon.
