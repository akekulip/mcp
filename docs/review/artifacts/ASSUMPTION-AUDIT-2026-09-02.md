# Assumption audit — claims carried forward without re-verification (2026-09-02)

Prompted directly by Philip: "you have to review old files that have an implication on what we
currently have as implementations... we assumed it held and now we have to go back." This follows
the gap-event mirror defect (`HW-LEDGER-WIRE-REDUCTION-SOAK-ANOMALY-2026-09-02.md`), which is
exactly this failure mode: the receiver-ledger redesign kept the CLF program's mirror-notification
code "because it didn't change," and nobody re-tested it under the new design. (NOTE added same
day: the mirror-emission "defect" that framed this audit turned out to be an instrument artifact,
not a real defect — see §1 and §2 corrections. The audit pattern it prompted is still valid and
still turned up the real §3 gaps, so this document stands with those corrections applied.) This
document looks for the same pattern elsewhere.

## 1. [Root cause, now closed] The redesign plan itself named the gap and nobody circled back

`docs/superpowers/plans/2026-09-01-receiver-ledger-plan.md`: `mcp_fabric_ledger.p4` is created by
copying `mcp_fabric_clf_eg.p4` and changing exactly three things (TX frontier width, the hi/lo
ledger, the Bernoulli injector). Its own "Non-goals" section says deleting the ingress
attention/gate control loop — the exact mirror/gap-event machinery — "is a separate, smaller
follow-up." `docs/review/artifacts/LEDGER-COMPILE-GATE.md` confirms this loop was verified only
for **stage cost** ("CSIG telemetry and the ingress attention/gate loop... are both untouched"),
never for **function**, on the ledger program. This is not a new risk: it was disclosed on
2026-09-01 and nobody functionally re-tested the inherited mirror path under the new design.
**Corrected same day**: once the capture listener was fixed (it had reproduced two documented
harness bugs), the inherited mirror path was shown to WORK — there is no mirror-emission defect.
The audit-pattern lesson still holds (function was assumed from "code unchanged," never re-tested),
but the specific thing feared here does not exist. See §2 and the soak-anomaly doc's CORRECTION.

## 2. [CORRECTED — no defect; the audit-receipt mirror works] The audit/probation receipt path

The concern that opened this section: `set_audit_receipt()`/`set_audit_gap_event()` share the
`ig_dprsr_md.mirror_type = 3w1` / `md.mirror_sid` mechanism with `set_gap_event()`, and
`docs/review/VERIFICATION-2026-08-29.md`'s PASS for the audit path (`CAMPAIGN-PLAN.md`'s B5) only
ever tested "unauthorized audit-shaped **model** traffic" — the model, not silicon, and the
rejection behavior, not whether an authorized audit's receipt reaches a mirror on hardware. That
gap in the record was real and worth closing. What closing it showed is below — and it is good
news: the receipt path works. (This section originally concluded the opposite; that conclusion was
the same instrument artifact as the gap-event one, and is corrected in place below.)

**CORRECTION (same day):** the conclusion first recorded here — that the audit-receipt mirror is
broken — was WRONG, and is retracted. It rested on a listener that lacked promiscuous mode
(`HW-CLOSED-LOOP.md` defect #1) and used an `ETH_P_ALL` bind (defect #4), so Vision's NIC
hardware-dropped the mirror copies (they are addressed to `a5:a5:a5:a5:a5:a5`, not the NIC MAC).
After fixing the listener exactly as `controller_loop.open_mirror_socket()` does, the same
declared-audit test produced **10 `FLAG_AUDIT_RECEIPT` mirror copies** (`flags=0x10/0x11`, vlink 0
= the declared spray, witness seq 21..30) — the receipt path is healthy. The register-observable
finding below (the audit path fires; the flow moves to the pinned spray) was and stays correct;
only the "0 copies -> defect" inference was the artifact. There is no mirror-emission defect on
either call site.

**Tested the same session, on Philip's instruction to close it.** No bind cycle was needed:
`gate_agent.py` already exposes `U <udp_dst> <udp_src> <spray>`, which installs exactly the
`tbl_audit_steer` entry `(md.audit_src=1, dst_port, src_port) -> set_audit_spray(spray)`. A small
raw-socket sender (`p4/hw/loop/audit_probe.py`, the `multicontext_probe.py` recipe with the UDP
identity and 64 B payload of `p4/ptf/gap_event/test.py`'s `host_packet`) sent 10 packets per leg
from Vision (`audit_src=1` via dp9's `tbl_port_role` row), with the mirror listener live.

The register-observable discriminator was the spray pin, not the mirror. Same 5-tuple
(`10.0.1.1:40001 -> 10.0.1.3:4792`) sent three times:

| leg | `tbl_audit_steer` entry | sublink 0 (vlink 0) Δseq/Δobs | sublink 16 (vlink 1) Δseq/Δobs |
|---|---|---|---|
| no entry | absent | 0/0 | **+10/+10** (hash spray picks spray 1) |
| no entry, quarantine on spray 0 | absent | 0/0 | +10/+10 (quarantine never matched — flow was already on spray 1; this leg proved nothing and is reported as such) |
| entry declared (`U 4792 40001 0`) | **present** | **+10/+10** | 0/0 |

The only change between the first and third legs is the audit entry, and the flow moved from the
hash's spray 1 to the declared spray 0 — which only `set_audit_spray()` can do, and that action
sets `md.is_audit = 1` in the same statement. So `is_audit` provably fired for all 10 packets at
hop 0. (At hop != 0 it is re-derived by the same entry on the same fields — loop ports carry
`AUDIT_SRC_OK` per `plan_roles()` for exactly this reason — so the receipt condition
`md.hop != 0 && hdr.witness.isValid() && md.is_audit != 0` should have held; that re-derivation is
inferred from identical matching, not independently observed.) All 10 traversed and were counted
exactly (Δseq = Δobs on the declared sublink). **Zero `FLAG_AUDIT_RECEIPT` mirror copies arrived**
(and zero copies of any kind, across 40 packets in the whole test).

**Both call sites verified healthy** once the listener was fixed: `set_gap_event()` and
`set_audit_receipt()` both reach the wire (gap: `flags=0x9`; receipt: `flags=0x10/0x11`). Entry and
quarantine were cleared afterward (`AUDIT-CLEARED`, `D` acknowledged); nothing left armed.

## 3. [Closed — re-verified, two real gaps found and fixed] Campaign blocker closures cited a different program's numbers

`docs/review/CAMPAIGN-PLAN.md`'s blocker table:

```
B1 | Post-stamp fault injector       | DONE: ...; current compile 11/4
B4 | Runtime setup coverage          | DONE: schema-derived audit covers 50 BFRT objects...
B5 | Audit-path authorization        | DONE: ...; unauthorized audit-shaped model traffic...
```

"11/4" is `mcp_fabric_gate_event.p4`'s stage count (confirmed via `grep`, line 159: "C4 compile on
9.13.2 — DONE 2026-08-29, both programs 11/4"). The ledger program is 11/5 — a different egress
count, and a genuinely different schema (no `reg_rx_frontier`, no bank fields, no `tbl_wit_link` as
of today). None of B1/B4/B5's closures were re-verified against the ledger's actual schema when the
project moved from the gate-event program to the ledger redesign.

**Partially mitigated already**: B1's underlying mechanism (`tbl_eg_fail`, the deterministic
one-shot injector) has been directly, repeatedly verified working correctly on the current ledger
program throughout today's sessions (every `A <sublink> <n>` command used in this investigation
exercises exactly this table) — so B1's *function* holds even though its *cited number* is stale
documentation, not a live functional gap. B4's "50 BFRT objects" claim and B5's audit-path claim
have **not** been independently re-checked against the ledger's schema; B5 specifically is
subsumed by finding #2 above.

**Re-run the same session.** B4's audit is `p4/hw/setup_audit.py` (schema-derived, offline mode —
the same mode the original closure used). Run against `p4/witness/artifacts/mcp_fabric_ledger.bfrt.json`
it **failed, exit 1, two tables "required and unplanned"** — B4's "zero" did not hold on the
program actually deployed:

- `tbl_eg_bern` — the Bernoulli injector the 2026-09-01 ledger redesign added. A runtime-armed
  fault injector of the same class as `tbl_eg_fail`/`tbl_fail` (both already exempt, empty-is-
  healthy), never added to the exempt list when the ledger grew it. Fixed: exempted with the
  evidence the list's own convention requires (armed by `p4/ptf/test_ledger.py` `arm_bernoulli()`,
  cleared in its `setUp`, tiling recipe in `LEDGER-COMPILE-GATE.md` §5).
- `tbl_wit_link_recon` — today's wire-reduction table, with no planner registered in the audit.
  Fixed: `_planners()` now maps it to `setup_attention.plan_wit_link_recon()` (the same list the
  installer iterates, so it cannot drift).

After both fixes: ledger schema audits **PASS, 12 planned, 0 unplanned**; the gate_event schema is
unchanged (still PASS — the extra planner key is inert where the table is absent), so no
regression. `CAMPAIGN-PLAN.md` B1 and B4 rows corrected in place with dated notes rather than
silently rewritten. Not run: `--live` mode (needs the bfrt bind `gate_agent.py` holds); the
original closure was offline too, so this is a like-for-like re-verification, and the live check
remains a cheap follow-up for any session that has the switch without the agent up.

## 4. [Already self-disclosed, tracked] PREREG.md's own staleness note

Amendment v1.9 states plainly that §1's hypothesis table, §3's baseline set, and §7.4's frozen
attention rule "describe the retired design" and were deliberately left unedited, per the
document's append-only convention — a reader has to manually reconcile three amendments to
reconstruct current truth. Not hidden (the document says so itself), and already tracked in
`WORKING_NOTES.md`'s reconciliation-debt note. No new action beyond what's already tracked.

## What was checked and found clean

The novelty-gate history (`NOVELTY-GATE-2/3/4.md`, `NOVELTY-GATE-DSHARK.md`) and `HURDLES.md` were
skimmed for the same carried-forward-assumption pattern. Each novelty gate re-derives its verdict
from the then-current scope rather than inheriting an earlier gate's reasoning under a since-
narrowed scope (e.g., the blackhole+grayhole -> grayhole-only narrowing from earlier this session)
— no live risk found there in the time budgeted for this pass.

## Bottom line

All four closed or tracked, same session. §1: root cause traced to the 2026-09-01 redesign's own
deferred "follow-up" (closed). §2: the audit-receipt mirror confirmed broken on hardware by a
register-observable test — a second, independent call site of the one mirror-emission defect
(closed as a finding; the defect itself is a tracked follow-up for whoever fixes both call sites
together). §3: B4's audit re-run against the deployed program found two real gaps its original
closure never covered; both fixed, both blocker rows corrected in place (closed). §4: already
self-disclosed and tracked; no change.

**The pattern, named so it stops recurring**: every one of these was a claim verified against an
EARLIER program or an EARLIER mode (the gate_event program, the software model, an offline schema)
and then carried across a redesign as if it transferred. The concrete guard going forward is
mechanical, not aspirational: `p4/hw/setup_audit.py` now sees the ledger's real schema, and
`p4/hw/loop/audit_probe.py` plus the mirror listener give any future session a five-minute,
register-observable re-check of the audit path on real silicon — so "does the inherited code still
work under the new design" is a command to run, not an assumption to make.
