# P3 partial-loss closed loop on Tofino — 2026-08-30

## Claim tested

For a **partial-loss** fault with a later survivor in the same behavioral context, the deployed
path can execute:

```text
downstream C-W4 discontinuity
  -> attributed mirror event
  -> pooled, frozen inference decision
  -> one batch containing every affected exact health-gate row
  -> first exact experiment packet observed on the backup vlink
```

Both endpoints of the headline interval use the switch's 48-bit ingress timestamp. `t0` is the
downstream gap event; `t1` is the first backup-vlink copy whose inner IPv4/UDP 5-tuple matches the
controlled probe. The interval is **feedback/actuation latency after detection**, not fault-onset
to detection time.

## Final mechanism

- Four demand-carrying C-W4 cells `(vlink 0, contexts 2/6/10/14)` supply one batched pooled census
  update every 500 ms. A targeted read takes 7.7 ms median instead of about 250 ms for all 1,024
  possible cells.
- One 655-packet post-stamp drop range targets only sublink 2. Modular ranges split at the 16-bit
  wrap; a silicon canary at sequence 65,300 armed `[65303..65535]` and `[0..421]`, and clearing
  removed both entries.
- The controller holds the gap for 1 ms for an immediate reorder credit. Its receive timeout is
  bounded by that deadline rather than the former fixed 10 ms poll.
- One decision expands to four `(src,dst,spray,context)` rows and sends them in one agent request
  and exactly one BFRT batch. A batch error fails the trial; it cannot silently degrade into
  row-by-row writes. Controller and inference state commit only after the writer returns a valid
  `OK <time>` reply, so failed evidence remains retryable without being counted twice.
- Campaign mode requires an explicit demand-targeted census. Census `ERR`, truncation, malformed
  rows, inconsistent context identity, and a missing success terminator are all counted as errors,
  never converted into empty clean evidence.
- The switch agent accepts commands only from the collector and switch localhost. Gate and injector
  cleanup are fail-closed except for an explicitly absent gate row.
- The backup path's attention register was temporarily set to `65535` so the first rerouted probe
  was observed with probability 255/256 rather than waiting for the production floor sampler.
  This changes observation overhead only; it does not change detection, inference, the gate, or
  forwarding. The pre-campaign value was restored afterward. At the ordinary sampler, a prior
  correct run measured 165.995 ms because the gate was already live but proof waited for a random
  backup sample; that is not gate latency.

## Frozen trial shape

| item | value |
|---|---:|
| chip / SDE | Tofino 1 / 9.13.2 |
| loaded program | `mcp_fabric_gate_event` |
| offered link | 25 Gb/s, link up |
| baseline | 160,000 packets, round-robin across contexts 2/6/10/14 at 48 kpps |
| minimum baseline required by frozen inference | 100,000 packets |
| fault | 655 consecutive post-stamp drops on sublink 2 |
| post-fault stream | 4,000 context-2 packets at 2 kpps |
| threshold | frozen `h = 6.5` |
| valid-trial requirements | one gap, one quarantine, one batch op, zero census errors, baseline >= 100k, exact backup proof |
| repetitions | 20; invalid trials retained by rule |

The 2 kpps post-fault stream gives the `t1` proof 0.5 ms packet-time resolution.

## Result

All 20 trials met every validity condition.

| metric | result |
|---|---:|
| event-to-first-rerouted packet | **4.998 ms median** |
| range | 3.998–5.499 ms |
| trials at or below 4.999 ms | 18/20 |
| mean | 4.924 ms |
| gate RPC | 3.582 ms median, 4.082 ms max |
| switch-agent batch | 2.755 ms median, 3.250 ms max |
| targeted census | 7.7 ms median, 7.9 ms max |
| baseline actually fed | 160,504 min; 160,570.5 median; 160,627 max |
| gaps / quarantines / batch writes | 20 / 20 / 20 |
| census errors | 0 |

The per-run values and raw-log SHA-256 digests are in
`P3-HW-CLOSED-LOOP-HARDENED-2026-08-30.csv`; the immutable concatenated logs are
`P3-HW-CLOSED-LOOP-HARDENED-RAW-2026-08-30.txt`. The source campaign id is
`20260830T062052Z_hardened`; its source logs were
`/tmp/mcp_campaign_20260830T062052Z_hardened_repNN.log` on Vision. The earlier unhardened CSV/raw
pair remains historical and is not the authoritative dataset.

The hardened artifact SHA-256 values are:

- CSV: `0048ab2fc64b6fb112494e52b16c58f7b785a375fee9a82655dbe3ff6e71057c`
- concatenated raw logs: `1512bbafbb230531fc4a9c3e19aeece2c97a9219fe9300ae8f9f8a7e73182dd5`

The deployed and local source hashes matched exactly:

| component | SHA-256 |
|---|---|
| controller loop | `a8e1f05da6a3d624e584799313cd5b77650805f3d1e464258e7513dc9ffcdbb4` |
| feedback core | `7e4228092f34c3332af15b137aaa900e9232030f3fa544124dcb4ae4b8a39895` |
| mirror parser | `dc241d01dabf214f14ef772bbea18566070d25e53bb8d30e08d8dd54044b6987` |
| switch gate agent | `a8ab48ae8cbb26c603baaeabb3d9bbfcfd2d8dba6d60aaf3110e71bfbc101423` |
| strict agent helpers | `36d246e92f8d4b932e839830700832362b3f0a9ea3f06e691c7d8e364bfb26af` |
| modular injector helper | `c81c2cc17061bb6a7a5c81a64c86cca06f191f585dfd8bfef9a58e8019be9f9b` |

## Reproduction order

Each retained trial used the same ordering:

1. clear the post-stamp injector and raise backup path 5's attention state to `65535/0` for the
   t1 observation only;
2. start `controller_loop.py --seconds 12 --h 6.5 --backup-vlink 1 --epoch-ms 500 --ctx 2
   --probe-diffserv 0 --census-sublinks 2,6,10,14 --reorder-wait-ms 1 --reset
   --stop-after-result`;
3. wait for capture readiness, then send `160000` interleaved packets with
   `multicontext_probe.py --pps 48000 --contexts all`;
4. allow 600 ms for the final census, arm `A 2 655`, then send `4000` context-2 packets at
   `2000` packets/s;
5. retain the log whether valid or invalid, clear injector/gates, and begin the next trial;
6. after all repetitions, restore path 5's pre-campaign attention state (`4077/992`).

Campaign mode refuses to start without the explicit census sublinks. Validity is computed from the
retained log; a failed reset, census, batch, exact t1 proof, or baseline threshold is not rerun away.

## Independent selective-isolation check

After installing the same context-2 gate, 8,000 interleaved packets (2,000 per context) produced
these wrap-safe C-W4 stamp deltas:

| sublink | meaning | delta |
|---:|---|---:|
| 2 | primary vlink 0, bad context 2 | **0** |
| 6 | primary vlink 0, healthy context 6 | 2,000 |
| 10 | primary vlink 0, healthy context 10 | 2,000 |
| 14 | primary vlink 0, healthy context 14 | 2,001 (one background packet) |
| 18 | backup vlink 1, context 2 | **2,000** |

Thus the physical link remained in use for all three healthy contexts while only the quarantined
context moved to the backup.

## Defects found and corrected

1. mirror socket did not explicitly join promiscuous mode;
2. synchronous 1,024-cell BFRT census starved mirror capture;
3. feeding census rows one by one repeatedly discounted one pooled epoch and suppressed alarms;
4. an `ETH_P_ALL` socket admitted the looped production stream and queued the event behind it;
5. the first-reroute matcher required a capsule that silicon strips on the delivery copy;
6. ordinary probabilistic sampling was mistaken for gate-actuation latency;
7. a fixed 10 ms receive timeout inflated the 1 ms reorder hold;
8. full census and gate writes shared one single-threaded agent, causing 32 ms head-of-line delay;
9. injector ranges did not split at 16-bit wrap;
10. one logical quarantine used four serial connections/writes instead of one batch.
11. remote `ERR` and malformed write replies were treated as successful controller operations;
12. a failed batch silently fell back to row-by-row writes, invalidating the one-batch contract;
13. plain delivery copies matched only the shared five-tuple, so another DiffServ context could be
    mistaken for the reroute proof;
14. cleanup masked gate/injector failures and the mutation service accepted any management peer;
15. census transport errors and truncation could look like an empty clean census;
16. failed actuation retained the event but had already committed its inference update, so a retry
    could count the same loss twice.

Each correction has a regression test or a direct silicon canary. No frozen inference threshold was
changed to obtain the result.

## Cleanup and claim boundary

After the hardened campaign, injector and all eight possible context-2 gate entries were cleared,
the backup attention value was restored, and no controller or traffic process remained. Vision's NIC reported
25,000 Mb/s and link detected; `bf_switchd` and the bound gate agent remained alive.

This closes only the **partial-loss detection-to-quarantine** portion of P3. It does not prove:

- passive detection of a context that becomes a total black hole (C-W4 needs a survivor);
- audit/probation-driven restoration on silicon;
- reordering correctness of the currently loaded resynchronizing witness;
- false-quarantine bounds under a statistically powered background-loss campaign;
- Ring-AllReduce/MoE application benefit at matched safety;
- production overhead at the temporarily elevated backup observation probability.

Those remain explicit publication gates.
