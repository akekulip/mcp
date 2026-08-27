# Tier-1 pilot at the frozen §14 point — re-issued under the pre-registered detector (M0, 2026-08-27)

Detector provenance matters: `mcp.cpp:133-152` writes a `correct` column from a ratio rule
(argmax drop/tx over the probed set > 1e-5); PREREG §3.3 requires the frozen localizer
(`controller/infer.py`, hash be12e7b2, h=6.5, delta=1e-4, pooled). Medians are read off the
Kaplan-Meier curve (§2.1); the raw median is shown beside it. 30 paired seeds, same faults,
same onsets.

| arm | detector | KM median | raw median | censored |
|---|---|---|---|---|
| uniform | simulator ratio rule | 16.0 | 15.0 | 1/30 |
| random | simulator ratio rule | 23.0 | 23.0 | 11/30 |
| oracle | simulator ratio rule | 8.0 | 8.0 | 0/30 |
| cusum | simulator ratio rule | 16.0 | 15.0 | 1/30 |
| mcp | simulator ratio rule | 19.0 | 18.0 | 1/30 |
| cusum | **frozen localizer (§3.3)** | **20.0** | 19.5 | 6/30 |
| mcp | **frozen localizer (§3.3)** | **19.0** | 19.0 | 2/30 |

(uniform/random/oracle have no bridge log — they were not driven through the controller —
so their localizer TTL requires offline replay over the recorded counters: M1 harness.)

- Paired MCP vs cusum(=uniform schedule), simulator ratio rule: MCP faster 7, slower 23, tied 0; two-sided sign p = 0.005
- Paired MCP vs cusum(=uniform schedule), frozen localizer: MCP faster 11, slower 19, tied 0; two-sided sign p = 0.200

**Correction on the record.** The previously reported "MCP slower in 23/30, p = 0.005" came
from the simulator's ratio rule. Under the detector the pre-registration names, the arms are
statistically indistinguishable, and **no arm meets H1** (>= 30 % below the best baseline).

**Replay soundness (verified this session).** The per-link `counters.csv` files are byte-identical
across all five arms for every seed (120/120 arm-seed pairs), so at Tier-1 the measurement policy
does not perturb the fabric: beta_probe = beta_tag = 0 for every budgeted arm, and offline replay
of any read schedule against the recorded counters is exact, not approximate.
