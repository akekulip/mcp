# Tier-1 pilot at the frozen §14 point — paired on 30 seeds (same faults, onsets)

| arm | n | median TTL (epochs) | IQR | censored | vs uniform: faster / tie / slower |
|---|---|---|---|---|---|
| oracle | 30 | 8 | [5, 9] | 0/30 | 28 / 2 / 0 |
| uniform | 30 | 15 | [10, 22] | 1/30 | 0 / 30 / 0 |
| random | 30 | 23 | [16, 27] | 11/30 | 8 / 0 / 22 |
| cusum | 30 | 15 | [10, 22] | 1/30 | 0 / 30 / 0 |
| mcp | 30 | 18 | [14, 24] | 1/30 | 7 / 0 / 23 |

Sign test MCP vs uniform: 7 faster, 23 slower of 30 non-ties, two-sided p = 0.0052. H1 requires MCP >= 30 % LOWER median TTL than the best baseline (uniform 15): MCP 18 -> NOT met (pilot config, untuned at Tier-1).
cusum vs uniform identical per seed: True
