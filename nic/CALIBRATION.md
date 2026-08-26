# Calibration measurements (feed into htsim; see PREREG §9)

| date | path | test | result |
|---|---|---|---|
| 2026-08-25 | Vision↔Hulk direct 10 G, Soft-RoCE rxe0, 1 QP | ICMP ping | rtt 0.30/0.40/0.58 ms min/avg/max |
| 2026-08-25 | same | `ib_write_bw` 64 KiB × 2000 | 2.35 Gb/s peak, 2.31 avg, 4.4 kmsg/s (single QP) |
| 2026-08-25 | same | `ib_write_lat` 2 B × 2000 | t_min 32.2 µs, avg 56.7, typical 61.5, p99 78.9, p99.9 89.8 µs |

Notes: rxe is kernel-CPU bound (H6); expect scaling with QPs/cores, not per-QP. These are
end-host numbers with no switch in path — the switch-in-path delta is measured in S-UP.
