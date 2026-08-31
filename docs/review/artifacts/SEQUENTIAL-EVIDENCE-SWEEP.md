# Sealed-Epoch Sequential Evidence Sweep

Date: 2026-08-31
Status: simulation result; promoted on silicon for blackhole, 95% gray loss, and healthy control
Preregistration: `sim/clf/SEQUENTIAL-PREREG.md`

Command:

```text
python3.12 -m sim.clf.sequential_eval --runs 2000 --packets-per-epoch 32 --horizon 50
```

Fixed configuration: 2,000 campaigns per survival point, 32 exact departures per epoch, 50-epoch
horizon, seed 20260830, healthy-delivery null 0.99, alpha 0.05 per repair generation, and the
preregistered six-component alternative mixture. Counts never approach the saturation value 255.

| Survival | Presence action | Fixed RX/TX <= 1/8 | Sealed ledger action | Ledger median epoch | Statistical alarm |
|---:|---:|---:|---:|---:|---:|
| 0.000 | 100.0% | 100.0% | 100.0% | 1 | 100.0% |
| 0.010 | 100.0% | 100.0% | 100.0% | 1 | 100.0% |
| 0.050 | 100.0% | 100.0% | 100.0% | 1 | 100.0% |
| 0.100 | 82.4% | 100.0% | 100.0% | 1 | 100.0% |
| 0.125 | 51.0% | 100.0% | 100.0% | 1 | 100.0% |
| 0.150 | 22.8% | 100.0% | 100.0% | 1 | 100.0% |
| 0.250 | 0.4% | 97.6% | 100.0% | 1 | 100.0% |
| 0.500 | 0.0% | 0.0% | 100.0% | 1 | 100.0% |
| 0.750 | 0.0% | 0.0% | 100.0% | 1 | 100.0% |
| 0.900 | 0.0% | 0.0% | 100.0% | 2 | 100.0% |
| 0.950 | 0.0% | 0.0% | 100.0% | 4 | 100.0% |
| 0.970 | 0.0% | 0.0% | 99.5% | 12 | 99.5% |
| 0.990 | 0.0% | 0.0% | 0.4% | 17.5 | 0.4% |
| 1.000 | 0.0% | 0.0% | 0.0% | — | 0.0% |

The result identifies the missing contribution cleanly. Presence is the right one-epoch shape for
a total blackhole, and the fixed 1/8 threshold covers near-total starvation, but neither produces
evidence in the broad 50–97% survival band. The sealed mixture fills that band without changing the
data plane: at 95% survival it acted in every campaign with median four epochs; at 97% it acted in
99.5% with median twelve epochs. At the null boundary, empirical statistical action was 0.4%, below
the preregistered 5% bound; perfect delivery produced none.

This is not yet a production threshold recommendation. The 0.99 null is an explicit engineering
contract that must be calibrated against benign congestion and real traffic before deployment.
The defensible systems claim is narrower: exact CLF counts can be sealed into a typed, fail-closed
controller ledger, and a proved sequential rule extracts gray-loss evidence that the existing
presence and one-epoch threshold arms discard.

Silicon validation on the Tofino testbed reproduced the count records while preserving sealed
identity end to end. The first silicon runner default accidentally omitted the `0.01` alternative
and therefore used five mixture components; those measurements are historical only. A regression
test now locks the runner to the same six alternatives as the preregistration, and the final matched
triad below was rerun with that corrected runner, one build, and one runtime:

```text
program=mcp_fabric_clf_eg
build=158d63f370a84264157a4a7d0c87036a86b224f148ae582357153b1a631c85d9
setup=022f95f0d34cd2d3398aba55f225c6c8b2538a3730c03c4b7abfb9ac86d838b4
runtime=1ba36ada91bdd44fdc4fe525dcea46fa868d9ebd6ecc35fd8619c055b8e8441b
switchd_pid=168913
```

Fresh hardware commands, rerun 2026-08-31 from Vision as root because
`multicontext_probe.py` uses raw AF_PACKET sends:

```text
python3 p4/hw/loop/sequential_trials.py --program mcp_fabric_clf_eg \
  --expected-build-id 158d63f370a84264157a4a7d0c87036a86b224f148ae582357153b1a631c85d9 \
  --expected-runtime-id 1ba36ada91bdd44fdc4fe525dcea46fa868d9ebd6ecc35fd8619c055b8e8441b \
  --sublink 6 --epoch 2500 --epochs 4 --packets 40 --pps 200 --contexts 6 \
  --survival 0.95 --guard 2.0

python3 p4/hw/loop/sequential_trials.py --program mcp_fabric_clf_eg \
  --expected-build-id 158d63f370a84264157a4a7d0c87036a86b224f148ae582357153b1a631c85d9 \
  --expected-runtime-id 1ba36ada91bdd44fdc4fe525dcea46fa868d9ebd6ecc35fd8619c055b8e8441b \
  --sublink 6 --epoch 2600 --epochs 4 --packets 40 --pps 200 --contexts 6 \
  --survival 1.0 --guard 2.0

python3 p4/hw/loop/sequential_trials.py --program mcp_fabric_clf_eg \
  --expected-build-id 158d63f370a84264157a4a7d0c87036a86b224f148ae582357153b1a631c85d9 \
  --expected-runtime-id 1ba36ada91bdd44fdc4fe525dcea46fa868d9ebd6ecc35fd8619c055b8e8441b \
  --sublink 6 --epoch 3000 --epochs 3 --packets 40 --pps 200 --contexts 6 \
  --survival 0.0 --guard 2.0
```

Results:

| Silicon scenario | Result |
|---|---|
| 95% survival gray loss, sublink 6, 40 packets/epoch | epochs 2500–2503 measured exact `tx=40 rx=38 drops=2`; the six-point-mixture e-values were `1.13899`, `4.05357`, `15.0464`, and `57.6701`, so threshold 40 produced `GRAYHOLE` on the fourth sealed epoch |
| 100% survival healthy control, sublink 6, 40 packets/epoch | epochs 2600–2603 measured exact `tx=40 rx=40`; all stayed `MONITOR`, with e-values decaying from `0.0773583` to `0.00636353` |
| Total blackhole, sublink 6, 40 packets/epoch | epochs 3000–3002 measured exact `tx=40 rx=0 drops=40`; all returned `BLACKHOLE`, including the first sealed epoch |

The silicon run also found and fixed four harness defects: the switch-side `A` reply lacked the
standard `OK <range-count>` terminator; target frontier reset needed a bounded retry; the total-loss
arm incorrectly used a bounded sequence range instead of the full-range `K` primitive; and receipt
validation accepted a drop count that matched the observed deficit even when it did not match the
declared injection. A fifth implementation mismatch—the hardware default's missing `0.01`
alternative—was found during the final comparison review and fixed before the triad above. The
final runner now arms only after zero readback, requires `TX` to equal the
declared sent count, requires partial-loss receipts to match both the declared injection and the
observed deficit, and uses `K <sublink> 0 65535` for total blackholes.

An overlapping parallel campaign, the pre-fix ranged "blackhole" attempt, and censored epochs are
intentionally excluded from the success counts. In the six-point rerun, sublink-2 epochs 2200 and
2203 measured `tx=41 rx=39` after exactly 40 declared sends; sublink-6 epoch 2700 measured
`tx=41 rx=0 drops=41`. All three became `INCONCLUSIVE`, as required, and none was silently selected
as positive evidence. These and the earlier exclusions produced
plausible-looking values without valid isolation or exact injection truth; none contributes to the
positive table entries. This censoring is useful negative evidence: the runner refuses to convert a
contaminated epoch into a blackhole claim. After the final triad, the
gate reported `OK 0` active injections, repeated the exact program/build/runtime identity and
switchd PID above, and Vision had no surviving trial or probe process.

The final compiler evidence is independently anchored: build-manifest SHA-256
`158d63f370a84264157a4a7d0c87036a86b224f148ae582357153b1a631c85d9` names source SHA-256
`9010a44d1935853db133e3af21cc0fa0e810b25e52d57d1c257ef9cddcba77c0`. The compiler reported
0 errors and 5 warnings, 11 ingress and 5 egress stages, and 42 allocated tables. The raw manifest,
artifact hashes, timestamps, and complete `table_summary.log` are preserved in
[`FINAL-COMPILE-EVIDENCE.txt`](FINAL-COMPILE-EVIDENCE.txt).
