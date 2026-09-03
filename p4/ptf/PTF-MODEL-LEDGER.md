# Receiver ledger: model validation — 9 asserted tests, all pass; no defect found in the P4

> **Update 2026-09-02:** this report documents the 2026-09-01 run against the pre-wire-reduction
> `test_ledger.py` (4-byte `wit_h` with `link_id`). `test_ledger.py` has since been updated for the
> 2-byte seq-only wire format, and the suite was re-run against the wire-reduction program: **all 9
> tests pass with byte-identical values** (the ledger arithmetic is unchanged by dropping
> `link_id`). See `docs/review/artifacts/HW-LEDGER-WIRE-REDUCTION-SMOKE-TEST.md` /
> `LEDGER-WIRE-REDUCTION-2026-09-02.md`. The numbers below therefore still hold; only the test's
> packet builder changed.


Ran 2026-09-01 on the laptop's SDE 9.13.1 software model. **The shared Tofino was never touched**:
no `ssh`, no `scp`, no chip access, no `bf_switchd` on the switch, no port or table write on
`decps@10.10.54.81`. `p4/ptf/model/run_ledger.sh` contains no reference to the switch at all; every
process it starts is local (`tofino-model`, `bf_switchd`, `ptf`) and it refuses to start if any
model process is already alive.

Suite: `p4/ptf/test_ledger.py` — **9 asserted tests, 0 diagnostics**. Harness:
`p4/ptf/model/run_ledger.sh`, which recompiles `p4/witness/mcp_fabric_ledger.p4` from the current
source on every run and generates a matching temporary model config, so the suite can never run
against a stale schema.

The program under test was **not modified**. The source hash the runner printed,
`4e889bfdb9630aeb339e05ce5f97b344d35744b073dbfc847513462e2ac136f3`, is byte-identical to the one
`docs/review/artifacts/LEDGER-COMPILE-GATE.md` §1 records, and the local build placed at
**11 ingress / 5 egress** stages and 40 tables, matching that gate.

## Result

| # | Semantics | Verdict |
|---|---|---|
| 60 | **the core estimator** — 40 packets stamped by the program's own egress, 5 lost on the wire; `Δhi − Δlo` equals the injected loss count exactly | PASS |
| 61 | trailing loss is invisible until the next survivor, then exposed in full — the estimator's known limit, pinned | PASS |
| 62 | **the 32-bit TX frontier counts past 255** — 300 packets read back as exactly 300, not saturated and not wrapped | PASS |
| 63 | **reorder manufactures no phantom loss (H33)** — arrival order 0,1,3,2,4 leaves the frontier monotone, raises no event on the in-order packet after the reorder, and scores exactly zero loss | PASS |
| 64 | a duplicate drives the estimate NEGATIVE (−1) — a controller requirement, confirmed against the compiled program | PASS |
| 65 | `tbl_eg_bern` realised rate at p = 0.25 over 800 packets is inside a ±4σ band, and `drop + none` equals packets offered exactly | PASS |
| 66 | a full-range `[0, 65535]` entry is all-or-nothing in both directions — 30/30 dropped when armed to drop, 0/30 when armed to pass | PASS |
| 67 | **`tbl_eg_fail` still drops exactly one packet** beside the new stochastic arm, and the ledger scores that in-pipeline post-TM drop as exactly one loss | PASS |
| 68 | the **model's own** `Random<bit<16>>` is uniform across an 8-way range tiling (χ² = 6.53 on 7 df) and the eight ranges tile `[0, 65535]` with nothing falling through to the default entry | PASS |

Wall time for the whole suite including compile and stack bring-up: **1 m 43 s**.

## The measured numbers

Every test prints its realised values before asserting on them, because in this repo a PASS with
no printed numbers is a claim and not a measurement. Verbatim from one complete run:

```
EVIDENCE 60 estimator            delivered=35  est=5  hi=40  injected_loss=5  lo=35  stamped=40  tx=40
EVIDENCE 61 trailing loss        est=2  hi=7  lo=5
EVIDENCE 62 tx frontier          old_bit8_would_read=255  sent=300  seq=300  tx=300
EVIDENCE 63 reorder              frontier=[1, 2, 4, 4, 5]  gaps=[None, None, '0xffff', '0x2', None]  order=[0, 1, 3, 2, 4]
EVIDENCE 63 reorder ledger       est=0  hi=5  lo=5
EVIDENCE 64 duplicate            est=-1  hi=3  lo=4  order=[0, 1, 2, 2]
EVIDENCE 65 bernoulli rate       N=800  W=16384  band=0.06124  drop=183  none=617  offered=800  p_cfg=0.25  p_hat=0.22875  survivors=617
EVIDENCE 66 bernoulli all-drop   N=30  drop=30  none=None  survivors=0
EVIDENCE 66 bernoulli all-pass   N=30  drop=None  none=30  survivors=30
EVIDENCE 67 one-shot             N=6  armed_seq=3  est=1  fail_ctr=1  hi=6  lo=5  survived=[0, 1, 2, 4, 5]  tx=6
EVIDENCE 68 draw histogram       N=2400  chi2=6.527  counts=[296, 319, 309, 293, 264, 311, 305, 303]  expected=300.0  low_quarter_frac=0.25625  survivors=2400  total=2400
```

Three things to read off that block.

**Test 60 is the whole redesign in one line.** The pipeline stamped 40 sequence numbers itself;
PTF re-injected 35 of them and silently discarded 5. `hi` reached 40, `lo` reached 35, and
`Δhi − Δlo = 5`. The loss is genuinely post-stamp — the sender's egress had already consumed the
sequence number and already bumped `reg_tx_frontier` (which reads 40, not 35) — which is precisely
the loss a pre-stamp ingress injector like `tbl_fail` cannot produce.

**Test 62 puts a number where the compile gate had only an argument.** The gate measured that
widening `reg_tx_frontier` from 512 × `bit<8>` to 2048 × `bit<32>` cost 0 SRAM blocks and 0 stages;
it never ran a packet through the widened register. 300 packets read back as 300. The old
saturating `bit<8>` would have read 255 and an 8-bit wrap would have read 44, so the measurement
separates the fixed shape from both failure modes it replaces.

**Test 65's p̂ needed a cross-check, and got one.** The first run of that test came out at
p̂ = 0.21125 against a configured 0.25 — inside the ±4σ band, but −2.5σ, which is a 1-in-88 draw
and not something to accept on one sample. Test 68 was written to separate the draw from the drop:
eight all-pass ranges of 8192 apiece make the DirectCounters a pure histogram of `md.eg_rnd` with
nothing dropped at all. Pooling every measurement of the `[0, 16383]` fraction taken this session —
**169, 183 and 181 out of 800** from three Test 65 runs and **593, 615 and 594 out of 2400** from
three histogram runs — gives **2335 / 9600 = 0.24323, which is −1.53σ from 0.25**. The model's RNG
is uniform; the first run was chance. All three χ² values measured (7.51, 6.53 and 3.63 on 7
degrees of freedom) are ordinary; the largest of them sits at the 62nd percentile.

Run history, stated exactly. The complete 9-test suite ran to completion **twice, 9/9 both times**;
the block above is verbatim from the first of the two. Before Test 68 was added the 8-test suite
ran to completion twice, 8/8 both times. Between the two 9-test runs the two random arms moved as
expected (p̂ = 0.22875 → 0.22625, χ² = 6.53 → 3.63) and **every other printed value was byte-identical**
— which is itself worth stating, because a deterministic arm that moved between runs would be a
harness problem rather than a result. The third Test 65 sample (169/800) and the first histogram
sample (593/2400) come from earlier partial runs of the same unchanged tests.

## Reorder: the model's own per-packet trace (HURDLES H33)

Test 63 is the one that targets a defect the ledger was partly built to prevent, so it is worth
showing at the register level rather than at the assertion level. Extracted from
`/home/philip/mcp_model/ledger.model.log` for one run of Test 63 alone — register index `0x71` is
`REORDER_SUBLINK = (7 << 4) | 1 = 113`:

```
pkt    half seq          before     after      returned
0x1    hi   0x00000000   0x00000000 0x00000001 0x0
0x1    lo   -            0x00000000 0x00000001 0x0
0x2    hi   0x00000001   0x00000001 0x00000002 0x0
0x2    lo   -            0x00000001 0x00000002 0x1
0x3    hi   0x00000003   0x00000002 0x00000004 0xffff     <- the forward hole
0x3    lo   -            0x00000002 0x00000003 0x2
0x4    hi   0x00000002   0x00000004 0x00000004 0x2        <- THE LATE PACKET: no rewind
0x4    lo   -            0x00000003 0x00000004 0x3
0x5    hi   0x00000004   0x00000004 0x00000005 0x0        <- and no phantom hole after it
0x5    lo   -            0x00000004 0x00000005 0x4
```

Packet `0x4` is the whole point. It carries `seq = 2`, arriving after `seq = 3` has already pushed
the frontier to 4. The advance-only SALU returns a small **positive** gap (`0x2`) and leaves the
register at 4. Under the unconditional `hi = seq + 1` resync that H33 recorded, this packet would
have written `hi = 3`, and packet `0x5` (`seq = 4`) would then have returned `0xffff` — one
adjacent reorder reported as two events and one phantom lost packet. Here `0x5` returns `0x0`.

The magnitudes are also separable, which is what makes the pair usable: a forward hole of one reads
as `0xffff` and a late arrival of one reads as `0x2`. `lo` advanced on all five arrivals, so
`Δhi − Δlo = 5 − 5 = 0`: a pure reorder with no loss scores no loss.

## No defect was found in `mcp_fabric_ledger.p4`

Stated plainly because the W4 pass at `PTF-MODEL.md` did find one and the comparison is the point.
Nothing in this pass required a change to the P4, and the source hash above proves none was made.

That is a weaker claim than "the program is correct", so here is what was actually ruled out. Every
assertion in Tests 60, 62, 66, 67 and 68 is an exact equality against a count the test controls, so
a harness that silently delivered nothing, delivered everything, or double-counted would fail
rather than pass: if the "lost" packets had reached the receiver anyway, `lo` would have read 40
and the estimate 0; if none of the re-injections had landed, `lo` would have read 0. Both were
checked by construction, not assumed. The one arm that is statistical (Test 65) was cross-checked
against a second, independent, non-statistical measurement of the same quantity (Test 68).

## Findings that are NOT about the P4

Three, all in the tooling around it, recorded so they are not rediscovered cold.

**1. `bfrt`'s `entry_get` yields `(Data, Key)`, not `(Key, Data)`.** Getting it backwards is not an
error at the read — it is a silent wrong-field read that only surfaces later. The first version of
this suite had it backwards and Test 65 *failed* as a result, because the action name was being
looked up in the key half; the same bug made Test 66 die with `KeyError: '$COUNTER_SPEC_BYTES'`
inside `entry_del`, because the "key" being deleted was really a Data object carrying the direct
counter. `p4/control/setup_skeleton.py:1242` already documents this hazard in `_rows()` and gets it
right. **`p4/ptf/test_fabric.py:276-281` has it backwards**: its `counter()` helper returns
`{str(data_dict): None}` for every row, because `$COUNTER_SPEC_PKTS` is looked up in the key. It is
not called anywhere in that file, so nothing currently asserts on the wrong values, and it was left
alone — fixing it needs a model run of that suite, which is outside this pass.

**2. The model logs `if (c) apply(t)` gateways with INVERTED polarity.** bf-p4c compiles the
control-flow test into a gateway that matches on ¬c and *inhibits* the table, so the model prints
"matched" exactly when the source predicate is FALSE. From the same run, unedited:

```
:0x1:...:Gateway table condition ((md.wit_result.gap != 0)) matched.
:0x1:...:Table Ingress.tbl_wit_arm is inhibited by a gateway condition        <- gap WAS 0
:0x3:...:Gateway table condition ((md.wit_result.gap != 0)) not matched.
:0x3:...:Associated table Ingress.tbl_wit_arm is executed                     <- gap was 0xffff
```

All ten occurrences in the run follow that polarity (packets `0x1`, `0x2`, `0x5` with `gap == 0`
print "matched" and are inhibited; `0x3`, `0x4` with `gap != 0` print "not matched" and execute).
This matters because the W4 defect in `PTF-MODEL.md` was diagnosed by reading exactly these lines.
It does **not** invalidate that diagnosis — the W4 line quoted there has an *empty* condition
`()`, which is the folded-const-entry-table case rather than an `if`, and the conclusion was
independently confirmed by counting `act_attn_exceed` executions. But anyone reading a gateway line
for an explicit `if` should read the polarity backwards, and this note is the only place that says
so.

**3. The suite must reset state between test cases, and this program makes that unusually
important.** `lo` is by design a never-reset lifetime counter and the model keeps register and
DirectCounter state across cases in one PTF run, so `LedgerBase.setUp` re-seeds `hi`, `lo`, `tx`
and `seq` on all three sublinks it uses and deletes every entry from both injector tables. A test
written against a "fresh chip" assumption would silently read the previous test's traffic and could
pass for the wrong reason.

## Reproducing

```bash
p4/ptf/model/run_ledger.sh                                  # all 9
p4/ptf/model/run_ledger.sh test.Test63ReorderManufacturesNoPhantomLoss   # one
```

The runner needs `sudo` (from the repo's `0600` `.env`, never echoed) because `tofino-model`,
`bf_switchd` and PTF all need `CAP_NET_RAW` on the veths, and it needs
`sudo $SDE/install/bin/veth_setup.sh` to have been run once on the machine. The three environment
workarounds `PTF-MODEL.md` documents — invoking the binaries directly under sudo rather than
through the SDE wrappers, a model conf without the platform agent, and
`p4/ptf/model/pyfix/sitecustomize.py` repointing the `google` namespace at the SDE's protobuf
3.20.3 — are all inherited unchanged and were not re-debugged.

`run_ledger.sh` follows the safety contract `p4/ptf/model/test_runner_contract.py` pins for
`run_context_regressions.sh`: no global `pkill`, an exclusive local lock, a refusal to start when
any `bf_switchd`/`tofino-model` is already alive, and a `kill_owned` that will only signal a PID
this invocation recorded *and* whose `/proc/<pid>/cmdline` names this invocation's own temporary
config. It is not yet covered *by* that test — see below.

## Still open

- **Statistical resolution of the rate test.** Test 65 at N = 800 resolves the configured
  probability to about ±0.06 and Test 68 to about ±0.018. Neither can detect a few-percent bias in
  the injector; that needs N ~ 10⁴ and a run measured in hours. The band in each test was chosen
  before the measurement and bounds the test's own false-failure rate, and is not a claim about how
  accurate the injector is.
- **Range endpoint inclusivity is proven, but only where it was tested.** Test 67's width-1 range
  `[3, 3]` matching exactly one sequence number, and Test 68's eight-way tiling summing to exactly
  2400, are strong evidence that TCAM range bounds are inclusive at both ends *on the model*. A
  specific off-by-one at an interior boundary of a two-entry Bernoulli tiling is not separable from
  chance by a random draw and was not attempted.
- **`run_ledger.sh` is not covered by `test_runner_contract.py`.** That test hard-codes
  `run_context_regressions.sh`. Parameterising it over every runner in `p4/ptf/model/` is a small
  change to a tracked test and was left out of this pass; the new runner was checked against the
  same two textual contracts by hand instead.
- **The reorder-credit window is still not implemented and was not tested.** Test 63 shows that
  advance-only stops a reorder from *manufacturing* loss. It does not show that a read taken while
  a reorder is outstanding is correct — Test 63's own trace makes the gap visible: between packets
  `0x3` and `0x4` the pair reads `hi = 4, lo = 3`, i.e. one apparent loss, which the later arrival
  then retires. Scoring that correctly is the controller-side debt/credit accounting flagged as an
  open item in `LEDGER-COMPILE-GATE.md` §3, and per this task's scope it was reported rather than
  implemented.
- **The duplicate case still needs a controller clamp.** Test 64 confirms `Δhi − Δlo = −1` against
  the compiled program. Nothing in the data plane can prevent it and nothing in the controller
  currently handles it.
- **The two downstream consumers `LEDGER-COMPILE-GATE.md` §3 called broken have since been
  reworked — that bullet in the gate report is now STALE — but nothing here tested them.**
  Checked against the current tree rather than carried over from the gate:
  `p4/hw/loop/gate_agent.py:90-101` now resolves `reg_rx_frontier` optionally and disables the
  `F`/`X`/`Z` commands with an explicit message when it is absent, instead of raising or silently
  applying the old `idx >> 8` bank decode; and `controller/hw_adapter.py:216-249` now documents
  the lifetime-counter semantics and hands `observed_packets` off to
  `p4/hw/loop/controller_loop.py`'s `--ledger` mode, which replaces it with an exact 32-bit census
  read (`resolve_ledger_gap_event`, `controller_loop.py:513`). None of that Python is exercised by
  this suite — controller code was explicitly out of scope for this pass — so "reworked" here means
  "read", not "verified". Their own tests are in the 334 below; an end-to-end check of the
  controller against a running ledger pipeline is still owed.
- **Two live queues on one port** stays a silicon check, inherited from `PTF-MODEL.md`: this suite
  uses qid 0 throughout and does not re-open that question.
- **Re-measurement on 9.13.2.** Everything here is 9.13.1. A model PASS is necessary, not
  sufficient — the model accepts control-plane writes the ASIC rejects, and the model's own
  `Random<bit<16>>` is not the silicon's. Silicon remains a separate step.

## Regression check on the rest of the local suite

```
$ python3 -m pytest controller/tests p4/control/tests p4/hw p4/witness p4/ptf/model -q
334 passed in 8.93s
```

Unchanged by this pass: the two files added here (`p4/ptf/test_ledger.py`,
`p4/ptf/model/run_ledger.sh`) are the only untracked additions and neither is collected by that
command — `p4/ptf/test_ledger.py` sits in `p4/ptf/`, not `p4/ptf/model/`, and needs the SDE's `ptf`
module, which is why it runs through `run_ledger.sh` instead. The five modules
`p4/ptf/test_{capsule,cw4_sublinks,fabric,health_gate,w4_witness}.py` remain uncollectable under
the system python for the same pre-existing reason (`ModuleNotFoundError: No module named 'ptf'`),
so the 334 does not cover them.
