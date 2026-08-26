#!/usr/bin/env bash
# PREREG §10 gate experiment — real configuration (1024-NIC fat tree, Mixtral-class MoE trace).
#   policy x seed -> results_real/<trace>/<policy>/seed<N>.csv   (the -mcp_log file)
# Designed to be run on Vision/Hulk with a slice of the seed range each:
#   SEEDS="$(seq 1000 1014)" JOBS=45 ./run_gate_real.sh      # Vision
#   SEEDS="$(seq 1015 1029)" JOBS=45 ./run_gate_real.sh      # Hulk
# Env overrides: TRACE, TOPO, NODES, LINKSPEED, STRIDE, END_MS, EPOCH_US, BUDGET, LOSS, POLICIES, RTO_MIN_US
set -euo pipefail
GATE=$(cd "$(dirname "$0")" && pwd)
S=$GATE/../htsim/htsim/sim
H=$S/datacenter
TRACE=${TRACE:-moe8x8b_n16}                       # sim/traces/<TRACE>/moe.bin (ATLAHS MoE8x8B_N16_GPU64, 64 ranks)
BIN=$GATE/../traces/$TRACE/moe.bin
TOPO=${TOPO:-$H/topologies/fat_tree_1024_1os.topo}  # 16 pods x 8 agg x 8 core = 1024 agg->core uplinks, 200G
NODES=${NODES:-1024}
LINKSPEED=${LINKSPEED:-200000}                    # Mbps, must match the topology file
STRIDE=${STRIDE:-16}                              # GOAL rank -> host stride: 64 ranks x 16 = all 16 pods
END_MS=${END_MS:-200000}                          # upper bound only; a run ends when the trace finishes
EPOCH_US=${EPOCH_US:-100000}                      # 100 ms measurement epochs (PREREG says 1 s; see WORKING_NOTES 2026-08-26)
BUDGET=${BUDGET:-20}                              # 2 % of 1024 uplinks
LOSS=${LOSS:-AGG:0:0:1e-4}                        # F1: silent 1e-4 Bernoulli loss on one spine uplink
ONSET_LO_MS=${ONSET_LO_MS:-300}                   # F1 onset ~ U[lo,hi] ms per seed (PREREG U[10,30] s of 120 s, scaled to the 3.5 s iteration)
ONSET_HI_MS=${ONSET_HI_MS:-900}
POLICIES=${POLICIES:-"uniform random oracle"}
SEEDS=${SEEDS:-$(seq 1000 1029)}
JOBS=${JOBS:-30}
RTO_MIN_US=${RTO_MIN_US:-300}                     # HURDLES H25
TIMEOUT=${TIMEOUT:-12h}
OUT=${OUT:-$GATE/results_real}

[ -s "$BIN" ] || { echo "missing trace $BIN" >&2; exit 1; }

one_run() {
    local policy=$1 seed=$2
    local out=$OUT/$TRACE/$policy
    mkdir -p "$out"
    [ -s "$out/seed$seed.csv" ] && return 0
    [ -e "$out/seed$seed.STALLED" ] && return 0
    # deterministic per-seed onset draw (recorded next to the result)
    local onset; onset=$(python3 -c "import random; r=random.Random($seed ^ 0x4d43); print(round(r.uniform($ONSET_LO_MS,$ONSET_HI_MS),1))")
    echo "$onset" > "$out/seed$seed.onset"
    ( ulimit -f 4000000; /usr/bin/time -f "wall_s=%e maxrss_kb=%M" -o "$out/seed$seed.time" \
      timeout "$TIMEOUT" "$H/htsim_uec" -topo "$TOPO" -goal "$BIN" -nodes "$NODES" \
        -linkspeed "$LINKSPEED" -mtu 4096 -paths "$NODES" -strat ecmp_host -load_balancing_algo oblivious \
        -q 1000000 -seed "$seed" -end "$END_MS" -o /dev/null -rto_min_us "$RTO_MIN_US" \
        -mcp_rank_stride "$STRIDE" -mcp_loss "$LOSS" -mcp_loss_onset_ms "$onset" -mcp_epoch_us "$EPOCH_US" \
        -mcp_policy "$policy" -mcp_budget "$BUDGET" -mcp_log "$out/seed$seed.csv.tmp" -mcp_counters "$out/seed$seed.counters.csv" \
        > "$out/seed$seed.log" 2>&1 ) || true
    if grep -q "Finished all" "$out/seed$seed.log"; then
        grep -o "Maximum finishing time.*" "$out/seed$seed.log" | head -1 > "$out/seed$seed.finish"
        # keep the log small: drop the per-event LGS chatter, keep drops/RTO/summary lines
        grep -v "^LGS \|^progress:" "$out/seed$seed.log" > "$out/seed$seed.log.small" && mv "$out/seed$seed.log.small" "$out/seed$seed.log"
        mv "$out/seed$seed.csv.tmp" "$out/seed$seed.csv"
    else
        tail -c 20000 "$out/seed$seed.log" > "$out/seed$seed.log.tail" && mv "$out/seed$seed.log.tail" "$out/seed$seed.log"
        echo "STALLED $(date -Is): no 'Finished all' within $TIMEOUT / 4 GB log" > "$out/seed$seed.STALLED"
        echo "STALLED $TRACE/$policy/seed$seed"
    fi
}
export -f one_run; export OUT TRACE BIN TOPO NODES LINKSPEED STRIDE END_MS EPOCH_US BUDGET LOSS ONSET_LO_MS ONSET_HI_MS RTO_MIN_US TIMEOUT H

{ for p in $POLICIES; do for s in $SEEDS; do echo "$p $s"; done; done; } \
  | xargs -P "$JOBS" -L 1 bash -c 'one_run "$@"' _
echo "gate-real runs done on $(hostname): $(find "$OUT" -name 'seed*.csv' | wc -l) result files"
