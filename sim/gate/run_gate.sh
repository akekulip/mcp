#!/usr/bin/env bash
# PREREG §10 gate experiment on the htsim mcp-hooks branch.
#   trace x policy x seed -> results/<trace>/<policy>/seed<N>.csv  (the -mcp_log file)
# Env overrides: SEEDS="1 2 3", LULESH_SEEDS="1 2", JOBS=16, POLICIES="uniform random oracle"
set -euo pipefail
GATE=$(cd "$(dirname "$0")" && pwd)
S=$GATE/../htsim/htsim/sim
H=$S/datacenter
TOPO=$H/topologies/fat_tree_128_1os.topo
LOSS=${LOSS:-AGG:0:0:1e-4}        # one spine uplink, silent 1e-4 Bernoulli loss
EPOCH_US=${EPOCH_US:-100}
BUDGET=${BUDGET:-4}               # of 128 agg->core uplinks
POLICIES=${POLICIES:-"uniform random oracle"}
SEEDS=${SEEDS:-$(seq 1 30)}
LULESH_SEEDS=${LULESH_SEEDS:-$(seq 1 5)}   # LULESH is ~1 min wall per run (measured 2026-08-26); 5 seeds by default
JOBS=${JOBS:-15}
# -q 1e6 pkts makes htsim's queue-derived min RTO ~2 s (> -end), which disables retransmission of
# silently lost data (stall on incast seeds 11/26, 2026-08-26). Override to a sane value.
RTO_MIN_US=${RTO_MIN_US:-300}

INCAST_BIN=$GATE/incast_8_1_2MiB.bin
[ -f "$INCAST_BIN" ] || "$S/lgs/txt2bin" -i "$S/lgs/incast_8_1_2MiB.goal" -o "$INCAST_BIN"
LULESH_BIN=$GATE/../traces/lulesh_8/lulesh_8.bin

# trace name, bin, rank stride (spreads GOAL ranks across pods so traffic crosses the spine), -end (ms)
one_run() {
    local trace=$1 bin=$2 stride=$3 end_ms=$4 policy=$5 seed=$6
    local out=$GATE/results/$trace/$policy
    mkdir -p "$out"
    [ -s "$out/seed$seed.csv" ] && return 0
    [ -e "$out/seed$seed.STALLED" ] && return 0
    # Guard: if a flow never completes before -end, the GOAL loop spins forever printing
    # "progress:" (seen for incast seeds 11/26 -> 6.5 GB log in 5 min). Cap wall time and
    # log size (ulimit -f is in 1 KiB blocks -> 512 MiB) and record the seed as STALLED.
    local to; [ "$trace" = incast ] && to=20m || to=4h
    ( ulimit -f 524288; timeout "$to" "$H/htsim_uec" -topo "$TOPO" -goal "$bin" -nodes 128 \
        -linkspeed 100000 -mtu 4096 -paths 128 -strat ecmp_host -load_balancing_algo oblivious \
        -q 1000000 -seed "$seed" -end "$end_ms" -o /dev/null -rto_min_us "$RTO_MIN_US" \
        -mcp_rank_stride "$stride" -mcp_loss "$LOSS" -mcp_epoch_us "$EPOCH_US" \
        -mcp_policy "$policy" -mcp_budget "$BUDGET" -mcp_log "$out/seed$seed.csv.tmp" \
        > "$out/seed$seed.log" 2>&1 ) || true
    if grep -q "Finished all" "$out/seed$seed.log"; then
        mv "$out/seed$seed.csv.tmp" "$out/seed$seed.csv"
    else
        # keep the measurement log up to the stall, shrink the runaway stdout log
        tail -c 20000 "$out/seed$seed.log" > "$out/seed$seed.log.tail" && mv "$out/seed$seed.log.tail" "$out/seed$seed.log"
        echo "STALLED $(date -Is): no 'Finished all' within $to / 512MiB log" > "$out/seed$seed.STALLED"
        echo "STALLED $trace/$policy/seed$seed"
    fi
}
export -f one_run; export GATE S H TOPO LOSS EPOCH_US BUDGET RTO_MIN_US

{
    for p in $POLICIES; do for s in $SEEDS; do echo "incast $INCAST_BIN 8 1000 $p $s"; done; done
    for p in $POLICIES; do for s in $LULESH_SEEDS; do echo "lulesh $LULESH_BIN 16 100000 $p $s"; done; done
} | xargs -P "$JOBS" -L 1 bash -c 'one_run "$@"' _
echo "gate runs done: $(find "$GATE/results" -name 'seed*.csv' | wc -l) result files"
