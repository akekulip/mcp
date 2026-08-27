#!/usr/bin/env bash
# Tier-1 co-simulation at the FROZEN operating point (PREREG §14, 2026-08-27): MoE-64 on the
# 1024-NIC fat tree, 100 ms epochs, budget 41, F1 1e-4 on a per-seed random uplink, onset
# U[300,900] ms — arms driven by controller/sim_bridge.py (mcp | cusum). Same seeds/faults/onsets as
# run_gate_real.sh so results are paired with the uniform/random/oracle gate runs.
#   SEEDS="$(seq 1000 1014)" JOBS=10 ARMS="mcp cusum" ./run_tier1_cosim.sh
set -euo pipefail
GATE=$(cd "$(dirname "$0")" && pwd); S=$GATE/../htsim/htsim/sim; H=$S/datacenter; BR=$GATE/../../controller/sim_bridge.py
TRACE=${TRACE:-moe8x8b_n16}; BIN=$GATE/../traces/$TRACE/moe.bin; TOPO=$H/topologies/fat_tree_1024_1os.topo
EPOCH_US=${EPOCH_US:-100000}; BUDGET=${BUDGET:-41}; LOSS_P=${LOSS_P:-1e-4}; NAGG=128
ONSET_LO_MS=${ONSET_LO_MS:-300}; ONSET_HI_MS=${ONSET_HI_MS:-900}; RTO_MIN_US=${RTO_MIN_US:-300}
ARMS=${ARMS:-"mcp cusum"}; SEEDS=${SEEDS:-$(seq 1000 1029)}; JOBS=${JOBS:-10}; TIMEOUT=${TIMEOUT:-6h}
OUT=${OUT:-$GATE/results_tier1_cosim}
MCP_ARGS=${MCP_ARGS:-"--learner dlinucb --alpha 0 --explore-floor 0.75"}   # LULESH-tuned (pilot); Tier-1 tuning pending
CUSUM_ARGS=${CUSUM_ARGS:-"--explore 0"}
one_run() {
    local arm=$1 seed=$2; local out=$OUT/$TRACE/$arm; mkdir -p "$out"
    [ -s "$out/seed$seed.csv" ] && return 0
    [ -e "$out/seed$seed.STALLED" ] && return 0
    local onset; onset=$(python3 -c "import random; r=random.Random($seed ^ 0x4d43); print(round(r.uniform($ONSET_LO_MS,$ONSET_HI_MS),1))")
    local loss; loss=$(python3 -c "import random; r=random.Random($seed ^ 0x4641); a=r.randrange($NAGG); c=a%8+8*r.randrange(8); print(f'AGG:{a}:{c}:$LOSS_P')")
    echo "$onset" > "$out/seed$seed.onset"; echo "$loss" | awk -F: '{print "US"$2"->CS"$3}' > "$out/seed$seed.fault"
    local T; T=$(mktemp -d); mkfifo $T/o $T/a
    local args; [ "$arm" = mcp ] && args="$MCP_ARGS" || args="$CUSUM_ARGS"
    ( timeout "$TIMEOUT" python3 "$BR" --obs $T/o --act $T/a --policy "$arm" --baseline-mode pooled --epoch-us $EPOCH_US $args --log "$out/seed$seed.bridge.csv" > "$out/seed$seed.bridge.log" 2>&1 & )
    ( ulimit -f 4000000; /usr/bin/time -f "wall_s=%e maxrss_kb=%M" -o "$out/seed$seed.time" \
      timeout "$TIMEOUT" "$H/htsim_uec" -topo "$TOPO" -goal "$BIN" -nodes 1024 -linkspeed 200000 -mtu 4096 -paths 1024 \
        -strat ecmp_host -load_balancing_algo oblivious -q 1000000 -seed "$seed" -end 200000 -o /dev/null -rto_min_us "$RTO_MIN_US" \
        -mcp_rank_stride 16 -mcp_loss "$loss" -mcp_loss_onset_ms "$onset" -mcp_epoch_us "$EPOCH_US" \
        -mcp_policy "extern:$T/o:$T/a" -mcp_budget "$BUDGET" -mcp_log "$out/seed$seed.csv.tmp" -mcp_counters "$out/seed$seed.counters.csv" \
        > "$out/seed$seed.log" 2>&1 ) || true
    rm -rf "$T"
    if grep -q "Finished all" "$out/seed$seed.log"; then
        grep -o "Maximum finishing time.*" "$out/seed$seed.log" | head -1 > "$out/seed$seed.finish"
        grep -v "^LGS \|^progress:" "$out/seed$seed.log" > "$out/seed$seed.log.small" && mv "$out/seed$seed.log.small" "$out/seed$seed.log"
        mv "$out/seed$seed.csv.tmp" "$out/seed$seed.csv"
    else
        tail -c 20000 "$out/seed$seed.log" > "$out/seed$seed.log.tail" && mv "$out/seed$seed.log.tail" "$out/seed$seed.log"
        echo "STALLED $(date -Is)" > "$out/seed$seed.STALLED"; echo "STALLED $arm/seed$seed"
    fi
}
export -f one_run; export OUT TRACE BIN TOPO EPOCH_US BUDGET LOSS_P NAGG ONSET_LO_MS ONSET_HI_MS RTO_MIN_US TIMEOUT H BR MCP_ARGS CUSUM_ARGS
{ for a in $ARMS; do for s in $SEEDS; do echo "$a $s"; done; done; } | xargs -P "$JOBS" -L 1 bash -c 'one_run "$@"' _
echo "tier1 cosim done on $(hostname): $(find "$OUT" -name 'seed*.csv' ! -name '*.counters.csv' ! -name '*.bridge.csv' | wc -l) result files"
