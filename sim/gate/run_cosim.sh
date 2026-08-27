#!/usr/bin/env bash
# Co-simulation mini-gate: LULESH-8 on the 128-node fat tree, F1 1e-3 on one uplink with onset
# 500 ms, epoch 100 ms; arms = C++ uniform | bridge cusum | bridge mcp (pooled localizer).
#   SEEDS="1 2 3" BUDGETS="4 32" ./run_cosim.sh
set -euo pipefail
G=$(cd "$(dirname "$0")" && pwd); S=$G/../htsim/htsim/sim; H=$S/datacenter; BR=$G/../../controller/sim_bridge.py
OUT=${OUT:-$G/results_cosim}; SEEDS=${SEEDS:-"1 2 3 4 5"}; BUDGETS=${BUDGETS:-"4 32"}; LOSS_P=${LOSS_P:-1e-3}; BG_LOSS=${BG_LOSS:-0}
T=$(mktemp -d); mkfifo $T/o $T/a
one(){ local arm=$1 seed=$2 budget=$3 policy=$4 bridge=$5; local d=$OUT/b$budget/$arm; mkdir -p $d
  [ -s $d/seed$seed.csv ] && return 0
  local fault; fault=$(python3 -c "import random; r=random.Random($seed ^ 0x4641); a=r.randrange(32); c=a%4+4*r.randrange(4); print(f'AGG:{a}:{c}')")
  echo "US${fault#AGG:}" | sed 's/:/->CS/' > $d/seed$seed.fault
  [ -n "$bridge" ] && ( timeout 600 python3 $BR --obs $T/o --act $T/a --policy $bridge --baseline-mode pooled --log $d/seed$seed.bridge.csv >/dev/null 2>&1 & )
  ( ulimit -f 200000; timeout 600 $H/htsim_uec -topo $H/topologies/fat_tree_128_1os.topo -goal $G/../traces/lulesh_8/lulesh_8.bin -nodes 128 -linkspeed 100000 -mtu 4096 -paths 128 -strat ecmp_host -load_balancing_algo oblivious -q 1000000 -seed $seed -end 100000 -o /dev/null -rto_min_us 300 -mcp_rank_stride 16 -mcp_bg_loss $BG_LOSS -mcp_loss $fault:$LOSS_P -mcp_loss_onset_ms 500 -mcp_epoch_us 100000 -mcp_policy "$policy" -mcp_budget $budget -mcp_log $d/seed$seed.csv.tmp > $d/seed$seed.log 2>&1 ) || true
  grep -q "Finished all" $d/seed$seed.log && mv $d/seed$seed.csv.tmp $d/seed$seed.csv || echo "FAILED $arm b$budget seed$seed"
}
for b in $BUDGETS; do for s in $SEEDS; do
  one uniform $s $b uniform ""
  one cusum   $s $b "extern:$T/o:$T/a" cusum
  one mcp     $s $b "extern:$T/o:$T/a" mcp
done; done
rm -rf $T; echo "cosim done: $(find $OUT -name 'seed*.csv' | wc -l) runs"
