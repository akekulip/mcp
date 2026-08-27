#!/usr/bin/env bash
# PREREG §3.2 equal-tuning-budget sweep on the tuning split (LULESH-128, seeds 6-10): 64 configs
# per arm, budgets 4 and 32; TTL from onset per run. Output: results_tuning/<arm>/<budget>/cfg<i>/seed<s>.csv
set -euo pipefail
G=$(cd "$(dirname "$0")" && pwd); S=$G/../htsim/htsim/sim; H=$S/datacenter; BR=$G/../../controller/sim_bridge.py
OUT=${OUT:-$G/results_tuning}; SEEDS=${SEEDS:-"6 7 8 9 10"}; BUDGETS=${BUDGETS:-"4 32"}; LOSS_P=${LOSS_P:-1e-3}
T=$(mktemp -d); mkfifo $T/o $T/a
run(){ local arm=$1 cfg=$2 budget=$3 seed=$4; shift 4; local d=$OUT/$arm/b$budget/cfg$cfg; mkdir -p $d
  [ -s $d/seed$seed.csv ] && return 0
  echo "$*" > $d/args
  local fault; fault=$(python3 -c "import random; r=random.Random($seed ^ 0x4641); a=r.randrange(32); c=a%4+4*r.randrange(4); print(f'AGG:{a}:{c}')")
  ( timeout 600 python3 $BR --obs $T/o --act $T/a --policy $arm --baseline-mode pooled "$@" >/dev/null 2>&1 & )
  ( ulimit -f 200000; timeout 600 $H/htsim_uec -topo $H/topologies/fat_tree_128_1os.topo -goal $G/../traces/lulesh_8/lulesh_8.bin -nodes 128 -linkspeed 100000 -mtu 4096 -paths 128 -strat ecmp_host -load_balancing_algo oblivious -q 1000000 -seed $seed -end 100000 -o /dev/null -rto_min_us 300 -mcp_rank_stride 16 -mcp_loss $fault:$LOSS_P -mcp_loss_onset_ms 500 -mcp_epoch_us 100000 -mcp_policy "extern:$T/o:$T/a" -mcp_budget $budget -mcp_log $d/seed$seed.csv.tmp > $d/seed$seed.log 2>&1 ) || true
  grep -q "Finished all" $d/seed$seed.log && mv $d/seed$seed.csv.tmp $d/seed$seed.csv || echo "FAILED $arm cfg$cfg b$budget seed$seed"
}
# 64 mcp configs: learner x alpha x explore_floor x ablation-free grid
i=0
for learner in linucb dlinucb swlinucb; do for alpha in 0 0.5 1 2; do for floor in 0 0.25 0.5 0.75; do
  i=$((i+1)); [ $i -gt 48 ] && break
  for b in $BUDGETS; do for s in $SEEDS; do run mcp $i $b $s --learner $learner --alpha $alpha --explore-floor $floor; done; done
done; done; done
# 16 more: no_context / reset ablations at the linucb alpha=1 point
for floor in 0 0.25 0.5 0.75; do for ab in no_context reset no_context,reset no_prices; do
  i=$((i+1)); for b in $BUDGETS; do for s in $SEEDS; do run mcp $i $b $s --learner linucb --alpha 1 --explore-floor $floor --ablation $ab; done; done
done; done
# cusum arm: its only knob is explore (64 values would be silly; PREREG allows fewer configs when the arm has fewer knobs — document)
j=0; for ex in 0 0.125 0.25 0.375 0.5 0.625 0.75 0.875 1.0; do j=$((j+1)); for b in $BUDGETS; do for s in $SEEDS; do run cusum $j $b $s --explore $ex; done; done; done
rm -rf $T; echo "tuning done: $(find $OUT -name 'seed*.csv' ! -name '*.bridge.csv' | wc -l) runs"
