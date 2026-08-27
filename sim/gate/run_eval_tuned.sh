#!/usr/bin/env bash
# Evaluation split (seeds 1-5) with the §3.2-tuned configurations from conf/tuned/*.yaml.
set -euo pipefail
G=$(cd "$(dirname "$0")" && pwd); S=$G/../htsim/htsim/sim; H=$S/datacenter; BR=$G/../../controller/sim_bridge.py; CONF=$G/../../conf/tuned
OUT=${OUT:-$G/results_eval_tuned}; SEEDS=${SEEDS:-"1 2 3 4 5"}; BUDGETS=${BUDGETS:-"4 32"}; LOSS_P=${LOSS_P:-1e-3}
T=$(mktemp -d); mkfifo $T/o $T/a
tuned_args(){ python3 - "$1" "$2" <<PY
import sys,re
arm,b=sys.argv[1],sys.argv[2]; txt=open("$CONF/%s.yaml"%arm).read()
m=re.search(r"b%s:\n  cfg: \S+\n  args: \"([^\"]*)\""%b, txt); print(m.group(1) if m else "")
PY
}
run(){ local arm=$1 seed=$2 budget=$3 policy=$4 bridge=$5; shift 5; local d=$OUT/b$budget/$arm; mkdir -p $d
  [ -s $d/seed$seed.csv ] && return 0
  local fault; fault=$(python3 -c "import random; r=random.Random($seed ^ 0x4641); a=r.randrange(32); c=a%4+4*r.randrange(4); print(f'AGG:{a}:{c}')")
  echo "US${fault#AGG:}" | sed 's/:/->CS/' > $d/seed$seed.fault
  [ -n "$bridge" ] && ( timeout 600 python3 $BR --obs $T/o --act $T/a --policy $bridge --baseline-mode pooled "$@" --log $d/seed$seed.bridge.csv >/dev/null 2>&1 & )
  ( ulimit -f 200000; timeout 600 $H/htsim_uec -topo $H/topologies/fat_tree_128_1os.topo -goal $G/../traces/lulesh_8/lulesh_8.bin -nodes 128 -linkspeed 100000 -mtu 4096 -paths 128 -strat ecmp_host -load_balancing_algo oblivious -q 1000000 -seed $seed -end 100000 -o /dev/null -rto_min_us 300 -mcp_rank_stride 16 -mcp_loss $fault:$LOSS_P -mcp_loss_onset_ms 500 -mcp_epoch_us 100000 -mcp_policy "$policy" -mcp_budget $budget -mcp_log $d/seed$seed.csv.tmp > $d/seed$seed.log 2>&1 ) || true
  grep -q "Finished all" $d/seed$seed.log && mv $d/seed$seed.csv.tmp $d/seed$seed.csv || echo "FAILED $arm b$budget seed$seed"
}
for b in $BUDGETS; do for s in $SEEDS; do
  run uniform $s $b uniform ""
  run random  $s $b random ""
  run cusum   $s $b "extern:$T/o:$T/a" cusum $(tuned_args cusum $b)
  run mcp     $s $b "extern:$T/o:$T/a" mcp   $(tuned_args mcp $b)
done; done
rm -rf $T; echo "eval done: $(find $OUT -name 'seed*.csv' ! -name '*.bridge.csv' | wc -l) runs"
