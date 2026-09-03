#!/usr/bin/env bash
# Make-or-break app-impact chain driver (one htsim at a time; ~21.5 GB/run).
# CLEAN is already running externally. This waits for it, then runs DO-NOTHING @ rto40,
# self-verifies the injected flags reached the log, computes the CCT gap, and if the gap
# > 5% brackets with DO-NOTHING @ rto10. All echoes also go to PROG for live inspection.
set -uo pipefail
cd /home/philip/Projects/mcp
GATE=sim/gate
RUN=$GATE/run_gate_real.sh
BASE=$GATE/results_makebreak
PROG=$BASE/chain.progress.log
: > "$PROG"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$PROG"; }

ps_of(){ awk -F'[:()]' '/Maximum finishing time/{print $2}' "$1" | tr -dc '0-9'; }  # picoseconds

wait_free_ram(){ while pgrep -x htsim_uec >/dev/null; do sleep 10; done; }

# generic: run one arm via run_gate_real.sh, self-verify flags, wait for finish
# args: outdir fault(0|1) loss rto expect_grep(regex that MUST appear in log)
run_arm(){
  local out=$1 fault=$2 loss=$3 rto=$4 expect=$5
  local D=$out/moe8x8b_n16/uniform
  if [ -s "$D/seed1000.finish" ]; then log "SKIP $(basename $out): already has .finish"; return 0; fi
  wait_free_ram
  log "LAUNCH $(basename $out): fault=$fault loss='${loss:-none}' rto=$rto"
  ( FAULT=$fault LOSS="$loss" POLICIES=uniform SEEDS=1000 JOBS=1 RTO_MIN_US=$rto \
      TIMEOUT=2h OUT="$out" bash "$RUN" > "$out.driver.log" 2>&1 ) &
  # self-verify flags within 150s
  local ok="" i
  for i in $(seq 1 30); do
    sleep 5
    [ -f "$D/seed1000.log" ] || continue
    if grep -qE "$expect" "$D/seed1000.log"; then ok=1; break; fi
  done
  if [ -z "$ok" ]; then
    log "ABORT $(basename $out): expected flags /$expect/ NOT in log after 150s — killing htsim"
    grep -E "Setting min RTO|MCP policy|MCP silent|MCP background" "$D/seed1000.log" 2>/dev/null | sed 's/^/    LOG: /' | tee -a "$PROG"
    pkill -x htsim_uec
    return 1
  fi
  log "FLAGS OK $(basename $out):"
  grep -E "Setting min RTO|MCP policy|MCP silent|MCP background" "$D/seed1000.log" | sed 's/^/    /' | tee -a "$PROG"
  # wait for finish / stall / death
  until [ -s "$D/seed1000.finish" ] || [ -e "$D/seed1000.STALLED" ] || ! pgrep -x htsim_uec >/dev/null; do sleep 20; done
  sleep 2
  if [ -s "$D/seed1000.finish" ]; then
    log "DONE $(basename $out): $(cat $D/seed1000.finish)  [$(grep -o 'wall_s=[0-9.]*' $D/seed1000.time 2>/dev/null)]"
    return 0
  else
    log "FAIL $(basename $out): no .finish"; [ -e "$D/seed1000.STALLED" ] && cat "$D/seed1000.STALLED" | tee -a "$PROG"
    return 1
  fi
}

# --- 1. wait for CLEAN (launched externally) ---
CLEAN=$BASE/clean_rto40/moe8x8b_n16/uniform
log "waiting for CLEAN .finish ..."
until [ -s "$CLEAN/seed1000.finish" ] || [ -e "$CLEAN/seed1000.STALLED" ]; do sleep 20; done
[ -s "$CLEAN/seed1000.finish" ] || { log "CLEAN did not finish; aborting chain"; exit 1; }
CLEAN_PS=$(ps_of "$CLEAN/seed1000.finish")
log "CLEAN done: ${CLEAN_PS} ps = $(cat $CLEAN/seed1000.finish)"

# --- 2. DO-NOTHING @ rto40 (fault US41->CS1 1e-3) ---
run_arm "$BASE/donothing_rto40" 1 "AGG:41:1:1e-3" 40000 \
  "MCP silent loss p=0.001 on US41->CS1 onset_ms=381.7" || { log "DO-NOTHING rto40 failed"; exit 1; }
DN40=$BASE/donothing_rto40/moe8x8b_n16/uniform
DN40_PS=$(ps_of "$DN40/seed1000.finish")

# --- 3. gap ---
GAP=$(python3 -c "c=$CLEAN_PS; d=$DN40_PS; print(f'{100*(d-c)/c:.3f}')")
log "GAP rto40: CLEAN=$CLEAN_PS DO-NOTHING=$DN40_PS -> slowdown ${GAP}%"

# --- 4. conditional rto10 bracket ---
DN10_PS=""
if python3 -c "import sys; sys.exit(0 if $GAP>5.0 else 1)"; then
  log "gap>5% -> bracketing with DO-NOTHING @ rto10"
  run_arm "$BASE/donothing_rto10" 1 "AGG:41:1:1e-3" 10000 \
    "MCP silent loss p=0.001 on US41->CS1 onset_ms=381.7" && \
    DN10_PS=$(ps_of "$BASE/donothing_rto10/moe8x8b_n16/uniform/seed1000.finish")
  [ -n "$DN10_PS" ] && log "GAP rto10: $(python3 -c "c=$CLEAN_PS; d=$DN10_PS; print(f'{100*(d-c)/c:.3f}')")%"
else
  log "gap<=5% -> skipping rto10 bracket (NULL regime)"
fi

# --- 5. summary ---
{
  echo "=== MAKE-OR-BREAK SUMMARY ($(date -Is)) ==="
  echo "fault link: US41->CS1  p=1e-3  onset=381.7ms  seed=1000  (denominator: 4,805,187 pkt healthy)"
  echo "CLEAN     rto40  : $CLEAN_PS ps"
  echo "DO-NOTHING rto40 : $DN40_PS ps  gap=${GAP}%"
  [ -n "$DN10_PS" ] && echo "DO-NOTHING rto10 : $DN10_PS ps  gap=$(python3 -c "c=$CLEAN_PS;d=$DN10_PS;print(f'{100*(d-c)/c:.3f}')")%"
  if python3 -c "import sys; sys.exit(0 if $GAP>5.0 else 1)"; then echo "VERDICT: PROCEED (>5% recoverable slowdown at tau=40ms)"; else echo "VERDICT: NULL (pipeline-hidden at tau=40ms)"; fi
} | tee -a "$PROG" > "$BASE/SUMMARY.txt"
cat "$BASE/SUMMARY.txt"
log "CHAIN COMPLETE"
