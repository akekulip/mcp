#!/usr/bin/env bash
# canary.sh — the T+60s check that CLAUDE.md's "monitor long runs" rule requires.
#
# It samples at T+0, waits, samples again, and kills the run loudly if any of six
# things is wrong.  Every check is written against the ARTEFACT the run produced,
# never against the command someone believes they typed:
#
#   1. FLAGS      the run LOG contains each intended flag.  Grepping the log, not the
#                 command line, is the whole point: `-mcp_loss` was on the command
#                 line and in the run log once and STILL did not do what the flag
#                 said (H32), so reading the log is the weakest check we will accept
#                 and reading the typed command is no check at all.
#   2. COUNTERS   tbl_vlink packet counters advanced between T+0 and T+wait.
#   3. CAPTURE    the capture file grew between T+0 and T+wait.
#   4. CONTROLLER the controller process is alive AND its CSV has rows AND the
#                 parsed-event column sums above zero.  Alive-but-parsing-nothing is
#                 the failure this catches: a controller that never fires is not a
#                 safe controller, it is a useless one.
#   5. RESOURCES  free RAM and free disk above floors (sim blocks here are memory
#                 bound; H26/H31 were both "we ran out" failures).
#   6. OWNERSHIP  `pgrep -x bf_switchd` returns exactly ONE pid and it is OURS.
#                 Two pids, or a different pid, means the chip changed hands mid-run
#                 and every number after that point is meaningless.
#
# On failure it kills the run — the controller pid, plus any --kill-pid — by EXACT
# PID.  It never uses `pkill -f` (H30) and never touches bf_switchd.
#
# Usage:
#   p4/hw/canary.sh --run-log PATH --expect FLAG [--expect FLAG ...] \
#                   --capture PATH --controller-pid N --controller-csv PATH \
#                   [--program NAME] [--wait 60] [--events-column n_samples] \
#                   [--capture-host user@host] [--switchd-pid N] \
#                   [--min-free-mb 2048] [--min-free-disk-gb 10] [--no-kill] [--dry-run]
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=p4/hw/common.sh
. "${HERE}/common.sh"
hw_open_narration

PROGRAM="mcp_fabric_gate_event"
RUN_LOG=""
CAPTURE=""
CAPTURE_HOST=""
CONTROLLER_PID=""
CONTROLLER_CSV=""
EVENTS_COLUMN="n_samples"
SWITCHD_PID=""
WAIT=60
MIN_FREE_MB=2048
MIN_FREE_DISK_GB=10
KILL_ON_FAIL=1
EXPECT=()
KILL_PIDS=()

while [ $# -gt 0 ]; do
    if hw_parse_common_flag "$1" "${2:-}"; then
        shift "$HW_SHIFT"
        continue
    fi
    case $1 in
        --program)          PROGRAM=${2:?};        shift 2 ;;
        --run-log)          RUN_LOG=${2:?};        shift 2 ;;
        --expect)           EXPECT+=("${2:?}");    shift 2 ;;
        --capture)          CAPTURE=${2:?};        shift 2 ;;
        --capture-host)     CAPTURE_HOST=${2:?};   shift 2 ;;
        --controller-pid)   CONTROLLER_PID=${2:?}; shift 2 ;;
        --controller-csv)   CONTROLLER_CSV=${2:?}; shift 2 ;;
        --events-column)    EVENTS_COLUMN=${2:?};  shift 2 ;;
        --switchd-pid)      SWITCHD_PID=${2:?};    shift 2 ;;
        --wait)             WAIT=${2:?};           shift 2 ;;
        --min-free-mb)      MIN_FREE_MB=${2:?};    shift 2 ;;
        --min-free-disk-gb) MIN_FREE_DISK_GB=${2:?}; shift 2 ;;
        --kill-pid)         KILL_PIDS+=("${2:?}"); shift 2 ;;
        --no-kill)          KILL_ON_FAIL=0;        shift ;;
        -h|--help)          sed -n '2,32p' "$0"; exit 0 ;;
        *)                  hw_die "unknown argument: $1" ;;
    esac
done

[ -n "$RUN_LOG" ]        || hw_die "--run-log is required (the canary greps the LOG, never the typed command)"
[ "${#EXPECT[@]}" -gt 0 ] || hw_die "--expect FLAG is required at least once"
[ -n "$CAPTURE" ]        || hw_die "--capture is required"
[ -n "$CONTROLLER_PID" ] || hw_die "--controller-pid is required"
[ -n "$CONTROLLER_CSV" ] || hw_die "--controller-csv is required"
CAPTURE_HOST=${CAPTURE_HOST:-$SWITCH}

if [ -z "$SWITCHD_PID" ] && [ -f "${ARTIFACT_DIR}/switchd.pid" ]; then
    SWITCHD_PID=$(tr -d '[:space:]' <"${ARTIFACT_DIR}/switchd.pid")
fi
[ -n "$SWITCHD_PID" ] || hw_die "--switchd-pid not given and ${ARTIFACT_DIR}/switchd.pid absent; bringup.sh records it"

hw_banner "canary (T+${WAIT}s)"
hw_info "program        : ${PROGRAM}"
hw_info "run log        : ${RUN_LOG}"
hw_info "expected flags : ${EXPECT[*]}"
hw_info "capture        : ${CAPTURE_HOST}:${CAPTURE}"
hw_info "controller     : pid ${CONTROLLER_PID}, csv ${CONTROLLER_CSV}, column ${EVENTS_COLUMN}"
hw_info "our bf_switchd : pid ${SWITCHD_PID}"
hw_info "floors         : ${MIN_FREE_MB} MB RAM, ${MIN_FREE_DISK_GB} GB disk"

# The remote sampler.  One round trip produces every number the checks need, so the
# T+0 and T+wait samples are strictly comparable.
sample() {
    hw_ssh_script "sample $1" <<EOF
set -u
export SDE='${SDE}'
export SDE_INSTALL='${SDE_INSTALL}'
export LD_LIBRARY_PATH="\$SDE_INSTALL/lib"
P="\$SDE_INSTALL/lib/python3.8/site-packages"
export PYTHONPATH="\$P/tofino:\$P/tofino/bfrt_grpc:\$P"
cd '${REMOTE_DIR}'
pkts=\$(python3 setup_skeleton.py --program '${PROGRAM}' counters --json 2>/dev/null \
       | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(int(v["pkts"]) for v in d.get("vlink_totals",{}).values()))' 2>/dev/null || echo -1)
echo "vlink_pkts=\${pkts}"
echo "switchd_pids=\$(pgrep -x bf_switchd | tr '\n' ',' )"
echo "controller_alive=\$(kill -0 ${CONTROLLER_PID} 2>/dev/null && echo 1 || echo 0)"
echo "csv_rows=\$(( \$(wc -l < '${CONTROLLER_CSV}' 2>/dev/null || echo 1) - 1 ))"
echo "events=\$(python3 - '${CONTROLLER_CSV}' '${EVENTS_COLUMN}' <<'PY'
import csv, sys
try:
    with open(sys.argv[1]) as fh:
        print(sum(int(float(r[sys.argv[2]] or 0)) for r in csv.DictReader(fh)))
except Exception:
    print(-1)
PY
)"
echo "free_mb=\$(free -m | awk '/^Mem:/{print \$7}')"
echo "free_disk_gb=\$(df -BG --output=avail /home | tail -1 | tr -dc '0-9')"
EOF
}

sample_capture() {
    hw_ssh_script_on "$CAPTURE_HOST" "capture size $1" <<EOF
set -u
echo "capture_bytes=\$(stat -c %s '${CAPTURE}' 2>/dev/null || echo -1)"
EOF
}

# ------------------------------------------------------------------ flags, from the LOG
hw_step "check 1 — the intended flags are in the LOG (never the typed command line)"
LOGGREP=$(hw_ssh_script "grep run log for flags" <<EOF
set -u
if [ ! -f '${RUN_LOG}' ]; then echo "log_missing=1"; exit 0; fi
echo "log_missing=0"
$(for f in "${EXPECT[@]}"; do
    printf "echo \"flag:%s=\$(grep -c -- '%s' '%s' || true)\"\n" "$f" "$f" "$RUN_LOG"
done)
EOF
)
if is_dry; then
    hw_say "[dry-run] would then require log_missing=0 and every flag count >= 1."
else
    printf '%s\n' "$LOGGREP" | sed 's/^/   /'
fi

# ------------------------------------------------------------------ T+0
hw_step "check 2-6 — sample at T+0"
S0=$(sample "T+0")
C0=$(sample_capture "T+0")
if is_dry; then
    hw_say "[dry-run] would then sleep ${WAIT}s and take an identical second sample."
else
    printf '%s\n%s\n' "$S0" "$C0" | sed 's/^/   /'
    sleep "$WAIT"
fi

hw_step "sample at T+${WAIT}"
S1=$(sample "T+${WAIT}")
C1=$(sample_capture "T+${WAIT}")

if is_dry; then
    hw_say ""
    hw_say "[dry-run] the six verdicts that would then be computed:"
    hw_say "[dry-run]   1 FLAGS      every --expect flag appears at least once in ${RUN_LOG}"
    hw_say "[dry-run]   2 COUNTERS   vlink_pkts(T+${WAIT}) > vlink_pkts(T+0)"
    hw_say "[dry-run]   3 CAPTURE    capture_bytes(T+${WAIT}) > capture_bytes(T+0)"
    hw_say "[dry-run]   4 CONTROLLER controller_alive=1 AND csv_rows>0 AND events>0"
    hw_say "[dry-run]   5 RESOURCES  free_mb >= ${MIN_FREE_MB} AND free_disk_gb >= ${MIN_FREE_DISK_GB}"
    hw_say "[dry-run]   6 OWNERSHIP  exactly ONE bf_switchd pid, and it equals ${SWITCHD_PID}"
    hw_say "[dry-run] on ANY failure: print the failing check loudly, kill pid ${CONTROLLER_PID} ${KILL_PIDS[*]:-}"
    hw_say "[dry-run] by EXACT pid (never pkill -f, H30), never touch bf_switchd, and exit 1."
    hw_step "done"
    hw_info "[dry-run] nothing was executed: no ssh, no scp, no local write."
    exit 0
fi

printf '%s\n%s\n' "$S1" "$C1" | sed 's/^/   /'

field() { printf '%s\n' "$2" | awk -F= -v k="$1" '$1==k {print $2}'; }

FAILED=()

# 1 flags
if [ "$(field log_missing "$LOGGREP")" != "0" ]; then
    FAILED+=("FLAGS: run log ${RUN_LOG} does not exist")
else
    for f in "${EXPECT[@]}"; do
        n=$(printf '%s\n' "$LOGGREP" | awk -F= -v k="flag:$f" '$1==k {print $2}')
        if [ "${n:-0}" -lt 1 ]; then
            FAILED+=("FLAGS: '${f}' never appears in ${RUN_LOG} — the run is not the run you think it is")
        fi
    done
fi

# 2 counters
p0=$(field vlink_pkts "$S0"); p1=$(field vlink_pkts "$S1")
hw_info "counters: ${p0} -> ${p1}"
if [ "${p0}" = "-1" ] || [ "${p1}" = "-1" ]; then
    FAILED+=("COUNTERS: could not read tbl_vlink counters at all")
elif [ "$p1" -le "$p0" ]; then
    FAILED+=("COUNTERS: vlink packets did not advance (${p0} -> ${p1}) — no traffic is reaching the fabric")
fi

# 3 capture
b0=$(field capture_bytes "$C0"); b1=$(field capture_bytes "$C1")
hw_info "capture bytes: ${b0} -> ${b1}"
if [ "${b0}" = "-1" ] || [ "${b1}" = "-1" ]; then
    FAILED+=("CAPTURE: ${CAPTURE_HOST}:${CAPTURE} does not exist")
elif [ "$b1" -le "$b0" ]; then
    FAILED+=("CAPTURE: ${CAPTURE} did not grow (${b0} -> ${b1} bytes)")
fi

# 4 controller
alive=$(field controller_alive "$S1")
rows=$(field csv_rows "$S1")
events=$(field events "$S1")
hw_info "controller: alive=${alive} csv_rows=${rows} ${EVENTS_COLUMN}_sum=${events}"
[ "$alive" = "1" ]        || FAILED+=("CONTROLLER: pid ${CONTROLLER_PID} is not alive")
[ "${rows:-0}" -gt 0 ]    || FAILED+=("CONTROLLER: ${CONTROLLER_CSV} has no data rows")
[ "${events:-0}" -gt 0 ]  || FAILED+=("CONTROLLER: ${EVENTS_COLUMN} sums to ${events} — the controller is alive but parsing nothing")

# 5 resources
fm=$(field free_mb "$S1"); fd=$(field free_disk_gb "$S1")
hw_info "resources: ${fm} MB RAM free, ${fd} GB disk free"
[ "${fm:-0}" -ge "$MIN_FREE_MB" ]      || FAILED+=("RESOURCES: only ${fm} MB RAM free (floor ${MIN_FREE_MB})")
[ "${fd:-0}" -ge "$MIN_FREE_DISK_GB" ] || FAILED+=("RESOURCES: only ${fd} GB disk free (floor ${MIN_FREE_DISK_GB})")

# 6 ownership
pids=$(field switchd_pids "$S1"); pids=${pids%,}
n_pids=0
[ -n "$pids" ] && n_pids=$(printf '%s\n' "$pids" | tr ',' '\n' | grep -c .)
hw_info "bf_switchd pids: '${pids}' (n=${n_pids}), ours=${SWITCHD_PID}"
if [ "$n_pids" -ne 1 ]; then
    FAILED+=("OWNERSHIP: expected exactly ONE bf_switchd, found ${n_pids} ('${pids}')")
elif [ "$pids" != "$SWITCHD_PID" ]; then
    FAILED+=("OWNERSHIP: bf_switchd pid is ${pids}, not ours (${SWITCHD_PID}) — the chip changed hands mid-run")
fi

# ------------------------------------------------------------------ verdict
hw_step "verdict"
if [ "${#FAILED[@]}" -eq 0 ]; then
    hw_pass "all six checks passed at T+${WAIT}s — the run may be left to continue"
    exit 0
fi

printf '\n'
printf '################################################################\n' >&2
printf '## CANARY FAILED — %d check(s).  KILLING THE RUN.\n' "${#FAILED[@]}" >&2
for m in "${FAILED[@]}"; do printf '##   %s\n' "$m" >&2; done
printf '################################################################\n' >&2

if [ "$KILL_ON_FAIL" = 1 ]; then
    hw_ssh_script "kill the run by exact pid" <<EOF
set -u
# Exact pids only.  'pkill -f' would match this ssh command line and kill the
# session (H30), and bf_switchd is never touched by the canary.
for p in ${CONTROLLER_PID} ${KILL_PIDS[*]:-}; do
    echo "kill \$p (\$(ps -o comm= -p "\$p" 2>/dev/null || echo gone))"
    kill "\$p" 2>/dev/null || true
done
sleep 2
echo "still alive: \$(for p in ${CONTROLLER_PID} ${KILL_PIDS[*]:-}; do kill -0 \$p 2>/dev/null && echo -n "\$p "; done)"
EOF
else
    hw_warn "--no-kill given: the run is left running despite the failure"
fi
exit 1
