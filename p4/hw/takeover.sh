#!/usr/bin/env bash
# takeover.sh — take the shared Tofino away from whatever program currently owns it,
# safely and reversibly.
#
# Philip authorised displacing the sibling program `defense4_rrc_bor_unified12` and
# did NOT ask for it to be restored.  He did not authorise a reboot, and this script
# never reboots anything.
#
# The order matters and is not negotiable:
#
#   1. ENUMERATE every auto-restart path and PRINT it — systemd units and their
#      is-enabled state, systemd timers, the user AND root crontabs, /etc/cron.d,
#      /etc/crontab, tmux and screen sessions.  Anything that can bring bf_switchd
#      back is a landmine, and the only defence is to see it before stepping.
#   2. SNAPSHOT the running program to a LOCAL file BEFORE anything is stopped:
#      pid, full command line, cwd, the --conf-file path and its contents, the
#      parent chain, and the port table as ucli sees it.  Once bf_switchd is gone
#      that information is unrecoverable, and the sibling project may want it.
#   3. STOP the LAUNCHER first, then bf_switchd (H31: killing a child that a wrapper
#      supervises just gets it respawned).  Both are killed by exact PID or with
#      `pkill -x`.  NEVER `pkill -f` — the pattern matches this very SSH session's
#      own command line and kills the session (H30).
#   4. RE-CHECK TWICE, 30 s apart.  A respawn that lands between two checks is the
#      whole point of the second one.  If anything comes back, STOP and report which
#      restart path was missed.  Do NOT escalate to `kill -9` blindly — an unseen
#      supervisor will simply respawn again, and -9 loses the chance to find it.
#
# Usage:
#   p4/hw/takeover.sh [--dry-run] [--switch user@host] [--settle-secs N]
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=p4/hw/common.sh
. "${HERE}/common.sh"
hw_open_narration

SETTLE=30
while [ $# -gt 0 ]; do
    if hw_parse_common_flag "$1" "${2:-}"; then
        shift "$HW_SHIFT"
        continue
    fi
    case $1 in
        --settle-secs) SETTLE=${2:?--settle-secs needs a value}; shift 2 ;;
        -h|--help)     sed -n '2,30p' "$0"; exit 0 ;;
        *)             hw_die "unknown argument: $1" ;;
    esac
done

hw_banner "takeover"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
SNAP="${SNAPSHOT_DIR}/${STAMP}-takeover.txt"

# =============================================================== 1. restart paths
hw_step "1. enumerate every auto-restart path (print, do not touch)"
RESTART=$(hw_ssh_script "enumerate restart paths" <<'EOF'
set -u
echo "----- systemd units mentioning switchd/bf/tofino/gc/defense -----"
systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null \
  | grep -Ei 'switchd|bf[-_]|tofino|gc-|defense|rrc|bor' || echo "(none)"
echo "----- unit FILES (enabled state is what survives a kill) -----"
systemctl list-unit-files --no-pager --no-legend 2>/dev/null \
  | grep -Ei 'switchd|bf[-_]|tofino|gc-|defense|rrc|bor' || echo "(none)"
echo "----- explicit is-enabled probes -----"
for u in bf-switchd gc-switchd switchd mcp-switchd defense4 rrc-bor tofino; do
    printf '%-16s %s\n' "$u" "$(systemctl is-enabled "$u.service" 2>&1 | head -1)"
done
echo "----- systemd timers -----"
systemctl list-timers --all --no-pager --no-legend 2>/dev/null | head -20 || echo "(none)"
echo "----- user crontab ($USER) -----"
crontab -l 2>&1 | grep -v '^no crontab' || echo "(none)"
echo "----- ROOT crontab -----"
sudo crontab -l 2>&1 | grep -v '^no crontab' || echo "(none)"
echo "----- /etc/crontab and /etc/cron.d -----"
grep -vE '^\s*(#|$)' /etc/crontab 2>/dev/null || echo "(no /etc/crontab entries)"
for f in /etc/cron.d/*; do
    [ -e "$f" ] || continue
    echo "--- $f"; grep -vE '^\s*(#|$)' "$f" || true
done
echo "----- @reboot / switchd in cron.{hourly,daily,weekly} -----"
grep -rilE 'switchd|tofino|bf-sde' /etc/cron.hourly /etc/cron.daily /etc/cron.weekly 2>/dev/null || echo "(none)"
echo "----- tmux sessions (all users' sockets under /tmp) -----"
tmux ls 2>&1 | grep -v 'no server running' || echo "(none for $USER)"
ls -d /tmp/tmux-* 2>/dev/null || echo "(no tmux sockets)"
echo "----- screen sessions -----"
screen -ls 2>&1 | grep -vi 'no sockets found' || echo "(none for $USER)"
sudo ls -d /run/screen/S-* 2>/dev/null || echo "(no system screen sockets)"
EOF
)
if is_dry; then
    hw_say "[dry-run] would then print the enumeration above verbatim and keep it in the snapshot."
else
    printf '%s\n' "$RESTART" | sed 's/^/   /'
fi

# =============================================================== 2. snapshot first
hw_step "2. snapshot the running program BEFORE stopping anything -> ${SNAP}"
STATE=$(hw_ssh_script "snapshot running bf_switchd" <<'EOF'
set -u
PIDS=$(pgrep -x bf_switchd || true)
echo "bf_switchd pids: ${PIDS:-<none>}"
for p in $PIDS; do
    echo "--- pid $p cmdline"
    sudo tr '\0' ' ' < "/proc/$p/cmdline"; echo
    echo "--- pid $p cwd"
    sudo readlink "/proc/$p/cwd" || true
    echo "--- pid $p start / user"
    ps -o pid=,ppid=,user=,lstart=,etime= -p "$p" || true
    echo "--- pid $p parent chain (H31: a wrapper respawns its child)"
    q=$p
    for _ in 1 2 3 4 5; do
        q=$(ps -o ppid= -p "$q" 2>/dev/null | tr -d ' ')
        [ -n "$q" ] && [ "$q" != "0" ] || break
        ps -o pid=,comm=,args= -p "$q" || break
        [ "$q" = "1" ] && break
    done
    echo "--- pid $p environment keys of interest"
    sudo tr '\0' '\n' < "/proc/$p/environ" 2>/dev/null | grep -E '^(SDE|SDE_INSTALL|LD_LIBRARY_PATH|OUT|PWD)=' || echo "(none readable)"
    CONF=$(sudo tr '\0' '\n' < "/proc/$p/cmdline" | grep -A1 -- '--conf-file' | tail -1)
    case "$CONF" in
        --conf-file=*) CONF=${CONF#--conf-file=} ;;
    esac
    echo "--- pid $p conf-file: ${CONF:-<none>}"
    if [ -n "${CONF:-}" ] && [ -f "$CONF" ]; then
        echo "--- conf contents"
        cat "$CONF"
    fi
done
echo "--- \$PORT / D_P table as ucli sees it (read-only; best effort)"
printf 'ucli\npm show\nexit\nexit\n' | sudo -E /home/decps/Downloads/bf-sde-9.13.2/install/bin/bfshell 2>&1 | head -60 || echo "(bfshell unavailable)"
echo "--- free / disk at snapshot time"
free -m | head -2
df -h /home | tail -1
EOF
)
if is_dry; then
    hw_say "[dry-run] would then write the enumeration + this state to ${SNAP} and REFUSE to continue if the write failed."
    hw_mkdir "$SNAPSHOT_DIR"
else
    printf '%s\n' "$STATE" | sed 's/^/   /'
    hw_mkdir "$SNAPSHOT_DIR"
    {
        printf '# takeover snapshot %s  switch=%s\n\n' "$STAMP" "$SWITCH"
        printf '## auto-restart paths\n%s\n\n' "$RESTART"
        printf '## running program state\n%s\n' "$STATE"
    } | hw_write_file "$SNAP"
    [ -s "$SNAP" ] || hw_die "snapshot ${SNAP} is empty — refusing to stop anything"
    hw_pass "snapshot written: ${SNAP} ($(wc -l <"$SNAP") lines)"
fi

# =============================================================== 3. stop
hw_step "3. stop the launcher, then bf_switchd (pkill -x only; NEVER pkill -f, H30)"
STOP=$(hw_ssh_script "stop launcher then bf_switchd" <<'EOF'
set -u
PIDS=$(pgrep -x bf_switchd || true)
if [ -z "$PIDS" ]; then
    echo "bf_switchd not running; nothing to stop"
    exit 0
fi
# H31: stop the LAUNCHER first.  A shell wrapper supervising bf_switchd will
# respawn it the moment the child dies, and the respawn is what the two-phase
# recheck below is designed to catch.  Killed by exact PID, never by pattern.
for p in $PIDS; do
    pp=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
    if [ -n "$pp" ] && [ "$pp" != "1" ] && [ "$pp" != "0" ]; then
        pcomm=$(ps -o comm= -p "$pp" 2>/dev/null | tr -d ' ')
        echo "parent of $p is pid $pp ($pcomm)"
        case "$pcomm" in
            bash|sh|dash|zsh|screen|tmux*)
                echo "  -> looks like a launcher; sending TERM to pid $pp by exact pid"
                sudo kill "$pp" 2>&1 || true
                ;;
            *)  echo "  -> not a shell launcher; leaving it alone" ;;
        esac
    else
        echo "pid $p is reparented to init; no launcher to stop"
    fi
done
# The ONLY safe pattern kill on this box.  `pkill -f bf_switchd` would match this
# very ssh command line and kill the session (H30).
echo "pkill -x bf_switchd"
sudo pkill -x bf_switchd 2>&1 || true
sleep 3
echo "immediately after TERM: $(pgrep -x bf_switchd | tr '\n' ' ' || true)"
EOF
)
if is_dry; then
    hw_say "[dry-run] would then print the stop transcript; no SIGKILL is ever sent by this script."
else
    printf '%s\n' "$STOP" | sed 's/^/   /'
fi

# =============================================================== 4. two-phase recheck
hw_step "4. recheck twice, ${SETTLE} s apart — a respawn between the checks is the landmine"
if is_dry; then
    hw_say "[dry-run] check A : ssh ${SWITCH} -- pgrep -x bf_switchd     (expect: empty)"
    hw_say "[dry-run] sleep ${SETTLE}"
    hw_say "[dry-run] check B : ssh ${SWITCH} -- pgrep -x bf_switchd     (expect: still empty)"
    hw_say "[dry-run] if either check is non-empty: print the respawned cmdline, name the"
    hw_say "[dry-run] restart path that was missed from step 1, exit 3, and do NOT escalate to -9."
else
    check_a=$(hw_ssh_script "recheck A" <<'EOF'
pgrep -x bf_switchd | tr '\n' ' ' || true
EOF
)
    hw_info "check A (t+0)   : '${check_a## }'"
    sleep "$SETTLE"
    check_b=$(hw_ssh_script "recheck B" <<'EOF'
pgrep -x bf_switchd | tr '\n' ' ' || true
EOF
)
    hw_info "check B (t+${SETTLE}s) : '${check_b## }'"

    if [ -n "${check_a// }" ] || [ -n "${check_b// }" ]; then
        hw_fail "bf_switchd is back — something respawned it."
        RESPAWN=$(hw_ssh_script "identify respawn" <<'EOF'
set -u
for p in $(pgrep -x bf_switchd || true); do
    echo "--- respawned pid $p"
    sudo tr '\0' ' ' < "/proc/$p/cmdline"; echo
    ps -o pid=,ppid=,user=,lstart= -p "$p" || true
    pp=$(ps -o ppid= -p "$p" | tr -d ' ')
    ps -o pid=,comm=,args= -p "$pp" 2>/dev/null || true
    systemctl status "$(ps -o comm= -p "$pp" | tr -d ' ')" --no-pager 2>/dev/null | head -5 || true
done
EOF
)
        printf '%s\n' "$RESPAWN" | sed 's/^/   /'
        printf '\n' >&2
        hw_fail "STOP. The restart path that did this is in the step-1 enumeration above and was missed."
        hw_fail "Disable that unit/cron/tmux launcher explicitly, then re-run takeover.sh."
        hw_fail "NOT escalating to 'kill -9': an unseen supervisor would just respawn again,"
        hw_fail "and -9 destroys the evidence of which supervisor it is."
        exit 3
    fi
    hw_pass "chip is free: no bf_switchd at t+0 or t+${SETTLE}s"
    hw_info "snapshot of the displaced program: ${SNAP}"
    hw_info "the sibling program was NOT restored, per Philip's instruction; nothing was rebooted."
fi

hw_step "done"
if is_dry; then
    hw_info "[dry-run] nothing was executed: no ssh, no scp, no local write."
fi
