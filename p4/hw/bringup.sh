#!/usr/bin/env bash
# bringup.sh — load a program onto the freed chip and prove the fabric is actually up.
#
#   1. Refuse if anything already owns the chip (run takeover.sh first).
#   2. Rewrite the compiler-generated .conf to ABSOLUTE paths.  bf-p4c emits a conf
#      whose "context"/"config"/"bfrt-config" paths are RELATIVE, so bf_switchd only
#      finds them if its cwd happens to be the build directory.  The one hand-made
#      conf on the switch (mcp/p4/mcp_fabric_abs.conf) is absolute for exactly this
#      reason; this script stops that being a manual step.
#   3. Launch bf_switchd under tmux with LD_LIBRARY_PATH set and stdin kept open —
#      a bare nohup closes stdin and bf_switchd exits (H11).
#   4. Wait for the bfrt gRPC readiness line in the log.  The pattern is taken from
#      the SDE binary itself (strings install/lib/libdriver.so):
#          "bfruntime gRPC server started on %s"
#      and the listening socket is checked as a second, independent witness.
#   5. Run  setup_skeleton.py --program <program> up .
#   6. Verify port state on BOTH sides of every cage-5/cage-6 loop pair, reading the
#      D_P (dev_port) column.
#
# EXPECTED AND NOT A BUG: a cold bf_switchd load has NO $PORT entries at all, so
# between step 3 and step 5 nothing forwards and every port query is empty.  That is
# the normal state of a freshly loaded chip — the ports are created by step 5.  It is
# printed loudly below so nobody spends an hour debugging it.
#
# Usage:
#   p4/hw/bringup.sh <program> [--dry-run] [--switch user@host] [--ready-timeout N]
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=p4/hw/common.sh
. "${HERE}/common.sh"
hw_open_narration

PROG=""
READY_TIMEOUT=180
TMUX_SESSION=${TMUX_SESSION:-mcp_switchd}
while [ $# -gt 0 ]; do
    if hw_parse_common_flag "$1" "${2:-}"; then
        shift "$HW_SHIFT"
        continue
    fi
    case $1 in
        --ready-timeout) READY_TIMEOUT=${2:?--ready-timeout needs a value}; shift 2 ;;
        -h|--help)       sed -n '2,28p' "$0"; exit 0 ;;
        -*)              hw_die "unknown flag: $1" ;;
        *)               [ -z "$PROG" ] || hw_die "only one program name accepted"; PROG=$1; shift ;;
    esac
done
[ -n "$PROG" ] || hw_die "usage: bringup.sh <program> [--dry-run]"

hw_banner "bringup ${PROG}"
CONF_SRC="${REMOTE_DIR}/${PROG}.tofino/${PROG}.conf"
CONF_ABS="${REMOTE_DIR}/${PROG}_abs.conf"
SWLOG="${REMOTE_DIR}/${PROG}.switchd.log"
SETUP_REMOTE="${REMOTE_DIR}/setup_skeleton.py"

# ================================================================ 0. chip ownership
hw_step "0. who owns the chip? (CLAUDE.md: check before ANY port or table write)"
OWNER=$(hw_ssh_script "chip ownership" <<'EOF'
set -u
P=$(pgrep -x bf_switchd | tr '\n' ' ' || true)
echo "pgrep -x bf_switchd: '${P}'"
for p in $P; do sudo tr '\0' ' ' < "/proc/$p/cmdline"; echo; done
EOF
)
if is_dry; then
    hw_say "[dry-run] would then REFUSE to continue unless 'pgrep -x bf_switchd' is empty,"
    hw_say "[dry-run] naming the program that owns the chip and pointing at p4/hw/takeover.sh."
else
    printf '%s\n' "$OWNER" | sed 's/^/   /'
    if printf '%s\n' "$OWNER" | grep -qE "^pgrep -x bf_switchd: '[0-9]"; then
        hw_die "the chip is still owned by a running bf_switchd (above). Run p4/hw/takeover.sh first."
    fi
    hw_pass "chip is free"
fi

# ================================================================ 1. control plane
hw_step "1. ship the control plane (setup_skeleton.py) next to the build"
hw_scp_up "${REPO_ROOT}/p4/control/setup_skeleton.py" "$SETUP_REMOTE"

# ================================================================ 2. absolute conf
hw_step "2. rewrite ${PROG}.conf to absolute paths -> ${CONF_ABS}"
CONFOUT=$(hw_ssh_script "absolute conf" <<EOF
set -eu
python3 - <<'PY'
import json, os
src = "${CONF_SRC}"
dst = "${CONF_ABS}"
root = "${REMOTE_DIR}"
with open(src) as fh:
    cfg = json.load(fh)

def absolute(p):
    return p if os.path.isabs(p) else os.path.normpath(os.path.join(root, p))

for dev in cfg.get("p4_devices", []):
    for prog in dev.get("p4_programs", []):
        for k in ("bfrt-config", "model_json_path"):
            if k in prog:
                prog[k] = absolute(prog[k])
        for pl in prog.get("p4_pipelines", []):
            for k in ("context", "config", "path"):
                if k in pl:
                    pl[k] = absolute(pl[k])
        # model_json_path points at aug_model.json, which bf-p4c emits only into an
        # INSTALLED layout and which only the software model ever reads.  On silicon it
        # is dead weight -- the program displaced from this chip carried no such key at
        # all.  Drop it rather than refusing to boot, but say so, because silently
        # rewriting a conf is how you end up debugging the wrong binary.
        if "model_json_path" in prog and not os.path.exists(prog["model_json_path"]):
            print("note: dropping model_json_path (%s does not exist; it is read only by "
                  "the software model, not by hardware)" % prog["model_json_path"])
            del prog["model_json_path"]
        if "bfrt-config" in prog and not os.path.exists(prog["bfrt-config"]):
            raise SystemExit("missing build artifact: %s" % prog["bfrt-config"])
        for pl in prog.get("p4_pipelines", []):
            for k in ("context", "config"):
                if not os.path.exists(pl[k]):
                    raise SystemExit("missing build artifact: %s" % pl[k])
with open(dst, "w") as fh:
    json.dump(cfg, fh, indent=4)
print("wrote %s" % dst)
print(json.dumps(cfg["p4_devices"][0]["p4_programs"][0], indent=2))
PY
EOF
) || { printf '%s\n' "$CONFOUT" | sed 's/^/   /'; hw_die "could not build an absolute conf for ${PROG} — is it deployed and compiled?"; }
if is_dry; then
    hw_say "[dry-run] would then verify every rewritten path exists on the switch and abort if not."
else
    printf '%s\n' "$CONFOUT" | sed 's/^/   /'
fi

# ================================================================ 3. launch
# NOTE: sudo STRIPS LD_LIBRARY_PATH (and every LD_*) from the environment even with -E;
# that is a sudo security behaviour, not a quoting bug.  Exporting it before sudo is not
# enough and fails as 'libdriver.so: cannot open shared object file'.  It must be set on
# the sudo'd child via env(1).  Do not 'simplify' this back to a plain export.
hw_step "3. launch bf_switchd under tmux (LD_LIBRARY_PATH via sudo env, stdin kept open — H11)"
LAUNCH=$(hw_ssh_script "launch bf_switchd" <<EOF
set -u
tmux kill-session -t '${TMUX_SESSION}' 2>/dev/null || true
rm -f '${SWLOG}'
tmux new-session -d -s '${TMUX_SESSION}' \
  "export SDE='${SDE}'; export SDE_INSTALL='${SDE_INSTALL}'; \
   export LD_LIBRARY_PATH='${SDE_INSTALL}/lib'; \
   sudo -E env LD_LIBRARY_PATH='${SDE_INSTALL}/lib' SDE='${SDE}' SDE_INSTALL='${SDE_INSTALL}' \
        '${SDE_INSTALL}/bin/bf_switchd' --install-dir '${SDE_INSTALL}' \
        --conf-file '${CONF_ABS}' --init-mode=cold --status-port 7777 2>&1 \
   | tee '${SWLOG}'"
sleep 2
tmux ls 2>&1 | head -5
EOF
)
if is_dry; then
    hw_say "[dry-run] tmux session '${TMUX_SESSION}' would carry bf_switchd; log -> ${SWLOG}"
    hw_say "[dry-run] NOTE: nohup is deliberately not used — it closes stdin and bf_switchd exits (H11)."
else
    printf '%s\n' "$LAUNCH" | sed 's/^/   /'
fi

# ================================================================ 4. readiness
hw_step "4. wait up to ${READY_TIMEOUT}s for: ${BFRT_READY_RE}"
READY=$(hw_ssh_script "wait for bfrt gRPC" <<EOF
set -u
deadline=\$(( \$(date +%s) + ${READY_TIMEOUT} ))
while [ "\$(date +%s)" -lt "\$deadline" ]; do
    if grep -q '${BFRT_READY_RE}' '${SWLOG}' 2>/dev/null; then
        echo "READY: \$(grep -m1 '${BFRT_READY_RE}' '${SWLOG}')"
        break
    fi
    if ! pgrep -x bf_switchd >/dev/null; then
        echo "DEAD: bf_switchd exited before the gRPC server came up"
        tail -30 '${SWLOG}' 2>/dev/null
        exit 4
    fi
    sleep 2
done
grep -q '${BFRT_READY_RE}' '${SWLOG}' 2>/dev/null || { echo "TIMEOUT after ${READY_TIMEOUT}s"; tail -30 '${SWLOG}'; exit 5; }
echo "pid: \$(pgrep -x bf_switchd | tr '\n' ' ')"
echo "socket:"
ss -ltnp 2>/dev/null | grep ':${GRPC_PORT}' || echo "  (port ${GRPC_PORT} not visible to this user; the log line above is authoritative)"
EOF
) || { printf '%s\n' "$READY" | sed 's/^/   /'; hw_die "bf_switchd never reached bfrt gRPC readiness"; }
if is_dry; then
    hw_say "[dry-run] two independent witnesses are required: the log line, and a listener on ${GRPC_PORT}."
    hw_say "[dry-run] would record the bf_switchd pid to ${ARTIFACT_DIR}/switchd.pid for canary.sh."
    hw_mkdir "$ARTIFACT_DIR"
else
    printf '%s\n' "$READY" | sed 's/^/   /'
    hw_mkdir "$ARTIFACT_DIR"
    printf '%s\n' "$READY" | awk '/^pid: /{print $2}' | hw_write_file "${ARTIFACT_DIR}/switchd.pid"
    hw_pass "bfrt gRPC up; pid recorded in ${ARTIFACT_DIR}/switchd.pid"
fi

cat <<'NOTE'

   -------------------------------------------------------------------------
   EXPECTED, NOT A BUG: a cold bf_switchd load has NO $PORT entries at all.
   Until step 5 creates them, every port is absent, nothing links, and nothing
   forwards.  This is the normal state of a freshly loaded chip.  Do not go
   looking for a cabling or FEC fault here — run step 5 and look after it.
   -------------------------------------------------------------------------
NOTE

# ================================================================ 5. setup
hw_step "5. setup_skeleton.py --program ${PROG} up"
SETUP=$(hw_ssh_script "setup_skeleton up" <<EOF
set -u
export SDE='${SDE}'
export SDE_INSTALL='${SDE_INSTALL}'
export LD_LIBRARY_PATH="\$SDE_INSTALL/lib"
P="\$SDE_INSTALL/lib/python3.8/site-packages"
export PYTHONPATH="\$P/tofino:\$P/tofino/bfrt_grpc:\$P"
cd '${REMOTE_DIR}'
python3 setup_skeleton.py --program '${PROG}' up
EOF
) || { printf '%s\n' "$SETUP" | sed 's/^/   /'; hw_die "setup_skeleton.py up failed"; }
if is_dry; then
    hw_say "[dry-run] would then require every table write to be accepted and no 'required ports DOWN' warning."
else
    printf '%s\n' "$SETUP" | sed 's/^/   /'
    if printf '%s\n' "$SETUP" | grep -q 'required ports DOWN'; then
        hw_warn "setup_skeleton reported ports DOWN — see the port check below"
    fi
fi

# ================================================================ 6. port check
hw_step "6. verify BOTH sides of every loop pair, reading the D_P (dev_port) column"
hw_info "loop pairs (5/k <-> 6/k): ${LOOP_PAIRS[*]}   host ports: ${HOST_DPS[*]}"
PORTS=$(hw_ssh_script "setup_skeleton ports" <<EOF
set -u
export SDE='${SDE}'
export SDE_INSTALL='${SDE_INSTALL}'
export LD_LIBRARY_PATH="\$SDE_INSTALL/lib"
P="\$SDE_INSTALL/lib/python3.8/site-packages"
export PYTHONPATH="\$P/tofino:\$P/tofino/bfrt_grpc:\$P"
cd '${REMOTE_DIR}'
python3 setup_skeleton.py --program '${PROG}' ports
EOF
) || { printf '%s\n' "$PORTS" | sed 's/^/   /'; hw_die "could not read the port table"; }

if is_dry; then
    hw_say "[dry-run] setup_skeleton.py's 'dp' column IS \$PORT.\$DEV_PORT, i.e. the ucli D_P column."
    hw_say "[dry-run] would then require, for each pair a:b, that BOTH dpa and dpb are present and up=True:"
    for pair in "${LOOP_PAIRS[@]}"; do
        hw_say "[dry-run]   pair ${pair%%:*} <-> ${pair##*:}  : both sides up"
    done
    for dp in "${HOST_DPS[@]}"; do
        hw_say "[dry-run]   host dp${dp}                : present and up"
    done
    hw_say "[dry-run] a pair with one side up and one down is a half-link and fails bringup."
else
    printf '%s\n' "$PORTS" | sed 's/^/   /'
    bad=0
    port_up() {   # $1 = dev_port -> echoes True/False/ABSENT
        printf '%s\n' "$PORTS" | awk -v want="dp$1" '$1==want {print $4; found=1} END{if(!found) print "ABSENT"}'
    }
    for pair in "${LOOP_PAIRS[@]}"; do
        a=${pair%%:*}; b=${pair##*:}
        ua=$(port_up "$a"); ub=$(port_up "$b")
        if [ "$ua" = "True" ] && [ "$ub" = "True" ]; then
            hw_pass "loop pair dp${a} <-> dp${b}: both sides up"
        else
            hw_fail "loop pair dp${a} <-> dp${b}: dp${a}=${ua} dp${b}=${ub} (a half-link forwards nothing)"
            bad=1
        fi
    done
    for dp in "${HOST_DPS[@]}"; do
        u=$(port_up "$dp")
        if [ "$u" = "True" ]; then hw_pass "host dp${dp}: up"
        else hw_fail "host dp${dp}: ${u}"; bad=1; fi
    done
    [ "$bad" = 0 ] || hw_die "port verification failed — do not start a campaign on a half-up fabric"
    hw_pass "all loop pairs and host ports up"
fi

hw_step "done"
if is_dry; then
    hw_info "[dry-run] nothing was executed: no ssh, no scp, no local write."
fi
