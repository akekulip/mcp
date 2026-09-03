#!/usr/bin/env bash
# bringup.sh — load a program onto the freed chip and prove the fabric is actually up.
#
#   1. Refuse unless the chip is free or exactly one bf_switchd serves this program.
#   2. Rewrite the compiler-generated .conf to ABSOLUTE paths.  bf-p4c emits a conf
#      whose "context"/"config"/"bfrt-config" paths are RELATIVE, so bf_switchd only
#      finds them if its cwd happens to be the build directory.  The one hand-made
#      conf on the switch (mcp/p4/mcp_fabric_abs.conf) is absolute for exactly this
#      reason; this script stops that being a manual step.
#   3. Launch bf_switchd under tmux with LD_LIBRARY_PATH set and stdin kept open —
#      a bare nohup closes stdin and bf_switchd exits (H11).
#   4. Wait for the bfrt gRPC listener.  Some SDE builds omit the expected readiness
#      log line, so the socket is authoritative and the log is corroboration only.
#   5. Verify the sealed setup scripts shipped by deploy.sh, then run
#      setup_skeleton.py --program <program> up .
#   6. Wait a bounded interval for cold-link training, then verify port state on
#      BOTH sides of every cage-5/cage-6 loop pair, reading the D_P (dev_port)
#      column.
#
# EXPECTED AND NOT A BUG: a cold bf_switchd load has NO $PORT entries at all, so
# between step 3 and step 5 nothing forwards and every port query is empty.  That is
# the normal state of a freshly loaded chip — the ports are created by step 5.  It is
# printed loudly below so nobody spends an hour debugging it.
#
# Usage:
#   p4/hw/bringup.sh <program> [--dry-run] [--switch user@host]
#                          [--ready-timeout N] [--port-timeout N]
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=p4/hw/common.sh
. "${HERE}/common.sh"
hw_open_narration

PROG=""
READY_TIMEOUT=180
PORT_TIMEOUT=60
PORT_POLL=2
TMUX_SESSION=${TMUX_SESSION:-mcp_switchd}
while [ $# -gt 0 ]; do
    if hw_parse_common_flag "$1" "${2:-}"; then
        shift "$HW_SHIFT"
        continue
    fi
    case $1 in
        --ready-timeout) READY_TIMEOUT=${2:?--ready-timeout needs a value}; shift 2 ;;
        --port-timeout)  PORT_TIMEOUT=${2:?--port-timeout needs a value}; shift 2 ;;
        -h|--help)       sed -n '2,28p' "$0"; exit 0 ;;
        -*)              hw_die "unknown flag: $1" ;;
        *)               [ -z "$PROG" ] || hw_die "only one program name accepted"; PROG=$1; shift ;;
    esac
done
[ -n "$PROG" ] || hw_die "usage: bringup.sh <program> [--dry-run]"
case $READY_TIMEOUT in *[!0-9]*|'') hw_die "--ready-timeout must be a non-negative integer" ;; esac
case $PORT_TIMEOUT in *[!0-9]*|'') hw_die "--port-timeout must be a non-negative integer" ;; esac

hw_banner "bringup ${PROG}"
CONF_SRC="${REMOTE_DIR}/${PROG}.tofino/${PROG}.conf"
CONF_ABS="${REMOTE_DIR}/${PROG}_abs.conf"
SWLOG="${REMOTE_DIR}/${PROG}.switchd.log"
BUILD_MANIFEST="${REMOTE_DIR}/${PROG}.build-manifest.sha256"
SETUP_MANIFEST="${REMOTE_DIR}/${PROG}.setup-manifest.sha256"
LOAD_RECEIPT="${REMOTE_DIR}/${PROG}.loaded-build.sha256"

# ================================================================ 0. chip ownership
hw_step "0. who owns the chip? (CLAUDE.md: check before ANY port or table write)"
OWNER=$(hw_ssh_script "chip ownership" <<'EOF'
set -u
PIDS=$(pgrep -x bf_switchd || true)
set -- $PIDS
echo "pgrep -x bf_switchd: '$(printf '%s ' "$@")'"
if [ "$#" -eq 0 ]; then
    echo "OWNER_STATUS=FREE"
elif [ "$#" -ne 1 ]; then
    echo "OWNER_STATUS=MULTIPLE count=$#"
    for p in "$@"; do printf 'pid=%s cmd=' "$p"; sudo tr '\0' ' ' < "/proc/$p/cmdline"; echo; done
else
    p=$1
    CMD=$(sudo tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null || true)
    printf 'pid=%s cmd=%s\n' "$p" "$CMD"
    echo "OWNER_STATUS=ONE pid=$p"
fi
EOF
)
if is_dry; then
    hw_say "[dry-run] would then continue only if no bf_switchd exists or exactly one process"
    hw_say "[dry-run] names ${CONF_ABS}; multiple or foreign owners fail closed."
else
    printf '%s\n' "$OWNER" | sed 's/^/   /'
    case "$OWNER" in
        *OWNER_STATUS=FREE*) hw_pass "chip is free" ;;
        *OWNER_STATUS=MULTIPLE*) hw_die "multiple bf_switchd processes own the chip (above); run p4/hw/takeover.sh first" ;;
        *OWNER_STATUS=ONE*)
            printf '%s\n' "$OWNER" | grep -qF -- "${CONF_ABS}" \
                || hw_die "the chip is owned by a different bf_switchd (above); run p4/hw/takeover.sh first"
            hw_pass "exactly one bf_switchd owns the expected conf"
            ;;
        *) hw_die "could not establish chip ownership; refusing to continue" ;;
    esac
fi

# ================================================================ 1. absolute conf
hw_step "1. rewrite ${PROG}.conf to absolute paths -> ${CONF_ABS}"
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

# ============================================ 1b. are the artifacts one sealed build?
# deploy.sh creates this manifest only after bf-p4c succeeds.  Checking every hash is
# an identity check, unlike comparing mtimes, and catches stale or partially replaced
# source/schema/context/binary sets before a process is launched or reused.
hw_step "1b. provenance: verify the sealed compiler inputs and loadable outputs"
PROV=$(hw_ssh_script "build provenance" <<EOF
set -eu
cd '${REMOTE_DIR}'
MAN='${PROG}.build-manifest.sha256'
[ -f "\$MAN" ] || { echo "MISSING \$MAN — run p4/hw/deploy.sh ${PROG}"; exit 6; }
sha256sum -c "\$MAN"
echo "BUILD_ID=\$(sha256sum "\$MAN" | awk '{print \$1}')"
EOF
) || { printf '%s\n' "$PROV" | sed 's/^/   /'; hw_die "build artifacts do not match the deploy manifest"; }
if is_dry; then
    hw_say "[dry-run] would require every SHA-256 entry in ${BUILD_MANIFEST} to match."
else
    printf '%s\n' "$PROV" | sed 's/^/   /'
fi

# ================================================ 1c. are the setup scripts sealed?
# deploy.sh ships setup_skeleton.py and setup_attention.py and writes this separate
# manifest.  It is intentionally not part of BUILD_MANIFEST/LOAD_RECEIPT: changing
# setup policy must fail closed before setup runs, but must not force a binary reload.
hw_step "1c. setup provenance: verify shipped setup scripts"
SETUP_PROV=$(hw_ssh_script "setup provenance" <<EOF
set -eu
cd '${REMOTE_DIR}'
MAN='${PROG}.setup-manifest.sha256'
[ -f "\$MAN" ] || { echo "MISSING \$MAN — run p4/hw/deploy.sh ${PROG}"; exit 6; }
sha256sum -c "\$MAN"
echo "SETUP_ID=\$(sha256sum "\$MAN" | awk '{print \$1}')"
EOF
) || { printf '%s\n' "$SETUP_PROV" | sed 's/^/   /'; hw_die "setup scripts do not match the deploy manifest"; }
if is_dry; then
    hw_say "[dry-run] would require every SHA-256 entry in ${SETUP_MANIFEST} to match before setup_skeleton.py or setup_attention.py runs."
else
    printf '%s\n' "$SETUP_PROV" | sed 's/^/   /'
fi

# ================================================================ 3. launch
# NOTE: sudo STRIPS LD_LIBRARY_PATH (and every LD_*) from the environment even with -E;
# that is a sudo security behaviour, not a quoting bug.  Exporting it before sudo is not
# enough and fails as 'libdriver.so: cannot open shared object file'.  It must be set on
# the sudo'd child via env(1).  Do not 'simplify' this back to a plain export.
ALREADY=$(hw_ssh_script "already serving?" <<EOF
pids=\$(pgrep -x bf_switchd || true)
set -- \$pids
if [ "\$#" -eq 0 ]; then
    echo "NO_PROCESS"
    exit 0
fi
[ "\$#" -eq 1 ] || { echo "REFUSE_MULTIPLE count=\$#"; exit 0; }
p=\$1
cmd=\$(sudo tr '\\0' ' ' < "/proc/\$p/cmdline" 2>/dev/null || true)
case "\$cmd" in *'${CONF_ABS}'*) ;; *) echo "REFUSE_OTHER pid=\$p"; exit 0 ;; esac
ss -ltn 2>/dev/null | grep -q ':${GRPC_PORT}' || { echo "REFUSE_NO_LISTENER pid=\$p"; exit 0; }
[ -f '${LOAD_RECEIPT}' ] || { echo "REFUSE_NO_RECEIPT pid=\$p"; exit 0; }
build_id=\$(sha256sum '${BUILD_MANIFEST}' | awk '{print \$1}')
read -r loaded_pid loaded_id < '${LOAD_RECEIPT}' || { echo "REFUSE_BAD_RECEIPT pid=\$p"; exit 0; }
[ "\$loaded_pid" = "\$p" ] && [ "\$loaded_id" = "\$build_id" ] \
    || { echo "REFUSE_STALE_RECEIPT pid=\$p"; exit 0; }
echo "SERVING pid=\$p build_id=\$build_id"
EOF
) || true
if ! is_dry && printf '%s\n' "$ALREADY" | grep -q '^SERVING '; then
    hw_say "3. bf_switchd is ALREADY serving this conf with a live gRPC listener — not relaunching"
    hw_say "   $(printf '%s' "$ALREADY" | grep SERVING)"
    hw_say "   (relaunching would drop a running experiment; use takeover.sh if you really want a fresh load)"
else
if ! is_dry && ! printf '%s\n' "$ALREADY" | grep -q '^NO_PROCESS$'; then
    printf '%s\n' "$ALREADY" | sed 's/^/   /'
    hw_die "an existing bf_switchd cannot be proven to serve this exact sealed build; run takeover.sh before relaunching"
fi
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
fi

# ================================================================ 4. readiness
hw_step "4. wait up to ${READY_TIMEOUT}s for: ${BFRT_READY_RE}"
READY=$(hw_ssh_script "wait for bfrt gRPC" <<EOF
set -u
deadline=\$(( \$(date +%s) + ${READY_TIMEOUT} ))
while [ "\$(date +%s)" -lt "\$deadline" ]; do
    # H41(c): the LISTENER is the primary witness.  This SDE never prints
    # '${BFRT_READY_RE}' at all -- grep -c over a healthy run returns 0 -- so a
    # log-string probe times out on a perfectly good server.  Check the socket
    # first and treat any log line as corroboration only.
    if ss -ltn 2>/dev/null | grep -q ':${GRPC_PORT}'; then
        echo "READY: listener on ${GRPC_PORT}"
        grep -m1 '${BFRT_READY_RE}' '${SWLOG}' 2>/dev/null \
            && echo "  (log line also present)" \
            || echo "  (this SDE prints no matching log line; the listener is authoritative)"
        break
    fi
    if ! pgrep -x bf_switchd >/dev/null; then
        echo "DEAD: bf_switchd exited before the gRPC server came up"
        tail -30 '${SWLOG}' 2>/dev/null
        exit 4
    fi
    sleep 2
done
ss -ltn 2>/dev/null | grep -q ':${GRPC_PORT}' || { echo "TIMEOUT after ${READY_TIMEOUT}s: no listener on ${GRPC_PORT}"; tail -30 '${SWLOG}'; exit 5; }
echo "pid: \$(pgrep -x bf_switchd | tr '\n' ' ')"
echo "socket:"
ss -ltnp 2>/dev/null | grep ':${GRPC_PORT}' || echo "  (listener was visible to ss -ltn but process details are hidden from this user)"
EOF
) || { printf '%s\n' "$READY" | sed 's/^/   /'; hw_die "bf_switchd never reached bfrt gRPC readiness"; }
if is_dry; then
    hw_say "[dry-run] would require a live listener on ${GRPC_PORT}; the readiness log is corroboration when present."
    hw_say "[dry-run] would record the bf_switchd pid to ${ARTIFACT_DIR}/switchd.pid for canary.sh."
    hw_mkdir "$ARTIFACT_DIR"
else
    printf '%s\n' "$READY" | sed 's/^/   /'
    hw_mkdir "$ARTIFACT_DIR"
    printf '%s\n' "$READY" | awk '/^pid: /{print $2}' | hw_write_file "${ARTIFACT_DIR}/switchd.pid"
    LOAD_SEAL=$(hw_ssh_script "record loaded build identity" <<EOF
set -eu
set -- \$(pgrep -x bf_switchd || true)
[ "\$#" -eq 1 ] || { echo "expected one bf_switchd, found \$#"; exit 8; }
build_id=\$(sha256sum '${BUILD_MANIFEST}' | awk '{print \$1}')
tmp='${LOAD_RECEIPT}.tmp.'\$\$
printf '%s %s\n' "\$1" "\$build_id" > "\$tmp"
mv "\$tmp" '${LOAD_RECEIPT}'
echo "pid=\$1 build_id=\$build_id"
EOF
) || { printf '%s\n' "$LOAD_SEAL" | sed 's/^/   /'; hw_die "could not record the loaded build identity"; }
    printf '%s\n' "$LOAD_SEAL" | sed 's/^/   /'
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

# ---------------------------------------------------------------- 5b. attention tables
# setup_skeleton does NOT install tbl_eg_vlink; setup_attention does.  That table maps
# (egress_port, egress_qid) -> virtual link and composes md.sublink, and its miss action is
# set_eg_vlink(0, 0).  So when it is empty the chip does not fail -- every packet silently
# reports virtual link 0, and any per-link measurement collapses onto one link while still
# looking plausible.  That cost a full misdiagnosis on 2026-08-30: a per-link frontier read
# vlink 0 for traffic the ingress counters put on vlink 1, and the disagreement between the
# two instruments was the only thing that exposed it.  Bring-up installs it from now on.
hw_step "5b. setup_attention.py --program ${PROG} up  (tbl_eg_vlink — see note in source)"
ATTN=$(hw_ssh_script "setup_attention up" <<EOF
set -u
export SDE='${SDE}'
export SDE_INSTALL='${SDE_INSTALL}'
export LD_LIBRARY_PATH="\$SDE_INSTALL/lib"
P="\$SDE_INSTALL/lib/python3.8/site-packages"
export PYTHONPATH="\$P/tofino:\$P/tofino/bfrt_grpc:\$P"
cd '${REMOTE_DIR}'
python3 setup_attention.py --program '${PROG}' up
EOF
) || { printf '%s\n' "$ATTN" | sed 's/^/   /'; hw_die "setup_attention.py up failed"; }
if is_dry; then
    hw_say "[dry-run] would require setup_attention.py to print: tbl_eg_vlink verified: 16 exact rows"
    hw_say "[dry-run] would then require every table write to be accepted and no 'required ports DOWN' warning."
else
    printf '%s\n' "$ATTN" | grep -E 'eg_vlink|rows installed|exact rows' | sed 's/^/   /' || true
    if ! printf '%s\n' "$ATTN" | grep -qF 'tbl_eg_vlink verified: 16 exact rows'; then
        hw_die "setup_attention did not prove the exact tbl_eg_vlink readback"
    fi
    printf '%s\n' "$SETUP" | sed 's/^/   /'
    if printf '%s\n' "$SETUP" | grep -q 'required ports DOWN'; then
        hw_warn "setup_skeleton reported ports DOWN — see the port check below"
    fi
fi

# ============================================== 5c. loaded-setup receipt
# gate_agent_core.verify_loaded_setup() (added on the switch, pulled back in commit
# b1a5ec1) refuses to start unless <PROG>.loaded-setup.sha256 exists and names the
# CURRENT bf_switchd pid, this machine's stable switch identity, and the sealed
# setup-manifest hash. Nothing wrote this receipt until 2026-09-02's wire-reduction
# hardware pass hit it as a hard failure -- deploy.sh/bringup.sh predate the guard.
# Writing it here, right after setup succeeds, closes that gap for every future
# bring-up instead of requiring the same manual receipt each time.
hw_step "5c. write the loaded-setup receipt gate_agent.py requires to start"
SETUP_RECEIPT="${REMOTE_DIR}/${PROG}.loaded-setup.sha256"
SETUP_SEAL=$(hw_ssh_script "write loaded-setup receipt" <<EOF
set -eu
cd '${REMOTE_DIR}'
pid=\$(pgrep -x bf_switchd) || { echo "no bf_switchd running"; exit 9; }
[ "\$(printf '%s\n' "\$pid" | wc -l)" -eq 1 ] || { echo "expected exactly one bf_switchd, found: \$pid"; exit 9; }
switch_identity=\$(python3 -c "
import pathlib, socket, hashlib
machine_id = pathlib.Path('/etc/machine-id').read_text()
hostname = socket.gethostname()
normalized = '%s\n%s\n%d\n' % (machine_id.strip(), hostname.strip(), 0)
print(hashlib.sha256(normalized.encode('utf-8')).hexdigest())
")
setup_identity=\$(sha256sum '${SETUP_MANIFEST}' | awk '{print \$1}')
tmp='${SETUP_RECEIPT}.tmp.'\$\$
printf '%s %s %s\n' "\$pid" "\$switch_identity" "\$setup_identity" > "\$tmp"
mv "\$tmp" '${SETUP_RECEIPT}'
cat '${SETUP_RECEIPT}'
EOF
) || { printf '%s\n' "$SETUP_SEAL" | sed 's/^/   /'; hw_die "could not write the loaded-setup receipt"; }
if is_dry; then
    hw_say "[dry-run] would write ${SETUP_RECEIPT} as '<bf_switchd pid> <switch identity> <setup-manifest sha256>'."
else
    printf '%s\n' "$SETUP_SEAL" | sed 's/^/   /'
    hw_pass "loaded-setup receipt written: ${SETUP_RECEIPT}"
fi

# ================================================================ 6. port check
hw_step "6. wait up to ${PORT_TIMEOUT}s for all loop pairs and host ports"
hw_info "loop pairs (5/k <-> 6/k): ${LOOP_PAIRS[*]}   host ports: ${HOST_DPS[*]}"
hw_info "training poll every ${PORT_POLL}s; final verdict reads the D_P (dev_port) column"

read_ports() {
    hw_ssh_script "setup_skeleton ports" <<EOF
set -u
export SDE='${SDE}'
export SDE_INSTALL='${SDE_INSTALL}'
export LD_LIBRARY_PATH="\$SDE_INSTALL/lib"
P="\$SDE_INSTALL/lib/python3.8/site-packages"
export PYTHONPATH="\$P/tofino:\$P/tofino/bfrt_grpc:\$P"
cd '${REMOTE_DIR}'
python3 setup_skeleton.py --program '${PROG}' ports
EOF
}

port_up() {   # $1 = dev_port -> echoes True/False/ABSENT from current PORTS
    printf '%s\n' "$PORTS" | awk -v want="dp$1" '$1==want {print $4; found=1} END{if(!found) print "ABSENT"}'
}

all_ports_up() {
    local pair a b dp
    for pair in "${LOOP_PAIRS[@]}"; do
        a=${pair%%:*}; b=${pair##*:}
        [ "$(port_up "$a")" = "True" ] && [ "$(port_up "$b")" = "True" ] || return 1
    done
    for dp in "${HOST_DPS[@]}"; do
        [ "$(port_up "$dp")" = "True" ] || return 1
    done
    return 0
}

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
    deadline=$(( $(date +%s) + PORT_TIMEOUT ))
    polls=0
    while :; do
        polls=$((polls + 1))
        if ! PORTS=$(read_ports); then
            printf '%s\n' "$PORTS" | sed 's/^/   /'
            hw_die "could not read the port table"
        fi
        all_ports_up && break
        [ "$(date +%s)" -ge "$deadline" ] && break
        hw_info "ports still training after poll ${polls}; retrying in ${PORT_POLL}s"
        sleep "$PORT_POLL"
    done
    printf '%s\n' "$PORTS" | sed 's/^/   /'
    bad=0
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
