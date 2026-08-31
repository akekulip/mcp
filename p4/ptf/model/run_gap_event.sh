#!/bin/bash
# Run the P3 gap-event suite on the local Tofino software model. No physical pipeline is loaded.
set -u
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
MODEL_DIR=/home/philip/mcp_model
REPO_DIR=/home/philip/Projects/mcp
PROG=mcp_fabric_gate_event
SOURCE=$REPO_DIR/p4/witness/$PROG.p4
BUILD_DIR=$(mktemp -d /tmp/mcp-gap-event-model.XXXXXX)
CONF=$BUILD_DIR/model_gate_event.conf
MODEL_PIDFILE=$BUILD_DIR/tofino-model.pid
SWITCHD_PIDFILE=$BUILD_DIR/bf_switchd.pid
# shellcheck disable=SC1091
. "$REPO_DIR/.env"
. "$REPO_DIR/p4/ptf/model/runner_lib.sh"
runner_acquire_local_model_lock
S() { printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"; }
kill_owned() {
    pidfile=$1
    expected=$2
    [ -f "$pidfile" ] || return 0
    pid=$(cat "$pidfile")
    case "$pid" in *[!0-9]*|'') echo "refusing invalid $expected pid '$pid'" >&2; return 1 ;; esac
    [ -d "/proc/$pid" ] || return 0
    comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    if [ "$comm" != "$expected" ] || ! printf '%s\n' "$cmd" | grep -qF -- "$CONF"; then
        echo "refusing to kill pid $pid: expected owned $expected with config $CONF, got '$comm' '$cmd'" >&2
        return 1
    fi
    S kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        [ -d "/proc/$pid" ] || return 0
        sleep 0.1
    done
    S kill -KILL "$pid" 2>/dev/null || true
}
cleanup() {
    kill_owned "$SWITCHD_PIDFILE" bf_switchd || true
    kill_owned "$MODEL_PIDFILE" tofino-model || true
}
trap cleanup EXIT

# This runner never takes over shared local processes.  An earlier version used
# global pkill-by-name in cleanup, which could terminate an unrelated model session.
existing=$(pgrep -x bf_switchd; pgrep -x tofino-model) || true
if [ -n "$existing" ]; then
    echo "refusing to run: an existing bf_switchd/tofino-model process is active: $existing" >&2
    exit 2
fi

# Never run the semantic suite against a stale binary. The campaign added BFRT-visible
# fields after the first model build, and the old fixed config continued to load the older
# schema while the source-level tests stayed green. Compile the exact current source and
# generate a matching temporary model config on every run.
$SDE_INSTALL/bin/bf-p4c --target tofino --arch tna --verbose 2 \
    -o "$BUILD_DIR/$PROG.tofino" --bf-rt-schema "$BUILD_DIR/$PROG.bfrt.json" \
    "$SOURCE" > "$BUILD_DIR/build.log" 2>&1 || {
        tail -60 "$BUILD_DIR/build.log"
        exit 1
    }
jq --arg b "$BUILD_DIR/$PROG.bfrt.json" \
   --arg c "$BUILD_DIR/$PROG.tofino/pipe/context.json" \
   --arg f "$BUILD_DIR/$PROG.tofino/pipe/tofino.bin" \
   --arg p "$BUILD_DIR/$PROG.tofino" \
   --arg m "$BUILD_DIR/$PROG.tofino/share/$PROG/aug_model.json" \
   '.p4_devices[0].p4_programs[0]["bfrt-config"]=$b |
    .p4_devices[0].p4_programs[0].p4_pipelines[0].context=$c |
    .p4_devices[0].p4_programs[0].p4_pipelines[0].config=$f |
    .p4_devices[0].p4_programs[0].p4_pipelines[0].path=$p |
    .p4_devices[0].p4_programs[0].model_json_path=$m' \
   "$REPO_DIR/p4/ptf/model/model_gate_event.conf" > "$CONF"
echo "=== current source/build ==="
sha256sum "$SOURCE" "$BUILD_DIR/$PROG.tofino/pipe/logs/table_summary.log"
grep -E 'Number of stages|Number of tables allocated' \
    "$BUILD_DIR/$PROG.tofino/pipe/logs/table_summary.log" | tail -n 5

# The single quotes are intentional: the privileged child shell, not this runner,
# expands its positional parameters and writes its own post-sudo PID.
# shellcheck disable=SC2016
S sh -c 'pidfile=$1; shift; echo $$ > "$pidfile"; exec "$@"' sh "$MODEL_PIDFILE" \
    env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    tofino-model --p4-target-config "$CONF" --install-dir "$SDE_INSTALL" \
    -d 1 -k 1 -f "$MODEL_DIR/ports.json" --chip-type 2 --log-dir "$MODEL_DIR" \
    > "$MODEL_DIR/gap_event.model.log" 2>&1 &
sleep 6
# shellcheck disable=SC2016
S sh -c 'pidfile=$1; shift; echo $$ > "$pidfile"; exec "$@"' sh "$SWITCHD_PIDFILE" \
    env "SDE=$SDE" "SDE_INSTALL=$SDE_INSTALL" "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bf_switchd --install-dir "$SDE_INSTALL" --conf-file "$CONF" --init-mode=cold \
    --status-port 7777 --skip-port-add \
    > "$MODEL_DIR/gap_event.switchd.log" 2>&1 &

if runner_wait_ready "$SWITCHD_PIDFILE" "$MODEL_PIDFILE" "$MODEL_DIR/gap_event.switchd.log" "$MODEL_DIR/gap_event.model.log" 7777 "$PROG" 180; then
    echo "=== ready=1 ==="
else
    echo "=== ready=0 ==="
    exit 1
fi

printf '%s\n' "$SUDO_PASS" | sudo -S -p '' -E env "SDE=$SDE" "SDE_INSTALL=$SDE_INSTALL" \
    "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    "PYTHONPATH=$MODEL_DIR/pyfix:$SDE_INSTALL/lib/python3.8/site-packages:$SDE_INSTALL/lib/python3.8/site-packages/tofino" \
    PKTPY=false "$SDE/run_p4_tests.sh" -p "$PROG" \
    -t "$REPO_DIR/p4/ptf/gap_event" -f "$MODEL_DIR/ports.json" --arch tofino \
    -- --test-params="arch='tofino'"
