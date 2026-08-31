#!/usr/bin/env bash
# Rebuild and run the P1 capsule and P2 health-gate suites on the local Tofino model.
# No physical pipeline is loaded, and no process is killed unless this invocation
# recorded its exact PID and temporary config first.
set -euo pipefail
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
MODEL_DIR=/home/philip/mcp_model
REPO_DIR=/home/philip/Projects/mcp
BUILD_ROOT=$(mktemp -d /tmp/mcp-context-model.XXXXXX)
TEMPLATE=${REPO_DIR}/p4/ptf/model/model_gate_event.conf
ACTIVE_CONF=""
MODEL_PIDFILE=""
SWITCHD_PIDFILE=""
# shellcheck disable=SC1091
. "$REPO_DIR/.env"
. "$REPO_DIR/p4/ptf/model/runner_lib.sh"
runner_acquire_local_model_lock

S() { printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"; }

kill_owned() {
    pidfile=$1
    expected=$2
    conf=$3
    [ -n "$pidfile" ] && [ -f "$pidfile" ] || return 0
    pid=$(cat "$pidfile")
    case "$pid" in
        *[!0-9]*|'') echo "refusing invalid $expected pid '$pid'" >&2; return 1 ;;
    esac
    [ -d "/proc/$pid" ] || return 0
    comm=$(cat "/proc/$pid/comm" 2>/dev/null || true)
    cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
    if [ "$comm" != "$expected" ] || ! printf '%s\n' "$cmd" | grep -qF -- "$conf"; then
        echo "refusing to kill pid $pid: expected owned $expected with config $conf, got '$comm' '$cmd'" >&2
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
    [ -n "$ACTIVE_CONF" ] || return 0
    kill_owned "$SWITCHD_PIDFILE" bf_switchd "$ACTIVE_CONF"
    kill_owned "$MODEL_PIDFILE" tofino-model "$ACTIVE_CONF"
}
trap 'cleanup || true' EXIT

# Refuse shared local ownership. Cleanup below is limited to exact pidfile/config
# pairs, but fixed status/BFRT ports still mean two model sessions cannot coexist.
existing=$(pgrep -x bf_switchd; pgrep -x tofino-model) || true
if [ -n "$existing" ]; then
    echo "refusing to run: an existing bf_switchd/tofino-model process is active: $existing" >&2
    exit 2
fi

run_one() {
    prog=$1
    test_file=$2
    source="${REPO_DIR}/p4/witness/${prog}.p4"
    build_dir="${BUILD_ROOT}/${prog}"
    test_dir="${build_dir}/ptf"
    conf="${build_dir}/model.conf"
    model_log="${build_dir}/model.log"
    switchd_log="${build_dir}/switchd.log"

    cleanup
    ACTIVE_CONF=$conf
    MODEL_PIDFILE="${build_dir}/tofino-model.pid"
    SWITCHD_PIDFILE="${build_dir}/bf_switchd.pid"
    mkdir -p "$test_dir"
    cp "$test_file" "$test_dir/test.py"
    [ -f "$source" ] || { echo "missing current source: $source" >&2; return 1; }

    "$SDE_INSTALL/bin/bf-p4c" --target tofino --arch tna --verbose 2 \
        -o "$build_dir/$prog.tofino" --bf-rt-schema "$build_dir/$prog.bfrt.json" \
        "$source" > "$build_dir/build.log" 2>&1 || {
            tail -60 "$build_dir/build.log"
            return 1
        }
    jq --arg n "$prog" \
       --arg b "$build_dir/$prog.bfrt.json" \
       --arg c "$build_dir/$prog.tofino/pipe/context.json" \
       --arg f "$build_dir/$prog.tofino/pipe/tofino.bin" \
       --arg p "$build_dir/$prog.tofino" \
       --arg m "$build_dir/$prog.tofino/share/$prog/aug_model.json" \
       '.p4_devices[0].p4_programs[0]["program-name"]=$n |
        .p4_devices[0].p4_programs[0]["bfrt-config"]=$b |
        .p4_devices[0].p4_programs[0].p4_pipelines[0].context=$c |
        .p4_devices[0].p4_programs[0].p4_pipelines[0].config=$f |
        .p4_devices[0].p4_programs[0].p4_pipelines[0].path=$p |
        .p4_devices[0].p4_programs[0].model_json_path=$m' \
       "$TEMPLATE" > "$conf"

    echo "=== ${prog} current source/build ==="
    sha256sum "$source" "$build_dir/$prog.tofino/pipe/logs/table_summary.log"
    grep -E 'Number of stages|Number of tables allocated' \
        "$build_dir/$prog.tofino/pipe/logs/table_summary.log" | tail -n 5

    # The privileged child writes its own post-sudo PID before exec.
    # shellcheck disable=SC2016
    S sh -c 'pidfile=$1; shift; echo $$ > "$pidfile"; exec "$@"' sh "$MODEL_PIDFILE" \
        env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
        tofino-model --p4-target-config "$conf" --install-dir "$SDE_INSTALL" \
        -d 1 -k 1 -f "$MODEL_DIR/ports.json" --chip-type 2 --log-dir "$MODEL_DIR" \
        > "$model_log" 2>&1 &
    sleep 6
    # shellcheck disable=SC2016
    S sh -c 'pidfile=$1; shift; echo $$ > "$pidfile"; exec "$@"' sh "$SWITCHD_PIDFILE" \
        env "SDE=$SDE" "SDE_INSTALL=$SDE_INSTALL" "PATH=$PATH" \
        "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
        bf_switchd --install-dir "$SDE_INSTALL" --conf-file "$conf" --init-mode=cold \
        --status-port 7777 --skip-port-add > "$switchd_log" 2>&1 &

    if runner_wait_ready "$SWITCHD_PIDFILE" "$MODEL_PIDFILE" "$switchd_log" "$model_log" 7777 "$prog" 180; then
        echo "=== ${prog} ready=1 ==="
    else
        echo "=== ${prog} ready=0 ==="
        return 1
    fi

    printf '%s\n' "$SUDO_PASS" | sudo -S -p '' -E env "SDE=$SDE" \
        "SDE_INSTALL=$SDE_INSTALL" "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
        "PYTHONPATH=$MODEL_DIR/pyfix:$SDE_INSTALL/lib/python3.8/site-packages:$SDE_INSTALL/lib/python3.8/site-packages/tofino" \
        PKTPY=false "$SDE/run_p4_tests.sh" -p "$prog" -t "$test_dir" \
        -f "$MODEL_DIR/ports.json" --arch tofino -- --test-params="arch='tofino'"
}

run_one mcp_fabric_capsule "$REPO_DIR/p4/ptf/test_capsule.py"
run_one mcp_fabric_gate "$REPO_DIR/p4/ptf/test_health_gate.py"
