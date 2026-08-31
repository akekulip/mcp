#!/usr/bin/env bash

runner_proc_root() {
    printf '%s\n' "${MODEL_RUNNER_PROC_ROOT:-/proc}"
}

runner_acquire_local_model_lock() {
    lock_path=${MODEL_RUNNER_LOCK_PATH:-/tmp/mcp-tofino-model.lock}
    exec 8>"$lock_path"
    if ! flock -n 8; then
        echo "another local Tofino model runner holds $lock_path; refusing fixed-port overlap" >&2
        return 1
    fi
}

runner_pid_alive() {
    pid=$1
    proc_root=$(runner_proc_root)
    case "$pid" in
        *[!0-9]*|'') return 1 ;;
    esac
    [ -d "${proc_root}/${pid}" ]
}

runner_read_pid() {
    pidfile=$1
    [ -f "$pidfile" ] || return 1
    pid=$(tr -d '[:space:]' < "$pidfile")
    case "$pid" in
        *[!0-9]*|'') return 1 ;;
    esac
    printf '%s\n' "$pid"
}

runner_switchd_log_has_fatal_readiness_error() {
    log=$1
    [ -f "$log" ] || return 1
    grep -Eiq \
        "No address added out of total .*0\.0\.0\.0:50052|Address already in use|BF-RT Server Failed to start Server on 0\.0\.0\.0:50052|Failed to start bfrt grpc server" \
        "$log"
}

runner_status_port_listens() {
    port=$1
    ss -ltn 2>/dev/null | grep -Eq "(^|[[:space:]])[^[:space:]]*:${port}([[:space:]]|$)"
}

runner_bfrt_probe_ready() {
    program=$1
    grpc_port=$2
    python_bin=${MODEL_RUNNER_PYTHON:-python3}
    probe_pythonpath=${PYTHONPATH:-}
    if [ -n "${SDE_INSTALL:-}" ]; then
        probe_pythonpath="${SDE_INSTALL}/lib/python3.8/site-packages:${SDE_INSTALL}/lib/python3.8/site-packages/tofino:${probe_pythonpath}"
    fi
    PYTHONPATH=$probe_pythonpath "$python_bin" - "$program" "$grpc_port" <<'PY'
import sys

program = sys.argv[1]
grpc_port = sys.argv[2]

try:
    import bfrt_grpc.client as gc

    iface = gc.ClientInterface("localhost:%s" % grpc_port, client_id=0, device_id=0)
    iface.bind_pipeline_config(program)
    iface.bfrt_info_get(program)
except Exception as exc:
    print("BFRT probe failed: %s" % exc, file=sys.stderr)
    raise SystemExit(1)
PY
}

runner_tail_logs() {
    switchd_log=$1
    model_log=$2
    [ -f "$switchd_log" ] && tail -20 "$switchd_log"
    [ -f "$model_log" ] && tail -20 "$model_log"
}

runner_wait_ready() {
    switchd_pidfile=$1
    model_pidfile=$2
    switchd_log=$3
    model_log=$4
    status_port=$5
    program=$6
    timeout=$7

    case "$timeout" in
        *[!0-9]*|'') echo "invalid readiness timeout: $timeout" >&2; return 1 ;;
    esac

    for _ in $(seq 1 "$timeout"); do
        if runner_switchd_log_has_fatal_readiness_error "$switchd_log"; then
            echo "fatal bf_switchd readiness log; refusing to start PTF" >&2
            runner_tail_logs "$switchd_log" "$model_log" >&2
            return 1
        fi

        switchd_pid=$(runner_read_pid "$switchd_pidfile" 2>/dev/null || true)
        model_pid=$(runner_read_pid "$model_pidfile" 2>/dev/null || true)
        if [ -n "$switchd_pid" ] && [ -n "$model_pid" ] \
           && runner_pid_alive "$switchd_pid" \
           && runner_pid_alive "$model_pid" \
           && runner_status_port_listens "$status_port" \
           && runner_bfrt_probe_ready "$program" 50052; then
            return 0
        fi
        sleep 1
    done

    if runner_switchd_log_has_fatal_readiness_error "$switchd_log"; then
        echo "fatal bf_switchd readiness log; refusing to start PTF" >&2
    else
        echo "timed out waiting for bf_switchd readiness" >&2
    fi
    runner_tail_logs "$switchd_log" "$model_log" >&2
    return 1
}
