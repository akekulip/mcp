#!/bin/bash
# Run the P3 gap-event suite on the local Tofino software model. No physical pipeline is loaded.
set -u
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
MODEL_DIR=/home/philip/mcp_model
REPO_DIR=/home/philip/Projects/mcp
CONF=$REPO_DIR/p4/ptf/model/model_gate_event.conf
. $REPO_DIR/.env
S() { printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"; }
cleanup() {
    S pkill -x bf_switchd 2>/dev/null || true
    S pkill -x tofino-model 2>/dev/null || true
}
trap cleanup EXIT

cleanup
sleep 1
( printf '%s\n' "$SUDO_PASS" | sudo -S -p '' env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    tofino-model --p4-target-config "$CONF" --install-dir "$SDE_INSTALL" \
    -d 1 -k 1 -f "$MODEL_DIR/ports.json" --chip-type 2 --log-dir "$MODEL_DIR" \
  ) > "$MODEL_DIR/gap_event.model.log" 2>&1 &
sleep 6
( printf '%s\n' "$SUDO_PASS" | sudo -S -p '' env "SDE=$SDE" "SDE_INSTALL=$SDE_INSTALL" \
    "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bf_switchd --install-dir "$SDE_INSTALL" --conf-file "$CONF" --init-mode=cold \
    --status-port 7777 --skip-port-add \
  ) > "$MODEL_DIR/gap_event.switchd.log" 2>&1 &

ready=0
for _ in $(seq 1 180); do
    if grep -qi "bf_switchd: server started\|bfruntime grpc server started" \
        "$MODEL_DIR/gap_event.switchd.log" 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
echo "=== ready=$ready ==="
if [ "$ready" != "1" ]; then
    tail -20 "$MODEL_DIR/gap_event.switchd.log"
    tail -20 "$MODEL_DIR/gap_event.model.log"
    exit 1
fi

printf '%s\n' "$SUDO_PASS" | sudo -S -p '' -E env "SDE=$SDE" "SDE_INSTALL=$SDE_INSTALL" \
    "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    "PYTHONPATH=$MODEL_DIR/pyfix:$SDE_INSTALL/lib/python3.8/site-packages:$SDE_INSTALL/lib/python3.8/site-packages/tofino" \
    PKTPY=false "$SDE/run_p4_tests.sh" -p mcp_fabric_gate_event \
    -t "$REPO_DIR/p4/ptf/gap_event" -f "$MODEL_DIR/ports.json" --arch tofino \
    -- --test-params="arch='tofino'"
