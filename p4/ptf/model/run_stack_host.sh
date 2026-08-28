#!/bin/bash
# tofino-model + bf_switchd for mcp_fabric_w4, then run "$@" (usually PTF) against them.
# The model and PTF both need CAP_NET_RAW on the veths, which is why the SDE's own wrappers
# use sudo. The password is read from the 0600 .env that .gitignore covers, is never echoed
# and never reaches a log. NOTHING HERE TOUCHES THE SHARED TOFINO SWITCH: this is the
# laptop's software model (SDE 9.13.1).
set -u
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
DIR=/home/philip/mcp_model
cd $DIR
. /home/philip/Projects/mcp/.env
S() { printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"; }

S pkill -x tofino-model 2>/dev/null; S pkill -x bf_switchd 2>/dev/null; sleep 1

( printf '%s\n' "$SUDO_PASS" | sudo -S -p '' env "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    tofino-model --p4-target-config $DIR/model_arm2.conf --install-dir $SDE_INSTALL \
    -d 1 -k 1 -f $DIR/ports.json --chip-type 2 --log-dir $DIR ) > $DIR/model.log 2>&1 &
sleep 6
( printf '%s\n' "$SUDO_PASS" | sudo -S -p '' env "SDE=$SDE" "SDE_INSTALL=$SDE_INSTALL" \
    "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" \
    bf_switchd --install-dir $SDE_INSTALL --conf-file $DIR/model_arm2.conf --init-mode=cold \
    --status-port 7777 --skip-port-add ) > $DIR/switchd.log 2>&1 &
ready=0
for i in $(seq 1 180); do
    grep -qi "bf_switchd: server started\|bfruntime grpc server started" $DIR/switchd.log 2>/dev/null && { ready=1; break; }
    sleep 1
done
echo "=== ready=$ready ==="
if [ "$ready" != "1" ]; then
    echo "--- switchd tail ---"; tail -6 $DIR/switchd.log
    echo "--- model tail ---";  tail -6 $DIR/model.log
    S pkill -x bf_switchd; S pkill -x tofino-model; exit 1
fi
grep -i "grpc server started" $DIR/switchd.log | tail -1
rc=0
if [ $# -gt 0 ]; then "$@"; rc=$?; fi
S pkill -x bf_switchd 2>/dev/null; S pkill -x tofino-model 2>/dev/null
exit $rc
