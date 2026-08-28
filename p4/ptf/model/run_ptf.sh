#!/bin/bash
# Run the W4 witness PTF suite against the already-running model stack.
set -u
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
. /home/philip/Projects/mcp/.env
printf '%s\n' "$SUDO_PASS" | sudo -S -p '' -E env "SDE=$SDE" "SDE_INSTALL=$SDE_INSTALL" \
    "PATH=$PATH" "LD_LIBRARY_PATH=$LD_LIBRARY_PATH" "PYTHONPATH=/home/philip/mcp_model/pyfix:$SDE_INSTALL/lib/python3.8/site-packages:$SDE_INSTALL/lib/python3.8/site-packages/tofino" \
    PKTPY=false $SDE/run_p4_tests.sh -p mcp_fabric_w4_arm -t /home/philip/mcp_model/ptf_w4 \
    -f /home/philip/mcp_model/ports.json --arch tofino \
    -- --test-params="arch='tofino'" 2>&1
