#!/bin/bash
# Compile one variant on the switch's SDE 9.13.2.  Compile only: never touches the chip.
set -u
PROG="$1"
export SDE=/home/decps/Downloads/bf-sde-9.13.2
export SDE_INSTALL=$SDE/install
cd /home/decps/mcp_m2_gate || exit 9
rm -rf "${PROG}.tofino" "${PROG}.bfrt.json"
$SDE_INSTALL/bin/bf-p4c --target tofino --arch tna --verbose 2 \
    -o "${PROG}.tofino" --bf-rt-schema "${PROG}.bfrt.json" \
    "${PROG}.p4" > "${PROG}.build.log" 2>&1
st=$?
echo "=== bf-p4c exit status: $st ==="
echo "--- last 60 lines of ${PROG}.build.log ---"
tail -60 "${PROG}.build.log"
exit $st
