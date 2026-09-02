#!/bin/bash
set -u
P="$1"
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
cd "$(dirname "$0")" || exit 9
rm -rf "${P}.tofino" "${P}.bfrt.json"
$SDE_INSTALL/bin/bf-p4c --target tofino --arch tna --verbose 2 \
  -o "${P}.tofino" --bf-rt-schema "${P}.bfrt.json" "${P}.p4" > "${P}.build.log" 2>&1
echo "EXIT=$?"
