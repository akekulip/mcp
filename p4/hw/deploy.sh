#!/usr/bin/env bash
# deploy.sh — ship one P4 program to the switch, verify it arrived byte-identical,
# compile it there (compile only — the chip is never touched), and print the stage
# counts from the compiler's own table_summary.log.
#
# Two things this script is deliberately fussy about, because both have bitten this
# project already:
#
#  1. It reads stage counts from  <prog>.tofino/pipe/logs/table_summary.log , NOT
#     from context.json.  And it reports the "Number of stages" COUNT, printing the
#     highest zero-based stage INDEX beside it so the two can never be confused
#     again — a published number once came from exactly that confusion.  The count
#     must equal the highest index + 1; if it does not, the script says so.
#  2. It sha256s every shipped file on BOTH sides before compiling and aborts on any
#     mismatch.  A truncated scp that still compiles is the worst possible outcome.
#
# Usage:
#   p4/hw/deploy.sh <program> [--dry-run] [--switch user@host] [--remote-dir DIR]
#
# <program> is a bare name, e.g. mcp_fabric_gate_event; the source is looked up as
# p4/witness/<program>.p4 and then p4/<program>.p4.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=p4/hw/common.sh
. "${HERE}/common.sh"
hw_open_narration

PROG=""
while [ $# -gt 0 ]; do
    if hw_parse_common_flag "$1" "${2:-}"; then
        shift "$HW_SHIFT"
        continue
    fi
    case $1 in
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        -*)        hw_die "unknown flag: $1" ;;
        *)         [ -z "$PROG" ] || hw_die "only one program name accepted"; PROG=$1; shift ;;
    esac
done
[ -n "$PROG" ] || hw_die "usage: deploy.sh <program> [--dry-run]"

hw_banner "deploy ${PROG}"

# --------------------------------------------------------------- 1. local inputs
SRC=""
for cand in "${REPO_ROOT}/p4/witness/${PROG}.p4" "${REPO_ROOT}/p4/${PROG}.p4"; do
    [ -f "$cand" ] && { SRC=$cand; break; }
done
[ -n "$SRC" ] || hw_die "no source for ${PROG}: looked in p4/witness/ and p4/"

BUILD_SH="${REPO_ROOT}/p4/witness/build.sh"
[ -f "$BUILD_SH" ] || hw_die "missing build input ${BUILD_SH}"

# build.sh hardcodes its working directory.  Refuse rather than compile into a
# directory the build script will not cd to.
if [ "$REMOTE_DIR" != "$BUILD_SH_PINNED_DIR" ]; then
    hw_die "p4/witness/build.sh hardcodes 'cd ${BUILD_SH_PINNED_DIR}', so --remote-dir ${REMOTE_DIR} would compile in the wrong place. Change build.sh (out of scope here) or drop --remote-dir."
fi

SHIP=("$SRC" "$BUILD_SH")

hw_step "1. build inputs and local sha256"
LOCAL_MANIFEST=""
for f in "${SHIP[@]}"; do
    sum=$(sha256sum "$f" | cut -d' ' -f1)
    base=$(basename "$f")
    hw_info "$(printf '%-64s %s' "$sum" "$base")"
    LOCAL_MANIFEST="${LOCAL_MANIFEST}${sum}  ${base}"$'\n'
done

# --------------------------------------------------------------- 2. ship
hw_step "2. ship to ${SWITCH}:${REMOTE_DIR}"
hw_ssh_script "mkdir remote dir" <<EOF
set -eu
mkdir -p '${REMOTE_DIR}'
EOF
for f in "${SHIP[@]}"; do
    hw_scp_up "$f" "${REMOTE_DIR}/$(basename "$f")"
done

# --------------------------------------------------------------- 3. verify sha256
hw_step "3. verify sha256 on the switch (fail loudly on any mismatch)"
REMOTE_MANIFEST=$(hw_ssh_script "remote sha256" <<EOF
set -eu
cd '${REMOTE_DIR}'
sha256sum $(printf "'%s' " "${SHIP[@]##*/}")
EOF
) || hw_die "could not read back the shipped files on ${SWITCH}"
if is_dry; then
    hw_say "[dry-run] would then compare, line for line, against the local sums above:"
    printf '%s' "$LOCAL_MANIFEST" | sed 's/^/[dry-run] | /' >&3
    hw_say "[dry-run] any difference aborts before the compiler is invoked."
else
    printf '%s\n' "$REMOTE_MANIFEST" | sed 's/^/   remote: /'
    bad=0
    while read -r sum base; do
        [ -n "$sum" ] || continue
        got=$(printf '%s\n' "$REMOTE_MANIFEST" | awk -v b="$base" '$2==b {print $1}')
        if [ "$got" != "$sum" ]; then
            hw_fail "sha256 mismatch for ${base}: local ${sum} remote ${got:-<absent>}"
            bad=1
        fi
    done <<<"$LOCAL_MANIFEST"
    [ "$bad" = 0 ] || hw_die "shipped files do not match — refusing to build"
    hw_pass "all ${#SHIP[@]} shipped files match on both sides"
fi

# --------------------------------------------------------------- 4. compile only
hw_step "4. compile on the switch SDE (compile only — the chip is not touched)"
BUILD_OUT=$(hw_ssh_script "bf-p4c compile" <<EOF
set -u
cd '${REMOTE_DIR}'
bash build.sh '${PROG}'
EOF
) || { printf '%s\n' "$BUILD_OUT"; hw_die "bf-p4c build failed for ${PROG}"; }
if is_dry; then
    hw_say "[dry-run] would then require 'bf-p4c exit status: 0' in the build output."
else
    printf '%s\n' "$BUILD_OUT" | sed 's/^/   /'
    hw_pass "bf-p4c exit status 0"
fi

# --------------------------------------------------------------- 5. stage counts
hw_step "5. stage counts from pipe/logs/table_summary.log (NOT context.json)"
SUMMARY=$(hw_ssh_script "table_summary.log" <<EOF
set -eu
LOG='${REMOTE_DIR}/${PROG}.tofino/pipe/logs/table_summary.log'
if [ ! -f "\$LOG" ]; then
    echo "MISSING \$LOG"
    echo "  (bf-p4c writes pipe/logs/ only with --verbose 2; build.sh passes it)"
    exit 7
fi
grep -E 'Number of stages' "\$LOG"
grep -E 'Number of tables allocated' "\$LOG" || true
awk -F'|' '\$2 ~ /^ *[0-9]+ *\$/ { n=\$2+0; if (n>m) m=n } END { printf "max_stage_index: %d\n", m+0 }' "\$LOG"
EOF
) || { printf '%s\n' "$SUMMARY" | sed 's/^/   /'; hw_die "table_summary.log unreadable for ${PROG}"; }
if is_dry; then
    hw_say "[dry-run] would then parse:"
    hw_say "[dry-run] |   'Number of stages in table allocation: N'      <- the COUNT, this is what we publish"
    hw_say "[dry-run] |   'Number of stages for ingress/egress ...'      <- per-direction COUNTS"
    hw_say "[dry-run] |   'max_stage_index: M'                          <- highest ZERO-BASED index in the table body"
    hw_say "[dry-run] and require N == M + 1, printing both so the two can never be confused."
else
    printf '%s\n' "$SUMMARY" | sed 's/^/   /'
    N_STAGES=$(printf '%s\n' "$SUMMARY" | awk -F': *' '/Number of stages in table allocation/ {print $2+0}')
    MAX_IDX=$(printf '%s\n' "$SUMMARY" | awk -F': *' '/max_stage_index/ {print $2+0}')
    hw_info ""
    hw_info "stage COUNT              = ${N_STAGES}"
    hw_info "highest stage INDEX      = ${MAX_IDX}   (zero-based; count = index + 1)"
    if [ "$N_STAGES" = "$((MAX_IDX + 1))" ]; then
        hw_pass "count and index agree — publish ${N_STAGES}, never ${MAX_IDX}"
    else
        hw_warn "count ${N_STAGES} != index ${MAX_IDX} + 1 — read the log by hand before quoting either"
    fi
fi

hw_step "done"
hw_info "artifacts on the switch: ${REMOTE_DIR}/${PROG}.tofino , ${PROG}.bfrt.json , ${PROG}.build.log"
if is_dry; then
    hw_info "[dry-run] nothing was executed: no ssh, no scp, no local write."
fi
