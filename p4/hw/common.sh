# shellcheck shell=bash
# shellcheck disable=SC2034   # sourced library: every var here is read by the sourcing script
# common.sh — shared plumbing for the p4/hw deploy driver.  SOURCED, never executed.
#
# Every remote call in p4/hw goes through hw_ssh_script / hw_scp_up / hw_scp_down.
# Nothing else in this directory may invoke `ssh` or `scp` directly, because that is
# what makes --dry-run a *structural* guarantee rather than a promise:
#
#     grep -nE '(^|[^_[:alnum:]])(ssh|scp)[[:space:]]' p4/hw/*.sh
#
# returns hits only inside these three functions, and each one returns early when
# DRY_RUN=1.  The proof required by the campaign plan (a PATH shim that logs and
# fails on any ssh/scp) exercises exactly that.
#
# Local mutation is funnelled the same way through hw_mkdir / hw_write_file.

# --------------------------------------------------------------------------- config
SWITCH_USER=${SWITCH_USER:-decps}
SWITCH_HOST=${SWITCH_HOST:-10.10.54.81}
SWITCH=${SWITCH:-${SWITCH_USER}@${SWITCH_HOST}}

# SDE on the SWITCH.  The laptop's 9.13.1 is reference only (CLAUDE.md); every
# compile and every run in this directory happens on the switch's 9.13.2.
SDE=${SDE:-/home/decps/Downloads/bf-sde-9.13.2}
SDE_INSTALL=${SDE_INSTALL:-${SDE}/install}

# p4/witness/build.sh hardcodes `cd /home/decps/mcp_m2_gate`, so REMOTE_DIR is not
# free.  deploy.sh checks this and fails loudly rather than compiling somewhere the
# build script will not look.
REMOTE_DIR=${REMOTE_DIR:-/home/decps/mcp_m2_gate}
BUILD_SH_PINNED_DIR=/home/decps/mcp_m2_gate

GRPC_ADDR=${GRPC_ADDR:-localhost:50052}
GRPC_PORT=${GRPC_PORT:-50052}

# The exact readiness line, taken from the SDE binary itself
# (strings install/lib/libdriver.so | grep 'gRPC server'), not from memory:
#     "bfruntime gRPC server started on %s"
BFRT_READY_RE=${BFRT_READY_RE:-'bfruntime gRPC server started on'}

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10)

# The virtual fabric's physical ports, mirroring setup_skeleton.py.  LOOP_PAIRS are
# the cage-5 <-> cage-6 DAC lanes: 5/k = dev_port 164+k, 6/k = dev_port 172+k.
HOST_DPS=(9 10)
LOOP_PAIRS=("164:172" "165:173" "166:174" "167:175")

HW_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd -- "${HW_DIR}/../.." && pwd)
ARTIFACT_DIR=${ARTIFACT_DIR:-${HW_DIR}/artifacts}
SNAPSHOT_DIR=${SNAPSHOT_DIR:-${HW_DIR}/snapshots}

DRY_RUN=${DRY_RUN:-0}

# --------------------------------------------------------------------------- output
hw_die()  { printf 'FATAL: %s\n' "$*" >&2; exit 1; }
hw_step() { printf '\n== %s\n' "$*"; }
hw_info() { printf '   %s\n' "$*"; }
hw_warn() { printf '   WARNING: %s\n' "$*"; }
hw_fail() { printf '   FAIL: %s\n' "$*" >&2; }
hw_pass() { printf '   PASS: %s\n' "$*"; }

is_dry() { [ "$DRY_RUN" = 1 ]; }

# fd 3 is the "narration" channel.  Dry-run banners go there so that a caller doing
# `out=$(hw_ssh_script ...)` still SEES the plan on the terminal while capturing an
# empty result, instead of capturing the banner and parsing it as remote output.
hw_open_narration() { exec 3>&1; }
hw_say() { printf '%s\n' "$*" >&3; }

# ------------------------------------------------------------------ remote (guarded)
# hw_ssh_script_on <host> <label>   ; the remote bash script arrives on stdin.
hw_ssh_script_on() {
    local host=$1 label=$2 script
    script=$(cat)
    if is_dry; then
        hw_say "[dry-run] ssh ${host} -- bash -s        # ${label}"
        printf '%s\n' "$script" | sed 's/^/[dry-run] | /' >&3
        return 0
    fi
    printf '%s\n' "$script" | ssh "${SSH_OPTS[@]}" "$host" "bash -s"
}

# hw_ssh_script <label>   ; same, against $SWITCH.
hw_ssh_script() {
    hw_ssh_script_on "$SWITCH" "$1"
}

# hw_scp_up <local> <remote-path>
hw_scp_up() {
    if is_dry; then
        hw_say "[dry-run] scp $1 ${SWITCH}:$2"
        return 0
    fi
    scp "${SSH_OPTS[@]}" "$1" "${SWITCH}:$2"
}

# hw_scp_down <remote-path> <local>
hw_scp_down() {
    if is_dry; then
        hw_say "[dry-run] scp ${SWITCH}:$1 $2"
        return 0
    fi
    scp "${SSH_OPTS[@]}" "${SWITCH}:$1" "$2"
}

# ------------------------------------------------------------------- local (guarded)
hw_mkdir() {
    if is_dry; then
        hw_say "[dry-run] mkdir -p $1"
        return 0
    fi
    mkdir -p "$1"
}

# hw_write_file <path>   ; content on stdin
hw_write_file() {
    if is_dry; then
        hw_say "[dry-run] would write local file $1"
        cat >/dev/null
        return 0
    fi
    cat >"$1"
}

# --------------------------------------------------------------------------- argv
# hw_parse_common_flag <flag> <value>  -> 0 if consumed, and sets HW_SHIFT to the
# number of argv words eaten.
HW_SHIFT=1
hw_parse_common_flag() {
    HW_SHIFT=1
    case $1 in
        --dry-run)    DRY_RUN=1; return 0 ;;
        --switch)     SWITCH=${2:?--switch needs a value};     HW_SHIFT=2; return 0 ;;
        --remote-dir) REMOTE_DIR=${2:?--remote-dir needs a value}; HW_SHIFT=2; return 0 ;;
        *)            return 1 ;;
    esac
}

hw_banner() {
    printf '=== %s\n' "$1"
    printf '    switch      : %s\n' "$SWITCH"
    printf '    remote dir  : %s\n' "$REMOTE_DIR"
    printf '    SDE         : %s\n' "$SDE"
    if is_dry; then
        printf '    MODE        : DRY RUN — no ssh, no scp, no local writes\n'
    else
        printf '    MODE        : LIVE\n'
    fi
}
