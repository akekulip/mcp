#!/usr/bin/env bash
# Run a command as root on Vision or Hulk without ever putting the password on a
# command line, in the process table, or on the terminal.
#
# WHY THIS EXISTS.  Vision and Hulk need password SSH, so we go through sshpass --
# and sshpass allocates its own pty for the SSH password prompt, which SWALLOWS
# piped stdin.  So `printf pw | sshpass ssh host 'sudo -S ...'` reaches sudo with
# nothing at all and fails as "no password was provided", which reads like a wrong
# password and is not.  Forcing a remote TTY with -tt does deliver the password,
# but the TTY then ECHOES it -- that leaked a credential into a session transcript
# once.  The combination that is both functional and safe is: -tt to get stdin
# through, `stty -echo` on the remote before sudo reads, and all output captured to
# a file rather than streamed back.
#
#   usage: host_run.sh <vision|hulk|IP> '<shell command run as root>'
#          host_run.sh vision 'ip -br addr show enp59s0f0np0'      # no sudo needed
#          host_run.sh --user vision 'ip -br addr'                 # run unprivileged
set -u
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
AS_ROOT=1
[ "${1:-}" = "--user" ] && { AS_ROOT=0; shift; }
TARGET="${1:?usage: host_run.sh [--user] <vision|hulk|IP> '<command>'}"; shift
CMD="${*:?no command given}"

if [ -f "$REPO/.env" ]; then
    set -a
    # shellcheck source=/dev/null
    . "$REPO/.env"
    set +a
fi
# shellcheck source=/dev/null
. "$HOME/.lab_env" 2>/dev/null || true
: "${SSHPASS:?SSHPASS not set — source ~/.lab_env}"
: "${HOST_SUDO_PASS:?HOST_SUDO_PASS not set — see .env}"
USER_NAME="${HOST_SUDO_USER:-decps}"

case "$TARGET" in
    vision) IP=10.10.54.166 ;;
    hulk)   IP=10.10.54.158 ;;
    *)      IP="$TARGET" ;;
esac

REMOTE_OUT="/tmp/host_run.$$.out"
if [ "$AS_ROOT" -eq 1 ]; then
    printf '%s\n' "$HOST_SUDO_PASS" | sshpass -e ssh -tt \
        -o StrictHostKeyChecking=no -o ConnectTimeout=15 "$USER_NAME@$IP" \
        "stty -echo 2>/dev/null; sudo -S -k -p '' bash -c $(printf '%q' "$CMD") > $REMOTE_OUT 2>&1; \
         echo \$? > $REMOTE_OUT.rc; stty echo 2>/dev/null; exit" >/dev/null 2>&1
else
    sshpass -e ssh -o StrictHostKeyChecking=no -o ConnectTimeout=15 "$USER_NAME@$IP" \
        "bash -c $(printf '%q' "$CMD") > $REMOTE_OUT 2>&1; echo \$? > $REMOTE_OUT.rc" >/dev/null 2>&1
fi

# Fetch output and exit status separately, then remove them from the host.  Keep the
# SSH status: piping directly through tr used to mask fetch failures.  Also fail closed
# if the remote .rc file is absent; `exit ---RC---` previously hid the real harness
# failure behind bash's "numeric argument required" diagnostic.
LOCAL_RAW="/tmp/host_run.raw.$$"
LOCAL_OUT="/tmp/host_run.local.$$"
if ! sshpass -e ssh -o StrictHostKeyChecking=no "$USER_NAME@$IP" \
    "cat $REMOTE_OUT 2>/dev/null; echo '---RC---'; cat $REMOTE_OUT.rc 2>/dev/null; \
     rm -f $REMOTE_OUT $REMOTE_OUT.rc" > "$LOCAL_RAW" 2>/dev/null; then
    rm -f "$LOCAL_RAW" "$LOCAL_OUT"
    echo "host_run: could not fetch remote output or exit status" >&2
    exit 1
fi
tr -d '\r' < "$LOCAL_RAW" > "$LOCAL_OUT"
rm -f "$LOCAL_RAW"

sed '/^---RC---$/,$d' "$LOCAL_OUT"
RC=$(sed -n '/^---RC---$/,$p' "$LOCAL_OUT" | sed '1d')
rm -f "$LOCAL_OUT"
case "$RC" in
    ''|*[!0-9]*)
        echo "host_run: missing or invalid remote exit status" >&2
        exit 1
        ;;
esac
[ "$RC" -le 255 ] || {
    echo "host_run: missing or invalid remote exit status" >&2
    exit 1
}
exit "$RC"
