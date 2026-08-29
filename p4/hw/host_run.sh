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

set -a; . "$REPO/.env"; set +a
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

# fetch output and exit status separately, then remove them from the host
sshpass -e ssh -o StrictHostKeyChecking=no "$USER_NAME@$IP" \
    "cat $REMOTE_OUT 2>/dev/null; echo '---RC---'; cat $REMOTE_OUT.rc 2>/dev/null; \
     rm -f $REMOTE_OUT $REMOTE_OUT.rc" 2>/dev/null | tr -d '\r' > "/tmp/host_run.local.$$"
sed '/^---RC---$/,$d' "/tmp/host_run.local.$$"
RC=$(sed -n '/^---RC---$/,$p' "/tmp/host_run.local.$$" | tail -1)
rm -f "/tmp/host_run.local.$$"
exit "${RC:-1}"
