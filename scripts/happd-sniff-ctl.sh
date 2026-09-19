#!/usr/bin/env bash
# Dev tool: record the Happ GUI <-> happd protocol by proxying /tmp/happd.sock.
#
#   sudo bash scripts/happd-sniff-ctl.sh start
#       then: FULLY quit the Happ GUI, start it again, press «Connect»,
#       wait ~10 s, press «Disconnect»
#   sudo bash scripts/happd-sniff-ctl.sh stop
#
# The capture lands in /tmp/happd-sniff.log (may contain session keys —
# it stays local, delete it after analysis).
set -euo pipefail
umask 077  # captures may contain session keys — never group/other readable

SOCK=/tmp/happd.sock
REAL=/tmp/happd-real.sock
PIDFILE=/tmp/happd-sniff.pid
LOG=/tmp/happd-sniff.log
PROXY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/happd-sniff.py"

start() {
    [[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
    pgrep -x happd >/dev/null || { echo "happd is not running — start Happ first"; exit 1; }
    [[ -S $SOCK && ! -S $REAL ]] || { echo "unexpected socket state:"; ls -la /tmp/happd* 2>&1; exit 1; }
    mv "$SOCK" "$REAL"
    nohup python3 "$PROXY" >"${LOG}.boot" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 0.5
    [[ -S $SOCK ]] || { echo "proxy failed to start:"; cat "${LOG}.boot"; exit 1; }
    chmod 600 "$LOG" 2>/dev/null || true
    echo "sniffing -> $LOG"
    echo "now: fully quit Happ GUI, start it again, press «Connect», wait ~10 s, «Disconnect»"
}

stop() {
    [[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
    [[ -f $PIDFILE ]] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE" "$SOCK"
    if pgrep -x happd >/dev/null && [[ -S $REAL ]]; then
        # original daemon still holds the moved inode — put the path back
        mv "$REAL" "$SOCK"
        echo "restored $SOCK"
    else
        rm -f "$REAL"
        echo "happd respawned or died; stale sockets removed"
        echo "if Happ misbehaves: fully quit and start it again"
    fi
}

case "${1:-}" in
    start) start ;;
    stop) stop ;;
    *) grep '^#' "$0" | head -8; exit 1 ;;
esac
