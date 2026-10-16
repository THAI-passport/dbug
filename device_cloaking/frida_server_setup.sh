#!/usr/bin/env bash
# frida_server_setup.sh: Manages the Frida server on the rooted Android test device
# for Gate G4 stealth dynamic instrumentation.
#
# STEALTH REQUIREMENTS (AGENTS.md):
#   - Frida runs on a non-standard port (38921, not the default 27042) so
#     infostealers querying /proc/net/tcp do not detect the standard Frida port.
#   - The frida-server binary is renamed (default: hl_daemon) so its process
#     name does not fingerprint a Frida session.
#
# Usage:
#   frida_server_setup.sh install [--binary /path/to/frida-server] [--port 38921] [--name hl_daemon] [--serial SERIAL]
#   frida_server_setup.sh start   [--port 38921] [--name hl_daemon] [--serial SERIAL]
#   frida_server_setup.sh stop    [--name hl_daemon] [--serial SERIAL]
#   frida_server_setup.sh status  [--port 38921] [--name hl_daemon] [--serial SERIAL]
#   frida_server_setup.sh --dry-run <action>
set -euo pipefail

ACTION="install"
DRY_RUN=false
SERIAL=""
REMOTE_DIR="/data/local/tmp"
DAEMON_NAME="hl_daemon"
FRIDA_PORT="38921"
FRIDA_SERVER_BIN=""

log() { echo "[*] $*"; }
ok()  { echo "[+] $*"; }
err() { echo "[!] $*" >&2; }

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        install|start|stop|status)
            ACTION="$1"; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --binary) FRIDA_SERVER_BIN="$2"; shift 2 ;;
        --port) FRIDA_PORT="$2"; shift 2 ;;
        --name) DAEMON_NAME="$2"; shift 2 ;;
        --serial) SERIAL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 {install|start|stop|status} [--dry-run] [--binary path] [--port 38921] [--name hl_daemon] [--serial SERIAL]"; exit 0 ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

adb_cmd() {
    local args=("adb")
    [[ -n "$SERIAL" ]] && args+=("-s" "$SERIAL")
    args+=("$@")
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY-RUN] adb ${args[*]}"
        return 0
    fi
    "${args[@]}"
}

run() {
    if [[ "$DRY_RUN" == true ]]; then
        echo "[DRY-RUN] $*"
    else
        "$@"
    fi
}

case "$ACTION" in
    install)
        log "Installing Frida server on device (stealth port ${FRIDA_PORT}, daemon name ${DAEMON_NAME})..."
        if [[ -z "$FRIDA_SERVER_BIN" ]]; then
            # Auto-discover a host frida-server binary
            for cand in \
                "$HOME/.local/share/frida-server/frida-server" \
                "/usr/local/share/frida-server/frida-server" \
                "./frida-server" \
                "/opt/frida-server/frida-server"; do
                if [[ -f "$cand" ]]; then FRIDA_SERVER_BIN="$cand"; break; fi
            done
        fi
        if [[ -z "$FRIDA_SERVER_BIN" || ! -f "$FRIDA_SERVER_BIN" ]]; then
            err "frida-server binary not found. Download the Android ARM64 frida-server from"
            err "https://github.com/frida/frida/releases and pass it with --binary."
            exit 1
        fi
        ok "Using frida-server binary: $FRIDA_SERVER_BIN"

        log "Pushing frida-server to ${REMOTE_DIR}/${DAEMON_NAME} ..."
        run adb_cmd push "$FRIDA_SERVER_BIN" "${REMOTE_DIR}/${DAEMON_NAME}"
        run adb_cmd shell chmod 755 "${REMOTE_DIR}/${DAEMON_NAME}"
        ok "Frida server installed as ${REMOTE_DIR}/${DAEMON_NAME}"
        ;;

    start)
        log "Starting Frida server on port ${FRIDA_PORT} ..."
        # Kill any previously running instance with the stealth name
        run adb_cmd shell "pkill -f '${DAEMON_NAME}' 2>/dev/null || true"
        run adb_cmd shell "${REMOTE_DIR}/${DAEMON_NAME} -l 0.0.0.0:${FRIDA_PORT} >/dev/null 2>&1 &"
        sleep 1
        ok "Frida server start requested on port ${FRIDA_PORT}"
        ;;

    stop)
        log "Stopping Frida server (${DAEMON_NAME}) ..."
        run adb_cmd shell "pkill -f '${DAEMON_NAME}' 2>/dev/null || true"
        ok "Frida server stopped"
        ;;

    status)
        log "Checking Frida server status ..."
        PID=$(adb_cmd shell "pidof ${DAEMON_NAME}" 2>/dev/null || true)
        if [[ -n "$PID" ]]; then
            ok "Frida server RUNNING (PID ${PID}, daemon ${DAEMON_NAME})"
            exit 0
        else
            err "Frida server NOT running"
            exit 1
        fi
        ;;
esac