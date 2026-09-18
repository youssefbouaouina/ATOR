#!/usr/bin/env bash
# =============================================================================
# ATOR DFIR - Bare Linux Endpoint Automated Bootstrap & Token Enrollment
#
# Linux counterpart of bootstrap_endpoint.ps1. Idempotent bootstrap for a
# fresh Linux endpoint (Debian/Ubuntu, RHEL/Fedora/Rocky/Alma, SUSE, Alpine,
# Arch). It will:
#   1. Check the ATOR server is reachable.
#   2. Install Python 3 (+ venv/pip) if no usable Python 3.8+ is present.
#   3. Download the ATOR agent package (ator-agent-deploy.tar.gz) from the
#      server, or copy it from a local repo next to this script.
#   4. Create an isolated virtual environment and install dependencies.
#   5. Enroll using the admin-approved enrollment token.
#   6. Run a one-time verification collection.
#   7. Install a systemd service (cron @reboot fallback) so the agent runs
#      continuously.
# Every step logs to /var/log/ator_enroll.log and each step is idempotent.
#
# Usage:
#   curl -fsSL http://<server>:8000/static/bootstrap_endpoint.sh -o /tmp/ator_bootstrap.sh
#   sudo bash /tmp/ator_bootstrap.sh --server http://<server>:8000 --token <enrollment-token>
#
# Options:
#   --server URL         ATOR DFIR server URL (use its LAN IP, not 127.0.0.1)
#   --token TOKEN        enrollment token shown after the admin accepts the request
#   --install-dir DIR    install location (default /opt/ator-agent)
#   --no-persistence     do not install the systemd service / cron job
# =============================================================================
set -euo pipefail

SERVER_URL=""
ENROLLMENT_TOKEN=""
INSTALL_DIR="/opt/ator-agent"
ENABLE_PERSISTENCE=1
SERVICE_NAME="ator-agent"
LOG_FILE="/var/log/ator_enroll.log"

usage() {
    cat <<'USAGE'
Usage: sudo bash bootstrap_endpoint.sh --server URL --token TOKEN [options]
  --server URL         ATOR DFIR server URL (use its LAN IP, not 127.0.0.1)
  --token TOKEN        enrollment token shown after the admin accepts the request
  --install-dir DIR    install location (default /opt/ator-agent)
  --no-persistence     do not install the systemd service / cron job
USAGE
    exit "${1:-1}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --server|-s)        SERVER_URL="${2:-}"; shift 2 ;;
        --server=*)         SERVER_URL="${1#*=}"; shift ;;
        --token|-t)         ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
        --token=*)          ENROLLMENT_TOKEN="${1#*=}"; shift ;;
        --install-dir)      INSTALL_DIR="${2:-}"; shift 2 ;;
        --install-dir=*)    INSTALL_DIR="${1#*=}"; shift ;;
        --no-persistence)   ENABLE_PERSISTENCE=0; shift ;;
        --enable-persistence) ENABLE_PERSISTENCE=1; shift ;;
        -h|--help)          usage 0 ;;
        *) echo "Unknown option: $1" >&2; usage 1 ;;
    esac
done

if [ -z "$SERVER_URL" ] || [ -z "$ENROLLMENT_TOKEN" ]; then
    echo "ERROR: --server and --token are required." >&2
    usage 1
fi
SERVER_URL="${SERVER_URL%/}"

# --- 0. Ensure root (self-elevate once) ---------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        echo "Root privileges required. Re-launching with sudo..."
        args=(--server "$SERVER_URL" --token "$ENROLLMENT_TOKEN" --install-dir "$INSTALL_DIR")
        [ "$ENABLE_PERSISTENCE" -eq 0 ] && args+=(--no-persistence)
        exec sudo bash "$0" "${args[@]}"
    fi
    echo "ERROR: run this script as root (sudo not available)." >&2
    exit 1
fi

: > "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/ator_enroll.log"
chmod 600 "$LOG_FILE" 2>/dev/null || true
log()  { local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"; echo "[$ts] $*"; echo "[$ts] $*" >> "$LOG_FILE"; }
fail() { log "ERROR: $*"; exit 1; }

log "=== ATOR Endpoint Bootstrap Started $(date -Iseconds 2>/dev/null || date) ==="
log "Target server : $SERVER_URL"
log "Install dir   : $INSTALL_DIR"

# HTTP helper: curl preferred, wget fallback (minimal images often have one).
http_get() {  # http_get URL OUTFILE
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 10 --max-time "${3:-120}" -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T "${3:-120}" -O "$2" "$1"
    else
        return 127
    fi
}

# --- 1. Package manager + HTTP client -------------------------------------------
PKG_MGR=""
for pm in apt-get dnf yum zypper apk pacman; do
    if command -v "$pm" >/dev/null 2>&1; then PKG_MGR="$pm"; break; fi
done

pkg_install() {
    log "Installing packages via $PKG_MGR: $*"
    case "$PKG_MGR" in
        apt-get) DEBIAN_FRONTEND=noninteractive apt-get update -qq >>"$LOG_FILE" 2>&1 || true
                 DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >>"$LOG_FILE" 2>&1 ;;
        dnf)     dnf install -y -q "$@" >>"$LOG_FILE" 2>&1 ;;
        yum)     yum install -y -q "$@" >>"$LOG_FILE" 2>&1 ;;
        zypper)  zypper --non-interactive install "$@" >>"$LOG_FILE" 2>&1 ;;
        apk)     apk add --no-cache "$@" >>"$LOG_FILE" 2>&1 ;;
        pacman)  pacman -Sy --noconfirm "$@" >>"$LOG_FILE" 2>&1 ;;
        *)       return 1 ;;
    esac
}

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    pkg_install curl || fail "Neither curl nor wget is available and they could not be installed."
fi

# --- 2. Validate server URL -------------------------------------------------------
case "$SERVER_URL" in
    *127.0.0.1*|*localhost*)
        log "WARN: server URL uses loopback ($SERVER_URL). On a remote endpoint the server will NOT be reachable - use its LAN IP." ;;
esac
HEALTH_TMP="$(mktemp)"
if ! http_get "$SERVER_URL/health" "$HEALTH_TMP" 10 || ! grep -q '"ok"' "$HEALTH_TMP"; then
    rm -f "$HEALTH_TMP"
    fail "Cannot reach $SERVER_URL/health. Check the server LAN IP and firewall (allow port 8000)."
fi
rm -f "$HEALTH_TMP"
log "[OK] Server reachable: $SERVER_URL/health"

# --- 3. Python 3.8+ with venv ---------------------------------------------------
find_python() {
    local c
    for c in python3.13 python3.12 python3.11 python3.10 python3.9 python3 python3.8 python; do
        if command -v "$c" >/dev/null 2>&1 && \
           "$c" -c 'import sys, venv, ensurepip; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
            command -v "$c"
            return 0
        fi
    done
    return 1
}

PYTHON="$(find_python || true)"
if [ -z "$PYTHON" ]; then
    log "No usable Python 3.8+ with venv found. Installing..."
    case "$PKG_MGR" in
        apt-get) pkg_install python3 python3-venv python3-pip ;;
        dnf|yum) pkg_install python3 python3-pip ;;
        zypper)  pkg_install python3 python3-pip ;;
        apk)     pkg_install python3 py3-pip ;;
        pacman)  pkg_install python python-pip ;;
        *)       fail "No supported package manager found. Install Python 3.8+ with venv manually and re-run." ;;
    esac || log "WARN: default Python package install reported an error (see $LOG_FILE)."
    PYTHON="$(find_python || true)"
    # RHEL/CentOS/Rocky 8 ship Python 3.6 as python3: pull a newer stream.
    if [ -z "$PYTHON" ] && { [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; }; then
        pkg_install python3.11 python3.11-pip || pkg_install python39 python39-pip || true
        PYTHON="$(find_python || true)"
    fi
    [ -n "$PYTHON" ] || fail "No Python 3.8+ interpreter with venv/ensurepip could be installed (see $LOG_FILE)."
    log "[OK] Python installed."
fi
log "[OK] Python: $("$PYTHON" --version 2>&1) ($PYTHON)"

# --- 4. Deploy agent package ------------------------------------------------------
# Stop a previous installation first so it does not run half-upgraded code.
if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files "$SERVICE_NAME.service" >/dev/null 2>&1; then
    systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
fi

mkdir -p "$INSTALL_DIR"
AGENT_DEST="$INSTALL_DIR/agent"
CONFIG_PATH="$AGENT_DEST/config.json"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Keep credentials from a previous enrollment across the package refresh.
SAVED_CONFIG=""
if [ -f "$CONFIG_PATH" ]; then
    SAVED_CONFIG="$STAGE/config.json.saved"
    cp -p "$CONFIG_PATH" "$SAVED_CONFIG"
fi

if [ -f "$SCRIPT_DIR/agent/agent.py" ]; then
    log "Using agent package from local repo ($SCRIPT_DIR)..."
    mkdir -p "$STAGE/pkg"
    cp -R "$SCRIPT_DIR/agent" "$STAGE/pkg/agent"
    if [ -d "$SCRIPT_DIR/rules/malware" ]; then
        mkdir -p "$STAGE/pkg/rules" && cp -R "$SCRIPT_DIR/rules/malware" "$STAGE/pkg/rules/malware"
    fi
else
    log "Downloading agent package from server: $SERVER_URL/static/ator-agent-deploy.tar.gz"
    http_get "$SERVER_URL/static/ator-agent-deploy.tar.gz" "$STAGE/pkg.tar.gz" 120 \
        || fail "Could not fetch agent archive from $SERVER_URL/static/ator-agent-deploy.tar.gz"
    mkdir -p "$STAGE/pkg"
    tar -xzf "$STAGE/pkg.tar.gz" -C "$STAGE/pkg" || fail "Agent archive is corrupt."
fi
[ -f "$STAGE/pkg/agent/agent.py" ] || fail "Agent package is missing agent/agent.py."

rm -rf "$AGENT_DEST"
mv "$STAGE/pkg/agent" "$AGENT_DEST"
find "$AGENT_DEST" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
rm -f "$CONFIG_PATH"
if [ -d "$STAGE/pkg/rules" ]; then
    rm -rf "$INSTALL_DIR/rules"
    mv "$STAGE/pkg/rules" "$INSTALL_DIR/rules"
fi
if [ -n "$SAVED_CONFIG" ]; then
    cp -p "$SAVED_CONFIG" "$CONFIG_PATH"
    log "[OK] Preserved existing agent config.json."
fi
log "[OK] Agent deployed to $AGENT_DEST"

# --- 5. Create isolated venv & install deps ---------------------------------------
VENV="$INSTALL_DIR/.venv"
VENV_PY="$VENV/bin/python"
if [ ! -x "$VENV_PY" ]; then
    log "Creating virtual environment..."
    "$PYTHON" -m venv "$VENV" >>"$LOG_FILE" 2>&1 || fail "venv creation failed (see $LOG_FILE)."
fi
log "Installing agent dependencies..."
if ! "$VENV_PY" -m pip install -q --disable-pip-version-check -r "$AGENT_DEST/requirements.txt" >>"$LOG_FILE" 2>&1; then
    # Optional collectors (python-evtx, yara-python) must not block enrollment.
    log "WARN: full requirements failed, installing core deps only (requests, psutil)."
    "$VENV_PY" -m pip install -q --disable-pip-version-check requests psutil >>"$LOG_FILE" 2>&1 \
        || fail "pip install failed (see $LOG_FILE). psutil may need gcc + python3-dev if no wheel exists for this platform."
fi
log "[OK] Dependencies installed."

# --- 6. Token enrollment (idempotent) ---------------------------------------------
log "Enrolling with token: $ENROLLMENT_TOKEN"
set +e
ENROLL_OUT="$(cd "$INSTALL_DIR" && "$VENV_PY" -m agent.agent enroll --token "$ENROLLMENT_TOKEN" --server "$SERVER_URL" 2>&1)"
ENROLL_RC=$?
set -e
log "Enrollment output: $(echo "$ENROLL_OUT" | tr '\n' ' ')"
[ "$ENROLL_RC" -eq 0 ] || fail "Enrollment failed (exit $ENROLL_RC). Check that the request was accepted and the token has not been used by another host."
chmod 600 "$CONFIG_PATH" 2>/dev/null || true
log "[OK] Enrollment complete. Credentials saved to $CONFIG_PATH"

# --- 7. Verification collection ----------------------------------------------------
log "Running one-time verification collection..."
set +e
VERIFY_OUT="$(cd "$INSTALL_DIR" && "$VENV_PY" -m agent.agent once 2>&1)"
VERIFY_RC=$?
set -e
log "Verification output: $(echo "$VERIFY_OUT" | tail -n 3 | tr '\n' ' ')"
[ "$VERIFY_RC" -eq 0 ] || log "WARN: verification collection exited with $VERIFY_RC."

# --- 8. Persistent background collection (systemd, cron fallback) ------------------
if [ "$ENABLE_PERSISTENCE" -eq 1 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        log "Installing systemd service '$SERVICE_NAME' (root, starts at boot)..."
        cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=ATOR DFIR Endpoint Agent (continuous collection)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$VENV_PY -m agent.agent loop
Environment=PYTHONUNBUFFERED=1
Restart=always
RestartSec=30
Nice=10
CPUQuota=20%
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME" >>"$LOG_FILE" 2>&1
        systemctl restart "$SERVICE_NAME"
        sleep 2
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log "[OK] systemd service '$SERVICE_NAME' enabled and running."
        else
            log "WARN: service '$SERVICE_NAME' is not active - check: journalctl -u $SERVICE_NAME"
        fi
    elif command -v crontab >/dev/null 2>&1; then
        log "systemd not available - installing root cron @reboot job instead..."
        CRON_LINE="@reboot cd $INSTALL_DIR && $VENV_PY -m agent.agent loop >> /var/log/ator-agent.log 2>&1"
        ( crontab -l 2>/dev/null | grep -v 'agent.agent loop' || true; echo "$CRON_LINE" ) | crontab -
        pkill -f "$VENV_PY -m agent.agent loop" 2>/dev/null || true
        ( cd "$INSTALL_DIR" && nohup "$VENV_PY" -m agent.agent loop >> /var/log/ator-agent.log 2>&1 & )
        log "[OK] cron @reboot job installed and agent loop started."
    else
        log "WARN: neither systemd nor cron found. Start the agent manually:"
        log "      cd $INSTALL_DIR && $VENV_PY -m agent.agent loop"
    fi
fi

log "=== ATOR Endpoint Bootstrap Completed Successfully ==="
echo ""
echo "[SUCCESS] Endpoint enrolled. Check /endpoints in the dashboard."
echo "Full log: $LOG_FILE"
