#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  RedVector AI v8.0 - Unified Launcher
#  Auto-starts the backend server (if not running) then launches the MCP client.
#  Used by Claude Desktop / AI agents via redvector-mcp.json.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Resolve the directory where this script lives (works with symlinks too)
SCRIPT_SOURCE="$(realpath -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname -- "$SCRIPT_SOURCE")" && pwd -P)"
cd "$SCRIPT_DIR"

# Configurable
SERVER_PORT="${REDVECTOR_PORT:-8888}"
SERVER_HOST="${REDVECTOR_HOST:-127.0.0.1}"
VENV_DIR="$SCRIPT_DIR/.venv"

# Select the project interpreter explicitly, including from Claude Desktop.
PYTHON=python3
if [ -x "$VENV_DIR/bin/python3" ]; then
    PYTHON="$VENV_DIR/bin/python3"
elif [ -x "$VENV_DIR/bin/python" ]; then
    PYTHON="$VENV_DIR/bin/python"
fi
export PATH="$VENV_DIR/bin:$PATH"

# ── Authentication token (CWE-798) ────────────────────────────────────────────
# No hard-coded default credential exists. An explicitly provided token is
# honoured and never rotated; the revoked published development token is
# rejected; otherwise a strong token is generated ONCE and PERSISTED in a
# protected, user-local file by redvector_credentials.py, so the backend and the
# MCP client share the SAME credential across restarts and reboots. This removes
# the per-launch ephemeral token that previously caused 401 / "Connection
# closed" when a detached backend outlived the launcher that started it.
if [ -n "${REDVECTOR_API_TOKEN:-}" ] && [ "$REDVECTOR_API_TOKEN" = "redvector-dev-token" ]; then
    echo "[RedVector] ERROR: REDVECTOR_API_TOKEN is set to the insecure published development token. Refusing to start. Unset it (the Claude Desktop manager migrates it automatically) or set a strong, unique token." >&2
    exit 1
fi

TOKEN="$("$PYTHON" "$SCRIPT_DIR/redvector_credentials.py" ensure)" || TOKEN=""
if [ -z "$TOKEN" ] || [ "$TOKEN" = "redvector-dev-token" ]; then
    echo "[RedVector] ERROR: Unable to establish a secure API token. Set REDVECTOR_API_TOKEN explicitly or check the credential store under \${XDG_CONFIG_HOME:-\$HOME/.config}/redvector." >&2
    exit 1
fi
if [ -z "${REDVECTOR_API_TOKEN:-}" ]; then
    echo "[RedVector] Using a persisted per-user API token (generated automatically on first run). No manual token setup or JSON editing is required." >&2
fi

export REDVECTOR_API_TOKEN="$TOKEN"

# Ownership comes from Linux socket/process metadata, never from HTTP alone.
backend_state() {
    "$PYTHON" "$SCRIPT_DIR/redvector_banner.py" --backend-check "$SCRIPT_DIR" --host "$SERVER_HOST" --port "$SERVER_PORT"
}
port_error() {
    echo "[RedVector] ERROR: Port $SERVER_PORT is used by another process or its installation cannot be verified. No process was stopped." >&2
    exit 1
}
healthy() {
    curl --noproxy '*' --connect-timeout 1 --max-time 2 -sf "http://${SERVER_HOST}:${SERVER_PORT}/health" >/dev/null 2>&1
}
# Authenticated probe: confirms a RUNNING backend accepts THIS session's token.
# A healthy /health response (unauthenticated) is NOT proof the MCP connection
# will authenticate, so credential conflicts are detected here without stopping
# any process.
auth_ok() {
    local code
    code="$(curl --noproxy '*' --connect-timeout 1 --max-time 3 -s -o /dev/null \
        -H "Authorization: Bearer ${TOKEN}" -w '%{http_code}' \
        "http://${SERVER_HOST}:${SERVER_PORT}/api/processes/list" 2>/dev/null)" || return 1
    [ "$code" = "200" ]
}
STATE=0
backend_state || STATE=$?
case "$STATE" in
    0|1) ;;
    *) port_error ;;
esac

# ── Auto-start the backend server if not already running ──────────────────────
if [ "$STATE" = 1 ]; then
    echo "[RedVector] Backend not running - starting redvector_server.py on port $SERVER_PORT ..." >&2

    # Use setsid to fully detach the server from this shell session.
    # This prevents the server from dying when the parent shell exits
    # (e.g., when 'exec' replaces it with the MCP client below).
    setsid "$PYTHON" "$SCRIPT_DIR/redvector_server.py" --host "$SERVER_HOST" --port "$SERVER_PORT" \
        > "$SCRIPT_DIR/server.log" 2>&1 < /dev/null &
    SERVER_PID=$!
    echo "[RedVector] Server PID: $SERVER_PID" >&2

    # Wait up to 30 seconds for the server to become healthy
    SERVER_HEALTHY=false
    for i in $(seq 1 30); do
        if healthy && backend_state && auth_ok; then
            echo "[RedVector] Server is healthy and authenticating after ${i}s" >&2
            SERVER_HEALTHY=true
            break
        fi
        sleep 1
    done
    if [ "$SERVER_HEALTHY" = false ]; then
        echo "[RedVector] ERROR: Server did not become healthy within 30s. Check server.log" >&2
        echo "[RedVector] Last 20 lines of server.log:" >&2
        tail -20 "$SCRIPT_DIR/server.log" >&2
        exit 1
    fi
else
    if ! healthy; then
        echo "[RedVector] ERROR: This installation's backend is listening but /health is unavailable. No process was stopped." >&2
        exit 1
    fi
    backend_state || port_error
    if ! auth_ok; then
        echo "[RedVector] ERROR: A RedVector backend is already running on ${SERVER_HOST}:${SERVER_PORT}, but it does not accept this session's API token (credential conflict). No process was stopped. Stop that backend and relaunch, or set REDVECTOR_API_TOKEN to the credential it was started with." >&2
        exit 1
    fi
    echo "[RedVector] Backend already running on ${SERVER_HOST}:${SERVER_PORT} (authenticated)" >&2
fi

# The original artwork is terminal-only; stdout remains exclusively MCP stdio.
# Render after ownership/health validation, without importing or starting the server.
if [ -t 0 ] && [ -t 2 ]; then
    "$PYTHON" "$SCRIPT_DIR/redvector_banner.py" --host "$SERVER_HOST" --port "$SERVER_PORT" >&2
fi

# ── Launch the MCP client (this replaces the current process) ─────────────────
exec "$PYTHON" "$SCRIPT_DIR/redvector_mcp.py" \
    --server "http://${SERVER_HOST}:${SERVER_PORT}" \
    "$@"
