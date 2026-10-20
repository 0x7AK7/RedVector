#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  RedVector AI v8.0 - Unified Launcher
#  Auto-starts the backend server (if not running) then launches the MCP client.
#  Used by Claude Desktop / AI agents via redvector-mcp.json.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# Resolve the directory where this script lives (works with symlinks too)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Configurable
SERVER_PORT="${REDVECTOR_PORT:-8888}"
SERVER_HOST="${REDVECTOR_HOST:-127.0.0.1}"
VENV_DIR="$SCRIPT_DIR/.venv"
TOKEN="${REDVECTOR_API_TOKEN:-redvector-dev-token}"

export REDVECTOR_API_TOKEN="$TOKEN"

# Activate virtualenv if it exists
if [ -f "$VENV_DIR/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
fi

# ── Auto-start the backend server if not already running ──────────────────────
if ! curl -sf "http://${SERVER_HOST}:${SERVER_PORT}/health" >/dev/null 2>&1; then
    echo "[RedVector] Backend not running - starting redvector_server.py on port $SERVER_PORT ..." >&2

    # Use setsid to fully detach the server from this shell session.
    # This prevents the server from dying when the parent shell exits
    # (e.g., when 'exec' replaces it with the MCP client below).
    setsid python3 "$SCRIPT_DIR/redvector_server.py" --port "$SERVER_PORT" \
        > "$SCRIPT_DIR/server.log" 2>&1 &
    SERVER_PID=$!
    echo "[RedVector] Server PID: $SERVER_PID" >&2

    # Wait up to 30 seconds for the server to become healthy
    SERVER_HEALTHY=false
    for i in $(seq 1 30); do
        if curl -sf "http://${SERVER_HOST}:${SERVER_PORT}/health" >/dev/null 2>&1; then
            echo "[RedVector] Server is healthy after ${i}s" >&2
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
    echo "[RedVector] Backend already running on ${SERVER_HOST}:${SERVER_PORT}" >&2
fi

# ── Launch the MCP client (this replaces the current process) ─────────────────
exec python3 "$SCRIPT_DIR/redvector_mcp.py" \
    --server "http://${SERVER_HOST}:${SERVER_PORT}" \
    "$@"
