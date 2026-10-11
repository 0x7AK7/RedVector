#!/usr/bin/env bash
# ===========================================================================
#  RedVector 8.0.0 - one-command first-run installer + launcher (Linux/Kali)
#
#  First run:   git clone ... && cd RedVector && chmod +x start_redvector.sh && ./start_redvector.sh
#  It creates a .venv when needed, installs dependencies only when
#  requirements.txt changed, starts the backend, waits for health, then starts
#  the MCP client. It never requires you to activate the virtualenv by hand.
# ===========================================================================

set -euo pipefail

# ---- resolve project root (works through symlinks) ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VERSION="8.0.0"
SERVER_HOST="${REDVECTOR_HOST:-127.0.0.1}"
SERVER_PORT="${REDVECTOR_PORT:-8888}"
TOKEN="${REDVECTOR_API_TOKEN:-redvector-dev-token}"
export REDVECTOR_API_TOKEN="$TOKEN"

VENV_DIR="$SCRIPT_DIR/.venv"
VENV_PY="$VENV_DIR/bin/python"
REQ_FILE="$SCRIPT_DIR/requirements.txt"
HASH_FILE="$VENV_DIR/.requirements.sha256"
HEALTH_URL="http://${SERVER_HOST}:${SERVER_PORT}/health"

log()  { echo "[RedVector] $*" >&2; }
die()  { echo "[RedVector] ERROR: $*" >&2; exit 1; }

# ---- 1. python3 present ----
if ! command -v python3 >/dev/null 2>&1; then
    die "Python 3 was not found. Install a supported Python (3.10+) and run the launcher again."
fi

# ---- 2/3. supported python version (>= 3.10) ----
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)'; then
    die "Python 3.10 or newer is required. Current: $(python3 -V 2>&1)."
fi

# ---- 4. requirements file present ----
[ -f "$REQ_FILE" ] || die "requirements.txt not found next to the launcher."

# ---- 5/6. create venv if missing ----
FRESH_VENV=false
if [ ! -x "$VENV_PY" ]; then
    log "[RedVector $VERSION] First-time setup detected"
    log "Creating Python environment..."
    python3 -m venv "$VENV_DIR" || die "Could not create the virtual environment (.venv)."
    FRESH_VENV=true
else
    log "[RedVector $VERSION] Environment ready"
fi
[ -x "$VENV_PY" ] || die "The virtual environment looks corrupt (no .venv/bin/python). Delete .venv and retry."

# ---- 8. verify pip inside the venv ----
"$VENV_PY" -m pip --version >/dev/null 2>&1 || {
    "$VENV_PY" -m ensurepip --upgrade >/dev/null 2>&1 || die "pip is not available in the virtual environment."
}

# ---- 9/10/18. deterministic requirements-hash change detection ----
cur_hash="$(sha256sum "$REQ_FILE" | awk '{print $1}')"
stored_hash=""
[ -f "$HASH_FILE" ] && stored_hash="$(cat "$HASH_FILE" 2>/dev/null || true)"

verify_deps() {
    # Verify only the CORE backend runtime imports that requirements.txt reliably
    # provides and that `python -m redvector` needs to start. The MCP SDK import
    # (mcp.server.fastmcp) is validated when the MCP client starts, not here: it is
    # not reliably provided by the pinned package on every distro, and gating on it
    # would spuriously force a reinstall on every run even when the hash matches.
    "$VENV_PY" - <<'PYCHECK' >/dev/null 2>&1
import importlib
for m in ("flask", "requests", "psutil"):
    importlib.import_module(m)
PYCHECK
}

need_install=false
if [ "$FRESH_VENV" = true ]; then need_install=true; fi
if [ "$cur_hash" != "$stored_hash" ]; then need_install=true; fi
if ! verify_deps; then need_install=true; fi

if [ "$need_install" = true ]; then
    log "Installing dependencies..."
    if "$VENV_PY" -m pip install --upgrade pip >/dev/null 2>&1 && \
       "$VENV_PY" -m pip install -r "$REQ_FILE"; then
        if verify_deps; then
            echo "$cur_hash" > "$HASH_FILE"      # store only after a verified install
            log "Dependencies ready"
        else
            die "Dependencies installed but a critical import still fails. See the pip output above."
        fi
    else
        die "Dependency installation failed. Check your network and the pip output above."
    fi
else
    log "Dependencies unchanged - skipping install"
fi

# ---- Phase 10: delegate setup commands to the shared Python layer ----
# A direct setup command (connect/disconnect/setup/diagnostics/provider/status)
# is handled entirely in Python and does NOT start the backend/MCP.
SETUP_CMD=false
for _a in "$@"; do
    case "$_a" in
        --connect-claude|--connect-cursor|--disconnect-claude|--disconnect-cursor| \
        --setup-ai|--setup-harness|--install-dsh|--diagnostics|--status|--provider|--provider=*)
            SETUP_CMD=true ;;
    esac
done
if [ "$SETUP_CMD" = true ]; then
    exec "$VENV_PY" -m redvector.setup "$@"
fi

# --chat is intercepted here: it needs the backend (for real tool execution) but
# must NOT be forwarded to redvector.mcp.server. It runs the chat loop instead of MCP.
CHAT_MODE=false
for _a in "$@"; do
    case "$_a" in --chat) CHAT_MODE=true ;; esac
done

# First-run / interactive preflight. Exit 10 means "start RedVector + MCP", 11 means
# "start RedVector + chat"; any other code means the menu handled things and we stop.
# Non-interactive (MCP-client) launches always return 10 and never block on a menu.
if [ "$CHAT_MODE" != true ]; then
    set +e
    "$VENV_PY" -m redvector.setup "$@"   # forwards --menu; no args -> smart auto-start vs menu
    PREFLIGHT_RC=$?
    set -e
    if [ "$PREFLIGHT_RC" = "11" ]; then
        CHAT_MODE=true
    elif [ "$PREFLIGHT_RC" != "10" ]; then
        exit "$PREFLIGHT_RC"
    fi
fi

# ---- 12/13/14. start backend if not already healthy ----
if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
    log "Backend already running on ${SERVER_HOST}:${SERVER_PORT}"
else
    log "Starting backend..."
    # setsid fully detaches the backend so it survives this shell being replaced by exec below
    setsid "$VENV_PY" -m redvector --port "$SERVER_PORT" --host "$SERVER_HOST" \
        > "$SCRIPT_DIR/server.log" 2>&1 &
    healthy=false
    for _ in $(seq 1 30); do
        if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then healthy=true; break; fi
        sleep 1
    done
    if [ "$healthy" != true ]; then
        log "ERROR: backend did not become healthy within 30s. Last lines of server.log:"
        tail -20 "$SCRIPT_DIR/server.log" >&2 || true
        die "backend startup failed."
    fi
    log "Backend ready on ${SERVER_HOST}:${SERVER_PORT}"
fi

# ---- concise aggregated status (read-only) ----
"$VENV_PY" -m redvector.setup --status || true

# ---- 15. start the chat loop, or the MCP client (each replaces this process) ----
if [ "$CHAT_MODE" = true ]; then
    log "Starting RedVector AI chat..."
    exec "$VENV_PY" -m redvector.setup --chat
fi
log "Starting MCP..."
exec "$VENV_PY" -m redvector.mcp.server --server "http://${SERVER_HOST}:${SERVER_PORT}" "$@"
