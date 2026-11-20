#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  RedVector AI — One-command installer (Linux / Kali)
#  Creates a virtualenv, installs dependencies, ensures a secure API token, and
#  (with explicit consent) registers the RedVector MCP server in Claude Desktop.
#
#  Reuses the existing project pieces: redvector_credentials.py (token) and
#  redvector_desktop_config.py (safe, consent-gated config write). The existing
#  interactive manager (redvector_ai_desktop_manager.sh) is left unchanged.
#
#  This installer makes NO change to RedVector's tools, schemas, execution
#  semantics or security controls. It never grants tool permissions and never
#  writes 'alwaysAllow'.
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")" && pwd -P)"
cd "$SCRIPT_DIR"

VENV_DIR="$SCRIPT_DIR/.venv"
REQ="$SCRIPT_DIR/requirements.txt"
ASSUME_YES="${REDVECTOR_INSTALL_YES:-0}"
SKIP_CONFIG="${REDVECTOR_SKIP_CLAUDE_CONFIG:-0}"

info() { printf '[RedVector] %s\n' "$*"; }
err()  { printf '[RedVector] ERROR: %s\n' "$*" >&2; }

# ── 1. Preflight: Python + pip (report version, do not arbitrarily cap it) ─────
PYBOOT=""
for cand in python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then PYBOOT="$cand"; break; fi
done
[ -n "$PYBOOT" ] || { err "Python 3 was not found on PATH. Install Python 3 and re-run."; exit 1; }

PYVER="$("$PYBOOT" -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])' 2>/dev/null || echo unknown)"
if ! "$PYBOOT" -c 'import sys;raise SystemExit(0 if sys.version_info[:2]>=(3,9) else 1)' 2>/dev/null; then
    err "Python $PYVER is too old; RedVector needs Python 3.9 or newer."
    exit 1
fi
info "Using Python $PYVER ($("$PYBOOT" -c 'import sys;print(sys.executable)'))"
[ -f "$REQ" ] || { err "requirements.txt not found next to this installer."; exit 1; }

# ── 2. Virtualenv (idempotent: reuse if present) ──────────────────────────────
VENV_PY="$VENV_DIR/bin/python3"
[ -x "$VENV_PY" ] || VENV_PY="$VENV_DIR/bin/python"
if [ -x "$VENV_PY" ]; then
    info "Reusing existing virtualenv at .venv"
else
    info "Creating virtualenv at .venv ..."
    if ! "$PYBOOT" -m venv "$VENV_DIR"; then
        err "Failed to create a virtualenv. On Debian/Kali install the venv package: sudo apt-get install -y python3-venv"
        exit 1
    fi
    VENV_PY="$VENV_DIR/bin/python3"
    [ -x "$VENV_PY" ] || VENV_PY="$VENV_DIR/bin/python"
fi

# ── 3. Dependencies (clear validation + error reporting) ──────────────────────
info "Upgrading pip ..."
"$VENV_PY" -m pip install --upgrade pip >/dev/null 2>&1 || info "pip self-upgrade skipped (continuing)."

info "Installing dependencies from requirements.txt ..."
PIP_LOG="$SCRIPT_DIR/.install-pip.log"
if ! "$VENV_PY" -m pip install -r "$REQ" >"$PIP_LOG" 2>&1; then
    err "Dependency installation failed. Last 25 lines of the pip log:"
    tail -25 "$PIP_LOG" >&2
    err "Common causes: no network/PyPI access (proxy/offline), or a dependency has no"
    err "wheel for Python $PYVER (try a Python version with published wheels). Full log: $PIP_LOG"
    exit 1
fi
info "Dependencies installed. Validating core imports ..."
MISSING="$("$VENV_PY" - <<'PY'
import importlib
missing = []
for mod in ("flask", "requests", "psutil", "mcp.server.fastmcp"):
    try:
        importlib.import_module(mod)
    except Exception as exc:  # noqa: BLE001
        missing.append(f"{mod} ({exc.__class__.__name__})")
print(";".join(missing))
PY
)"
if [ -n "$MISSING" ]; then
    err "Core dependencies did not import after installation: $MISSING"
    err "See $PIP_LOG. The install is incomplete."
    exit 1
fi
info "Core dependencies verified (flask, requests, psutil, mcp)."

# ── 4. Secure API token (reuse redvector_credentials.py; never a dev token) ───
TOKEN="$("$VENV_PY" "$SCRIPT_DIR/redvector_credentials.py" ensure 2>/dev/null)" || TOKEN=""
if [ -z "$TOKEN" ] || [ "$TOKEN" = "redvector-dev-token" ]; then
    err "Could not establish a secure API token via redvector_credentials.py."
    exit 1
fi
info "Secure per-user API token is in place (generated once, persisted, never shown here)."

# ── 5. Claude Desktop registration (EXPLICIT consent; safe merge; no alwaysAllow)
if [ "$SKIP_CONFIG" = "1" ]; then
    info "Skipping Claude Desktop registration (REDVECTOR_SKIP_CLAUDE_CONFIG=1)."
else
    CFG="${CLAUDE_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/Claude/claude_desktop_config.json}"
    DO_CONFIG=0
    if [ "$ASSUME_YES" = "1" ]; then
        DO_CONFIG=1
    elif [ -t 0 ]; then
        printf '[RedVector] Register the RedVector MCP server in Claude Desktop config?\n'
        printf '           File: %s\n' "$CFG"
        printf '           Other servers and your settings are preserved; no tool permissions are granted. [y/N] '
        read -r reply || reply=""
        case "$reply" in y|Y|yes|YES) DO_CONFIG=1 ;; esac
    else
        info "Non-interactive shell: skipping config write. Re-run with REDVECTOR_INSTALL_YES=1 to register, or use the manager menu."
    fi

    if [ "$DO_CONFIG" = "1" ]; then
        ASSUME_STOPPED=""
        if command -v pgrep >/dev/null 2>&1; then
            if pgrep -f 'claude-desktop/claude-desktop' >/dev/null 2>&1; then
                err "Claude Desktop is running. Fully quit it, then re-run the installer. No changes were made."
                exit 1
            fi
            # pgrep ran and found nothing: a reliable 'stopped' result we assert.
            ASSUME_STOPPED="--assume-stopped"
        fi
        # If pgrep is unavailable, ASSUME_STOPPED stays empty and the writer's own
        # check decides — failing safe if the running state cannot be determined.
        if ! "$VENV_PY" "$SCRIPT_DIR/redvector_desktop_config.py" register \
                --project "$SCRIPT_DIR" --config "$CFG" --platform posix $ASSUME_STOPPED; then
            err "Claude Desktop registration did not complete. No partial changes were written."
            exit 1
        fi
    else
        info "Claude Desktop was not modified. To register later, re-run with your consent"
        info "or use ./redvector_ai_desktop_manager.sh -> 'Configure RedVector MCP'."
    fi
fi

info "Installation complete. Start Claude Desktop (or ./start_redvector.sh) to use RedVector."
