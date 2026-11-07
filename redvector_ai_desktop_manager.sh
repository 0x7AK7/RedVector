#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  RedVector AI — Claude Desktop Manager  v1.0
#  One installer/manager for RedVector's supported AI desktop client:
#     [1] Claude Desktop  — install + register the RedVector MCP server
#
#  Runs as a normal desktop user. Uses sudo only for privileged package steps.
#  Official software sources only; signing keys verified where applicable.
#
#  ── Adding a new AI client later (future expansion) ───────────────────────────
#  The interactive layer is generic. To add a client WITHOUT redesigning the menu:
#    1. Implement <client>_menu() with its own submenu + handlers, mirroring
#       claude_menu() below.
#    2. Add one line to the dispatch in main_menu().
# ═══════════════════════════════════════════════════════════════════════════════

# No 'set -e': this is a long-lived interactive menu. Errors are handled per-call
# via explicit return codes so a failed action returns to the menu instead of
# killing the process.
set -uo pipefail

# ── Colours (green=success, yellow=warning, red=error, cyan=accent) ────────────
RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'
GREEN='\033[1;92m'; CYAN='\033[1;96m'; YELLOW='\033[1;93m'; RED='\033[1;91m'

# ── Paths / project location ───────────────────────────────────────────────────
SCRIPT_SOURCE="$(realpath -- "${BASH_SOURCE[0]}" 2>/dev/null || printf '%s' "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd -P)"
PROJECT="$SCRIPT_DIR"   # overridable via positional arg

# ── Claude Desktop official source constants (verified APT repository) ─────────
CLAUDE_KEY_URL='https://downloads.claude.ai/claude-desktop/key.asc'
CLAUDE_KEY_PATH='/usr/share/keyrings/claude-desktop-archive-keyring.asc'
CLAUDE_REPO_PATH='/etc/apt/sources.list.d/claude-desktop.list'
CLAUDE_REPO_LINE="deb [arch=amd64,arm64 signed-by=${CLAUDE_KEY_PATH}] https://downloads.claude.ai/claude-desktop/apt/stable stable main"
CLAUDE_EXPECTED_FPR='31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE'
CLAUDE_CONFIG="$HOME/.config/Claude/claude_desktop_config.json"

# ── System facts (filled by inspect_system) ───────────────────────────────────
OS_ID=''; OS_VERSION=''; OS_LIKE=''
IS_WSL=0
PROMPT_USER='user'; PROMPT_HOST='host'

# ── RedVector v8.0 runtime files required to register the MCP server ───────────
# Verified against github.com/0x7AK7/RedVector @ db644a0 (main). In v8.0:
#   * redvector_backend_check.py was DELETED; its Linux socket/process ownership
#     check migrated into redvector_banner.py, which start_redvector.sh now calls
#     as "redvector_banner.py --backend-check". The deleted module is therefore
#     NEVER required or referenced here.
#   * redvector_tool_manager.py EXISTS and is part of the runtime tool system.
# start_redvector.sh directly invokes redvector_banner.py, redvector_server.py and
# redvector_mcp.py; redvector_tool_manager.py is required by the runtime.
REDVECTOR_REQUIRED_FILES=(start_redvector.sh redvector_mcp.py redvector_server.py redvector_banner.py redvector_tool_manager.py)

# ═══════════════════════════════════════════════════════════════════════════════
#  UI helpers
# ═══════════════════════════════════════════════════════════════════════════════
say()  { printf '%b\n' "$*"; }
ok()   { printf "${GREEN}[OK]${RESET} %s\n"   "$*"; }
info() { printf "${CYAN}[INFO]${RESET} %s\n"  "$*"; }
warn() { printf "${YELLOW}[WARN]${RESET} %s\n" "$*"; }
err()  { printf "${RED}[ERROR]${RESET} %s\n"  "$*" >&2; }
hr()   { printf "${DIM}%s${RESET}\n" '────────────────────────────────────────────────────────────'; }
pause(){ printf '\n'; read -r -e -p 'Press Enter to return to the menu...' _ || true; }

confirm() {  # confirm "Question?"  -> 0 on explicit yes, 1 otherwise (default No)
  local answer
  read -r -e -p "$1 [y/N]: " answer || return 1
  [[ "$answer" == [yY] || "$answer" == [yY][eE][sS] ]]
}

# ═══════════════════════════════════════════════════════════════════════════════
#  System / environment detection
# ═══════════════════════════════════════════════════════════════════════════════
inspect_system() {
  PROMPT_USER="$(id -un 2>/dev/null || printf 'user')"
  PROMPT_HOST="$(hostname -s 2>/dev/null || uname -n 2>/dev/null || printf 'host')"

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-unknown}"; OS_VERSION="${VERSION_ID:-}"; OS_LIKE="${ID_LIKE:-}"
  else
    OS_ID='unknown'
  fi

  if grep -qiE '(microsoft|wsl)' /proc/sys/kernel/osrelease /proc/version 2>/dev/null; then
    IS_WSL=1
  fi
}

gui_available() { [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; }

require_non_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    err 'Run this manager as your normal desktop user, not root. It calls sudo only when needed.'
    return 1
  fi
}

# ═══════════════════════════════════════════════════════════════════════════════
#  RedVector project validation (shared)
# ═══════════════════════════════════════════════════════════════════════════════
redvector_project_ok() {  # prints resolved path on success
  [[ -d "$PROJECT" ]] || { err "RedVector folder not found: $PROJECT"; return 1; }
  local real file
  real="$(cd -- "$PROJECT" && pwd -P)" || return 1
  for file in "${REDVECTOR_REQUIRED_FILES[@]}"; do
    [[ -f "$real/$file" ]] || { err "RedVector file missing: $file (in $real)"; return 1; }
  done
  printf '%s' "$real"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  CLAUDE DESKTOP
# ═══════════════════════════════════════════════════════════════════════════════
claude_installed() {
  command -v dpkg-query >/dev/null 2>&1 \
    && dpkg-query -W -f='${Status}' claude-desktop 2>/dev/null | grep -qx 'install ok installed'
}
claude_version() { dpkg-query -W -f='${Version}' claude-desktop 2>/dev/null || true; }

claude_install() {
  require_non_root || return 1
  command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1 \
    || { err 'Claude Desktop install requires APT, dpkg and sudo (Debian/Ubuntu/Kali).'; return 1; }

  local distro=" ${OS_ID} ${OS_LIKE} "
  case "$distro" in
    *debian*|*ubuntu*|*kali*) ;;
    *) err 'The official Claude Desktop APT repository supports Kali, Debian and Ubuntu only.'; return 1;;
  esac

  local arch; arch="$(dpkg --print-architecture 2>/dev/null)"
  [[ "$arch" == amd64 || "$arch" == arm64 ]] || { err "Architecture '$arch' is not supported by the repository."; return 1; }

  if claude_installed; then
    ok "Claude Desktop is already installed: $(claude_version)"
    return 0
  fi

  if [[ "$IS_WSL" == 1 ]]; then
    warn 'WSL2 detected. Claude Desktop for Linux may have limited GUI support under WSL2.'
    confirm 'Continue with the Linux version anyway?' || { info 'Installation cancelled.'; return 0; }
  fi

  info 'Installing Claude Desktop from the verified official APT repository...'
  confirm 'This will add an APT repository and install claude-desktop with sudo. Proceed?' \
    || { info 'Installation cancelled.'; return 0; }

  sudo -v || { err 'sudo authentication failed.'; return 1; }
  sudo apt-get update || { err 'apt-get update failed.'; return 1; }
  sudo apt-get install -y curl gnupg ca-certificates || { err 'Failed to install prerequisites.'; return 1; }

  # Fetch key to a secure temp file and verify its fingerprint BEFORE trusting it.
  local temp_key actual_fpr
  temp_key="$(mktemp)" || return 1
  if ! curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 "$CLAUDE_KEY_URL" -o "$temp_key"; then
    rm -f -- "$temp_key"; err 'Could not download the signing key.'; return 1
  fi
  actual_fpr="$(gpg --batch --show-keys --with-colons "$temp_key" 2>/dev/null | awk -F: '$1=="fpr"{print toupper($10); exit}')"
  if [[ "$actual_fpr" != "$CLAUDE_EXPECTED_FPR" ]]; then
    rm -f -- "$temp_key"
    err "Signing-key fingerprint mismatch. Expected $CLAUDE_EXPECTED_FPR, got '${actual_fpr:-none}'. Aborting."
    return 1
  fi
  ok 'Signing-key fingerprint verified.'
  sudo install -m 0644 "$temp_key" "$CLAUDE_KEY_PATH" || { rm -f -- "$temp_key"; err 'Could not install the keyring.'; return 1; }
  rm -f -- "$temp_key"

  printf '%s\n' "$CLAUDE_REPO_LINE" | sudo tee "$CLAUDE_REPO_PATH" >/dev/null || { err 'Could not write the repository file.'; return 1; }
  sudo apt-get update || { err 'apt-get update failed after adding the repository.'; return 1; }
  sudo apt-get install -y claude-desktop || { err 'Installation of claude-desktop failed.'; return 1; }
  claude_installed || { err 'Claude Desktop could not be verified after installation.'; return 1; }
  ok "Claude Desktop installed: $(claude_version)"
}

# Register / refresh the RedVector MCP server in Claude Desktop config.
# Preserves other MCP servers, existing RedVector env, makes a timestamped backup,
# and writes atomically. Never prints tokens.
claude_configure_mcp() {
  require_non_root || return 1
  command -v python3 >/dev/null 2>&1 || { err 'python3 is required to update the configuration safely.'; return 1; }
  if ! claude_installed; then
    err 'Claude Desktop is not installed. Choose "Install Claude Desktop" first.'; return 1
  fi
  local real; real="$(redvector_project_ok)" || return 1

  if [[ ! -x "$real/.venv/bin/python3" && ! -x "$real/.venv/bin/python" ]]; then
    warn 'No Python virtualenv (.venv) found in the RedVector project. Install RedVector dependencies before using the MCP server.'
  fi

  RV_PROJECT="$real" RV_CONFIG="$CLAUDE_CONFIG" python3 -I - <<'PY'
import datetime, json, os, pathlib, shutil, stat, tempfile

project = pathlib.Path(os.environ['RV_PROJECT'])
config  = pathlib.Path(os.environ['RV_CONFIG'])
config.parent.mkdir(parents=True, exist_ok=True)

if config.exists():
    try:
        raw = config.read_text(encoding='utf-8-sig')
        data = json.loads(raw) if raw.strip() else {}
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f'Malformed configuration: {exc}. Nothing was changed.')
    if not isinstance(data, dict):
        raise SystemExit('Top-level configuration must be a JSON object. Nothing was changed.')
else:
    data = {}

servers = data.setdefault('mcpServers', {})
if not isinstance(servers, dict):
    raise SystemExit('mcpServers is not an object. Nothing was changed.')

# Preserve any existing RedVector env (e.g. REDVECTOR_API_TOKEN) untouched.
old = servers.get('redvector-ai', {})
env = dict(old.get('env', {})) if isinstance(old, dict) and isinstance(old.get('env', {}), dict) else {}
servers['redvector-ai'] = {
    'command': '/bin/bash',
    'args': [str(project / 'start_redvector.sh')],
    **({'env': env} if env else {}),
}

backup = None
if config.exists():
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    backup = config.with_name(config.name + f'.backup-{stamp}')
    shutil.copy2(config, backup)

fd, temp = tempfile.mkstemp(prefix='.rv-mcp-', suffix='.json', dir=str(config.parent))
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        json.dump(data, out, indent=2, ensure_ascii=False)
        out.write('\n'); out.flush(); os.fsync(out.fileno())
    os.chmod(temp, stat.S_IMODE(config.stat().st_mode) if config.exists() else 0o600)
    os.replace(temp, config)
finally:
    if os.path.exists(temp):
        os.unlink(temp)

print('[OK] RedVector MCP registered in Claude Desktop.')
print('RedVector project:', project)
print('Config file:', config)
if backup:
    print('Backup created:', backup)
print('Other MCP servers and any existing RedVector environment variables were preserved.')
print('Restart Claude Desktop if it is already running.')
PY
}

# Report installation + whether the RedVector MCP entry is correctly registered.
# Does NOT claim a live MCP connection unless the backend actually answers /health.
claude_check() {
  if claude_installed; then ok "Claude Desktop installed: $(claude_version)"
  else warn 'Claude Desktop is not installed.'; fi

  if [[ ! -f "$CLAUDE_CONFIG" ]]; then
    warn "No Claude Desktop config found at $CLAUDE_CONFIG. Use \"Configure RedVector MCP\"."
    return 0
  fi
  command -v python3 >/dev/null 2>&1 || { warn 'python3 not available; cannot inspect the config.'; return 0; }

  local real; real="$(cd -- "$PROJECT" && pwd -P 2>/dev/null)" || real="$PROJECT"
  RV_PROJECT="$real" RV_CONFIG="$CLAUDE_CONFIG" python3 -I - <<'PY'
import json, os, pathlib
config  = pathlib.Path(os.environ['RV_CONFIG'])
project = pathlib.Path(os.environ['RV_PROJECT'])
try:
    data = json.loads(config.read_text(encoding='utf-8-sig') or '{}')
except Exception as exc:
    raise SystemExit(f'[WARN] Could not parse config: {exc}')
srv = (data.get('mcpServers') or {}).get('redvector-ai')
if not isinstance(srv, dict):
    print('[WARN] RedVector MCP (redvector-ai) is NOT registered in the config.')
    raise SystemExit(0)
args = srv.get('args') or []
launcher = pathlib.Path(args[0]) if args else None
print('[OK] RedVector MCP entry present.')
print('     command:', srv.get('command'))
print('     launcher:', launcher)
if launcher and launcher.exists():
    print('[OK] Launcher script exists.')
else:
    print('[WARN] Launcher script path does not exist; re-run "Configure RedVector MCP".')
expected = project / 'start_redvector.sh'
if launcher and launcher.resolve() == expected.resolve():
    print('[OK] Launcher points at this RedVector project.')
else:
    print(f'[WARN] Launcher does not match this project ({expected}).')
if 'env' in srv:
    print('     env keys:', ', '.join(sorted(srv['env'])), '(values hidden)')
PY

  # Optional live check: the launcher auto-starts a local backend on this port.
  local host="${REDVECTOR_HOST:-127.0.0.1}" port="${REDVECTOR_PORT:-8888}"
  if command -v curl >/dev/null 2>&1 \
     && curl --noproxy '*' --connect-timeout 1 --max-time 2 -sf "http://${host}:${port}/health" >/dev/null 2>&1; then
    ok "RedVector backend is responding on ${host}:${port}/health (started by the launcher)."
  else
    info "RedVector backend is not currently listening on ${host}:${port}. It starts automatically when Claude Desktop launches the MCP server."
  fi
  info 'The live MCP handshake is performed by Claude Desktop itself; this check confirms registration, not an active session.'
}

# ── Best-effort Claude Desktop startup diagnostics ─────────────────────────────
# Appends ONLY explicitly constructed, non-sensitive status/error strings to a
# user-writable state file. It never captures process output (which could carry
# tokens), never logs environment variables or MCP configuration, and never
# fails its caller: every step is guarded so a logging problem cannot stop a
# launch. A simple size cap keeps the file from growing without bound.
CLAUDE_START_LOG="${XDG_STATE_HOME:-$HOME/.local/state}/redvector/claude-desktop-startup.log"
CLAUDE_START_LOG_MAX=262144   # 256 KiB; truncate once exceeded

claude_log() {  # claude_log "message"  — best-effort, always returns 0
  local dir ts size
  dir="$(dirname -- "$CLAUDE_START_LOG")"
  mkdir -p -- "$dir" 2>/dev/null || return 0
  if [[ -f "$CLAUDE_START_LOG" ]]; then
    size="$(wc -c < "$CLAUDE_START_LOG" 2>/dev/null || printf 0)"
    if [[ "${size:-0}" =~ ^[0-9]+$ && "$size" -gt "$CLAUDE_START_LOG_MAX" ]]; then
      : > "$CLAUDE_START_LOG" 2>/dev/null || true
    fi
  fi
  ts="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)"
  printf '%s %s\n' "${ts:-[no-date]}" "$1" >> "$CLAUDE_START_LOG" 2>/dev/null || true
  return 0
}

claude_start() {
  claude_installed || { err 'Claude Desktop is not installed. Choose option 1.'; claude_log 'ERROR start aborted: claude-desktop package not installed'; return 1; }
  gui_available   || { err 'No graphical session detected (DISPLAY/WAYLAND_DISPLAY).'; claude_log 'ERROR start aborted: no graphical session (DISPLAY/WAYLAND_DISPLAY unset)'; return 1; }
  command -v claude-desktop >/dev/null 2>&1 || { err 'The claude-desktop command was not found on PATH.'; claude_log 'ERROR start aborted: claude-desktop not found on PATH'; return 1; }

  # Prefer the officially documented deep link. Per Anthropic's "Open Claude
  # Desktop with a link" support article, claude://claude.ai/new opens the
  # regular Chat interface and launches Claude Desktop first if it is not
  # already running. Dispatching it with xdg-open also hands off to an existing
  # instance instead of spawning a duplicate. Used ONLY when the claude:// URL
  # scheme has a registered handler; otherwise we launch the binary directly.
  # No invented flags, no binary patching: this is the vendor-documented route.
  local chat_link='claude://claude.ai/new' handler=''
  command -v xdg-mime >/dev/null 2>&1 && handler="$(xdg-mime query default x-scheme-handler/claude 2>/dev/null || true)"

  if command -v xdg-open >/dev/null 2>&1 && [[ -n "$handler" ]]; then
    info 'Opening Claude Desktop to a new Chat (claude://claude.ai/new)...'
    nohup xdg-open "$chat_link" >/dev/null 2>&1 </dev/null &
    if command -v pgrep >/dev/null 2>&1; then
      local i
      for i in 1 2 3 4 5; do
        pgrep -f 'claude-desktop/claude-desktop' >/dev/null 2>&1 && break
        sleep 1
      done
      if pgrep -f 'claude-desktop/claude-desktop' >/dev/null 2>&1; then
        ok 'Claude Desktop is running; requested the Chat interface via the official deep link.'
      else
        warn 'Claude Desktop did not appear within a few seconds. If no Chat window opens, run: xdg-open "claude://claude.ai/new"'
        claude_log 'WARN deep link dispatched but no claude-desktop process detected within timeout'
      fi
    else
      sleep 2
      ok 'Requested Claude Desktop to open a new Chat (claude://claude.ai/new).'
    fi
    return 0
  fi

  # Fallback: no claude:// handler registered, or xdg-open unavailable. Launch
  # the graphical executable directly. This does NOT force Chat; Claude Desktop
  # restores whatever interface (Chat or Code) it last used.
  warn 'claude:// Chat deep link unavailable; launching Claude Desktop directly (it will open in its last-used view).'
  claude_log 'INFO deep link unavailable (no xdg-open or no claude:// handler); using direct claude-desktop launch'

  # Avoid spawning a duplicate when an instance is already running.
  if command -v pgrep >/dev/null 2>&1 && pgrep -f 'claude-desktop/claude-desktop' >/dev/null 2>&1; then
    ok 'Claude Desktop is already running; not starting a second instance.'
    return 0
  fi

  info 'Starting Claude Desktop...'
  nohup claude-desktop >/dev/null 2>&1 </dev/null &
  local pid=$!
  sleep 1
  if kill -0 "$pid" 2>/dev/null; then ok "Launch requested (PID $pid)."
  else warn 'The launch process exited quickly. Run "claude-desktop" in a terminal to see any error.'; claude_log 'WARN direct launch exited quickly; run claude-desktop in a terminal to see the error'; fi
}

claude_update() {
  require_non_root || return 1
  claude_installed || { warn 'Claude Desktop is not installed. Use option 1.'; return 1; }
  command -v apt-get >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1 || { err 'apt-get and sudo are required.'; return 1; }
  info 'Updating Claude Desktop via APT (official repository)...'
  sudo apt-get update || { err 'apt-get update failed.'; return 1; }
  sudo apt-get install -y --only-upgrade claude-desktop || { err 'Update failed.'; return 1; }
  ok "Claude Desktop is up to date: $(claude_version)"
}

claude_menu() {
  while true; do
    banner_claude
    read -r -e -p "  ${PROMPT_USER}@${PROMPT_HOST}:~\$ Select option [0-5]: " choice || break
    printf '\n'
    case "$choice" in
      1) claude_install       || warn 'Installation did not complete.' ;;
      2) claude_configure_mcp || warn 'MCP configuration did not complete.' ;;
      3) claude_check ;;
      4) claude_start         || warn 'Claude Desktop could not be started.' ;;
      5) claude_update        || warn 'Update did not complete.' ;;
      0) return 0 ;;
      *) warn 'Choose 0, 1, 2, 3, 4 or 5.' ;;
    esac
    [[ "$choice" == 0 ]] || pause
  done
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Banners
# ═══════════════════════════════════════════════════════════════════════════════
banner_main() {
  clear 2>/dev/null || true
  # Classic terminal green (#00FF41) foreground via truecolor ANSI, applied to
  # the RedVector banner ONLY and reset at the end of every line so no styling
  # leaks into the menu, prompt or elsewhere. No banner background colour is set:
  # the terminal's own background is used. Graceful fallback to the existing
  # bright green when the terminal does not advertise truecolor; success/warning/
  # error colours are untouched.
  local g
  if [[ "${COLORTERM:-}" == *truecolor* || "${COLORTERM:-}" == *24bit* ]]; then
    g='\033[1;38;2;0;255;65m'   # #00FF41
  else
    g="$GREEN"
  fi
  printf "%b" "${g}"
  cat <<'ART'
   ██████╗ ███████╗██████╗ ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗
   ██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
   ██████╔╝█████╗  ██║  ██║██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝
   ██╔══██╗██╔══╝  ██║  ██║╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
   ██║  ██║███████╗██████╔╝ ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
   ╚═╝  ╚═╝╚══════╝╚═════╝   ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
ART
  printf "%b" "${RESET}"
  say "        ${g}A I   D E S K T O P   M A N A G E R${RESET}  ${DIM}v1.0${RESET}"
  say "        ${g}By Adam K.${RESET}"
  hr
  say " ${g}SYSTEM${RESET}   ${OS_ID:-unknown} ${OS_VERSION:-} | $(uname -m 2>/dev/null) $([[ "$IS_WSL" == 1 ]] && printf '| WSL2')"
  say " ${g}PROJECT${RESET}  ${DIM}${PROJECT}${RESET}"
  hr
  printf '\n'
  say "   ${BOLD}AI DESKTOP CLIENT${RESET}"
  printf '\n'
  say "   ${GREEN}[1]${RESET} ${BOLD}Claude Desktop${RESET}"
  say "       ${DIM}Install Claude and register the RedVector MCP server${RESET}"
  say "   ${RED}[0]${RESET} Exit"
  printf '\n'
}

banner_claude() {
  clear 2>/dev/null || true
  printf "${GREEN}"
  cat <<'ART'
  ╔══════════════════════════════════════════════════╗
  ║            CLAUDE  DESKTOP  MANAGER               ║
  ╚══════════════════════════════════════════════════╝
ART
  printf "${RESET}"
  if claude_installed; then say "  ${GREEN}●${RESET} Claude Desktop installed ${DIM}($(claude_version))${RESET}"
  else say "  ${YELLOW}●${RESET} Claude Desktop not installed"; fi
  say "  ${DIM}RedVector project: ${PROJECT}${RESET}"
  hr
  say "   ${GREEN}[1]${RESET} Install Claude Desktop"
  say "   ${GREEN}[2]${RESET} Configure RedVector MCP"
  say "   ${GREEN}[3]${RESET} Check installation and MCP connection"
  say "   ${GREEN}[4]${RESET} Start Claude Desktop"
  say "   ${GREEN}[5]${RESET} Update Claude Desktop"
  say "   ${RED}[0]${RESET} Back to main menu"
  printf '\n'
}

# ═══════════════════════════════════════════════════════════════════════════════
#  --help / --status
# ═══════════════════════════════════════════════════════════════════════════════
print_help() {
  cat <<EOF
RedVector AI — Claude Desktop Manager v1.0

USAGE:
  $(basename "$0") [REDVECTOR_PROJECT_DIR]
  $(basename "$0") --status
  $(basename "$0") --help

DESCRIPTION:
  Interactive manager for RedVector's supported AI desktop client, Claude Desktop.

    [1] Claude Desktop  — install from the verified official APT repository and
                          register the RedVector MCP server (start_redvector.sh),
                          preserving existing MCP servers and RedVector env, with
                          a timestamped backup and atomic config writes.

ARGUMENTS:
  REDVECTOR_PROJECT_DIR  Path to the RedVector v8.0 project. Defaults to the
                         directory containing this script.

OPTIONS:
  --status   Print a non-interactive status report and exit.
  --help     Show this help and exit.

NOTES:
  Run as your normal desktop user (not root). sudo is used only for package steps.
EOF
}

print_status() {
  inspect_system
  hr
  say "${BOLD}RedVector AI Desktop Manager — status${RESET}"
  hr
  say " System      : ${OS_ID:-unknown} ${OS_VERSION:-} ($(uname -m 2>/dev/null))$([[ "$IS_WSL" == 1 ]] && printf ' [WSL2]')"
  say " GUI session : $(gui_available && echo available || echo 'not detected')"
  say " RedVector   : ${PROJECT}"
  local real; if real="$(redvector_project_ok 2>/dev/null)"; then
    say " RV files    : ${GREEN}present${RESET} (${REDVECTOR_REQUIRED_FILES[*]})"
  else
    say " RV files    : ${YELLOW}incomplete or folder not found${RESET}"
  fi
  hr
  if claude_installed; then say " Claude Desktop  : ${GREEN}installed${RESET} ($(claude_version))"
  else say " Claude Desktop  : ${YELLOW}not installed${RESET}"; fi
  if [[ -f "$CLAUDE_CONFIG" ]] && command -v python3 >/dev/null 2>&1 \
     && RV_CONFIG="$CLAUDE_CONFIG" python3 -I -c "import json,os,sys; d=json.loads(open(os.environ['RV_CONFIG'],encoding='utf-8-sig').read() or '{}'); sys.exit(0 if isinstance((d.get('mcpServers') or {}).get('redvector-ai'),dict) else 1)" 2>/dev/null; then
    say " RedVector MCP   : ${GREEN}registered${RESET} in Claude Desktop config"
  else
    say " RedVector MCP   : ${YELLOW}not registered${RESET} (use Claude menu → Configure RedVector MCP)"
  fi
  hr
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════════
main_menu() {
  while true; do
    banner_main
    read -r -e -p "  ${PROMPT_USER}@${PROMPT_HOST}:~\$ Select [0-1]: " choice || break
    printf '\n'
    case "$choice" in
      1) claude_menu ;;
      0) ok 'Exiting RedVector AI Desktop Manager.'; return 0 ;;
      *) warn 'Choose 0 or 1.'; pause ;;
    esac
  done
}

main() {
  # Flag parsing (before requiring interactivity).
  case "${1:-}" in
    -h|--help)  print_help; exit 0 ;;
    --status)   print_status; exit 0 ;;
    -*)         err "Unknown option: $1"; print_help; exit 2 ;;
  esac
  [[ $# -le 1 ]] || { err "Too many arguments."; print_help; exit 2; }
  [[ $# -eq 1 ]] && PROJECT="$1"

  require_non_root || exit 1
  inspect_system
  main_menu
}

main "$@"
