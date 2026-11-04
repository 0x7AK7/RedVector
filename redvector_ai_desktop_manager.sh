#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  RedVector AI — Unified AI Desktop Manager  v1.0
#  One installer/manager for the two supported AI desktop clients:
#     [1] Claude Desktop  — install + register the RedVector MCP server
#     [2] ChatGPT Desktop — install + check RedVector integration compatibility
#
#  Runs as a normal desktop user. Uses sudo only for privileged package steps.
#  Official software sources only; signing keys verified where applicable.
#
#  ── Adding a new AI client later (future expansion) ───────────────────────────
#  The interactive layer is generic. To add a client WITHOUT redesigning the menu:
#    1. Implement <client>_menu() with its own submenu + handlers, mirroring
#       claude_menu()/chatgpt_menu() below.
#    2. Add one line to the CLIENTS dispatch in main_menu().
#  Do not add speculative/placeholder clients: this release ships Claude Desktop
#  and ChatGPT Desktop only.
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

# ── ChatGPT Desktop official source constants (OpenAI Linux preview) ───────────
CHATGPT_DOCS='https://learn.chatgpt.com/docs/linux/linux-app'
CHATGPT_BASE='https://persistent.oaistatic.com/codex-app-prod/linux'

# ── System facts (filled by inspect_system) ───────────────────────────────────
OS_ID=''; OS_VERSION=''; OS_LIKE=''; ARCH=''; PKG=''
CHATGPT_SUPPORTED=0; IS_WSL=0
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

  case "$(uname -m 2>/dev/null)" in
    x86_64)        ARCH='amd64';;
    aarch64|arm64) ARCH='arm64';;
    *)             ARCH='';;
  esac

  # Package family (used by the ChatGPT installer)
  case "$OS_ID" in
    ubuntu|debian|kali) PKG='deb';;
    fedora)             PKG='rpm';;
    arch)               PKG='arch';;
    *)
      if   [[ " $OS_LIKE " == *' debian '* ]]; then PKG='deb'
      elif [[ " $OS_LIKE " == *' fedora '* ]]; then PKG='rpm'
      elif [[ " $OS_LIKE " == *' arch '*   ]]; then PKG='arch'
      fi;;
  esac

  # ChatGPT officially-tested distributions (OpenAI Linux preview)
  case "$OS_ID:$OS_VERSION" in
    ubuntu:24.04|ubuntu:26.04|debian:13|fedora:43|fedora:44) CHATGPT_SUPPORTED=1;;
  esac
  [[ "$OS_ID" == arch ]] && CHATGPT_SUPPORTED=1

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
#  CHATGPT DESKTOP  (official OpenAI Linux preview packages only)
# ═══════════════════════════════════════════════════════════════════════════════
chatgpt_installed() {
  command -v chatgpt >/dev/null 2>&1 && return 0
  command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' chatgpt 2>/dev/null | grep -qx 'install ok installed' && return 0
  command -v rpm    >/dev/null 2>&1 && rpm -q chatgpt >/dev/null 2>&1 && return 0
  command -v pacman >/dev/null 2>&1 && pacman -Q chatgpt >/dev/null 2>&1 && return 0
  return 1
}

chatgpt_install() {
  require_non_root || return 1
  [[ -n "$ARCH" ]] || { err 'Unsupported processor architecture.'; return 1; }
  [[ -n "$PKG"  ]] || { err "No installation procedure for this distribution. See $CHATGPT_DOCS"; return 1; }
  if chatgpt_installed; then ok 'ChatGPT Desktop appears to be installed already. Use "Check installation" or "Update".'; return 0; fi

  if [[ "$CHATGPT_SUPPORTED" != 1 ]]; then
    warn "${OS_ID:-This distribution} is not in OpenAI's officially tested list for the ChatGPT Linux preview."
    warn 'Installation may fail due to dependencies or desktop compatibility.'
    confirm 'Try installing the official package anyway?' || { info 'Installation cancelled.'; return 0; }
  fi

  case "$PKG" in
    deb)
      command -v apt  >/dev/null 2>&1 || { err 'apt not found.'; return 1; }
      command -v curl >/dev/null 2>&1 || { err 'curl is required.'; return 1; }
      local tmp url rc
      tmp="$(mktemp -d)" || return 1
      url="$CHATGPT_BASE/deb/latest/chatgpt_${ARCH}.deb"
      info "Downloading the official package from $url"
      if ! curl --proto '=https' --tlsv1.2 --fail --location --show-error --output "$tmp/chatgpt_${ARCH}.deb" "$url"; then
        err 'Download failed.'; rm -rf -- "$tmp"; return 1
      fi
      if ! dpkg-deb --info "$tmp/chatgpt_${ARCH}.deb" >/dev/null 2>&1; then
        err 'Downloaded file is not a valid Debian package.'; rm -rf -- "$tmp"; return 1
      fi
      confirm 'Package verified. Install it now with sudo apt (apt will show the changes)?' \
        || { info 'Installation cancelled.'; rm -rf -- "$tmp"; return 0; }
      sudo apt install "$tmp/chatgpt_${ARCH}.deb"; rc=$?
      rm -rf -- "$tmp"
      (( rc == 0 )) && ok 'Installation command completed.' || err "Installation failed (exit $rc)."
      return "$rc" ;;
    rpm)
      command -v dnf  >/dev/null 2>&1 || { err 'dnf not found.'; return 1; }
      command -v curl >/dev/null 2>&1 || { err 'curl is required.'; return 1; }
      local tmp url rc rpm_arch
      tmp="$(mktemp -d)" || return 1
      rpm_arch='x86_64'; [[ "$ARCH" == 'arm64' ]] && rpm_arch='aarch64'
      url="$CHATGPT_BASE/rpm/latest/chatgpt.${rpm_arch}.rpm"
      info "Downloading the official package from $url"
      if ! curl --proto '=https' --tlsv1.2 --fail --location --show-error --output "$tmp/chatgpt.${rpm_arch}.rpm" "$url"; then
        err 'Download failed.'; rm -rf -- "$tmp"; return 1
      fi
      confirm 'Install it now with sudo dnf (dnf will show the changes)?' \
        || { info 'Installation cancelled.'; rm -rf -- "$tmp"; return 0; }
      sudo dnf install "$tmp/chatgpt.${rpm_arch}.rpm"; rc=$?
      rm -rf -- "$tmp"
      (( rc == 0 )) && ok 'Installation command completed.' || err "Installation failed (exit $rc)."
      return "$rc" ;;
    arch)
      command -v curl >/dev/null 2>&1 || { err 'curl is required.'; return 1; }
      local tmp rc
      tmp="$(mktemp -d)" || return 1
      warn 'The official Arch installer configures the OpenAI repo and performs a FULL system upgrade.'
      confirm 'Download the official Arch installer for review?' || { info 'Cancelled.'; rm -rf -- "$tmp"; return 0; }
      if ! curl --proto '=https' --tlsv1.2 --fail --location --show-error --output "$tmp/install-arch.sh" "$CHATGPT_BASE/install-arch.sh"; then
        err 'Download failed.'; rm -rf -- "$tmp"; return 1
      fi
      info 'Review the script below (q to quit the pager). It will NOT run until you confirm.'
      "${PAGER:-less}" "$tmp/install-arch.sh" || true
      if confirm 'Execute the reviewed script with sudo (includes a full system upgrade)?'; then
        sudo bash "$tmp/install-arch.sh"; rc=$?
      else
        info 'Cancelled. Nothing was executed.'; rc=0
      fi
      rm -rf -- "$tmp"
      return "$rc" ;;
  esac
}

chatgpt_check() {
  if chatgpt_installed; then
    ok 'ChatGPT Desktop detected.'
    command -v chatgpt >/dev/null 2>&1 && say "     command: $(command -v chatgpt)"
    # Resolve a version from whichever package database actually knows chatgpt.
    # Previously all three managers were probed unconditionally; `rpm -q` prints
    # "package chatgpt is not installed" to STDOUT (so 2>/dev/null did not hide
    # it), which leaked a contradictory "not installed" line beside the detected
    # version. Here we capture output and report ONLY a real version, so a
    # missing dpkg/rpm/pacman entry never implies the app is absent.
    local ver=''
    if command -v dpkg-query >/dev/null 2>&1; then
      ver="$(dpkg-query -W -f='${Version}' chatgpt 2>/dev/null || true)"
    fi
    if [[ -z "$ver" ]] && command -v rpm >/dev/null 2>&1; then
      ver="$(rpm -q --qf '%{VERSION}-%{RELEASE}' chatgpt 2>/dev/null || true)"
      [[ "$ver" == *'is not installed'* ]] && ver=''
    fi
    if [[ -z "$ver" ]] && command -v pacman >/dev/null 2>&1; then
      ver="$(pacman -Q chatgpt 2>/dev/null | awk 'NR==1{print $2}' || true)"
    fi
    if [[ -n "$ver" ]]; then
      say "     version: $ver"
    else
      say "     version: present (executable verified; not registered with a system package manager)"
    fi
  else
    warn 'ChatGPT package/command not found. Choose "Install ChatGPT Desktop".'
  fi
  if gui_available; then ok 'Graphical session detected.'
  else warn 'No DISPLAY/WAYLAND_DISPLAY detected. Graphical launch may fail (e.g. over SSH or WSL without GUI).'; fi
}

# Honest RedVector-integration status for ChatGPT Desktop.
# RedVector's MCP server is designed and verified for Claude Desktop's
# claude_desktop_config.json. We do NOT claim or fabricate a ChatGPT integration.
chatgpt_integration_compat() {
  hr
  say "${BOLD}RedVector ↔ ChatGPT Desktop integration${RESET}"
  hr
  info 'RedVector exposes its toolset through the Model Context Protocol (MCP) server'
  info 'launched by start_redvector.sh, and this integration is verified for Claude Desktop'
  info '(via ~/.config/Claude/claude_desktop_config.json).'
  printf '\n'
  warn 'ChatGPT Desktop (OpenAI Linux preview) does NOT use the same local MCP'
  warn 'configuration file as Claude Desktop. A verified, first-party local-MCP'
  warn 'registration path equivalent to Claude Desktop is NOT available here.'
  printf '\n'
  say "  ${RED}●${RESET} RedVector MCP for ChatGPT Desktop: ${YELLOW}NOT SUPPORTED / NOT VERIFIED${RESET}"
  printf '\n'
  info 'This manager writes no ChatGPT configuration and will not display a RedVector'
  info 'connection status for ChatGPT unless a real connection is actually verified.'
  info "For verified RedVector MCP integration, use Claude Desktop (main menu option 1)."
  info "ChatGPT Desktop docs: $CHATGPT_DOCS"
}

# ── Best-effort ChatGPT Desktop startup diagnostics ───────────────────────────
# Same safe conventions as claude_log: only explicitly constructed, non-sensitive
# strings; never captures process output (which could carry tokens); never logs
# environment variables or configuration; never fails its caller; size-capped.
CHATGPT_START_LOG="${XDG_STATE_HOME:-$HOME/.local/state}/redvector/chatgpt-desktop-startup.log"
CHATGPT_START_LOG_MAX=262144   # 256 KiB; truncate once exceeded

chatgpt_log() {  # chatgpt_log "message"  — best-effort, always returns 0
  local dir ts size
  dir="$(dirname -- "$CHATGPT_START_LOG")"
  mkdir -p -- "$dir" 2>/dev/null || return 0
  if [[ -f "$CHATGPT_START_LOG" ]]; then
    size="$(wc -c < "$CHATGPT_START_LOG" 2>/dev/null || printf 0)"
    if [[ "${size:-0}" =~ ^[0-9]+$ && "$size" -gt "$CHATGPT_START_LOG_MAX" ]]; then
      : > "$CHATGPT_START_LOG" 2>/dev/null || true
    fi
  fi
  ts="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || true)"
  printf '%s %s\n' "${ts:-[no-date]}" "$1" >> "$CHATGPT_START_LOG" 2>/dev/null || true
  return 0
}

# Print the PIDs of LIVE ChatGPT Desktop processes (one per line). A process
# qualifies ONLY when its real executable (/proc/<pid>/exe) basename is the
# chatgpt binary. This deliberately excludes the RedVector manager script (which
# runs under bash), pagers/editors, and any other command whose arguments merely
# contain the word "chatgpt"; it also excludes defunct/zombie processes (whose
# /proc/<pid>/exe is empty). Best-effort: prints nothing if pgrep/ps or /proc are
# unavailable. It is used only for status, never to block launching.
chatgpt_running_pids() {
  command -v pgrep >/dev/null 2>&1 || return 0
  local p exe st
  for p in $(pgrep -f chatgpt 2>/dev/null); do
    exe="$(readlink -f "/proc/$p/exe" 2>/dev/null || true)"
    [[ "${exe##*/}" == chatgpt* ]] || continue
    st="$(ps -o state= -p "$p" 2>/dev/null || true)"
    [[ -n "$st" && "$st" != Z* ]] && printf '%s\n' "$p"
  done
}

chatgpt_start() {
  chatgpt_installed || { err 'ChatGPT Desktop is not installed. Choose option 1.'; chatgpt_log 'ERROR start aborted: ChatGPT not installed'; return 1; }
  gui_available     || { err 'No active graphical display detected. Log into a desktop session first.'; chatgpt_log 'ERROR start aborted: no graphical session (DISPLAY/WAYLAND_DISPLAY unset)'; return 1; }
  command -v chatgpt >/dev/null 2>&1 || { err 'The chatgpt executable is not on PATH.'; chatgpt_log 'ERROR start aborted: chatgpt not found on PATH'; return 1; }

  # Detect a genuine, LIVE ChatGPT process by its real executable (see
  # chatgpt_running_pids). This is used ONLY to inform the user and NEVER to skip
  # launching: the previous bare `pgrep -f chatgpt` early-return reported a false
  # "already running" (matching helper subprocesses, stale/zombie entries or
  # unrelated commands) while no usable window was open.
  local had_instance=0
  [[ -n "$(chatgpt_running_pids)" ]] && had_instance=1
  if [[ "$had_instance" == 1 ]]; then
    info 'An existing ChatGPT Desktop process is running; the launch below will focus/raise its window (the app is single-instance).'
    chatgpt_log 'INFO existing live chatgpt process detected via /proc; relaunch will focus it'
  fi

  # Default view limitation: the official OpenAI Linux desktop app bundles
  # ChatGPT Chat, ChatGPT Work and Codex in ONE application and exposes no
  # documented URI scheme, command-line flag, XDG desktop action or default-view
  # setting to force the regular Chat interface. We launch the graphical app
  # normally (no invented URI/flag); it opens its own default/last-used view
  # (which may be Codex). The OpenAI app is single-instance, so relaunching
  # focuses an existing window instead of creating a duplicate and opens a fresh
  # window when none exists -- which is why we always launch rather than
  # short-circuiting on a process match.
  info 'Starting ChatGPT Desktop...'
  chatgpt_log 'INFO launching chatgpt graphical app (no documented Chat deep link; opens app default view)'
  nohup chatgpt >/dev/null 2>&1 </dev/null &
  local pid=$!
  sleep 2

  # Report accurately. A bare PID is NOT success: confirm a live chatgpt binary
  # process. Window presence and focus cannot be guaranteed from a shell under
  # X11/Wayland, so we say so rather than claim a window exists.
  if [[ -n "$(chatgpt_running_pids)" ]]; then
    if [[ "$had_instance" == 1 ]]; then
      ok 'ChatGPT Desktop is running; asked the existing single-instance app to open/focus its window.'
    else
      ok 'ChatGPT Desktop started; a live application process is running.'
    fi
    info 'If no window appears, it may be minimized or on another workspace. This manager does not force window focus (no wmctrl/xdotool dependency).'
    chatgpt_log 'INFO chatgpt live process confirmed after launch (window presence not verified)'
  elif kill -0 "$pid" 2>/dev/null; then
    ok 'ChatGPT Desktop launch requested (process still starting up).'
    chatgpt_log 'INFO chatgpt launcher still alive shortly after start; window not yet confirmed'
  else
    warn 'ChatGPT Desktop did not start. Run "chatgpt" in a terminal to see the error.'
    chatgpt_log 'WARN chatgpt launch failed; no live process detected after start'
  fi
}

chatgpt_update() {
  require_non_root || return 1
  chatgpt_installed || { warn 'ChatGPT Desktop is not installed. Use option 1.'; return 1; }
  case "$PKG" in
    deb) command -v sudo >/dev/null 2>&1 || { err 'sudo required.'; return 1; }
         info 'Updating via the OpenAI APT repository configured at install time...'
         sudo apt update && sudo apt install --only-upgrade chatgpt ;;
    rpm) command -v sudo >/dev/null 2>&1 || { err 'sudo required.'; return 1; }
         info 'Updating via the OpenAI DNF repository...'
         sudo dnf upgrade --refresh chatgpt ;;
    arch) warn 'On Arch, the official update path is a full system upgrade (pacman -Syu).'
          confirm 'Run sudo pacman -Syu now?' && sudo pacman -Syu || info 'Cancelled.' ;;
    *)   err "No supported update procedure for this distribution. See $CHATGPT_DOCS"; return 1 ;;
  esac
}

chatgpt_menu() {
  while true; do
    banner_chatgpt
    read -r -e -p "  ${PROMPT_USER}@${PROMPT_HOST}:~\$ Select option [0-5]: " choice || break
    printf '\n'
    case "$choice" in
      1) chatgpt_install || warn 'Installation did not complete.' ;;
      2) chatgpt_check ;;
      3) chatgpt_integration_compat ;;
      4) chatgpt_start  || warn 'ChatGPT Desktop could not be started.' ;;
      5) chatgpt_update || warn 'Update did not complete.' ;;
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
  # Classic terminal green (#00FF41) on a dark background (#0B0F0B) via truecolor
  # ANSI, applied to the RedVector banner ONLY and reset at the end of every line
  # so no foreground/background styling leaks into the menu, prompt or elsewhere.
  # Graceful fallback to the existing bright green when the terminal does not
  # advertise truecolor; success/warning/error colours are untouched.
  local g bg
  if [[ "${COLORTERM:-}" == *truecolor* || "${COLORTERM:-}" == *24bit* ]]; then
    g='\033[1;38;2;0;255;65m'   # #00FF41
    bg='\033[48;2;11;15;11m'    # #0B0F0B (banner-scoped)
  else
    g="$GREEN"; bg=''
  fi
  printf "%b" "${bg}${g}"
  cat <<'ART'
   ██████╗ ███████╗██████╗ ██╗   ██╗███████╗ ██████╗████████╗ ██████╗ ██████╗
   ██╔══██╗██╔════╝██╔══██╗██║   ██║██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
   ██████╔╝█████╗  ██║  ██║██║   ██║█████╗  ██║        ██║   ██║   ██║██████╔╝
   ██╔══██╗██╔══╝  ██║  ██║╚██╗ ██╔╝██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
   ██║  ██║███████╗██████╔╝ ╚████╔╝ ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
   ╚═╝  ╚═╝╚══════╝╚═════╝   ╚═══╝  ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
ART
  printf "%b" "${RESET}"
  say "        ${bg}${g}A I   D E S K T O P   M A N A G E R${RESET}  ${DIM}v1.0${RESET}"
  say "        ${bg}${g}By Adam K.${RESET}"
  hr
  say " ${bg}${g}SYSTEM${RESET}   ${OS_ID:-unknown} ${OS_VERSION:-} | $(uname -m 2>/dev/null) $([[ "$IS_WSL" == 1 ]] && printf '| WSL2')"
  say " ${bg}${g}PROJECT${RESET}  ${DIM}${PROJECT}${RESET}"
  hr
  printf '\n'
  say "   ${BOLD}CHOOSE YOUR AI CLIENT${RESET}"
  printf '\n'
  say "   ${GREEN}[1]${RESET} ${BOLD}Claude Desktop${RESET}"
  say "       ${DIM}Install Claude and register the RedVector MCP server${RESET}"
  say "   ${GREEN}[2]${RESET} ${BOLD}ChatGPT Desktop${RESET}"
  say "       ${DIM}Install ChatGPT and check integration compatibility${RESET}"
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

banner_chatgpt() {
  clear 2>/dev/null || true
  printf "${GREEN}"
  cat <<'ART'
  ╔══════════════════════════════════════════════════╗
  ║            CHATGPT  DESKTOP  MANAGER              ║
  ╚══════════════════════════════════════════════════╝
ART
  printf "${RESET}"
  if chatgpt_installed; then say "  ${GREEN}●${RESET} ChatGPT Desktop installed"
  else say "  ${YELLOW}●${RESET} ChatGPT Desktop not installed"; fi
  [[ "$CHATGPT_SUPPORTED" == 1 ]] || say "  ${YELLOW}●${RESET} ${OS_ID:-This distribution} is not in OpenAI's officially tested list"
  say "  ${DIM}Docs: ${CHATGPT_DOCS}${RESET}"
  hr
  say "   ${GREEN}[1]${RESET} Install ChatGPT Desktop"
  say "   ${GREEN}[2]${RESET} Check installation"
  say "   ${GREEN}[3]${RESET} Check RedVector integration compatibility"
  say "   ${GREEN}[4]${RESET} Start ChatGPT Desktop"
  say "   ${GREEN}[5]${RESET} Update ChatGPT Desktop"
  say "   ${RED}[0]${RESET} Back to main menu"
  printf '\n'
}

# ═══════════════════════════════════════════════════════════════════════════════
#  --help / --status
# ═══════════════════════════════════════════════════════════════════════════════
print_help() {
  cat <<EOF
RedVector AI — Unified AI Desktop Manager v1.0

USAGE:
  $(basename "$0") [REDVECTOR_PROJECT_DIR]
  $(basename "$0") --status
  $(basename "$0") --help

DESCRIPTION:
  Interactive manager for the two supported AI desktop clients. Pick ONE client
  at a time from the main menu; return later to manage the other.

    [1] Claude Desktop  — install from the verified official APT repository and
                          register the RedVector MCP server (start_redvector.sh),
                          preserving existing MCP servers and RedVector env, with
                          a timestamped backup and atomic config writes.
    [2] ChatGPT Desktop — install the official OpenAI Linux-preview package and
                          report RedVector integration compatibility honestly
                          (no fabricated MCP configuration).

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
  if chatgpt_installed; then say " ChatGPT Desktop : ${GREEN}installed${RESET}"
  else say " ChatGPT Desktop : ${YELLOW}not installed${RESET}"; fi
  say " ChatGPT ↔ RedVector MCP : ${YELLOW}not supported / not verified${RESET}"
  hr
}

# ═══════════════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════════════
main_menu() {
  while true; do
    banner_main
    read -r -e -p "  ${PROMPT_USER}@${PROMPT_HOST}:~\$ Select [0-2]: " choice || break
    printf '\n'
    case "$choice" in
      1) claude_menu ;;
      2) chatgpt_menu ;;
      0) ok 'Exiting RedVector AI Desktop Manager.'; return 0 ;;
      *) warn 'Choose 0, 1 or 2.'; pause ;;
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
