#!/usr/bin/env bash
# Register an existing RedVector installation with Claude Desktop on Linux.
# Does not modify RedVector source code or other MCP entries.
set -euo pipefail

if [[ ${EUID} -eq 0 ]]; then
  echo 'Fel: kör som vanlig användare, inte med sudo.' >&2
  exit 1
fi

if [[ $# -gt 1 ]]; then
  echo "Användning: $0 [sökväg-till-RedVector]" >&2
  exit 2
fi

# Determine the script's real location, including when called via a symlink.
# This is independent of the caller's current working directory.
SCRIPT_SOURCE="$(realpath -- "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname -- "$SCRIPT_SOURCE")"

PROJECT="${1:-$SCRIPT_DIR}"

if [[ -z "$PROJECT" || ! -d "$PROJECT" ]]; then
  echo 'Kunde inte hitta RedVector. Ange projektsökvägen som argument:' >&2
  echo "  bash $0 /sökväg/till/RedVector" >&2
  exit 1
fi
PROJECT="$(cd "$PROJECT" && pwd -P)"
for file in start_redvector.sh redvector_mcp.py redvector_server.py redvector_backend_check.py redvector_banner.py; do
  if [[ ! -f "$PROJECT/$file" ]]; then
    echo "Saknad fil: $PROJECT/$file" >&2
    exit 1
  fi
done
if [[ ! -x /bin/bash ]]; then
  echo 'Saknar /bin/bash.' >&2
  exit 1
fi
if [[ ! -x "$PROJECT/.venv/bin/python3" && ! -x "$PROJECT/.venv/bin/python" ]]; then
  echo 'OBS: Ingen Python-venv hittades. Kör pip-installationen i RedVector först.' >&2
fi

# Claude Desktop's Linux configuration. Creates it if needed, never discards
# existing MCP servers or unrelated keys.
CONFIG="$HOME/.config/Claude/claude_desktop_config.json"
mkdir -p "$(dirname "$CONFIG")"
export RV_INSTALL_PROJECT="$PROJECT" RV_INSTALL_CONFIG="$CONFIG"
python3 - <<'PY'
import datetime
import json
import os
import pathlib
import shutil
import stat
import tempfile

project = pathlib.Path(os.environ['RV_INSTALL_PROJECT'])
config = pathlib.Path(os.environ['RV_INSTALL_CONFIG'])
if config.exists():
    raw = config.read_text(encoding='utf-8-sig')
    try:
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f'Felaktig JSON i {config}: {exc}. Inga ändringar gjorda.')
    if not isinstance(data, dict):
        raise SystemExit('Konfigurationsfilens toppnivå måste vara ett JSON-objekt.')
else:
    data = {}
servers = data.setdefault('mcpServers', {})
if not isinstance(servers, dict):
    raise SystemExit('mcpServers är inte ett JSON-objekt. Inga ändringar gjorda.')
old = servers.get('redvector-ai', {})
# Keep existing environment settings, especially custom API tokens.
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

fd, tmp_path = tempfile.mkstemp(prefix='.claude-mcp-', suffix='.json', dir=config.parent)
try:
    with os.fdopen(fd, 'w', encoding='utf-8') as out:
        json.dump(data, out, ensure_ascii=False, indent=2)
        out.write('\n')
        out.flush()
        os.fsync(out.fileno())
    if config.exists():
        os.chmod(tmp_path, stat.S_IMODE(config.stat().st_mode))
    else:
        os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, config)
finally:
    if os.path.exists(tmp_path):
        os.unlink(tmp_path)

print('Klart: Claude Desktop MCP-konfiguration uppdaterad.')
print('RedVector:', project)
print('Konfiguration:', config)
if backup:
    print('Säkerhetskopia:', backup)
print('Andra MCP-servrar behölls oförändrade.')
print('Avsluta och starta om Claude Desktop för att läsa den nya konfigurationen.')
PY
