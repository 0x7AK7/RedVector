#!/usr/bin/env bash
set -Eeuo pipefail

KEY_URL='https://downloads.claude.ai/claude-desktop/key.asc'
KEY_PATH='/usr/share/keyrings/claude-desktop-archive-keyring.asc'
REPO_PATH='/etc/apt/sources.list.d/claude-desktop.list'
REPO_LINE="deb [arch=amd64,arm64 signed-by=${KEY_PATH}] https://downloads.claude.ai/claude-desktop/apt/stable stable main"
EXPECTED_FPR='31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE'
ALLOW_WSL=0

say() { printf '\n\033[1;32m[Claude Desktop]\033[0m %s\n' "$*"; }
fail() { printf '\n\033[1;31m[FEL]\033[0m %s\n' "$*" >&2; exit 1; }
trap 'printf "\n[FEL] Installationen avbröts vid rad %s. Läs felmeddelandet ovan.\n" "$LINENO" >&2' ERR

for arg in "$@"; do
  case "$arg" in
    --allow-wsl) ALLOW_WSL=1 ;;
    -h|--help) printf 'Användning: bash %s [--allow-wsl]\n' "$0"; exit 0 ;;
    *) fail "Okänt argument: $arg" ;;
  esac
done

[[ "$(id -u)" -ne 0 ]] || fail 'Kör skriptet som vanlig användare, inte som root. Det använder sudo vid behov.'
command -v apt-get >/dev/null || fail 'APT saknas. Kräver Debianbaserat system.'
command -v dpkg >/dev/null || fail 'dpkg saknas.'
command -v sudo >/dev/null || fail 'sudo saknas.'

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  say "System: ${PRETTY_NAME:-okänt}"
  case " ${ID:-} ${ID_LIKE:-} " in
    *debian*|*ubuntu*|*kali*) ;;
    *) fail 'Detta skript är avsett för Kali, Debian och Ubuntu.' ;;
  esac
fi

ARCH="$(dpkg --print-architecture)"
[[ "$ARCH" == amd64 || "$ARCH" == arm64 ]] || fail "Arkitekturen $ARCH stöds inte. Endast amd64/arm64."
say "Arkitektur: $ARCH"

if grep -qiE '(microsoft|wsl)' /proc/sys/kernel/osrelease /proc/version 2>/dev/null; then
  printf '\nOBS: WSL2 har identifierats. Anthropic rekommenderar Claude Desktop i Windows\nmed Claude Code-sessioner i Kali WSL2. Linux-appen i WSL2 kan ha begränsningar.\n'
  if (( ! ALLOW_WSL )); then
    printf 'Om du ändå vill prova Linux-appen, kör igen med --allow-wsl.\n'
    exit 2
  fi
fi

say 'Kontrollerar sudo-behörighet ...'
sudo -v
say 'Installerar curl, gnupg och CA-certifikat ...'
sudo apt-get update
sudo apt-get install -y curl gnupg ca-certificates

TMP_KEY="$(mktemp)"
trap 'rm -f "${TMP_KEY:-}"' EXIT
say 'Laddar ned Anthropics signeringsnyckel ...'
curl --fail --silent --show-error --location --retry 3 "$KEY_URL" -o "$TMP_KEY"
ACTUAL_FPR="$(gpg --batch --show-keys --with-colons "$TMP_KEY" | awk -F: '$1 == "fpr" { print toupper($10); exit }')"
[[ "$ACTUAL_FPR" == "$EXPECTED_FPR" ]] || fail "Signeringsnyckelns fingerprint stämmer inte! Fick: ${ACTUAL_FPR:-tomt}. Förrådet registreras inte."
say 'Signeringsnyckeln verifierad.'
sudo install -m 0644 "$TMP_KEY" "$KEY_PATH"
printf '%s\n' "$REPO_LINE" | sudo tee "$REPO_PATH" >/dev/null

say 'Uppdaterar paketindex och installerar Claude Desktop ...'
sudo apt-get update
sudo apt-get install -y claude-desktop

dpkg-query -W -f='${Status}\n' claude-desktop | grep -qx 'install ok installed' || fail 'Installationen kunde inte verifieras.'
say "Klart! Installerad version: $(dpkg-query -W -f='${Version}' claude-desktop)"

if [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
  if command -v claude-desktop >/dev/null 2>&1; then
    say 'Startar Claude Desktop ...'
    nohup claude-desktop >/dev/null 2>&1 </dev/null &
  else
    printf 'Appen är installerad. Starta Claude via din programmeny.\n'
  fi
else
  printf 'Inget grafiskt skrivbord hittades. Starta senare med: claude-desktop\n'
fi

printf '\nFramtida uppdateringar: sudo apt-get update && sudo apt-get install --only-upgrade claude-desktop\n'
