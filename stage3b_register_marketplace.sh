#!/usr/bin/env bash
# ============================================================================
# Stage 3B: register RedVector Diagnostic Plugin v0.1 in a PRIVATE local
# marketplace on Kali. Exclusive creation + verification only.
#
# Guarantees:
#   * Verifies the five files against PINNED Stage-1/Stage-3 checksums AND the
#     package SHA256SUMS, before and after copying.
#   * Refuses to overwrite any existing file, directory or symlink; refuses if
#     any ancestor marketplace dir is a symlink.
#   * Rejects symlinks in the source package and copied tree (no symlink escape)
#     and confirms the copy stays inside the dedicated marketplace plugin dir
#     (no path traversal).
#   * Never executes or imports the MCP adapter; never runs start_redvector.sh /
#     redvector_mcp.py / the backend; never runs chatgpt or any install/activate
#     command; never restarts an app; never runs git.
#   * On any failure: stops immediately, prints what was created, performs NO
#     cleanup (no deletes/overwrites).
#
# Usage:
#   bash stage3b_register_marketplace.sh [PLUGIN_SRC_DIR] [SHA256SUMS_PATH]
#   defaults:
#     PLUGIN_SRC_DIR = ~/rv-diag-plugin-test/redvector-diagnostic-plugin
#     SHA256SUMS     = ~/rv-diag-plugin-test/SHA256SUMS
# ============================================================================
set -euo pipefail
umask 022

SRC_DIR="${1:-$HOME/rv-diag-plugin-test/redvector-diagnostic-plugin}"
SUMS="${2:-$HOME/rv-diag-plugin-test/SHA256SUMS}"
MP_ROOT="$HOME/.agents/plugins"
MP_JSON="$MP_ROOT/marketplace.json"
DEST_PARENT="$MP_ROOT/plugins"
DEST="$DEST_PARENT/redvector-diagnostic-plugin"

# Pinned, independently-known-good digests of the verified package (commit fea556c).
declare -A EXPECT=(
  ["adapter/redvector_diag_adapter.py"]="037614be0fea1790e437e2022ec551d6a9659015d35489c220850720e967446e"
  ["mcp.json"]="5267e864a102d40b9b17519c860f83e481dc15481bb136d1da82c8f656da5808"
  ["plugin.json"]="6e3f2d26e45ca114b707a03b2ab700f78da62b0fa59bdaa5134a5694d2f4256e"
  ["README.md"]="48272b2afffd427c847f1305065d3530525e5160694cf8371a88f3c1879e60b2"
  ["SECURITY-REVIEW.md"]="1c68660e1aa4363e40488b259484df9c94d89c95fa6aba1e06302d471c3a4da3"
)

created=()
note(){ printf '%s\n' "$*"; }
fail(){ printf 'ERROR: %s\n' "$*" >&2; printf 'Created so far (NO cleanup performed): %s\n' "${created[*]:-<none>}" >&2; exit 1; }

hash_of(){ sha256sum "$1" | awk '{print $1}'; }

verify_against_pins(){ # $1 = dir
  local rel f
  for rel in "${!EXPECT[@]}"; do
    f="$1/$rel"
    [ -f "$f" ] || fail "missing file: $f"
    [ -L "$f" ] && fail "refusing symlinked file: $f"
    if [ "$(hash_of "$f")" = "${EXPECT[$rel]}" ]; then
      printf '  MATCH    %s\n' "$rel"
    else
      fail "checksum mismatch (not the verified package): $rel"
    fi
  done
}

note "== 0. preconditions =="
command -v sha256sum >/dev/null || fail "sha256sum not available"
command -v python3   >/dev/null || fail "python3 not available"
[ -d "$SRC_DIR" ] || fail "source plugin dir not found: $SRC_DIR"
[ -L "$SRC_DIR" ] && fail "source plugin dir is a symlink: $SRC_DIR"
[ -f "$SUMS" ]    || fail "SHA256SUMS not found: $SUMS"
[ -L "$SUMS" ]    && fail "SHA256SUMS is a symlink: $SUMS"

note "== 1. confirm provided SHA256SUMS matches the pinned verified package =="
sums_count=0
while read -r h rel; do
  [ -n "${h:-}" ] || continue
  case "$h" in \#*) continue;; esac
  [ "${EXPECT[$rel]+x}" = "x" ] || fail "SHA256SUMS lists an unexpected path: $rel"
  [ "$h" = "${EXPECT[$rel]}" ] || fail "SHA256SUMS digest differs from pinned value: $rel"
  sums_count=$((sums_count+1))
done < "$SUMS"
[ "$sums_count" -eq "${#EXPECT[@]}" ] || fail "SHA256SUMS has $sums_count entries; expected ${#EXPECT[@]}"
note "  SHA256SUMS matches the pinned Stage-1/Stage-3 package ($sums_count files)"

note "== 2. refuse to overwrite existing marketplace / plugin dir / symlinks =="
for p in "$MP_JSON" "$DEST"; do
  if [ -e "$p" ] || [ -L "$p" ]; then fail "target already exists (not overwriting): $p"; fi
done
for d in "$HOME/.agents" "$MP_ROOT" "$DEST_PARENT"; do
  if [ -L "$d" ]; then fail "ancestor marketplace path is a symlink (refusing): $d"; fi
done
note "  ok: no existing targets; no symlinked ancestors"

note "== 3. re-verify FIVE source files vs pinned digests (before copy) =="
verify_against_pins "$SRC_DIR"

note "== 4. create marketplace dirs =="
[ -d "$MP_ROOT" ]     || { mkdir -p "$MP_ROOT";     created+=("$MP_ROOT"); }
[ -d "$DEST_PARENT" ] || { mkdir -p "$DEST_PARENT"; created+=("$DEST_PARENT"); }
chmod 755 "$MP_ROOT" "$DEST_PARENT" 2>/dev/null || true

note "== 5. copy plugin into the NEW isolated dir (no symlink following) =="
cp -R --no-dereference "$SRC_DIR" "$DEST"; created+=("$DEST")

note "== 6. reject symlinks in copied tree + confirm it stays inside the marketplace dir =="
if find "$DEST" -type l -print -quit | grep -q .; then fail "symlink present in copied tree: $DEST"; fi
real_dest="$(realpath "$DEST")"; real_parent="$(realpath "$DEST_PARENT")"
case "$real_dest/" in "$real_parent"/*) : ;; *) fail "copied dir escaped marketplace root: $real_dest";; esac

note "== 7. re-verify FIVE copied files vs pinned digests (after copy) =="
verify_against_pins "$DEST"

note "== 8. write NEW marketplace.json (exclusive; noclobber) =="
( set -C; cat > "$MP_JSON" <<'JSON'
{
  "name": "redvector-local",
  "interface": { "displayName": "RedVector Local (test)" },
  "plugins": [
    {
      "name": "redvector-diagnostic-plugin",
      "source": { "source": "local", "path": "./plugins/redvector-diagnostic-plugin" },
      "policy": { "installation": "AVAILABLE", "authentication": "ON_INSTALL" },
      "category": "Productivity"
    }
  ]
}
JSON
) || fail "marketplace.json already existed or could not be created exclusively"
created+=("$MP_JSON")
chmod 644 "$MP_JSON" 2>/dev/null || true

note "== 9. validate marketplace.json syntax =="
python3 -m json.tool "$MP_JSON" >/dev/null && note "  marketplace.json: valid JSON"

note "== 10. confirm ORIGINAL source package still unchanged =="
verify_against_pins "$SRC_DIR" >/dev/null && note "  source package unchanged"

note ""
note "== DONE: registration files created. NOT installed, NOT activated, app NOT restarted. =="
printf 'Created:\n'; printf '  %s\n' "${created[@]}"
note ""
note "Optional READ-ONLY check (does not restart the desktop app):"
note "  codex plugin marketplace list     # shows the resolved marketplace root + entries"
note "Desktop-app discovery requires an app restart, which is NOT authorized in this stage."
