#!/usr/bin/env bash
# Install RedVector Git hooks into the local repository.
# Safe opt-in: run manually after cloning.  Does not affect other repos.
# Usage: bash hooks/install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
  echo "ERROR: $REPO_ROOT is not a Git repository." >&2
  exit 1
fi

# Respect core.hooksPath if set; otherwise use the repository's hooks dir.
# git rev-parse --git-common-dir works in both normal repos and worktrees.
CUSTOM_HOOKS_PATH="$(git -C "$REPO_ROOT" config --get core.hooksPath 2>/dev/null || true)"
if [ -n "$CUSTOM_HOOKS_PATH" ]; then
  HOOKS_DIR="$CUSTOM_HOOKS_PATH"
else
  GIT_COMMON="$(git -C "$REPO_ROOT" rev-parse --git-common-dir 2>/dev/null)"
  HOOKS_DIR="$GIT_COMMON/hooks"
fi
mkdir -p "$HOOKS_DIR"

install_hook() {
  local name="$1"
  local src="$SCRIPT_DIR/$name"
  local dst="$HOOKS_DIR/$name"

  if [ ! -f "$src" ]; then
    echo "  SKIP  $name (template not found)"
    return
  fi

  if [ -f "$dst" ] && ! diff -q "$src" "$dst" >/dev/null 2>&1; then
    echo "  BACK  $name (existing hook backed up to $name.bak)"
    cp "$dst" "$dst.bak"
  fi

  cp "$src" "$dst"
  chmod +x "$dst"
  echo "  OK    $name"
}

echo "Installing RedVector Git hooks..."
echo ""
install_hook "commit-msg"
echo ""
echo "Done. Hooks are active for this local clone only."
