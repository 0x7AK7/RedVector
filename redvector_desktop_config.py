#!/usr/bin/env python3
"""Safe, cross-platform Claude Desktop MCP registration for RedVector.

Used by the one-command installers (`install.sh`, `install.ps1`) to register the
`redvector-ai` MCP server in `claude_desktop_config.json` with the SAME safety
guarantees the Linux manager (`redvector_ai_desktop_manager.sh`) already enforces
for its own menu — which stays unchanged:

  * Preserves every other MCP server and every pre-existing key of the
    `redvector-ai` entry (``env``, ``timeout``, ``alwaysAllow``, ``cwd`` …).
  * Never REPLACES a user's custom/secure launcher; only repoints the project's
    own default launcher, keeping all other keys.
  * NEVER adds, restores or modifies ``alwaysAllow`` — no automatic permission
    grant. An existing ``alwaysAllow`` is preserved untouched.
  * Never injects the revoked development token; migrates it away from the
    default launcher so a strong per-user token is generated on launch.
  * Refuses to write while Claude Desktop is running (consent/safety), takes a
    timestamped backup, and writes atomically (temp file + ``os.replace``),
    preserving file permissions. A malformed config is rejected with no change.

This module changes NO MCP tool, input schema, or execution behaviour.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import shutil
import stat
import sys
import tempfile

DEV_TOKEN = "redvector-dev-token"


class ConfigError(Exception):
    """A refusal that must abort without modifying the configuration."""


def claude_run_state() -> str:
    """Return whether Claude Desktop is running, as a tri-state:

        "running"  — a Claude Desktop process was found.
        "stopped"  — the process table was read and no Claude Desktop was found.
        "unknown"  — the state could NOT be determined (psutil missing, or the
                     process scan raised, e.g. permission denied).

    Callers must treat "unknown" as unsafe and refuse to write (fail-safe),
    unless a reliable platform-level check has already confirmed it is stopped.
    """
    try:
        import psutil
    except Exception:
        return "unknown"
    try:
        procs = list(psutil.process_iter(["name", "exe", "cmdline"]))
    except Exception:
        return "unknown"
    for proc in procs:
        try:
            name = (proc.info.get("name") or "").lower()
            exe = (proc.info.get("exe") or "").lower()
            cmd = " ".join(proc.info.get("cmdline") or []).lower()
        except Exception:
            continue
        hay = f"{name} {exe} {cmd}"
        if "claude-desktop" in hay or "claude.exe" in hay:
            return "running"
        # Bare "claude" only when it clearly looks like the desktop app, to
        # avoid matching this installer or an unrelated "claude" CLI.
        if name in ("claude", "claude desktop") and ("desktop" in hay or exe.endswith("claude.exe")):
            return "running"
    return "stopped"


def is_claude_running() -> bool:
    """Back-compat convenience: True only when definitely running."""
    return claude_run_state() == "running"


def default_config_path(platform: str | None = None) -> pathlib.Path:
    plat = _platform(platform)
    if plat == "windows":
        base = os.environ.get("APPDATA") or str(pathlib.Path.home() / "AppData" / "Roaming")
        return pathlib.Path(base) / "Claude" / "claude_desktop_config.json"
    base = os.environ.get("XDG_CONFIG_HOME") or str(pathlib.Path.home() / ".config")
    return pathlib.Path(base) / "Claude" / "claude_desktop_config.json"


def _platform(platform: str | None) -> str:
    if platform:
        p = platform.lower()
        if p in ("windows", "win", "nt"):
            return "windows"
        return "posix"
    return "windows" if os.name == "nt" else "posix"


def _default_launcher(project: pathlib.Path, platform: str):
    """Return (entry_command, entry_args, default_basename) for the platform."""
    if platform == "windows":
        ps1 = str(project / "start_redvector.ps1")
        return "powershell", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1], "start_redvector.ps1"
    sh = str(project / "start_redvector.sh")
    return "/bin/bash", [sh], "start_redvector.sh"


def _launcher_basename(args) -> str:
    for a in reversed(args or []):
        if isinstance(a, str) and a.strip():
            return os.path.basename(a)
    return ""


def register(config_path, project_dir, *, platform: str | None = None,
             check_running: bool = True, assume_stopped: bool = False) -> dict:
    """Register/refresh the redvector-ai MCP entry. Returns a result summary.

    Raises ConfigError (no write) if Claude Desktop is running, if its running
    state cannot be determined (fail-safe), or if the config is malformed.

    ``assume_stopped=True`` lets a caller that has ALREADY verified Claude
    Desktop is stopped with a reliable platform check (the installers' own
    ``pgrep`` / ``Get-Process`` guard) skip the psutil-based check — so a
    transient psutil "unknown" cannot block an otherwise-verified install. It is
    NOT a consent bypass (consent is the installer's prompt) and is never set
    from an unverified state.
    """
    plat = _platform(platform)
    project = pathlib.Path(project_dir).resolve()
    config = pathlib.Path(config_path)

    if check_running and not assume_stopped:
        state = claude_run_state()
        if state == "running":
            raise ConfigError(
                "Claude Desktop is currently running. Fully quit it (close all "
                "windows and let it exit completely), then re-run the installer. "
                "No changes were made."
            )
        if state == "unknown":
            raise ConfigError(
                "Could not determine whether Claude Desktop is running; refusing "
                "to modify the configuration (fail-safe). Fully quit Claude "
                "Desktop and re-run via the installer, which verifies this before "
                "writing. No changes were made."
            )

    config.parent.mkdir(parents=True, exist_ok=True)

    if config.exists():
        try:
            raw = config.read_text(encoding="utf-8-sig")
            data = json.loads(raw) if raw.strip() else {}
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ConfigError(f"Malformed configuration: {exc}. Nothing was changed.")
        if not isinstance(data, dict):
            raise ConfigError("Top-level configuration must be a JSON object. Nothing was changed.")
    else:
        data = {}

    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ConfigError("mcpServers is not an object. Nothing was changed.")

    command, args, default_base = _default_launcher(project, plat)

    old = servers.get("redvector-ai")
    is_dict = isinstance(old, dict)
    old_command = old.get("command") if is_dict else None
    old_args = old.get("args") if is_dict else None
    has_launcher = (isinstance(old_command, str) and old_command
                    and isinstance(old_args, list) and old_args)

    if has_launcher and _launcher_basename(old_args) != default_base:
        # Custom/secure launcher already configured: keep command, args and ALL
        # other keys exactly as they are.
        entry = dict(old)
        launcher_mode = "preserved-custom"
    else:
        # No usable entry yet, or our own default launcher: (re)point it at THIS
        # project's launcher while preserving every other pre-existing key
        # (env, timeout, alwaysAllow, cwd, description, ...).
        entry = dict(old) if is_dict else {}
        entry["command"] = command
        entry["args"] = args
        launcher_mode = "registered-default"

    # Never add/restore a dev token. Migrate it away ONLY from our own default
    # launcher; for a custom launcher, report but do not modify.
    migrated_dev_token = False
    custom_launcher_dev_token = False
    env = entry.get("env")
    if isinstance(env, dict) and env.get("REDVECTOR_API_TOKEN") == DEV_TOKEN:
        if launcher_mode == "registered-default":
            env = dict(env)
            env.pop("REDVECTOR_API_TOKEN", None)
            if env:
                entry["env"] = env
            else:
                entry.pop("env", None)
            migrated_dev_token = True
        else:
            custom_launcher_dev_token = True

    servers["redvector-ai"] = entry

    backup = None
    if config.exists():
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup = config.with_name(config.name + f".backup-{stamp}")
        shutil.copy2(config, backup)

    fd, temp = tempfile.mkstemp(prefix=".rv-mcp-", suffix=".json", dir=str(config.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, indent=2, ensure_ascii=False)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        try:
            os.chmod(temp, stat.S_IMODE(config.stat().st_mode) if backup else 0o600)
        except OSError:
            pass
        os.replace(temp, config)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

    return {
        "config": str(config),
        "project": str(project),
        "platform": plat,
        "launcher_mode": launcher_mode,
        "backup": str(backup) if backup else None,
        "migrated_dev_token": migrated_dev_token,
        "custom_launcher_dev_token": custom_launcher_dev_token,
    }


def _print_result(r: dict) -> None:
    print("[OK] RedVector MCP registered in Claude Desktop.")
    print("RedVector project:", r["project"])
    print("Config file:", r["config"])
    if r["launcher_mode"] == "preserved-custom":
        print("Existing custom redvector-ai launcher preserved (command and args unchanged).")
    if r["migrated_dev_token"]:
        print("Migrated the revoked published development token out of the RedVector env; "
              "a strong per-user token is generated and persisted automatically on launch.")
    if r["custom_launcher_dev_token"]:
        print("[WARN] The existing CUSTOM redvector-ai launcher sets REDVECTOR_API_TOKEN to the "
              "revoked development token. It was NOT modified (custom launcher).")
    if r["backup"]:
        print("Backup created:", r["backup"])
    print("Other MCP servers and any existing RedVector environment variables were preserved.")
    print("No tool permissions were granted; any existing 'alwaysAllow' was left unchanged.")
    print("Restart Claude Desktop if it is already running.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Register RedVector in Claude Desktop (safe, consent-gated).")
    ap.add_argument("action", choices=["register"], help="operation to perform")
    ap.add_argument("--project", required=True, help="RedVector project directory")
    ap.add_argument("--config", default=None, help="claude_desktop_config.json path (default: per-platform)")
    ap.add_argument("--platform", default=None, choices=["windows", "posix"], help="override platform")
    ap.add_argument("--assume-stopped", action="store_true",
                    help="caller has already verified (pgrep/Get-Process) that Claude Desktop is stopped")
    args = ap.parse_args(argv)
    config = pathlib.Path(args.config) if args.config else default_config_path(args.platform)
    try:
        result = register(config, args.project, platform=args.platform,
                          assume_stopped=args.assume_stopped)
    except ConfigError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    _print_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
