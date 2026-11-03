"""Opt-in backend-owned reviewed native-tool installation — official apt package ONLY.

This module exists so an operator can install a *supported* native Kali security tool that is
genuinely missing, through the official Debian/Kali package, after an explicit approval. It is
deliberately conservative:

  * Only a fixed allowlist of supported tool -> official apt package names may be installed.
  * Installation runs the system package manager as a FIXED argv vector (never a shell string),
    with no PPAs, no added repositories and no downloaded installer scripts of any kind.
  * It NEVER installs silently: ``run_install`` refuses unless the caller passes ``approved=True``
    (the client obtains the operator's explicit Yes and the system-change approval first).
  * It NEVER marks an installed executable as authorized or execution-ready: integrity/attestation
    and capability verification stay with the existing reviewed adapters, which the caller re-runs
    after a successful install. A fresh binary is "installed", never "verified", here.
  * ``nuclei`` is intentionally NOT apt-installable here: a reviewed, checksum-pinned build is
    required (tools/install_reviewed_nuclei.py), so this module reports it as not-apt-available
    rather than installing an unreviewed build.

The execution mode is reported honestly, mirroring the other reviewed adapters:

  * ``A`` — apt executed (install command actually ran; see return_code),
  * ``D`` — missing dependency (apt / package manager unavailable),
  * ``E`` — unsupported (non-Linux host, or runtime could not be used),
  * ``R`` — reviewed input rejected (unknown tool, non-installable tool, or approval not given;
            nothing executed).

All parsing/planning is pure and injectable, so it is fully unit-testable on any OS; only the
real apt invocation requires native Kali.
"""
import os
import shutil
import subprocess
import sys
import time

# Supported tool -> official Debian/Kali package and the reviewed profile the install enables.
# Only tools whose capability RedVector reviews are listed; the package name is a fixed constant,
# never operator-supplied. Keep this aligned with redvector_tool_manager / redvector_tool_registry.
PACKAGES = {
    "nmap":         {"package": "nmap",      "profiles": ("tcp-discovery-v1", "service-version-v1", "nse-vuln-v1")},
    "nikto":        {"package": "nikto",     "profiles": ("nikto-native-v1",)},
    "searchsploit": {"package": "exploitdb", "profiles": ("searchsploit-v1",)},
}
# Supported tools that must NOT be apt-installed here (a reviewed build is required instead).
NON_APT = {
    "nuclei": "A reviewed, checksum-verified Nuclei build is required (run tools/install_reviewed_nuclei.py); "
              "an unreviewed apt/snap build is never auto-installed or trusted.",
}
# Internal RedVector fallback available when the native tool is declined/skipped (honest identity).
INTERNAL_FALLBACK = {
    "nikto": "RedVector passive HTTP collector (NOT native Nikto): one confined root GET, "
             "security-header/cookie/banner review only; clearly labelled as not a native scan.",
}
_DEADLINE = 600          # apt can be slow; bounded hard
_LIMIT = 2 * 1024 * 1024


class InstallError(ValueError):
    pass


def plan(tool):
    """Pure install plan for a supported tool. Returns a dict describing exactly what WOULD happen,
    with no side effects, so the client can show the package name and action before asking."""
    name = str(tool or "").strip().lower()
    if name in PACKAGES:
        package = PACKAGES[name]["package"]
        return {"tool": name, "installable": True, "source": "apt", "package": package,
                "action": "apt-get install -y --no-install-recommends " + package,
                "enables": list(PACKAGES[name]["profiles"]),
                "internal_fallback": INTERNAL_FALLBACK.get(name, ""),
                "note": "Official Debian/Kali package only; no third-party repositories or scripts."}
    if name in NON_APT:
        return {"tool": name, "installable": False, "source": "", "package": "", "action": "",
                "enables": [], "internal_fallback": INTERNAL_FALLBACK.get(name, ""),
                "note": NON_APT[name]}
    return {"tool": name, "installable": False, "source": "", "package": "", "action": "",
            "enables": [], "internal_fallback": INTERNAL_FALLBACK.get(name, ""),
            "note": "Not a supported native tool with a reviewed install path."}


def fallback(tool):
    """The honest internal alternative for a tool, or '' when none exists (capability is then
    skipped and its coverage gap must be explained, never silently substituted)."""
    return INTERNAL_FALLBACK.get(str(tool or "").strip().lower(), "")


def _default_runner(argv):
    env = {"PATH": os.defpath, "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"}
    completed = subprocess.run(argv, capture_output=True, timeout=_DEADLINE,
                               stdin=subprocess.DEVNULL, env=env)
    out = (completed.stdout or b"")[:_LIMIT].decode("utf-8", "replace")
    err = (completed.stderr or b"")[:_LIMIT].decode("utf-8", "replace")
    return completed.returncode, out, err


def run_install(tool, approved=False, runner=None):
    """Install the official apt package for a supported, apt-installable tool — only when the caller
    has already obtained the operator's explicit approval (``approved=True``). Returns a structured
    result whose ``execution_mode`` (A/D/E/R) reports exactly what happened. NEVER marks the tool
    authorized or verified: the caller must re-run discovery/attestation afterwards."""
    started = time.monotonic()
    info = plan(tool)
    if not approved:
        return {"success": False, "execution_mode": "R", "profile": "reviewed-install-v1",
                "tool": info["tool"], "error": "Explicit operator approval is required before any system change; nothing was installed.",
                "execution_time": time.monotonic() - started}
    if not info["installable"]:
        return {"success": False, "execution_mode": "R", "profile": "reviewed-install-v1",
                "tool": info["tool"], "error": info["note"], "execution_time": time.monotonic() - started}
    if not sys.platform.startswith("linux"):
        return {"success": False, "execution_mode": "E", "profile": "reviewed-install-v1",
                "tool": info["tool"], "error": "Unsupported: native apt installation requires native Linux (Kali).",
                "execution_time": time.monotonic() - started}
    runner = runner or _default_runner
    apt = shutil.which("apt-get")
    if not apt:
        return {"success": False, "execution_mode": "D", "profile": "reviewed-install-v1",
                "tool": info["tool"], "error": "Missing Dependency: apt-get package manager unavailable on this host.",
                "execution_time": time.monotonic() - started}
    # Fixed argv: the package name is a constant from PACKAGES (never operator-supplied), so it can
    # never be interpreted as an option or a shell token. No repositories are added, no scripts run.
    argv = [apt, "install", "-y", "--no-install-recommends", info["package"]]
    try:
        code, out, err = runner(argv)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"success": False, "execution_mode": "E", "profile": "reviewed-install-v1",
                "tool": info["tool"], "error": "Native apt installation failed to run: " + str(exc)[:200],
                "execution_time": time.monotonic() - started}
    ok = code == 0
    return {"success": ok, "execution_mode": "A", "profile": "reviewed-install-v1", "tool": info["tool"],
            "package": info["package"], "command": argv, "return_code": code,
            "stdout": out[-4000:], "stderr": err[-4000:],
            "verification_required": True,
            "note": ("apt install command executed. The tool is now 'installed' only — capability and "
                     "integrity are NOT asserted here; re-run discovery/attestation to confirm it is "
                     "usable and reviewed before it is authorized for any operation."),
            "execution_time": time.monotonic() - started}
