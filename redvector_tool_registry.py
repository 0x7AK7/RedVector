"""Dynamic native-tool discovery and capability compatibility (no hardcoded versions or paths).

Discovers supported Kali security tools at runtime — executable path, version and the CLI
capabilities a reviewed adapter actually needs — and reports compatibility by **capability** rather
than by matching one operator's exact version. No operator's installed version is a global
requirement, and no install path is hardcoded (discovery is via PATH, with package layout differences
tolerated). Binary *identity/integrity* (e.g. the Nuclei checksum registry) is handled separately by
each reviewed adapter; this module reports *version and capability compatibility*.

The subprocess probes (version banner, help text) run on the backend (native Kali). All parsing,
capability-matching and status classification is pure and injectable, so the logic is fully unit
testable on any OS: pass a ``runner(path, args) -> (code, stdout, stderr)`` to discover()/probe().
"""
import re
import shutil
import subprocess

# Per-tool spec: the executable name(s) to look for, how to read a version, the help invocation,
# and the CLI flags a reviewed adapter depends on (capability, not version). required_flags is the
# compatibility contract; a build that lacks one is reported Incompatible rather than silently used.
TOOLS = {
    "nmap": {"which": ["nmap"], "version_args": ["--version"], "version_re": r"Nmap version ([0-9][0-9.]+)",
             "help_args": ["-h"], "required_flags": ["-oX", "-sV", "-sT", "--script"]},
    "nikto": {"which": ["nikto"], "version_args": ["-Version"], "version_re": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
              "help_args": ["-Help"], "required_flags": ["-Format", "-Tuning", "-maxtime", "-nointeractive"]},
    "nuclei": {"which": ["nuclei"], "version_args": ["-version"], "version_re": r"v?([0-9]+\.[0-9]+\.[0-9]+)",
               "help_args": ["-h"], "required_flags": ["-u", "-t", "-jsonl"]},
    "searchsploit": {"which": ["searchsploit"], "version_args": [], "version_re": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                     "help_args": ["-h"], "required_flags": ["--json"]},
    "whatweb": {"which": ["whatweb"], "version_args": ["--version"], "version_re": r"WhatWeb version ([0-9][0-9.]+)",
                "help_args": ["--help"], "required_flags": ["--log-json", "--color"]},
    "sqlmap": {"which": ["sqlmap"], "version_args": ["--version"], "version_re": r"([0-9]+\.[0-9]+\.[0-9]+)",
               "help_args": ["-hh"], "required_flags": ["--batch", "--url", "--level"]},
    "wpscan": {"which": ["wpscan"], "version_args": ["--version"], "version_re": r"([0-9]+\.[0-9]+\.[0-9]+)",
               "help_args": ["--help"], "required_flags": ["--url", "--format", "--no-update"]},
    "openvas": {"which": ["gvm-cli", "gvmd", "openvas"], "version_args": ["--version"], "version_re": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                "help_args": ["--help"], "required_flags": []},
}

_DEADLINE = 15


def parse_version(name, output):
    """Parse a tool's version banner (bytes or str) into a dotted version string, or '' if none.
    Uses the per-tool regex, falling back to a generic dotted-number match."""
    spec = TOOLS.get(name, {})
    text = output.decode("utf-8", "replace") if isinstance(output, (bytes, bytearray)) else str(output)
    for pattern in (spec.get("version_re"), r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"):
        if not pattern:
            continue
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return ""


def capabilities_supported(name, help_text):
    """Given a tool's help text, report which required CLI flags it supports (capability check,
    independent of version). Returns {flag: bool}."""
    spec = TOOLS.get(name, {})
    text = help_text.decode("utf-8", "replace") if isinstance(help_text, (bytes, bytearray)) else str(help_text)
    return {flag: (flag in text) for flag in spec.get("required_flags", [])}


def _default_runner(path, args):
    completed = subprocess.run([str(path), *args], capture_output=True, timeout=_DEADLINE,
                               stdin=subprocess.DEVNULL)
    return completed.returncode, completed.stdout, completed.stderr


def _text(out, err):
    def to_str(value):
        if isinstance(value, (bytes, bytearray)):
            return value.decode("utf-8", "replace")
        return "" if value is None else str(value)
    return to_str(out) + "\n" + to_str(err)


def discover(name, runner=None):
    """Discover a tool: locate its executable on PATH (tolerating package-layout differences),
    read its version and probe its help for required capabilities. Returns a structured record.
    runner is injectable for testing; by default a bounded subprocess is used (native)."""
    if name not in TOOLS:
        return {"tool": name, "installed": False, "path": "", "version": "", "source": "",
                "capabilities": {}, "error": "unknown tool"}
    runner = runner or _default_runner
    spec = TOOLS[name]
    path = ""
    for candidate in spec["which"]:
        found = shutil.which(candidate)
        if found:
            path = found
            break
    if not path:
        return {"tool": name, "installed": False, "path": "", "version": "", "source": "",
                "capabilities": {}}
    version = ""
    if spec.get("version_args"):
        try:
            _, out, err = runner(path, spec["version_args"])
            version = parse_version(name, _text(out, err))
        except (OSError, subprocess.SubprocessError):
            version = ""
    caps = {}
    if spec.get("required_flags"):
        try:
            _, out, err = runner(path, spec.get("help_args", []))
            caps = capabilities_supported(name, _text(out, err))
        except (OSError, subprocess.SubprocessError):
            caps = {flag: False for flag in spec["required_flags"]}
    return {"tool": name, "installed": True, "path": path, "version": version, "source": "PATH",
            "capabilities": caps}


def status(record):
    """Classify a discovery record into (state, detail). Capability compatibility, not version,
    decides usability: a tool present with all required flags is Ready even if its version differs
    from any reference; a missing required flag is Incompatible; absent is Missing Dependency."""
    name = record.get("tool", "")
    if not record.get("installed"):
        return "Missing Dependency", "Native " + name + " not found on PATH; install it or report it unavailable (never substituted)."
    caps = record.get("capabilities", {})
    missing = [flag for flag, ok in caps.items() if not ok]
    version = record.get("version") or "undetected"
    if missing:
        return "Incompatible", ("Native " + name + " " + version + " is installed but lacks required capability flag(s): "
                                + ", ".join(missing) + ". A reviewed adapter will not run against an incompatible build.")
    detail = "Native " + name + " " + version + " detected at " + record.get("path", "")
    detail += ("; required capabilities verified (" + ", ".join(caps) + ")." if caps else ".")
    return "Ready", detail


def engine_report(runner=None):
    """Discover and classify every supported engine. For operator-facing compatibility reporting;
    reports missing/incompatible/unknown accurately and never claims native execution."""
    report = {}
    for name in TOOLS:
        record = discover(name, runner=runner)
        state, detail = status(record)
        report[name] = {"state": state, "detail": detail, "version": record.get("version", ""),
                        "path": record.get("path", ""), "capabilities": record.get("capabilities", {})}
    return report
