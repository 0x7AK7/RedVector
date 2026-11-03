"""Dynamic native-tool discovery and capability compatibility (no hardcoded versions or paths).

Discovers supported Kali security tools at runtime and reports compatibility by **capability**, not
by matching one operator's exact version. Detected versions are runtime observations only — never
global requirements. It distinguishes four orthogonal states so presence is never mistaken for
readiness:

  * **Installed**            — the executable (or a component) is present.
  * **Capability Supported** — the CLI capabilities a reviewed adapter needs are present.
  * **Integrity Verified**   — binary identity/integrity checked (handled by each adapter's own
                               attestation, e.g. the Nuclei checksum registry); discovery does not
                               assess it and reports None.
  * **Execution Ready**      — genuinely proven by real native execution evidence. Discovery NEVER
                               sets this True; it stays False until a Kali verification is recorded.

Capability detection does not rely on brittle literal flag matching in abbreviated help: matching is
notation-aware (grouped `-sS/sT/sA` flags, `--[no-]update`), and a bounded, side-effect-aware option
probe (invoked with NO target, so no scan runs) can confirm a flag that help does not list. Version
falls back to trustworthy dpkg package metadata when a tool has no `--version`. Subprocess probes run
on the backend (native Kali); all parsing, matching and classification is pure and injectable, so the
logic is fully unit-testable on any OS.
"""
import re
import shutil
import subprocess

_DEADLINE = 15

# Per-tool spec. required_flags is the capability contract (verified by notation-aware help match,
# or by the option probe). version_re reads the version banner; dpkg lists package names whose
# metadata provides a version fallback. GVM is modeled as separate components; service_gated marks
# components whose execution also needs running services + an authenticated connection (never implied
# by presence). optional marks components that are not required.
TOOLS = {
    "nmap": {"which": ["nmap"], "version_args": ["--version"], "version_re": r"Nmap version ([0-9][0-9.]+)",
             "help_args": ["-h"], "required_flags": ["-sT", "-sV", "-oX", "--script"], "probe": "option", "dpkg": ["nmap"]},
    "nikto": {"which": ["nikto"], "version_args": ["-Version"], "version_re": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
              "help_args": ["-Help"], "required_flags": ["-Format", "-Tuning", "-maxtime", "-nointeractive"], "dpkg": ["nikto"]},
    "nuclei": {"which": ["nuclei"], "version_args": ["-version"], "version_re": r"v?([0-9]+\.[0-9]+\.[0-9]+)",
               "help_args": ["-h"], "required_flags": ["-u", "-t", "-jsonl"], "dpkg": []},
    "searchsploit": {"which": ["searchsploit"], "version_args": [], "version_re": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                     "help_args": ["-h"], "required_flags": ["--json"], "dpkg": ["exploitdb"]},
    "whatweb": {"which": ["whatweb"], "version_args": ["--version"], "version_re": r"WhatWeb version ([0-9][0-9.]+)",
                "help_args": ["--help"], "required_flags": ["--log-json", "--color"], "dpkg": ["whatweb"]},
    "sqlmap": {"which": ["sqlmap"], "version_args": ["--version"], "version_re": r"([0-9]+\.[0-9]+\.[0-9]+)",
               "help_args": ["-hh"], "required_flags": ["--batch", "--url", "--level"], "dpkg": ["sqlmap"]},
    "wpscan": {"which": ["wpscan"], "version_args": ["--version"], "version_re": r"([0-9]+\.[0-9]+\.[0-9]+)",
               "help_args": ["--help"], "required_flags": ["--url", "--format", "--no-update"], "dpkg": ["wpscan"]},
    "gvm-manager": {"which": ["gvmd"], "version_args": ["--version"], "version_re": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                    "help_args": ["--help"], "required_flags": [], "dpkg": ["gvmd"], "component": "manager", "service_gated": True},
    "gvm-scanner": {"which": ["openvas"], "version_args": ["--version"], "version_re": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                    "help_args": ["--help"], "required_flags": [], "dpkg": ["openvas-scanner", "openvas"], "component": "scanner", "service_gated": True},
    "gvm-ospd": {"which": ["ospd-openvas"], "version_args": ["--version"], "version_re": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                 "help_args": ["--help"], "required_flags": [], "dpkg": ["ospd-openvas"], "component": "ospd", "service_gated": True},
    "gvm-client": {"which": ["gvm-cli"], "version_args": ["--version"], "version_re": r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
                   "help_args": ["--help"], "required_flags": [], "dpkg": ["gvm-tools"], "component": "client", "optional": True},
}
GVM_COMPONENTS = ["gvm-manager", "gvm-scanner", "gvm-ospd", "gvm-client"]


def _as_text(value):
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return "" if value is None else str(value)


def parse_version(name, output):
    """Parse a tool's version banner (bytes or str) into a dotted version string, or ''."""
    spec = TOOLS.get(name, {})
    text = _as_text(output)
    for pattern in (spec.get("version_re"), r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"):
        if not pattern:
            continue
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return ""


def match_flag(flag, help_text):
    """Notation-aware check that a CLI flag is documented in help text. Handles: a direct token;
    `--[no-]x` notation (matches both `--x` and `--no-x`); and a short flag appearing as a bare,
    dash-dropped suffix inside a slash group such as nmap's `-sS/sT/sA` (matches `/sT`)."""
    text = _as_text(help_text)
    if re.search(r"(?<![\w-])" + re.escape(flag) + r"(?![\w-])", text):
        return True
    base = flag[5:] if flag.startswith("--no-") else (flag[2:] if flag.startswith("--") else "")
    if base and re.search(r"--\[no-\]" + re.escape(base) + r"(?![\w-])", text):
        return True
    if re.fullmatch(r"-[A-Za-z]{2,}", flag) and re.search(r"/" + re.escape(flag[1:]) + r"(?![\w-])", text):
        return True
    return False


def interpret_option_probe(flag, code, stdout, stderr):
    """Interpret a side-effect-aware option probe (the tool was run WITHOUT a target, so no scan
    occurred). The flag is *unsupported* only when the tool explicitly rejects it as an unknown
    option; any other outcome (a no-target warning, a value-level error such as an unknown script
    name, or normal output) means the flag was parsed and is recognized. Returns True/False."""
    text = (_as_text(stdout) + "\n" + _as_text(stderr)).lower()
    if re.search(r"(unrecognized|unknown|invalid|illegal)\s+(option|argument|flag)", text):
        return False
    if re.search(r"option\s+" + re.escape(flag.lower()) + r"[^\n]*\b(unknown|invalid|unrecognized|not recognized)\b", text):
        return False
    return True


def _default_runner(path, args):
    completed = subprocess.run([str(path), *args], capture_output=True, timeout=_DEADLINE, stdin=subprocess.DEVNULL)
    return completed.returncode, completed.stdout, completed.stderr


def _default_dpkg(package):
    completed = subprocess.run(["dpkg-query", "-W", "-f", "${Version}", package],
                               capture_output=True, timeout=_DEADLINE, stdin=subprocess.DEVNULL)
    return completed.returncode, completed.stdout, completed.stderr


def _dpkg_version(spec, dpkg_runner):
    """Trustworthy package-version fallback for tools without a --version flag (e.g. searchsploit)."""
    for package in spec.get("dpkg", []):
        try:
            code, out, err = dpkg_runner(package)
        except (OSError, subprocess.SubprocessError):
            continue
        text = _as_text(out).strip()
        if code == 0 and text:
            return text, "dpkg:" + package
    return "", ""


def discover(name, runner=None, dpkg_runner=None):
    """Discover a tool/component: locate its executable on PATH (package-layout tolerant), read its
    version (``--version`` else dpkg fallback), and determine required capabilities (notation-aware
    help match, with an optional side-effect-aware probe). Returns a four-state record. Execution
    readiness is never asserted here."""
    runner = runner or _default_runner
    dpkg_runner = dpkg_runner or _default_dpkg
    if name not in TOOLS:
        return {"tool": name, "installed": False, "error": "unknown tool",
                "capabilities": {}, "capability_supported": False, "integrity_verified": None,
                "execution_ready": False}
    spec = TOOLS[name]
    path = next((shutil.which(c) for c in spec["which"] if shutil.which(c)), "")
    record = {"tool": name, "component": spec.get("component"), "optional": spec.get("optional", False),
              "service_gated": spec.get("service_gated", False), "installed": bool(path), "path": path,
              "source": "PATH" if path else "", "version": "", "version_source": "",
              "capabilities": {}, "capability_supported": False, "integrity_verified": None,
              "execution_ready": False}
    if not path:
        return record
    # version: --version banner, else trustworthy dpkg metadata
    version = ""
    if spec.get("version_args"):
        try:
            _, out, err = runner(path, spec["version_args"])
            version = parse_version(name, _as_text(out) + "\n" + _as_text(err))
        except (OSError, subprocess.SubprocessError):
            version = ""
    if version:
        record["version"], record["version_source"] = version, "--version"
    else:
        dv, dsrc = _dpkg_version(spec, dpkg_runner)
        record["version"], record["version_source"] = dv, dsrc
    # capabilities: notation-aware help match, with the option probe as a fallback where help is
    # abbreviated (nmap). Never relies on a single literal-substring test.
    required = spec.get("required_flags", [])
    caps = {}
    help_text = ""
    if required:
        try:
            _, out, err = runner(path, spec.get("help_args", []))
            help_text = _as_text(out) + "\n" + _as_text(err)
        except (OSError, subprocess.SubprocessError):
            help_text = ""
    for flag in required:
        ok = match_flag(flag, help_text)
        if not ok and spec.get("probe") == "option":
            try:
                probe_args = ([flag] if flag != "--script" else ["--script", "redvector-nonexistent-sentinel"]) + ["-oX", "-"]
                code, out, err = runner(path, probe_args)
                verdict = interpret_option_probe(flag, code, out, err)
                ok = bool(verdict)
            except (OSError, subprocess.SubprocessError):
                ok = False
        caps[flag] = ok
    record["capabilities"] = caps
    record["capability_supported"] = all(caps.values()) if caps else True   # no required flags => vacuously supported
    return record


def status(record):
    """Headline state + detail from the four-state record. Presence never yields execution-ready:
    a fully capable installed tool is reported 'Installed' (execution not yet verified), and a
    service-gated GVM component additionally notes its services/connection are unverified."""
    name = record.get("tool", "")
    if not record.get("installed"):
        if record.get("optional"):
            return "Optional — Not Installed", "Optional component " + name + " is not installed; it is not required."
        return "Missing Dependency", "Native " + name + " not found on PATH; install it or report it unavailable (never substituted)."
    missing = [flag for flag, ok in record.get("capabilities", {}).items() if not ok]
    version = record.get("version") or "version-undetected"
    if missing:
        return "Incompatible", ("Native " + name + " " + version + " is installed but lacks required capability flag(s): "
                                + ", ".join(missing) + ". A reviewed adapter will not run against an incompatible build.")
    detail = ("Native " + name + " " + version + " installed at " + record.get("path", "")
              + "; capability supported; integrity not assessed by discovery; execution not yet verified on Kali.")
    if record.get("service_gated"):
        detail += " GVM component: execution also requires the gvmd/ospd services running and an authenticated GMP connection (not implied by presence)."
    return "Installed", detail


def gvm_report(runner=None, dpkg_runner=None):
    """Model GVM as separate components (manager/scanner/OSPd/optional client). Scanner readiness is
    never reported from presence alone: overall GVM stays not-execution-ready until the services and
    an authenticated connection are verified on Kali."""
    components = {}
    for name in GVM_COMPONENTS:
        record = discover(name, runner=runner, dpkg_runner=dpkg_runner)
        state, detail = status(record)
        components[name] = {"state": state, "detail": detail, "version": record.get("version", ""),
                            "component": record.get("component"), "installed": record.get("installed")}
    required = ["gvm-manager", "gvm-scanner", "gvm-ospd"]
    installed_all = all(components[c]["installed"] for c in required)
    return {"components": components,
            "execution_ready": False,   # never from presence; requires verified running services + GMP connection
            "detail": ("All required GVM components installed (manager/scanner/OSPd); scanner is NOT execution-ready "
                       "until the gvmd and ospd-openvas services and an authenticated GMP connection are verified on Kali."
                       if installed_all else
                       "GVM is incomplete: one or more of gvmd/openvas/ospd-openvas is missing; not execution-ready.")}


def engine_report(runner=None, dpkg_runner=None):
    """Discover and classify every supported engine/component (four-state). For operator-facing
    compatibility reporting; reports missing/incompatible/installed accurately and never claims
    native execution."""
    report = {}
    for name in TOOLS:
        record = discover(name, runner=runner, dpkg_runner=dpkg_runner)
        state, detail = status(record)
        report[name] = {"state": state, "detail": detail, "version": record.get("version", ""),
                        "version_source": record.get("version_source", ""), "path": record.get("path", ""),
                        "capabilities": record.get("capabilities", {}),
                        "states": {"installed": record.get("installed"),
                                   "capability_supported": record.get("capability_supported"),
                                   "integrity_verified": record.get("integrity_verified"),
                                   "execution_ready": record.get("execution_ready")}}
    return report
