"""RedVector tool resolution and installation management (Phase 8, MCP-first).

This module adds two capabilities on top of the EXISTING security-tool registry
(``redvector_security_tools.SECURITY_TOOL_REGISTRY``). It never creates a second
tool registry: every tool id it reasons about is a real, already-registered
RedVector integration.

* ``ToolResolver`` reports, for a registered tool, whether its backing command is
  INSTALLED, AVAILABLE_TO_INSTALL, INSTALLED_NOT_CONFIGURED, UNSUPPORTED, or
  UNAVAILABLE_ON_THIS_PLATFORM, and offers real registered alternatives.
* ``ToolInstallationManager`` turns a verified, hard-coded install definition into
  an explicit, confirmable plan and (only after confirmation) runs it through a
  controlled runner. It never executes model-supplied or user-supplied shell: the
  only commands it can run are the fixed argument-vector recipes defined here, from
  official sources, and it verifies the result afterwards.

Design rules honoured here:
  * Single source of truth for tools is SECURITY_TOOL_REGISTRY (read live).
  * No arbitrary shell. Install recipes are argument vectors (shell=False).
  * Nothing installs without an explicit confirmed=True.
  * Only official sources appear in the definitions.
  * Everything is deterministic/injectable so tests never touch the network,
    install anything, or probe the real machine.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional, Sequence

# Category derivation and the registry live in sibling modules; importing the
# agent's classifier keeps categories consistent (no second taxonomy).
try:  # pragma: no cover - exercised indirectly
    from redvector.agent import _classify_category
except Exception:  # pragma: no cover
    def _classify_category(tid: str) -> str:  # minimal fallback
        return "other"


# ============================================================================
# States and methods
# ============================================================================
class AvailabilityState(str, Enum):
    INSTALLED = "installed"
    AVAILABLE_TO_INSTALL = "available_to_install"
    INSTALLED_NOT_CONFIGURED = "installed_not_configured"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE_ON_THIS_PLATFORM = "unavailable_on_this_platform"


class InstallMethod(str, Enum):
    APT = "apt"
    PIP = "pip"
    PIPX = "pipx"
    GIT_RELEASE = "git_release"
    OFFICIAL_INSTALLER = "official_installer"
    MANUAL_REQUIRED = "manual_required"


# ============================================================================
# Executable resolution
# ============================================================================
# A handful of registered tools carry no provenance.executable because they are
# implemented natively inside RedVector (they need no external binary) or because
# their binary name differs from the tool id. We only override where it is both
# true and verifiable; everything else falls back to provenance.executable, then
# to the tool id itself.

# Tools implemented natively in RedVector (no external binary to install). These
# are always considered INSTALLED because the capability ships with RedVector.
_NATIVE_TOOLS = {
    "http-framework", "browser-agent", "burpsuite-alternative", "gtfobins-lookup",
    "lolbas-lookup", "sudo-check", "suid-finder", "reverse-shell-generator",
    "payload-staging", "persistence-manager", "cctv-default-creds",
    "cctv-rtsp-probe", "cctv-firmware-cve", "cctv-config-audit",
}

# External-binary tools whose executable name is not recorded in provenance.
_EXECUTABLE_OVERRIDES = {
    "evil-winrm": "evil-winrm",
    "kerbrute": "kerbrute",
    "chisel": "chisel",
    "ligolo-ng": "ligolo-ng",
    "proxychains": "proxychains4",
    "ssh-tunnel": "ssh",
    "netexec-exec": "netexec",
    "impacket-psexec": "impacket-psexec",
    "impacket-wmiexec": "impacket-wmiexec",
    "impacket-smbexec": "impacket-smbexec",
    "impacket-secretsdump": "impacket-secretsdump",
    "bloodhound-python": "bloodhound-python",
    "mimikatz": "mimikatz.exe",
    "powersploit": "powershell",
}

# Tools that need an API key / config even once their binary is present. Maps the
# tool id to the environment variable that, when set, marks it configured.
_CONFIG_ENV = {
    "shodan": "SHODAN_API_KEY",
    "censys": "CENSYS_API_ID",
}


# ============================================================================
# Verified install definitions (official sources only)
# ============================================================================
@dataclass(frozen=True)
class InstallDefinition:
    """A fixed, verified recipe for installing one registered tool.

    ``commands`` is a list of argument vectors (each a list of strings) executed
    with shell=False. They are never built from user or model input.
    """
    tool_id: str
    method: InstallMethod
    source_url: str
    commands: Sequence[Sequence[str]] = field(default_factory=tuple)
    requires_root: bool = False
    platforms: Sequence[str] = ("Linux", "Darwin", "Windows")
    verify_executable: Optional[str] = None
    license_note: str = ""
    instructions: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "tool": self.tool_id,
            "method": self.method.value,
            "source_url": self.source_url,
            "commands": [list(c) for c in self.commands],
            "requires_root": self.requires_root,
            "platforms": list(self.platforms),
            "verify_executable": self.verify_executable,
            "license_note": self.license_note,
            "instructions": self.instructions,
        }


def _apt(tool_id, pkg, exe, source, lic=""):
    return InstallDefinition(
        tool_id=tool_id, method=InstallMethod.APT, source_url=source,
        commands=(["apt-get", "update"], ["apt-get", "install", "-y", pkg]),
        requires_root=True, platforms=("Linux",), verify_executable=exe, license_note=lic,
        instructions="Debian/Ubuntu: installs the distribution package %r." % pkg)


def _pip(tool_id, pkg, exe, source, lic=""):
    return InstallDefinition(
        tool_id=tool_id, method=InstallMethod.PIP, source_url=source,
        commands=(["python", "-m", "pip", "install", "--user", pkg],),
        requires_root=False, verify_executable=exe, license_note=lic,
        instructions="Installs the official PyPI package %r for the current user." % pkg)


def _manual(tool_id, source, exe=None, lic="", note=""):
    return InstallDefinition(
        tool_id=tool_id, method=InstallMethod.MANUAL_REQUIRED, source_url=source,
        commands=(), requires_root=False, verify_executable=exe, license_note=lic,
        instructions=note or ("Install manually from the official source: %s" % source))


# Keyed by real registered tool ids. Conservative and verifiable; anything not
# listed falls back to a generic manual definition at resolve time.
INSTALL_DEFS: Dict[str, InstallDefinition] = {
    "nmap": _apt("nmap", "nmap", "nmap", "https://nmap.org/"),
    "masscan": _apt("masscan", "masscan", "masscan", "https://github.com/robertdavidgraham/masscan"),
    "nikto": _apt("nikto", "nikto", "nikto", "https://github.com/sullo/nikto"),
    "gobuster": _apt("gobuster", "gobuster", "gobuster", "https://github.com/OJ/gobuster"),
    "dirb": _apt("dirb", "dirb", "dirb", "https://salsa.debian.org/pkg-security-team/dirb"),
    "hydra": _apt("hydra", "hydra", "hydra", "https://github.com/vanhauser-thc/thc-hydra"),
    "john": _apt("john", "john", "john", "https://www.openwall.com/john/"),
    "hashcat": _apt("hashcat", "hashcat", "hashcat", "https://hashcat.net/hashcat/"),
    "sqlmap": _apt("sqlmap", "sqlmap", "sqlmap", "https://sqlmap.org/"),
    "whois": _apt("whois", "whois", "whois", "https://github.com/rfc1036/whois"),
    "dnsrecon": _apt("dnsrecon", "dnsrecon", "dnsrecon", "https://github.com/darkoperator/dnsrecon"),
    "dnsenum": _apt("dnsenum", "dnsenum", "dnsenum", "https://github.com/fwaeytens/dnsenum"),
    "enum4linux": _apt("enum4linux", "enum4linux", "enum4linux", "https://github.com/CiscoCXSecurity/enum4linux"),
    "smbmap": _pip("smbmap", "smbmap", "smbmap", "https://github.com/ShawnDEvans/smbmap"),
    "wafw00f": _pip("wafw00f", "wafw00f", "wafw00f", "https://github.com/EnableSecurity/wafw00f"),
    "theharvester": _pip("theharvester", "theHarvester", "theHarvester", "https://github.com/laramies/theHarvester"),
    "sherlock": _pip("sherlock", "sherlock-project", "sherlock", "https://github.com/sherlock-project/sherlock"),
    "arjun": _pip("arjun", "arjun", "arjun", "https://github.com/s0md3v/Arjun"),
    "shodan": _pip("shodan", "shodan", "shodan", "https://github.com/achillean/shodan-python",
                   lic="Requires a Shodan API key (SHODAN_API_KEY)."),
    "wpscan": _manual("wpscan", "https://github.com/wpscanteam/wpscan",
                      exe="wpscan", note="Install the official Ruby gem: 'gem install wpscan'."),
    "nuclei": _manual("nuclei", "https://github.com/projectdiscovery/nuclei/releases",
                      exe="nuclei", lic="MIT",
                      note="Download the official signed release binary from ProjectDiscovery, "
                           "or use their pdtm installer. RedVector does not auto-download binaries."),
    "subfinder": _manual("subfinder", "https://github.com/projectdiscovery/subfinder/releases",
                         exe="subfinder", lic="MIT",
                         note="Download the official ProjectDiscovery release binary or use pdtm."),
    "httpx": _manual("httpx", "https://github.com/projectdiscovery/httpx/releases",
                     exe="httpx", lic="MIT",
                     note="Download the official ProjectDiscovery release binary or use pdtm."),
    "katana": _manual("katana", "https://github.com/projectdiscovery/katana/releases",
                      exe="katana", lic="MIT",
                      note="Download the official ProjectDiscovery release binary or use pdtm."),
    "ffuf": _manual("ffuf", "https://github.com/ffuf/ffuf/releases",
                    exe="ffuf", lic="Apache-2.0",
                    note="Download the official ffuf release binary, or 'apt-get install ffuf' on recent Debian/Ubuntu."),
    "amass": _manual("amass", "https://github.com/owasp-amass/amass/releases",
                     exe="amass", lic="Apache-2.0",
                     note="Download the official OWASP Amass release binary."),
    "trivy": _manual("trivy", "https://github.com/aquasecurity/trivy/releases",
                     exe="trivy", lic="Apache-2.0",
                     note="Install from Aqua Security's official APT/YUM repository or release binary."),
    "metasploit": _manual("metasploit", "https://www.metasploit.com/download",
                          exe="msfconsole",
                          note="Use Rapid7's official installer (metasploit-framework). Large, multi-step install."),
    "msfvenom": _manual("msfvenom", "https://www.metasploit.com/download",
                        exe="msfvenom",
                        note="Ships with the official Metasploit Framework install."),
    "evil-winrm": _manual("evil-winrm", "https://github.com/Hackplayers/evil-winrm",
                          exe="evil-winrm", note="Install the official Ruby gem: 'gem install evil-winrm'."),
    "burpsuite-alternative": _manual("burpsuite-alternative", "https://portswigger.net/burp",
                                     note="RedVector provides a native HTTP framework for this capability; "
                                          "Burp Suite itself is commercial and installed from PortSwigger."),
}


# ============================================================================
# Resolved result
# ============================================================================
@dataclass
class ResolvedTool:
    tool_id: str
    registered: bool
    executable: Optional[str]
    state: AvailabilityState
    platform_ok: bool
    install_available: bool
    config_required: bool
    category: str
    alternatives: List[str]
    detail: str

    @property
    def runnable(self) -> bool:
        return self.state == AvailabilityState.INSTALLED

    def to_dict(self) -> Dict[str, object]:
        return {
            "tool": self.tool_id,
            "registered": self.registered,
            "executable": self.executable,
            "state": self.state.value,
            "platform_ok": self.platform_ok,
            "install_available": self.install_available,
            "config_required": self.config_required,
            "category": self.category,
            "alternatives": list(self.alternatives),
            "detail": self.detail,
        }


# ============================================================================
# Resolver
# ============================================================================
class ToolResolver:
    """Determine the availability state of a registered RedVector tool.

    ``which`` and ``system`` and ``env`` are injectable so tests are fully
    deterministic and never probe the real machine.
    """

    def __init__(self, registry, which: Callable[[str], Optional[str]] = shutil.which,
                 system: Callable[[], str] = platform.system,
                 env: Optional[Dict[str, str]] = None) -> None:
        self._registry = registry
        self._which = which
        self._system = system
        self._env = env if env is not None else os.environ

    # -- helpers --
    def _names(self) -> List[str]:
        return list(self._registry.names())

    def is_registered(self, tool_id: str) -> bool:
        return tool_id in set(self._names())

    def executable_for(self, tool_id: str) -> Optional[str]:
        if tool_id in _NATIVE_TOOLS:
            return None
        if tool_id in _EXECUTABLE_OVERRIDES:
            return _EXECUTABLE_OVERRIDES[tool_id]
        try:
            spec = self._registry.get(tool_id)
            ex = getattr(spec.provenance, "executable", None)
            if ex:
                return ex
        except Exception:
            pass
        return tool_id

    def alternatives(self, tool_id: str, limit: int = 5) -> List[str]:
        """Real registered tools in the same category (never invented)."""
        cat = _classify_category(tool_id)
        out = []
        for name in self._names():
            if name == tool_id:
                continue
            if _classify_category(name) == cat:
                out.append(name)
            if len(out) >= limit:
                break
        return out

    def install_definition(self, tool_id: str) -> InstallDefinition:
        if tool_id in INSTALL_DEFS:
            return INSTALL_DEFS[tool_id]
        # Generic, safe fallback: never fabricate an automated recipe.
        return _manual(tool_id, "official source for this tool",
                       exe=self.executable_for(tool_id),
                       note="No verified automated installer is registered for %r. Install it "
                            "manually from its official distribution, then re-check." % tool_id)

    # -- main --
    def resolve(self, tool_id: str) -> ResolvedTool:
        cat = _classify_category(tool_id)
        if not self.is_registered(tool_id):
            return ResolvedTool(tool_id, False, None, AvailabilityState.UNSUPPORTED,
                                False, False, False, cat, [],
                                "%r is not a RedVector security-tool integration." % tool_id)

        alts = self.alternatives(tool_id)
        exe = self.executable_for(tool_id)

        # Native capability: ships with RedVector, nothing to install.
        if exe is None:
            return ResolvedTool(tool_id, True, None, AvailabilityState.INSTALLED,
                                True, False, False, cat, alts,
                                "RedVector-native capability (no external binary required).")

        # Platform gating from the install definition.
        definition = INSTALL_DEFS.get(tool_id)
        sys_name = self._system()
        platform_ok = True
        if definition is not None and sys_name not in definition.platforms:
            platform_ok = False

        present = self._which(exe) is not None
        config_required = tool_id in _CONFIG_ENV
        configured = (not config_required) or bool(self._env.get(_CONFIG_ENV.get(tool_id, ""), ""))

        if present:
            if config_required and not configured:
                return ResolvedTool(tool_id, True, exe, AvailabilityState.INSTALLED_NOT_CONFIGURED,
                                    platform_ok, False, True, cat, alts,
                                    "%s is installed but not configured (missing %s)." %
                                    (exe, _CONFIG_ENV.get(tool_id)))
            return ResolvedTool(tool_id, True, exe, AvailabilityState.INSTALLED,
                                platform_ok, False, config_required, cat, alts,
                                "%s is installed and ready." % exe)

        # Not present.
        if not platform_ok:
            return ResolvedTool(tool_id, True, exe, AvailabilityState.UNAVAILABLE_ON_THIS_PLATFORM,
                                False, False, config_required, cat, alts,
                                "%s is not available on %s." % (exe, sys_name))

        return ResolvedTool(tool_id, True, exe, AvailabilityState.AVAILABLE_TO_INSTALL,
                            platform_ok, True, config_required, cat, alts,
                            "%s is not installed; an install path is available." % exe)


# ============================================================================
# Installation plan + result
# ============================================================================
@dataclass
class InstallPlan:
    tool_id: str
    method: InstallMethod
    source_url: str
    commands: List[List[str]]
    requires_root: bool
    verify_executable: Optional[str]
    license_note: str
    instructions: str
    needs_confirmation: bool = True
    automated: bool = True

    def to_dict(self) -> Dict[str, object]:
        return {
            "tool": self.tool_id,
            "method": self.method.value,
            "source_url": self.source_url,
            "commands": [list(c) for c in self.commands],
            "requires_root": self.requires_root,
            "verify_executable": self.verify_executable,
            "license_note": self.license_note,
            "instructions": self.instructions,
            "needs_confirmation": self.needs_confirmation,
            "automated": self.automated,
        }


@dataclass
class InstallResult:
    tool_id: str
    status: str            # installed | manual_required | not_confirmed | failed | not_installable | verify_failed
    ok: bool
    method: Optional[str]
    message: str
    verified_state: Optional[str] = None
    command_outputs: List[Dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "tool": self.tool_id,
            "status": self.status,
            "ok": self.ok,
            "method": self.method,
            "message": self.message,
            "verified_state": self.verified_state,
            "command_outputs": self.command_outputs,
        }


def _default_runner(cmd: Sequence[str]) -> Dict[str, object]:
    """Run one fixed argument vector with shell=False. Never used in tests."""
    proc = subprocess.run(list(cmd), capture_output=True, text=True, shell=False)  # noqa: S603
    return {"command": list(cmd), "returncode": proc.returncode,
            "stdout": (proc.stdout or "")[-4000:], "stderr": (proc.stderr or "")[-4000:]}


# ============================================================================
# Installation manager
# ============================================================================
class ToolInstallationManager:
    """Produce confirmable install plans and, only on confirmation, run the fixed
    verified recipe through a controlled runner. No arbitrary shell, ever."""

    def __init__(self, resolver: ToolResolver,
                 runner: Callable[[Sequence[str]], Dict[str, object]] = _default_runner) -> None:
        self._resolver = resolver
        self._runner = runner

    def plan(self, tool_id: str) -> InstallPlan:
        definition = self._resolver.install_definition(tool_id)
        automated = definition.method != InstallMethod.MANUAL_REQUIRED and bool(definition.commands)
        return InstallPlan(
            tool_id=tool_id, method=definition.method, source_url=definition.source_url,
            commands=[list(c) for c in definition.commands], requires_root=definition.requires_root,
            verify_executable=definition.verify_executable, license_note=definition.license_note,
            instructions=definition.instructions, needs_confirmation=True, automated=automated)

    def install_options(self, tool_id: str) -> Dict[str, object]:
        """Structured options an MCP client / agent presents to the user."""
        resolved = self._resolver.resolve(tool_id)
        plan = self.plan(tool_id)
        choices: List[str] = []
        if resolved.state == AvailabilityState.AVAILABLE_TO_INSTALL:
            choices.append("INSTALL" if plan.automated else "INSTALL_MANUAL")
        if resolved.alternatives:
            choices.append("USE_ALTERNATIVE")
        choices.append("CANCEL")
        return {
            "tool": tool_id,
            "resolution": resolved.to_dict(),
            "install_plan": plan.to_dict(),
            "alternatives": list(resolved.alternatives),
            "choices": choices,
        }

    def install(self, tool_id: str, confirmed: bool = False) -> InstallResult:
        resolved = self._resolver.resolve(tool_id)

        if resolved.state == AvailabilityState.INSTALLED:
            return InstallResult(tool_id, "installed", True, None,
                                 "%s is already installed." % tool_id,
                                 verified_state=resolved.state.value)
        if resolved.state == AvailabilityState.UNSUPPORTED:
            return InstallResult(tool_id, "not_installable", False, None,
                                 "%r is not a RedVector tool; nothing to install." % tool_id)
        if resolved.state == AvailabilityState.UNAVAILABLE_ON_THIS_PLATFORM:
            return InstallResult(tool_id, "not_installable", False, None,
                                 "%s cannot be installed on this platform." % tool_id,
                                 verified_state=resolved.state.value)

        plan = self.plan(tool_id)

        # Manual / no automated recipe: return instructions, never execute.
        if not plan.automated:
            return InstallResult(tool_id, "manual_required", False, plan.method.value,
                                 plan.instructions + " Source: " + plan.source_url,
                                 verified_state=resolved.state.value)

        # Automated recipe requires explicit confirmation.
        if not confirmed:
            return InstallResult(tool_id, "not_confirmed", False, plan.method.value,
                                 "Installation of %s requires explicit confirmation. Review the plan "
                                 "(%d command(s), source %s) and confirm." %
                                 (tool_id, len(plan.commands), plan.source_url))

        # Run the fixed recipe. Commands come only from the verified definition.
        outputs: List[Dict[str, object]] = []
        for cmd in plan.commands:
            try:
                res = self._runner(cmd)
            except Exception as e:  # pragma: no cover - runner is injectable
                return InstallResult(tool_id, "failed", False, plan.method.value,
                                     "Install command failed: %s" % e, command_outputs=outputs)
            outputs.append(res)
            if res.get("returncode", 1) != 0:
                return InstallResult(tool_id, "failed", False, plan.method.value,
                                     "Install command returned a non-zero exit code.",
                                     command_outputs=outputs)

        # Post-install verification via the resolver (re-checks the executable).
        after = self._resolver.resolve(tool_id)
        if after.state == AvailabilityState.INSTALLED:
            return InstallResult(tool_id, "installed", True, plan.method.value,
                                 "%s installed and verified." % tool_id,
                                 verified_state=after.state.value, command_outputs=outputs)
        if after.state == AvailabilityState.INSTALLED_NOT_CONFIGURED:
            return InstallResult(tool_id, "installed", True, plan.method.value,
                                 "%s installed; configuration still required (%s)." %
                                 (tool_id, _CONFIG_ENV.get(tool_id, "")),
                                 verified_state=after.state.value, command_outputs=outputs)
        return InstallResult(tool_id, "verify_failed", False, plan.method.value,
                             "Install commands ran but %s is still not detected." % tool_id,
                             verified_state=after.state.value, command_outputs=outputs)
