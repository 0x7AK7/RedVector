"""Honest, verifiable vendor metadata for Phase 10 setup.

Discovered from current official sources during implementation (2026-10). We never
invent package URLs and never silently install third-party desktop apps from an
apt repo + signing key; those are presented as official guided steps / MANUAL
status. Support claims are honest: Kali is Debian-based but is NOT asserted as an
officially validated distribution for any vendor unless that vendor's docs say so.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from redvector.setup.platform_probe import PlatformInfo


@dataclass
class PlatformSupport:
    status: str          # SUPPORTED | BETA | UNVALIDATED | NOT_SUPPORTED | UNKNOWN
    note: str
    official: bool       # whether the current platform is on the vendor's official list


@dataclass
class VendorInfo:
    key: str
    display_name: str
    docs_url: str
    # how RedVector handles install on a supported platform
    install_method: str  # MANUAL_REQUIRED | GUIDED | OFFICIAL_INSTALLER
    install_note: str
    official_steps: List[str] = field(default_factory=list)

    def support_for(self, info: PlatformInfo) -> PlatformSupport:  # overridden per vendor
        return PlatformSupport("UNKNOWN", "Support not determined.", False)


# --------------------------------------------------------------------------
# Claude Desktop (Anthropic) - official Linux app is a BETA for Debian/Ubuntu.
# Docs: https://code.claude.com/docs/en/desktop-linux
# --------------------------------------------------------------------------
class ClaudeDesktopVendor(VendorInfo):
    def __init__(self):
        super().__init__(
            key="claude_desktop", display_name="Claude Desktop",
            docs_url="https://code.claude.com/docs/en/desktop-linux",
            install_method="GUIDED",
            install_note=("On Linux, Claude Desktop is an official BETA for Debian 12+/Ubuntu 22.04+ "
                          "(x86_64/arm64), installed from Anthropic's apt repository with a signing key. "
                          "RedVector does not auto-add third-party apt repositories; follow the official "
                          "steps below."),
            official_steps=[
                "Open the official guide: https://code.claude.com/docs/en/desktop-linux",
                "Import Anthropic's signing key and register the apt repository as documented there",
                "Install the 'claude-desktop' package with apt (updates come through the repo)",
                "Launch Claude Desktop and sign in with your Anthropic account",
            ])

    def support_for(self, info: PlatformInfo) -> PlatformSupport:
        if info.is_windows or info.is_macos:
            return PlatformSupport("SUPPORTED", "Claude Desktop is available for this OS.", True)
        if info.is_linux:
            if info.is_kali:
                return PlatformSupport("UNVALIDATED",
                    "Kali Linux is Debian-based. Claude Desktop may work, but Kali Linux is not currently "
                    "an officially validated Claude Desktop distribution.", False)
            if info.distro_id in ("ubuntu", "debian") or info.is_debian_family:
                return PlatformSupport("BETA",
                    "Claude Desktop for Linux is an official beta for Debian 12+/Ubuntu 22.04+.", True)
            if info.is_fedora_family:
                return PlatformSupport("NOT_SUPPORTED",
                    "Fedora/RHEL are not covered by the current Claude Desktop Linux beta.", False)
            return PlatformSupport("UNVALIDATED",
                "The Claude Desktop Linux beta targets Debian-family distributions; this one is not listed.",
                False)
        return PlatformSupport("UNKNOWN", "Unknown platform.", False)


# --------------------------------------------------------------------------
# Cursor (Anysphere) - official apt repo + direct .deb; amd64/arm64.
# Docs: https://cursor.com/downloads
# --------------------------------------------------------------------------
class CursorVendor(VendorInfo):
    def __init__(self):
        super().__init__(
            key="cursor", display_name="Cursor",
            docs_url="https://cursor.com/downloads",
            install_method="GUIDED",
            install_note=("Cursor publishes an official apt repository and direct .deb/RPM/AppImage downloads "
                          "(amd64/arm64). RedVector does not auto-add third-party apt repositories or install "
                          "arbitrary .deb files; follow the official steps below."),
            official_steps=[
                "Open the official downloads page: https://cursor.com/downloads",
                "On Debian/Ubuntu/Kali: add Cursor's official apt repository (verify the signing-key "
                "fingerprint against the official page), or download the official .deb",
                "On Fedora/RHEL: use Cursor's official RPM package",
                "Install and launch Cursor, then re-run RedVector client setup to add the MCP entry",
            ])

    def support_for(self, info: PlatformInfo) -> PlatformSupport:
        if info.is_windows or info.is_macos:
            return PlatformSupport("SUPPORTED", "Cursor is available for this OS.", True)
        if info.is_linux:
            if info.machine not in ("x86_64", "arm64"):
                return PlatformSupport("NOT_SUPPORTED",
                    "Cursor's Linux packages target x86_64/arm64.", False)
            if info.is_kali:
                return PlatformSupport("UNVALIDATED",
                    "Kali Linux is Debian-based. Cursor's Debian package may work, but Kali is not a "
                    "separately validated Cursor distribution.", False)
            if info.is_debian_family:
                return PlatformSupport("SUPPORTED",
                    "Cursor provides an official Debian-family (apt/.deb) package.", True)
            if info.is_fedora_family:
                return PlatformSupport("SUPPORTED", "Cursor provides an official RPM package.", True)
            return PlatformSupport("UNVALIDATED",
                "Cursor publishes .deb/RPM/AppImage; this distribution is not explicitly listed.", False)
        return PlatformSupport("UNKNOWN", "Unknown platform.", False)


# --------------------------------------------------------------------------
# ChatGPT Desktop (OpenAI) - RedVector integrates via an in-app MCP connector,
# NOT a local stdio MCP config file. No fake localhost connectivity.
# --------------------------------------------------------------------------
class ChatGPTVendor(VendorInfo):
    def __init__(self):
        super().__init__(
            key="chatgpt", display_name="ChatGPT",
            docs_url="https://help.openai.com/",
            install_method="MANUAL_REQUIRED",
            install_note=("ChatGPT connects to RedVector as an MCP connector configured inside the ChatGPT "
                          "app, not by editing a local JSON file. There is no local stdio MCP mechanism."),
            official_steps=[
                "Expose RedVector's MCP server over a reachable URL (SSE transport, e.g. "
                "python -m redvector.mcp.server --transport sse --mcp-port 8889), tunneled securely if remote",
                "In the ChatGPT app, add RedVector as an MCP connector and authorize it with your account",
            ])

    def support_for(self, info: PlatformInfo) -> PlatformSupport:
        # RedVector integration is platform-dependent and lives in the ChatGPT app.
        if info.is_kali:
            return PlatformSupport("UNVALIDATED",
                "Kali Linux is Debian-based. A ChatGPT desktop package may be compatible, but Kali is not "
                "an officially listed ChatGPT desktop distribution.", False)
        return PlatformSupport("PLATFORM_DEPENDENT",
            "ChatGPT + RedVector integration is configured in the ChatGPT app (connector), not on disk.",
            False)


# --------------------------------------------------------------------------
# Ollama (local provider). Official install script at https://ollama.com.
# --------------------------------------------------------------------------
OLLAMA_DOCS = "https://ollama.com/download"
OLLAMA_INSTALL_STEPS = [
    "Linux: install from the official site (https://ollama.com/download) per its documented command",
    "macOS/Windows: download the official installer from https://ollama.com/download",
    "Start the service (ollama serve) and confirm http://127.0.0.1:11434 responds",
]

# Recommended default model (recommendation ONLY, never a runtime dependency).
RECOMMENDED_OLLAMA_MODEL = "dolphin-llama3:8b"
RECOMMENDED_OLLAMA_MODEL_NOTE = (
    "dolphin-llama3:8b (Dolphin 2.9, Llama-3 8B, ~4.7GB) is a recommended default. "
    "It is NOT a RedVector runtime dependency; any installed Ollama model works.")


# --------------------------------------------------------------------------
# DeepSeek Harness (DSH) - official scoped npm package @deepseek-ai/dsh.
# Repo: https://github.com/deepseek-ai/deepseek-harness  (developer preview)
# --------------------------------------------------------------------------
DSH_REPO = "https://github.com/deepseek-ai/deepseek-harness"
DSH_PACKAGE = "@deepseek-ai/dsh"
DSH_NODE_REQUIREMENT = "^22.19.0 || >=24.0.0"
DSH_RUN_COMMAND = ["npx", "@deepseek-ai/dsh", "web"]
DSH_DEFAULT_ENDPOINT = "http://127.0.0.1:3080"
DSH_PREVIEW = True   # upstream describes DSH as a developer preview (verify current status)
DSH_MCP_CAPABILITY = "UNVERIFIED"   # do not claim MCP support without current verification


def all_vendors():
    return {v.key: v for v in (ClaudeDesktopVendor(), CursorVendor(), ChatGPTVendor())}
