"""RedVector Phase 10 AI client / provider / harness setup UX.

One shared, testable Python setup layer that sits on top of the existing Phase 7
AI Integration Manager (``redvector.ai_integration``). It does not create a second
agent, MCP server, security-tool registry, or provider registry; it orchestrates
detection, configuration, diagnostics, and bounded recovery, with a polished
terminal UX. The platform launchers (start_redvector.sh / .ps1) delegate here.
"""
from redvector.version import __version__

__all__ = ["__version__"]
