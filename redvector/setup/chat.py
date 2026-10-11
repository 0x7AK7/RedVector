"""Provider-agnostic RedVector AI chat loop (Phase 10.5).

A thin terminal front-end over the EXISTING RedVector agent. All intent
interpretation, tool resolution, argument building, scope enforcement,
confirmation, and result grounding live in the agent (reached through
``/api/agent/chat``); this module only:

  * uses whatever provider/model is currently active (no hard-coded provider),
  * asserts the operator's authorization for exactly the target the user named
    (reusing the agent's own target extractor - no phrase routing, no scope
    expansion),
  * relays concise operational statuses and the agent's grounded summary,
  * relays the agent's confirmation request for higher-impact actions.

No hard-coded IPs, phrases, tools, or provider branching. No raw model shell.
"""
from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, List, Optional

from redvector.version import __version__


def default_target_extractor(message: str) -> List[str]:
    """Extract the exact target the user named, using the agent's own parser.
    Returns [] when no target is present (e.g. a follow-up about prior results)."""
    try:
        from redvector.agent import IntentParser
        t = IntentParser().parse(message).target
        return [t] if t else []
    except Exception:
        return []


class ChatSession:
    def __init__(self, terminal, active_fn: Callable[[], Dict[str, Any]],
                 agent_call: Callable[..., Dict[str, Any]],
                 target_extractor: Optional[Callable[[str], List[str]]] = None,
                 session_id: Optional[str] = None) -> None:
        self.t = terminal
        self._active = active_fn
        self._agent_call = agent_call
        self._extract = target_extractor or default_target_extractor
        self.session_id = session_id or ("chat-" + uuid.uuid4().hex[:12])

    def run(self) -> int:
        active = self._active() or {}
        provider = active.get("active_provider")
        model = active.get("active_model")
        if not provider:
            self.t.error("No active AI provider/model.")
            self.t.hint("Run: ./start_redvector.sh --setup-ai")
            return 0
        self.t.write(self.t.colorize("RedVector AI %s" % __version__, "red"))
        self.t.info("Provider: %s" % provider)
        self.t.info("Model: %s" % (model or "(provider default)"))
        self.t.hint("Type 'exit', 'quit', or '0' to return to the menu.")
        while True:
            line = self.t.ask(self.t.colorize("You> ", "cyan"))
            if self.t.eof:
                self.t.write()
                return "exit"
            line = line.strip()
            if not line:
                continue
            if line.lower() in ("exit", "quit", "/exit", "0"):
                return "exit"
            sig = self._handle(line)
            if sig:                 # "switch_provider" | "disable_ai"
                return sig

    def _handle(self, message: str):
        self.t.status("THINKING", "Understanding request...")
        targets = self._extract(message)
        authorization = {"authorized": True, "targets": targets}
        try:
            resp = self._agent_call(message, self.session_id, authorization, False)
        except Exception:
            return self._on_ai_lost(message, authorization, targets)
        # higher-impact action -> relay the agent's confirmation request
        if resp.get("needs_confirmation"):
            self.t.status("WARN", resp.get("message", "This action needs confirmation."))
            ans = self.t.ask("Confirm this action? [y/N] ").lower()
            if ans in ("y", "yes"):
                try:
                    resp = self._agent_call(message, self.session_id, authorization, True)
                except Exception:
                    return self._on_ai_lost(message, authorization, targets)
            else:
                self.t.status("INFO", "Cancelled. Nothing was run.")
                return None
        self._render(resp, targets)
        return None

    def _on_ai_lost(self, message, authorization, targets):
        """Graceful degradation: the active AI provider became unavailable."""
        self.t.warn("AI connection lost.")
        self.t.hint("RedVector can continue in manual mode.")
        c = self.t.choose("", ["Retry AI connection", "Choose another provider"],
                          back_label="Continue without AI")
        if c == 1:
            try:
                resp = self._agent_call(message, self.session_id, authorization, False)
            except Exception:
                self.t.status("FAILED", "Still unreachable.")
                return "disable_ai"
            self._render(resp, targets)
            return None
        if c == 2:
            return "switch_provider"
        return "disable_ai"   # 0 / EOF / anything else -> continue without AI (session-scoped)

    def _render(self, resp: Dict[str, Any], targets: List[str]) -> None:
        actions = resp.get("actions") or []
        if actions:
            a0 = actions[0]
            if a0.get("tool"):
                self.t.status("TOOL", a0["tool"])
            if targets:
                self.t.status("TARGET", targets[0])
            self.t.status("RUNNING", "Executing through RedVector...")
        self.t.status("READY", "")
        self.t.write()
        self.t.write(self.t.colorize("RedVector>", "red"))
        self.t.write(resp.get("message", "(no response)"))
        self.t.write()
