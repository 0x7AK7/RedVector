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
from redvector import session_trace as _trace


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
            if line.lower() in ("raw", "view raw", "raw evidence", "/raw"):
                self._show_raw()
                continue
            sig = self._handle(line)
            if sig:                 # "switch_provider" | "disable_ai"
                return sig

    def _show_raw(self) -> None:
        raw = getattr(self, "_last_raw", None)
        if not raw:
            self.t.status("INFO", "No raw evidence captured yet.")
            return
        self.t.write(self.t.colorize("RAW EVIDENCE", "cyan"))
        self.t.write(self.t.colorize("-" * 56, "dim"))
        self.t.write(raw)
        self.t.write()

    def _handle(self, message: str):
        self.t.status("THINKING", "Understanding request...")
        targets = self._extract(message)
        # Optional/None authorization (Phase 10.5 Fix #4): only send a scope update
        # when THIS message names a target. A follow-up with no target sends None so
        # the backend reuses the session's authorized scope instead of clearing it.
        authorization = {"authorized": True, "targets": targets} if targets else None
        self._seq = getattr(self, "_seq", 0) + 1
        _trace.trace("CHAT", session_id=self.session_id, seq=self._seq,
                     target_parsed=bool(targets),
                     authorization=("supplied" if authorization else "omitted"))
        try:
            resp = self._with_heartbeat(message, authorization, False)
        except Exception:
            return self._on_ai_lost(message, authorization, targets)
        # higher-impact action -> relay the agent's confirmation request
        if resp.get("needs_confirmation"):
            self.t.status("WARN", resp.get("message", "This action needs confirmation."))
            ans = self.t.ask("Confirm this action? [y/N] ").lower()
            if ans in ("y", "yes"):
                try:
                    resp = self._with_heartbeat(message, authorization, True)
                except Exception:
                    return self._on_ai_lost(message, authorization, targets)
            else:
                self.t.status("INFO", "Cancelled. Nothing was run.")
                return None
        self._render(resp, targets)
        return None

    # Braille spinner frames for the single live status line.
    _SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def _animate(self) -> bool:
        """Animate only on a real TTY with color/animation allowed (never when
        NO_COLOR, non-TTY, or output is redirected)."""
        try:
            return bool(self.t.color_enabled and self.t.stream.isatty())
        except Exception:
            return False

    def _with_heartbeat(self, message, authorization, confirm):
        """Call the agent on a worker thread while showing ONE in-place live status
        line (spinner + elapsed) for the real in-flight execution - no per-tick line
        spam. A single monotonic timer measures the elapsed shown here AND the final
        duration (see ``self._last_elapsed_ms``). Non-TTY emits one sparse milestone
        line only. Progress is truthful (real wall-clock), never fabricated."""
        import threading
        import time as _time
        result = {}

        def worker():
            try:
                result["resp"] = self._agent_call(message, self.session_id, authorization, confirm)
            except Exception as e:  # noqa: BLE001
                result["err"] = e

        th = threading.Thread(target=worker, daemon=True)
        start = _time.monotonic()
        th.start()
        animate = self._animate()
        stream = self.t.stream
        if not animate:
            # non-TTY / NO_COLOR: one sparse milestone, no animation, no spam
            self.t.status("STARTING", "executing...")
        i = 0
        last_render = 0.0
        while th.is_alive():
            th.join(timeout=0.12)
            if not th.is_alive():
                break
            now = _time.monotonic()
            if animate and (now - last_render) >= 0.12:
                el = int(now - start)
                frame = self._SPINNER[i % len(self._SPINNER)]
                i += 1
                last_render = now
                try:
                    stream.write("\r\x1b[2K%s %s  %02d:%02d" % (
                        self.t.colorize(frame, "cyan"),
                        self.t.colorize("RUNNING", "yellow"), el // 60, el % 60))
                    stream.flush()
                except Exception:
                    pass
        # stop the live line immediately on completion
        self._last_elapsed_ms = (_time.monotonic() - start) * 1000.0
        if animate:
            try:
                stream.write("\r\x1b[2K")   # clear the live status line
                stream.flush()
            except Exception:
                pass
        if "err" in result:
            raise result["err"]
        return result.get("resp", {})

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

    # finding severity/status -> semantic color (text label always present)
    _STATUS_COLOR = {"VALIDATED": "green", "CANDIDATE": "yellow", "VALIDATING": "yellow",
                     "INCONCLUSIVE": "yellow", "REJECTED": "dim"}

    def _render(self, resp: Dict[str, Any], targets: List[str]) -> None:
        actions = resp.get("actions") or []
        a0 = actions[0] if actions else {}
        tool = a0.get("tool") or resp.get("tool")
        stage = a0.get("stage") or resp.get("stage")
        status = a0.get("status")
        tgt = (targets[0] if targets else None) or resp.get("target")

        # True duration: prefer the backend's measured value; fall back to this
        # client's own monotonic timer around the call (ONE timer feeds both).
        dur_ms = resp.get("duration_ms") or getattr(self, "_last_elapsed_ms", 0) or 0
        secs = int(dur_ms // 1000)

        # 1) Concise, real milestones only (not a full pipeline echo).
        if stage:
            self.t.status("PLAN", stage.replace("_", " ").title())
        if tool:
            self.t.status("TOOL", tool)

        # 2) Structured RedVector result header.
        self.t.write()
        self.t.write(self.t.colorize("+" + "=" * 58 + "+", "red"))
        self.t.write(self.t.colorize("|" + "REDVECTOR RESULT".center(58) + "|", "red"))
        self.t.write(self.t.colorize("+" + "=" * 58 + "+", "red"))
        if tgt:
            self.t.write("  %s %s" % (self.t.colorize("TARGET  ", "cyan"), tgt))
        if stage:
            self.t.write("  %s %s" % (self.t.colorize("STAGE   ", "cyan"), stage.replace("_", " ").title()))
        if tool:
            self.t.write("  %s %s" % (self.t.colorize("TOOL    ", "cyan"), tool))
        if status:
            tag = "READY" if status in ("completed", "recalled") else (
                "WARN" if status.startswith(("blocked", "needs", "exploitation_blocked", "incompatible",
                                             "no_capability")) else "INFO")
            self.t.write("  %s %s" % (self.t.colorize("STATUS  ", "cyan"), self.t.tagged(tag)))
        self.t.write("  %s %02d:%02d" % (self.t.colorize("DURATION", "cyan"), secs // 60, secs % 60))

        # 3) Findings (lifecycle status per finding).
        findings = resp.get("findings") or []
        if findings:
            self.t.write()
            self.t.write("  " + self.t.colorize("FINDINGS", "cyan"))
            self.t.write("  " + self.t.colorize("-" * 54, "dim"))
            for f in findings[:12]:
                st = (f.get("status") or "").upper()
                color = self._STATUS_COLOR.get(st, "cyan")
                self.t.write("  %s %s" % (self.t.colorize("[%s]" % st, color), f.get("title") or f.get("tool")))
                if f.get("evidence"):
                    self.t.hint("        evidence: %s" % f["evidence"])

        # 4) Tool-availability resolution (never a silent dead-end).
        tstate = resp.get("tool_state")
        if tstate:
            self.t.write()
            self.t.status("WARN", "Tool not ready: %s" % tstate)
            if resp.get("choices"):
                self.t.hint("  options: %s" % ", ".join(resp["choices"]))
            if resp.get("alternatives"):
                self.t.hint("  registered alternatives: %s" % ", ".join(resp["alternatives"]))

        # 5) AI SUMMARY (grounded; raw output is NOT dumped here). Split a raw dump
        #    from the summary if the deterministic interpreter included one.
        message = resp.get("message", "(no response)")
        summary, raw_from_msg = self._split_summary(message)
        self._last_raw = resp.get("raw_evidence") or raw_from_msg
        self.t.write()
        self.t.write("  " + self.t.colorize("AI SUMMARY", "magenta"))
        self.t.write("  " + self.t.colorize("-" * 54, "dim"))
        self.t.write(summary)

        # 6) NEXT ACTIONS (contextual, non-fabricated).
        self.t.write()
        self.t.write("  " + self.t.colorize("NEXT ACTIONS", "cyan"))
        self.t.write("  " + self.t.colorize("-" * 54, "dim"))
        nxt = []
        if any((f.get("status") or "").upper() in ("CANDIDATE", "INCONCLUSIVE") for f in findings):
            nxt.append("validate candidate findings")
        if self._last_raw:
            nxt.append("type 'raw' to view raw evidence")
        nxt.append("continue the assessment")
        for n in nxt:
            self.t.hint("  - %s" % n)
        self.t.write()

    @staticmethod
    def _split_summary(message: str):
        """Separate a grounded summary from any raw dump the deterministic
        interpreter appended (keeps raw OUT of the summary section)."""
        if not message:
            return "(no response)", None
        for marker in ("\nOutput:\n", " Output:\n", "\nOutput:"):
            if marker in message:
                head, _, tail = message.partition(marker)
                return head.strip() or "Completed.", tail.strip() or None
        return message, None
