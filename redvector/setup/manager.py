"""AIIntegrationSetupManager - the single Phase 10 orchestrator.

Wires the terminal UX, platform probe, client/provider/harness setup, diagnostics,
and bounded reconnect. Drives the first-run main menu and the direct CLI commands.
Business logic lives here (Python); the shell/PowerShell launchers only bootstrap
the venv and then delegate to ``python -m redvector.setup``.

Launcher contract: this process exits 10 to mean "start RedVector normally" (the
launcher then runs its backend + MCP bootstrap), and 0 when a setup command was
handled. Non-interactive (non-TTY) invocations never block on a menu; they return
10 so MCP-client launches start RedVector directly.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from redvector import ai_integration as _ai
from redvector.version import __version__
from redvector.setup.terminal import Terminal
from redvector.setup.platform_probe import PlatformProbe
from redvector.setup.clients import ClientSetup
from redvector.setup.providers import ProviderSetup, OllamaModelManager
from redvector.setup.harness import DeepSeekHarnessManager
from redvector.setup.diagnostics import Diagnostics
from redvector.setup import reconnect as _reconnect
from redvector.setup import vendors
from redvector.setup import status as _S
from redvector.setup.chat import ChatSession

START_REDVECTOR = 10   # launcher exit-code contract: start backend + MCP
START_CHAT = 11        # launcher exit-code contract: start backend + chat
HANDLED = 0


def _default_chat_agent_call(env):
    """POST a chat turn to the local backend's /api/agent/chat (real tool execution)."""
    import json as _json
    import urllib.request
    host = env.get("REDVECTOR_HOST", "127.0.0.1")
    port = env.get("REDVECTOR_PORT", "8888")
    token = env.get("REDVECTOR_API_TOKEN", "redvector-dev-token")
    url = "http://%s:%s/api/agent/chat" % (host, port)

    def call(message, session_id, authorization, confirm):
        payload = {"message": message, "session_id": session_id,
                   "authorization": authorization, "confirm": bool(confirm)}
        data = _json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer %s" % token})
        with urllib.request.urlopen(req, timeout=300) as r:  # noqa: S310 (local backend)
            return _json.loads(r.read().decode("utf-8", "replace"))
    return call

# DSH observable-state -> display tag (READY only when actually reachable).
_DSH_TAG = {"READY": "READY", "INSTALLED_STOPPED": "INSTALLED / STOPPED",
            "STARTING": "STARTING", "NOT_INSTALLED": "NOT INSTALLED"}


def _project_root() -> str:
    # redvector/setup/manager.py -> project root is two levels up from the package
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _default_backend_probe(env: Optional[dict] = None) -> Callable[[], bool]:
    env = env if env is not None else os.environ
    host = env.get("REDVECTOR_HOST", "127.0.0.1")
    port = env.get("REDVECTOR_PORT", "8888")
    token = env.get("REDVECTOR_API_TOKEN", "redvector-dev-token")
    url = "http://%s:%s/health" % (host, port)

    def probe() -> bool:
        try:
            req = urllib.request.Request(url, headers={"Authorization": "Bearer %s" % token})
            with urllib.request.urlopen(req, timeout=3) as r:  # noqa: S310 (localhost health)
                return r.status == 200
        except Exception:
            return False
    return probe


def _default_backend_starter(env, probe, sleeper):
    """Start `python -m redvector` detached and wait (bounded) for health. Used by
    the in-process menu so the user never has to manage the backend by hand."""
    import subprocess
    host = env.get("REDVECTOR_HOST", "127.0.0.1")
    port = env.get("REDVECTOR_PORT", "8888")

    def start() -> bool:
        if probe():
            return True
        creationflags = 0
        kwargs = {}
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | \
                getattr(subprocess, "DETACHED_PROCESS", 0)
            kwargs["creationflags"] = creationflags
        else:
            kwargs["start_new_session"] = True   # detach so it survives this process
        try:
            subprocess.Popen([sys.executable, "-m", "redvector", "--port", str(port), "--host", str(host)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs)  # noqa: S603
        except Exception:
            return False
        for _ in range(30):
            if probe():
                return True
            sleeper(1)
        return False
    return start


# ---- stale-backend protection (Phase 10.5 surgical fix, BUG 8) ----

def _default_backend_identity(env: Optional[dict] = None) -> Callable[[], Optional[dict]]:
    """Return a callable that GETs /health and returns the backend's identity
    ({service, pid, build_fingerprint, version}) or None if nothing responds."""
    env = env if env is not None else os.environ
    host = env.get("REDVECTOR_HOST", "127.0.0.1")
    port = env.get("REDVECTOR_PORT", "8888")
    url = "http://%s:%s/health" % (host, port)

    def identity() -> Optional[dict]:
        import json as _json
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=3) as r:  # noqa: S310 (localhost health)
                if r.status != 200:
                    return None
                return _json.loads(r.read().decode("utf-8", "replace"))
        except Exception:
            return None
    return identity


def backend_reuse_decision(current_fingerprint: str, identity: Optional[dict]) -> str:
    """Decide what to do with whatever is answering on the backend port. Pure and
    testable. Returns one of:
      'start'    - nothing is running -> start the current backend;
      'reuse'    - a RedVector backend with a MATCHING fingerprint -> reuse it;
      'restart'  - a RedVector backend with a DIFFERENT fingerprint (stale) -> it
                   must be terminated (identity-verified) and restarted;
      'conflict' - something that is NOT the RedVector backend is on the port -> do
                   NOT touch it; report the conflict.
    """
    if not identity:
        return "start"
    if identity.get("service") != "redvector-backend":
        return "conflict"
    if identity.get("build_fingerprint") == current_fingerprint:
        return "reuse"
    return "restart"


def _terminate_backend_process(identity: dict) -> bool:
    """Terminate ONLY a verified RedVector backend process. Verifies the pid's
    process really is a RedVector backend (command line mentions redvector) before
    signalling it; never kills an arbitrary process that merely holds the port."""
    pid = identity.get("pid")
    if not isinstance(pid, int) or pid <= 0 or identity.get("service") != "redvector-backend":
        return False
    try:
        import psutil  # type: ignore
    except Exception:
        return False
    try:
        proc = psutil.Process(pid)
        cmdline = " ".join(proc.cmdline()).lower()
        if "redvector" not in cmdline:
            return False   # identity not confirmed -> refuse to kill
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except Exception:
            proc.kill()
        return True
    except Exception:
        return False


class AIIntegrationSetupManager:
    def __init__(self, terminal: Optional[Terminal] = None,
                 platform_probe: Optional[PlatformProbe] = None,
                 client_setup: Optional[ClientSetup] = None,
                 provider_setup: Optional[ProviderSetup] = None,
                 harness: Optional[DeepSeekHarnessManager] = None,
                 diagnostics: Optional[Diagnostics] = None,
                 backend_probe: Optional[Callable[[], bool]] = None,
                 marker_path: Optional[str] = None,
                 sleeper: Optional[Callable[[float], None]] = None,
                 env: Optional[dict] = None,
                 chat_agent_call: Optional[Callable[..., Dict[str, Any]]] = None,
                 backend_starter: Optional[Callable[[], bool]] = None,
                 readiness_fn: Optional[Callable[[str, str], bool]] = None,
                 backend_identity: Optional[Callable[[], Optional[dict]]] = None,
                 fingerprint_fn: Optional[Callable[[], str]] = None,
                 terminate_fn: Optional[Callable[[dict], bool]] = None) -> None:
        self.env = env if env is not None else os.environ
        self._chat_agent_call = chat_agent_call
        self._backend_starter = backend_starter
        self._backend_identity = backend_identity or _default_backend_identity(self.env)
        self._terminate_fn = terminate_fn or _terminate_backend_process
        if fingerprint_fn is not None:
            self._fingerprint_fn = fingerprint_fn
        else:
            from redvector import version as _v
            self._fingerprint_fn = _v.build_fingerprint
        self._readiness_fn = readiness_fn
        self._ai_disabled = False   # session-scoped "continue without AI"; never persisted
        self.t = terminal or Terminal(env=self.env)
        self.platform = platform_probe or PlatformProbe()
        self.clients = client_setup or ClientSetup()
        if provider_setup is None:
            # Persist the active provider/model to the SAME canonical state file the
            # backend uses, so a selection made in setup/CLI survives new processes.
            mgr = _ai.AIProviderManager(credentials=_ai.get_credential_store(),
                                        state_path=_ai.default_ai_state_path())
            provider_setup = ProviderSetup(mgr)
        self.providers = provider_setup
        self.harness = harness or DeepSeekHarnessManager()
        self.backend_probe = backend_probe or _default_backend_probe(self.env)
        self.diagnostics = diagnostics or Diagnostics(
            self.clients, self.providers, self.harness, backend_probe=self.backend_probe)
        self.marker_path = marker_path or os.path.join(_project_root(), ".redvector", "firstrun")
        self.sleeper = sleeper or __import__("time").sleep
        if self._backend_starter is None:
            self._backend_starter = _default_backend_starter(self.env, self.backend_probe, self.sleeper)

    # ---- first-run marker (local, non-secret, git-ignored) ----
    def firstrun_done(self) -> bool:
        return os.path.isfile(self.marker_path)

    def mark_firstrun(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.marker_path), exist_ok=True)
            with open(self.marker_path, "w", encoding="utf-8") as f:
                f.write("RedVector %s first-run setup acknowledged\n" % __version__)
        except Exception:
            pass

    # ---- bounded backend recovery (RedVector-owned) ----
    def recover_backend(self) -> _reconnect.RecoveryResult:
        return _reconnect.recover(self.backend_probe, sleeper=self.sleeper,
                                  success_state="READY", fail_state="FAILED")

    # ======================================================================
    # CLI entrypoint
    # ======================================================================
    def run(self, argv: List[str]) -> int:
        args = list(argv or [])
        flags = {a for a in args if a.startswith("--")}

        if "--menu" in flags:
            return self.main_menu()        # always the menu, even when AI is ready
        if "--chat" in flags:
            self.chat_cli(); return HANDLED
        if "--diagnostics" in flags:
            self.print_diagnostics(); return HANDLED
        if "--status" in flags:
            self.print_status(); return HANDLED
        if "--connect-claude" in flags:
            self._report_client_action(self.clients.connect("claude_desktop")); return HANDLED
        if "--connect-cursor" in flags:
            self._report_client_action(self.clients.connect("cursor")); return HANDLED
        if "--disconnect-claude" in flags:
            self._report_client_action(self.clients.disconnect("claude_desktop")); return HANDLED
        if "--disconnect-cursor" in flags:
            self._report_client_action(self.clients.disconnect("cursor")); return HANDLED
        if "--provider" in flags:
            pid = self._flag_value(args, "--provider")
            self.provider_flow(pid); return HANDLED
        if "--setup-ai" in flags:
            self.provider_menu(); return HANDLED
        if "--setup-harness" in flags or "--install-dsh" in flags:
            self.harness_flow(); return HANDLED
        if "--start" in flags:
            self.mark_firstrun(); return START_REDVECTOR

        # no recognized command
        if not self._interactive():
            # MCP-client / piped / redirected launch -> start backend + MCP, never a menu.
            return START_REDVECTOR
        # Smart auto-start: drop straight into the classic RedVector interface only when
        # the AI is actually ready (persisted + valid + reachable + model usable). Stale or
        # unreachable persistence does NOT count as ready; those get the main menu.
        if self.ai_ready():
            self.start_redvector()
        return self.main_menu()

    def ai_ready(self) -> bool:
        if self._ai_disabled:
            return False
        active = self.providers.manager.active()
        pid = active.get("active_provider")
        if not pid:
            return False
        model = active.get("active_model") or ""
        if self._readiness_fn is not None:
            try:
                return bool(self._readiness_fn(pid, model))
            except Exception:
                return False
        try:
            return bool(self.providers.test(pid, model).get("ok"))
        except Exception:
            return False

    def _interactive(self) -> bool:
        """Interactive only when BOTH stdin and stdout are real TTYs (never for
        MCP-client / piped / redirected launches). On Windows, isatty() can be True
        for the NUL device, so the menu additionally treats an immediate EOF as
        'start RedVector' (see main_menu)."""
        try:
            return bool(sys.stdin.isatty()) and bool(sys.stdout.isatty())
        except Exception:
            return False

    @staticmethod
    def _flag_value(args: List[str], flag: str) -> str:
        if flag in args:
            i = args.index(flag)
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                return args[i + 1]
        for a in args:
            if a.startswith(flag + "="):
                return a.split("=", 1)[1]
        return ""

    # ======================================================================
    # Menus
    # ======================================================================
    def main_menu(self) -> int:
        """Menu-first entry. Runs in-process and loops: actions return here, never
        restart the launcher. 0 = Exit. Items are ordered Providers, Clients, Start,
        Harnesses, Diagnostics, Status (intentional)."""
        self.t.banner()
        self.mark_firstrun()
        while True:
            # Warn (do not auto-start into) a configured-but-not-ready provider.
            active = self.providers.manager.active()
            if active.get("active_provider") and not self.ai_ready():
                self.t.warn("Configured AI provider (%s) is not ready." % active["active_provider"])
            c = self.t.choose("RedVector %s" % __version__, [
                "AI Providers       (choose the AI RedVector uses)",
                "AI Clients         (connect external AI apps to RedVector)",
                "Start RedVector",
                "AI Harnesses       (advanced: optional execution backends)",
                "Diagnostics        (full installation / configuration / connection)",
                "Status             (quick system summary)"], back_label="Exit")
            if c in (self.t.EOF, 0):
                return HANDLED
            if c == self.t.INVALID:
                # Non-numeric text at the menu is NOT an offensive command. Guide the
                # operator to enter RedVector commands inside "Start RedVector".
                self.t.status("INFO", 'Select 1-6, or choose "3. Start RedVector" '
                                      "to enter natural-language commands.")
                continue
            if c == 1:
                self.provider_menu()
            elif c == 2:
                self.client_menu()
            elif c == 3:
                self.start_redvector()
            elif c == 4:
                self.harness_menu()
            elif c == 5:
                self.print_diagnostics()
            elif c == 6:
                self.print_status()

    def classic_startup(self) -> None:
        self.t.classic_banner(self.env.get("REDVECTOR_HOST", "127.0.0.1"),
                              self.env.get("REDVECTOR_PORT", "8888"))

    def start_redvector(self) -> None:
        """Option 3 / auto-start: classic RedVector interface. Shows the classic
        red-team identity, ensures the backend, and opens the provider-agnostic chat
        when AI is ready (otherwise runs in manual mode). Returns to the main menu."""
        self.classic_startup()
        if not self.ensure_backend():
            return
        if self._ai_disabled or not self.ai_ready():
            active = self.providers.manager.active()
            if not active.get("active_provider"):
                self.t.info("RedVector is running without an AI provider. "
                            "Choose '1. AI Providers' to configure one.")
            else:
                self.t.warn("The configured AI provider is not ready; running in manual mode. "
                            "Use '1. AI Providers' to repair or switch it.")
            return
        active = self.providers.manager.active()
        self.t.write()
        self.t.status("LIVE", "All systems operational. Awaiting engagement.")
        self.t.info("AI: %s / %s" % (active["active_provider"], active.get("active_model") or "(default)"))
        result = self.chat_cli()
        if result == "switch_provider":
            self.provider_menu()
        elif result == "disable_ai":
            self._ai_disabled = True   # session-scoped; a new process re-detects readiness

    def ensure_backend(self) -> bool:
        # Stale-backend protection (BUG 8): a backend process can survive a code
        # update and keep serving old code. Compare the running backend's build
        # fingerprint against this checkout; reuse only on a match.
        current = self._fingerprint_fn()
        identity = self._backend_identity()
        decision = backend_reuse_decision(current, identity)

        if decision == "reuse":
            self.t.status("READY", "Backend ready (build matches).")
            return True
        if decision == "conflict":
            self.t.status("FAILED", "The backend port is held by a non-RedVector process; "
                                    "I will not terminate it. Free the port and retry.")
            return False
        if decision == "restart":
            self.t.status("WARN", "A stale RedVector backend (different build) is running; "
                                  "restarting it with the current build.")
            if not self._terminate_fn(identity or {}):
                self.t.status("FAILED", "Could not safely terminate the stale backend "
                                        "(identity unverified). Stop it manually and retry.")
                return False
            for _ in range(10):
                if self._backend_identity() is None:
                    break
                self.sleeper(1)

        self.t.status("INFO", "Starting RedVector backend...")
        try:
            ok = bool(self._backend_starter())
        except Exception:
            ok = False
        if not ok:
            self.t.status("FAILED", "Could not start the RedVector backend. Check logs and try again.")
            return False
        # Verify the freshly started backend reports the current fingerprint.
        fresh = self._backend_identity()
        if fresh is not None and fresh.get("build_fingerprint") not in (None, current):
            self.t.status("WARN", "Started backend reports a different build fingerprint than expected.")
        self.t.status("READY", "Backend ready.")
        return True

    def client_menu(self) -> None:
        info = self.platform.detect()
        while True:
            c = self.t.choose("Connect an AI client", [
                "Claude Desktop", "Claude Code", "Cursor", "ChatGPT", "Other MCP client"],
                back_label="Main menu")
            if c in (self.t.EOF, 0):
                return
            if c == self.t.INVALID:
                continue
            if c == 1:
                self._client_flow("claude_desktop", vendors.ClaudeDesktopVendor(), info)
            elif c == 2:
                self._claude_code_flow()
            elif c == 3:
                self._client_flow("cursor", vendors.CursorVendor(), info)
            elif c == 4:
                self._chatgpt_flow(vendors.ChatGPTVendor(), info)
            elif c == 5:
                self._generic_client_flow()

    def _claude_code_flow(self) -> None:
        """Claude Code is the `claude` CLI, DISTINCT from Claude Desktop."""
        cc = self.clients.claude_code()
        if cc["installation"] == _S.INSTALLED:
            self.t.status("INSTALLED", "Claude Code %s" % (cc.get("version") or ""))
            self.t.hint("Claude Code manages its own MCP servers. Add RedVector with its CLI, e.g.:")
            self.t.hint("  claude mcp add redvector -- python -m redvector.mcp.server --server "
                        "http://%s:%s" % (self.env.get("REDVECTOR_HOST", "127.0.0.1"),
                                          self.env.get("REDVECTOR_PORT", "8888")))
        else:
            self.t.status("NOT INSTALLED", "Claude Code (the `claude` CLI) was not found.")
            self.t.hint("Install Claude Code from the official source, then re-run.")

    def _client_flow(self, client_id: str, vendor, info) -> None:
        support = vendor.support_for(info)
        st = self.clients.status(client_id)
        self.t.status(st["state"].replace("_", " "), "%s (%s)" % (vendor.display_name, support.status))
        if support.status in ("UNVALIDATED", "NOT_SUPPORTED", "BETA"):
            self.t.warn(support.note)
        if st["state"] in ("NOT_INSTALLED",):
            self.t.info("%s was not found. Official setup: %s" % (vendor.display_name, vendor.docs_url))
            for s in vendor.official_steps:
                self.t.hint("  - " + s)
            self.t.status("MANUAL REQUIRED", "Install %s, then re-run this setup." % vendor.display_name)
            return
        choice = self.t.choose("%s: %s" % (vendor.display_name, st["state"]), [
            "Connect / update RedVector MCP entry", "Show status", "Disconnect RedVector"],
            back_label="Back")
        if choice == 1:
            self._report_client_action(self.clients.connect(client_id))
        elif choice == 2:
            self.t.info(json.dumps(st, indent=1, default=str))
        elif choice == 3:
            self._report_client_action(self.clients.disconnect(client_id))

    def _chatgpt_flow(self, vendor, info) -> None:
        support = vendor.support_for(info)
        self.t.status("PLATFORM DEPENDENT", "ChatGPT (%s)" % support.status)
        self.t.warn(vendor.install_note)
        for s in vendor.official_steps:
            self.t.hint("  - " + s)
        self.t.status("MANUAL REQUIRED",
                      "ChatGPT connects via an in-app MCP connector; RedVector cannot auto-configure it.")

    def _generic_client_flow(self) -> None:
        ex = self.clients.generic_example()
        self.t.info("Add this to your MCP client's config (transport: %s):" % ex["transport"])
        self.t.write(json.dumps(ex["config"], indent=2))
        self.t.hint("RedVector does not auto-edit unknown third-party configuration files.")

    def provider_menu(self) -> None:
        while True:
            c = self.t.choose("Configure an AI provider", [
                "Ollama", "Claude API", "Gemini API", "DeepSeek API", "Provider status"],
                back_label="Main menu")
            if c in (self.t.EOF, 0):
                return
            if c == self.t.INVALID:
                continue
            if c == 1:
                self.provider_flow("ollama")
            elif c == 2:
                self.provider_flow("claude")
            elif c == 3:
                self.provider_flow("gemini")
            elif c == 4:
                self.provider_flow("deepseek")
            elif c == 5:
                self.print_provider_status()

    def harness_menu(self) -> None:
        while True:
            c = self.t.choose("Configure an AI harness", [
                "DeepSeek Harness", "Harness status"], back_label="Main menu")
            if c in (self.t.EOF, 0):
                return
            if c == self.t.INVALID:
                continue
            if c == 1:
                self.harness_flow()
            elif c == 2:
                self._harness_status()

    def _harness_status(self) -> None:
        node = self.harness.node_entity()
        self.t.status(node["installation"].replace("_", " "),
                      "Node.js %s (prerequisite)" % (node["version"] or "absent"))
        dsh = self.harness.unified()
        self.t.status(_DSH_TAG.get(dsh["state"], "NOT INSTALLED"), "DeepSeek Harness")

    def provider_flow(self, provider_id: str) -> None:
        provider_id = (provider_id or "").lower()
        if provider_id == "ollama":
            return self._ollama_flow()
        if provider_id in ("claude", "gemini", "deepseek"):
            return self._api_provider_flow(provider_id)
        self.t.error("Unknown provider %r." % provider_id)

    def _api_provider_flow(self, provider_id: str) -> None:
        # test connectivity using whatever credential is already present (never echo secrets)
        res = self.providers.test(provider_id)
        if res["ok"]:
            self.t.status("READY", "%s connectivity OK." % provider_id)
            self.providers.activate(provider_id)
            self.t.status("CONFIGURED", "%s active." % provider_id)
        else:
            self.t.status("NOT CONFIGURED", "%s: %s" % (provider_id, res["message"]))
            self.t.hint("Set the provider's API key in the environment (it is never echoed or logged), "
                        "then re-run. RedVector stores secrets via %s." %
                        self.providers.manager.credentials.backend)

    def _ollama_flow(self) -> None:
        om = self.providers.ollama
        if not om.installed() and not om.endpoint_healthy():
            self.t.status("NOT INSTALLED", "Ollama was not found.")
            g = om.install_guidance()
            for s in g["steps"]:
                self.t.hint("  - " + s)
            self.t.status("MANUAL REQUIRED", "Install Ollama from %s, then re-run." % g["docs"])
            return
        models = om.installed_models()
        rec = om.recommended()
        self.t.info("Recommended model: %s" % rec["model"])
        self.t.hint(rec["note"])
        opts = ["Install recommended model: %s" % rec["model"],
                "Choose an already installed model", "Enter a custom Ollama model name"]
        choice = self.t.choose("Ollama model (installed: %s)" % (models or "none"), opts,
                               back_label="Back")
        if choice <= 0 or choice == self.t.INVALID:
            return
        if choice == 1:
            self._ollama_pull_and_activate(rec["model"])
        elif choice == 2:
            if not models:
                self.t.warn("No installed models found.")
                return
            sub = self.t.choose("Installed models", models, back_label="Back")
            if 1 <= sub <= len(models):
                self._ollama_activate(models[sub - 1])
        elif choice == 3:
            name = self.t.ask("Model name> ")
            if name:
                self._ollama_pull_and_activate(name)

    def _ollama_pull_and_activate(self, name: str) -> None:
        om = self.providers.ollama
        if not om.validate_model_name(name):
            self.t.error("Invalid model identifier; refused.")
            return
        self.t.info("Model: %s" % name)
        confirm = self.t.ask("Pull this model now? [y/N] ").lower() in ("y", "yes")
        res = om.pull(name, confirmed=confirm)
        if not res["ok"]:
            self.t.status("WARN" if res["state"] != "FAILED" else "FAILED", res["message"])
            return
        self._ollama_activate(name)

    def _ollama_activate(self, name: str) -> None:
        om = self.providers.ollama
        test = om.inference_test(name, on_cold=lambda m: self.t.status(
            "STARTING", "Loading %s... (first load can take ~1-2 minutes)" % m))
        if not test["ok"]:
            self.t.status("FAILED", "Model not ready: %s" % test["message"])
            return
        self.t.status("READY", "Model %s passed a minimal inference test." % name)
        r = self.providers.activate("ollama", name)
        if r["ok"]:
            self.t.status("CONFIGURED", "Active provider: Ollama | Active model: %s" % name)
        else:
            self.t.status("WARN", "Activation: %s" % r["message"])

    def chat_cli(self):
        """Provider-agnostic chat loop over the existing agent (uses the active
        provider/model; executes through the running backend). Returns the chat's
        control signal ('exit' | 'switch_provider' | 'disable_ai')."""
        agent_call = self._chat_agent_call or _default_chat_agent_call(self.env)
        return ChatSession(self.t, active_fn=self.providers.manager.active,
                           agent_call=agent_call).run()

    def harness_flow(self) -> None:
        pre = self.harness.prerequisites()
        self.t.info("DeepSeek Harness (%s)%s" % (self.harness.PACKAGE,
                    " [developer preview]" if self.harness.PREVIEW else ""))
        self.t.hint("Repository: %s" % self.harness.REPO)
        # Observable DSH state (independent of Node): never READY on Node presence alone.
        self.t.status(_DSH_TAG.get(self.harness.state(), "NOT INSTALLED"), "DeepSeek Harness state")
        if not pre["node_present"]:
            self.t.status("NOT INSTALLED", "Node.js was not found. DSH needs Node %s." % pre["node_requirement"])
            self.t.hint("Install Node.js from the official source (https://nodejs.org), then re-run.")
            return
        self.t.info("Node %s (requirement %s)" % (pre["node_version"], pre["node_requirement"]))
        if not pre["node_ok"]:
            self.t.status("WARN", "Node version does not satisfy %s." % pre["node_requirement"])
            return
        if not pre["npx_present"]:
            self.t.status("WARN", "npx was not found; it is required to run DSH.")
            return
        plan = self.harness.run_plan()
        self.t.info("Run (no global install): %s" % " ".join(plan["command"]))
        self.t.hint(plan["persistence_note"])
        cap = self.harness.mcp_capability()
        self.t.status("UNVERIFIED", "DSH MCP capability: %s" % cap["result"])
        self.t.hint(cap["message"])

    # ======================================================================
    # Status / diagnostics output
    # ======================================================================
    def print_provider_status(self) -> None:
        self.t.info(json.dumps(self.providers.status(), indent=1, default=str))

    # -- unified three-dimension rendering (Phase 10.2) --
    def _dims(self, entity: Dict[str, Any]) -> None:
        """Render an entity's Installation / Configuration / Connection dimensions,
        each on its own line with an explicit [TAG]. Omits a dimension only when the
        entity does not carry it (e.g. Claude Code has installation + version only)."""
        self.t.write("  %s" % self.t.colorize(entity.get("display_name", entity.get("client", "")), "cyan"))
        if "installation" in entity:
            self.t.write("    Installation:  %s" % self.t.tagged(_S.disp(entity["installation"])))
        if entity.get("version"):
            self.t.write("    Version:       %s" % entity["version"])
        if "configuration" in entity:
            self.t.write("    Configuration: %s" % self.t.tagged(_S.disp(entity["configuration"])))
        if "connection" in entity:
            self.t.write("    Connection:    %s" % self.t.tagged(_S.disp(entity["connection"])))

    def print_status(self) -> Dict[str, Any]:
        """Concise, scannable system summary (shorter than Diagnostics)."""
        backend_ok = self.backend_probe()
        active = self.providers.manager.active()
        pid = active.get("active_provider")
        model = active.get("active_model")
        ready = self.ai_ready()
        self.t.write(self.t.colorize("RedVector %s status" % __version__, "cyan"))
        self.t.write("  %-14s %s" % ("Backend", self.t.tagged("READY" if backend_ok else "NOT CONNECTED")))
        self.t.write("  %-14s %s" % ("MCP", self.t.tagged("READY" if backend_ok else "NOT CONNECTED")))
        self.t.write("  %-14s %s" % ("AI Provider", pid or self.t.tagged("NOT CONFIGURED")))
        if pid:
            self.t.write("  %-14s %s" % ("AI Model", model or "(provider default)"))
            self.t.write("  %-14s %s" % ("AI Connection", self.t.tagged("CONNECTED" if ready else "NOT CONNECTED")))
        self.t.write()
        self.t.write(self.t.colorize("Clients:", "cyan"))
        for cid in ("claude_desktop", "cursor", "chatgpt"):
            st = self.clients.unified(cid)
            self.t.write("  %-15s %s" % (st.get("display_name", cid), self.t.tagged(_S.disp(st["installation"]))))
        cc = self.clients.claude_code()
        self.t.write("  %-15s %s" % ("Claude Code", self.t.tagged(_S.disp(cc["installation"]))))
        return {"backend": backend_ok, "ai_ready": ready, "active_provider": pid}

    def print_diagnostics(self) -> Dict[str, Any]:
        data = self.diagnostics.collect()
        self.t.banner()
        self.t.write()
        self.t.write(self.t.colorize("RedVector %s Diagnostics (read-only)" % __version__, "cyan"))
        core = data["core"]
        self.t.write()
        self.t.write(self.t.colorize("Core", "cyan"))
        for k in ("python", "virtual_environment", "dependencies", "backend"):
            self.t.status(core[k].replace("_", " "), k.replace("_", " ").title())
        cap = data["capabilities"]
        self.t.write()
        self.t.write(self.t.colorize("Capabilities", "cyan"))
        self.t.write("  Historical MCP        %s" % cap["historical_mcp"])
        self.t.write("  Phase 8 meta-tools    %s" % cap["phase8_meta_tools"])
        self.t.write("  Live MCP              %s" % cap["live_mcp"])
        self.t.write("  Security integrations %s" % cap["security_integrations"])
        self._render_ai_sections(data)
        return data

    def _render_ai_sections(self, data: Dict[str, Any]) -> None:
        ai_clients = data["ai_clients"]
        self.t.write()
        self.t.write(self.t.colorize("AI Clients", "cyan"))
        self._dims(ai_clients["claude_desktop"])
        self._dims(ai_clients["claude_code"])
        self._dims(ai_clients["cursor"])
        self._dims(ai_clients["chatgpt"])
        self.t.write()
        self.t.write(self.t.colorize("AI Providers", "cyan"))
        for p in data["ai_providers"]:
            self._dims(p)
        self.t.write()
        self.t.write(self.t.colorize("AI Harnesses", "cyan"))
        # Node.js is its own prerequisite entity; it NEVER implies DSH readiness.
        self._dims(data["ai_harnesses"]["node"])
        self._dims(data["ai_harnesses"]["deepseek_harness"])

    def _report_client_action(self, res: Dict[str, Any]) -> None:
        outcome = res.get("outcome", "")
        tag = {"ADDED": "ADDED", "UPDATED": "UPDATED", "ALREADY_CONFIGURED": "CONFIGURED",
               "REMOVED": "OK", "NOT_PRESENT": "INFO", "SETUP_REQUIRED": "MANUAL REQUIRED"}.get(
                   outcome, "OK" if res.get("ok") else "ERROR")
        self.t.status(tag, res.get("message", outcome))
