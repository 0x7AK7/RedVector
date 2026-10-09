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

START_REDVECTOR = 10   # launcher exit-code contract
HANDLED = 0

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
                 env: Optional[dict] = None) -> None:
        self.env = env if env is not None else os.environ
        self.t = terminal or Terminal(env=self.env)
        self.platform = platform_probe or PlatformProbe()
        self.clients = client_setup or ClientSetup()
        if provider_setup is None:
            mgr = _ai.AIProviderManager(credentials=_ai.get_credential_store())
            provider_setup = ProviderSetup(mgr)
        self.providers = provider_setup
        self.harness = harness or DeepSeekHarnessManager()
        self.backend_probe = backend_probe or _default_backend_probe(self.env)
        self.diagnostics = diagnostics or Diagnostics(
            self.clients, self.providers, self.harness, backend_probe=self.backend_probe)
        self.marker_path = marker_path or os.path.join(_project_root(), ".redvector", "firstrun")
        self.sleeper = sleeper or __import__("time").sleep

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
            return START_REDVECTOR            # MCP-client / piped launch -> start normally
        if self.firstrun_done():
            return START_REDVECTOR
        return self.main_menu()

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
        self.t.banner()
        while True:
            choice = self.t.choose("RedVector %s" % __version__, [
                "Start RedVector", "Connect an AI client", "Configure an AI provider",
                "Install or configure an AI harness", "Diagnostics", "Exit"])
            if choice == self.t.EOF:
                # No interactive responder (e.g. NUL stdin): start RedVector safely.
                return START_REDVECTOR
            if choice == 6:
                return HANDLED
            if choice == 1:
                self.mark_firstrun(); return START_REDVECTOR
            if choice == 2:
                self.client_menu()
            elif choice == 3:
                self.provider_menu()
            elif choice == 4:
                self.harness_flow()
            elif choice == 5:
                self.print_diagnostics()
            # choice == 0 (invalid/out-of-range): reprompt

    def client_menu(self) -> None:
        info = self.platform.detect()
        choice = self.t.choose("Connect an AI client", [
            "Claude Desktop", "Cursor", "ChatGPT", "Other MCP client", "Back"])
        if choice <= 0 or choice == 5:
            return
        if choice == 1:
            self._client_flow("claude_desktop", vendors.ClaudeDesktopVendor(), info)
        elif choice == 2:
            self._client_flow("cursor", vendors.CursorVendor(), info)
        elif choice == 3:
            self._chatgpt_flow(vendors.ChatGPTVendor(), info)
        elif choice == 4:
            self._generic_client_flow()

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
            "Connect / update RedVector MCP entry", "Show status", "Disconnect RedVector", "Back"])
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
        choice = self.t.choose("Configure an AI provider", [
            "Ollama", "Claude API", "Gemini API", "DeepSeek API", "Show provider status", "Back"])
        if choice <= 0 or choice == 6:
            return
        if choice == 1:
            self.provider_flow("ollama")
        elif choice == 2:
            self.provider_flow("claude")
        elif choice == 3:
            self.provider_flow("gemini")
        elif choice == 4:
            self.provider_flow("deepseek")
        elif choice == 5:
            self.print_provider_status()

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
                "Choose an already installed model", "Enter a custom Ollama model name",
                "Continue without selecting a model", "Back"]
        choice = self.t.choose("Ollama model (installed: %s)" % (models or "none"), opts)
        if choice <= 0 or choice in (4, 5):
            return
        if choice == 1:
            self._ollama_pull_and_activate(rec["model"])
        elif choice == 2:
            if not models:
                self.t.warn("No installed models found.")
                return
            sub = self.t.choose("Installed models", models + ["Back"])
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
        test = om.inference_test(name)
        if not test["ok"]:
            self.t.status("FAILED", "Model not ready: %s" % test["message"])
            return
        self.t.status("READY", "Model %s passed a minimal inference test." % name)
        r = self.providers.activate("ollama", name)
        if r["ok"]:
            self.t.status("CONFIGURED", "Active provider: Ollama | Active model: %s" % name)
        else:
            self.t.status("WARN", "Activation: %s" % r["message"])

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

    def print_status(self) -> Dict[str, Any]:
        """Concise startup status (Step 37) with bounded backend recovery."""
        self.t.banner()
        rec = self.recover_backend()
        self.t.write()
        self.t.write(self.t.colorize("Core", "cyan"))
        self.t.status("READY" if rec.ok else "FAILED", "Backend")
        self.t.status("READY" if rec.ok else "DEGRADED", "MCP (viability depends on backend)")
        self.t.write()
        self.t.write(self.t.colorize("AI Clients", "cyan"))
        for cid in ("claude_desktop", "cursor", "chatgpt"):
            st = self.clients.status(cid)
            self.t.status(st["state"].replace("_", " "), st.get("display_name", cid))
        self.t.write()
        self.t.write(self.t.colorize("AI Providers", "cyan"))
        for p in self.providers.status()["providers"]:
            tag = "READY" if p.get("active") else ("CONFIGURED" if p.get("credential_present")
                                                   or p.get("is_local") else "NOT CONFIGURED")
            self.t.status(tag, p["display_name"])
        self.t.write()
        self.t.write(self.t.colorize("AI Harnesses", "cyan"))
        self.t.status(_DSH_TAG.get(self.harness.state(), "NOT INSTALLED"), "DeepSeek Harness")
        return {"backend": rec.to_dict()}

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
        self.t.write()
        self.t.write(self.t.colorize("AI Clients", "cyan"))
        for cid, st in data["clients"].items():
            self.t.status(st["state"].replace("_", " "), st.get("display_name", cid))
        self.t.write()
        self.t.write(self.t.colorize("AI Providers", "cyan"))
        for p in data["providers"]["providers"]:
            tag = "READY" if p.get("active") else ("CONFIGURED" if p.get("credential_present") else "NOT CONFIGURED")
            self.t.status(tag, p["display_name"])
        h = data["harness"]["deepseek_harness"]
        self.t.write()
        self.t.write(self.t.colorize("AI Harnesses", "cyan"))
        # Node.js is a PREREQUISITE shown separately; it NEVER implies DSH readiness.
        node_tag = "READY" if h["node_ok"] else ("WARN" if h["node_present"] else "NOT INSTALLED")
        self.t.status(node_tag, "Node.js %s (prerequisite; requires %s)" %
                      (h["node_version"] or "absent", h["node_requirement"]))
        self.t.status(_DSH_TAG.get(h.get("dsh_state", "NOT_INSTALLED"), "NOT INSTALLED"), "DeepSeek Harness")
        return data

    def _report_client_action(self, res: Dict[str, Any]) -> None:
        outcome = res.get("outcome", "")
        tag = {"ADDED": "ADDED", "UPDATED": "UPDATED", "ALREADY_CONFIGURED": "CONFIGURED",
               "REMOVED": "OK", "NOT_PRESENT": "INFO", "SETUP_REQUIRED": "MANUAL REQUIRED"}.get(
                   outcome, "OK" if res.get("ok") else "ERROR")
        self.t.status(tag, res.get("message", outcome))
