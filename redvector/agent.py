#!/usr/bin/env python3
"""
RedVector AI - provider-agnostic Chat Agent (Phase 8).

A single agent core lets a user control RedVector in natural language. It works
with any configured AI provider (Ollama / Claude / Gemini / DeepSeek) and any
MCP client, because all orchestration lives here and only a thin per-provider
chat adapter translates requests/responses.

Design rules (additive; existing behavior untouched):
  * The security-tool registry (``redvector_security_tools.SECURITY_TOOL_REGISTRY``,
    134 integrations) is the single source of truth. This module does NOT create
    a second tool registry; it adapts the existing one.
  * The model never runs raw shell. The flow is always:
        natural language -> intent + target -> scope check -> real registered
        tool -> validated ToolInvocation -> existing RedVector executor -> result
        -> provider summary.
  * No target IP/domain and no model name is hard-coded. Targets come from the
    user message validated against an AuthorizationContext; the model/provider
    come from the existing AI Integration Manager.
  * Secrets and hidden model reasoning are never logged or returned.

Everything network/provider/execution related is injectable so tests are fully
deterministic (no live providers, no live tools, no real lab IPs).
"""

from __future__ import annotations

import ipaddress
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from redvector import ai_integration as _ai
from redvector import planner as _planner
from redvector import evidence as _evidence


# ============================================================================
# Typed models
# ============================================================================

class ActionClass(str, Enum):
    READ_ONLY = "read_only"
    RECON = "recon"
    VALIDATION = "validation"
    ACTIVE_TEST = "active_test"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    INSTALLATION = "installation"


# Action classes that require explicit user confirmation before execution.
CONFIRM_REQUIRED = {ActionClass.ACTIVE_TEST, ActionClass.EXPLOITATION,
                    ActionClass.POST_EXPLOITATION, ActionClass.INSTALLATION}


@dataclass
class AuthorizationContext:
    authorized: bool = False
    targets: List[str] = field(default_factory=list)       # IPs / domains / CIDRs
    excluded_targets: List[str] = field(default_factory=list)
    engagement_id: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "AuthorizationContext":
        d = d or {}
        return cls(
            authorized=bool(d.get("authorized", False)),
            targets=list(d.get("targets", []) or []),
            excluded_targets=list(d.get("excluded_targets", []) or []),
            engagement_id=d.get("engagement_id"),
        )


@dataclass
class ToolIntent:
    raw_message: str
    action: str                      # free-text action phrase
    category_hint: Optional[str]     # e.g. "net", "web"
    target: Optional[str]            # extracted target (never hard-coded)
    references_prior: bool = False
    keyword: Optional[str] = None


@dataclass(frozen=True)
class ToolCandidate:
    tool_id: str
    display_name: str
    category: str
    handler_type: str
    path: str
    required_params: List[str]
    optional_params: List[str]
    action_class: ActionClass


@dataclass
class ToolInvocation:
    tool_id: str
    path: str
    params: Dict[str, Any]
    action_class: ActionClass


@dataclass
class ToolExecutionResult:
    tool_id: str
    ok: bool
    status: str                      # completed | failed | timeout | unavailable
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


@dataclass
class AgentStatusEvent:
    label: str                       # user-facing, no chain-of-thought
    detail: str = ""


@dataclass
class AgentMessage:
    role: str                        # "user" | "agent"
    content: str
    ts: float = field(default_factory=time.time)


@dataclass
class AgentSession:
    session_id: str
    messages: List[AgentMessage] = field(default_factory=list)
    last_target: Optional[str] = None
    last_result: Optional[ToolExecutionResult] = None
    pending_invocation: Optional[ToolInvocation] = None
    # A tool was selected but is not installed; remember the original request so a
    # follow-up INSTALL / USE_ALTERNATIVE / CANCEL choice can continue.
    pending_resolution: Optional[Dict[str, Any]] = None
    authorization: AuthorizationContext = field(default_factory=AuthorizationContext)
    # Phase 10.5#2: structured workflow/evidence state (single session store; reused by
    # the planner for follow-up classification, dynamic capability routing, and to gate
    # exploitation on validated evidence). No second state system.
    current_target: Optional[str] = None
    last_stage: Optional[str] = None
    last_tool: Optional[str] = None
    discovered_services: List[str] = field(default_factory=list)
    candidate_findings: List[Dict[str, Any]] = field(default_factory=list)
    validated_findings: List[Dict[str, Any]] = field(default_factory=list)
    completed_actions: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AgentRequest:
    message: str
    session_id: Optional[str] = None
    # Optional/None semantics (Phase 10.5 Fix #4): None means "no authorization
    # update supplied in this message" -> reuse the session's authorized scope. A
    # provided context with targets validates/replaces scope; a provided context
    # with authorized=False is an explicit revoke. A missing follow-up target is
    # NEVER silently converted into an empty scope that wipes the engagement.
    authorization: Optional[AuthorizationContext] = None
    confirm: bool = False            # user confirmed a pending higher-impact action
    # Structured follow-up to an install/alternative offer, e.g.
    # {"action": "install"|"use_alternative"|"cancel", "tool": <id>, "confirm": bool}
    choice: Optional[Dict[str, Any]] = None


@dataclass
class AgentResponse:
    success: bool
    session_id: str
    message: str
    provider: Optional[str] = None
    model: Optional[str] = None
    actions: List[Dict[str, Any]] = field(default_factory=list)
    status_events: List[str] = field(default_factory=list)
    needs_confirmation: bool = False
    # MCP-first tool-resolution fields (populated only when a tool is not ready).
    tool_state: Optional[str] = None
    choices: List[str] = field(default_factory=list)
    install_options: Optional[Dict[str, Any]] = None
    alternatives: List[str] = field(default_factory=list)
    # Structured finding snapshot (lifecycle status + provenance) for the result UX.
    findings: List[Dict[str, Any]] = field(default_factory=list)
    # Stage / target echo so the client can render a structured result header.
    stage: Optional[str] = None
    target: Optional[str] = None
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "session_id": self.session_id,
            "message": self.message,
            "provider": self.provider,
            "model": self.model,
            "actions": self.actions,
            "status": self.status_events,
            "needs_confirmation": self.needs_confirmation,
            "tool_state": self.tool_state,
            "choices": self.choices,
            "install_options": self.install_options,
            "alternatives": self.alternatives,
            "findings": self.findings,
            "stage": self.stage,
            "target": self.target,
            "duration_ms": self.duration_ms,
        }


# ============================================================================
# Tool registry adapter (reuses the existing security-tool registry)
# ============================================================================

# Map a registry category letter (from the Phase-3 specs' provenance/route) to a
# human category + default action class. Categories are derived here only for
# selection/classification; the registry remains the source of truth for tools.
_RECON_CATS = {"net", "osint"}


class ToolRegistryAdapter:
    """Normalizes the existing SECURITY_TOOL_REGISTRY into ToolCandidates. Does
    not store a second copy of tool definitions; it reads the registry live."""

    def __init__(self, registry) -> None:
        self._registry = registry

    def tool_ids(self) -> List[str]:
        return list(self._registry.names())

    def has(self, tool_id: str) -> bool:
        return tool_id in set(self._registry.names())

    def candidate(self, tool_id: str) -> Optional[ToolCandidate]:
        if not self.has(tool_id):
            return None
        spec = self._registry.get(tool_id)
        req = [p.name for p in spec.parameters if getattr(p, "required", False)]
        opt = [p.name for p in spec.parameters if not getattr(p, "required", False)]
        return ToolCandidate(
            tool_id=tool_id,
            display_name=tool_id,
            category=_classify_category(tool_id),
            handler_type=spec.handler_type,
            path=spec.path,
            required_params=req,
            optional_params=opt,
            action_class=_classify_action(tool_id),
        )


def _classify_category(tid: str) -> str:
    t = tid.lower()
    if any(k in t for k in ("nmap", "masscan", "rustscan", "arp", "nbtscan", "autorecon", "tcpdump", "tshark", "wafw00f")):
        return "net"
    if any(k in t for k in ("gobuster", "dirb", "dirsearch", "ferox", "ffuf", "wfuzz", "nikto", "wpscan", "sqlmap", "nosqlmap", "commix", "dalfox", "xsser", "katana", "hakrawler", "httpx", "zap", "http", "arjun", "paramspider", "x8", "gau", "wayback", "jaeles", "dotdotpwn", "uro", "qsreplace", "anew", "testssl", "browser")):
        return "web"
    if any(k in t for k in ("nuclei", "searchsploit", "shodan")):
        return "vuln"
    if any(k in t for k in ("amass", "subfinder", "dnsenum", "dnsrecon", "fierce", "theharvester", "whois", "sherlock")):
        return "osint"
    if any(k in t for k in ("hydra", "john", "hashcat", "hashpump", "kerbrute")):
        return "auth"
    if any(k in t for k in ("metasploit", "msfvenom", "responder", "mimikatz", "powersploit", "chisel", "ligolo", "proxychains", "ssh-tunnel", "evil-winrm", "reverse-shell", "payload", "persistence")):
        return "exploit"
    if any(k in t for k in ("impacket", "netexec", "smbmap", "enum4linux", "rpcclient", "bloodhound")):
        return "ad"
    if any(k in t for k in ("api_", "graphql", "jwt")):
        return "api"
    return "other"


# tools whose action is higher impact and should require confirmation
_ACTIVE = {"sqlmap", "nosqlmap", "commix", "dalfox", "xsser", "dotdotpwn", "wpscan", "hydra", "nikto"}
_EXPLOIT = {"metasploit", "msfvenom", "metasploit-search", "responder", "mimikatz", "powersploit",
            "evil-winrm", "reverse-shell-generator", "payload-staging"}
_POST = {"persistence-manager", "impacket-psexec", "impacket-wmiexec", "impacket-smbexec",
         "impacket-secretsdump", "netexec-exec", "lazagne"}


def _classify_action(tid: str) -> ActionClass:
    if tid in _POST:
        return ActionClass.POST_EXPLOITATION
    if tid in _EXPLOIT:
        return ActionClass.EXPLOITATION
    if tid in _ACTIVE:
        return ActionClass.ACTIVE_TEST
    cat = _classify_category(tid)
    if cat in ("auth",):
        return ActionClass.ACTIVE_TEST
    if cat in _RECON_CATS or cat in ("web", "vuln", "api"):
        return ActionClass.RECON
    return ActionClass.VALIDATION


# ============================================================================
# Intent parsing (dynamic target extraction; nothing hard-coded)
# ============================================================================

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b")

# keyword -> registry tool_id (validated against the live registry at selection)
_KEYWORD_TOOL = [
    (("port", "service", "scan", "open ports", "discovery"), "nmap"),
    (("subdomain", "subdomains"), "subfinder"),
    (("directory", "directories", "content discovery", "dirbust"), "gobuster"),
    (("sql injection", "sqli"), "sqlmap"),
    (("xss", "cross-site"), "dalfox"),
    (("vulnerability", "vulnerabilities", "cve", "nuclei"), "nuclei"),
    (("wordpress", "wp "), "wpscan"),
    (("dns",), "dnsrecon"),
    (("whois",), "whois"),
    (("smb", "share"), "smbmap"),
    (("web server", "nikto"), "nikto"),
]

_PRIOR_REFS = ("previous", "last", "that finding", "the finding", "earlier", "which services",
               "outdated", "show me the", "it ", "those ", "again")

# Stop-words excluded from capability-search terms (so generic verbs/articles do
# not accidentally match tool ids). Not a phrase->tool table; just noise removal.
_TERM_STOP = {"the", "and", "for", "run", "scan", "check", "test", "find", "with", "against",
              "please", "can", "you", "could", "would", "this", "that", "into", "onto", "from",
              "look", "show", "give", "want", "need", "now", "then", "some", "any", "all"}
_TERM_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9]{2,}")


def _query_terms(message: str) -> List[str]:
    """Lowercase alphanumeric tokens (>=3 chars, minus stop-words) used as a light
    capability search against tool ids. Purely lexical; no stored phrase mapping."""
    if not message:
        return []
    out = []
    for tok in _TERM_RE.findall(message.lower()):
        if tok not in _TERM_STOP and tok not in out:
            out.append(tok)
    return out


class IntentParser:
    def parse(self, message: str) -> ToolIntent:
        msg = message.strip()
        low = msg.lower()
        target = self._extract_target(msg)
        references_prior = any(k in low for k in _PRIOR_REFS) and target is None
        keyword_tool = None
        for keys, tool in _KEYWORD_TOOL:
            if any(k in low for k in keys):
                keyword_tool = tool
                break
        return ToolIntent(
            raw_message=msg,
            action=msg,
            category_hint=_classify_category(keyword_tool) if keyword_tool else None,
            target=target,
            references_prior=references_prior,
            keyword=keyword_tool,
        )

    @staticmethod
    def _extract_target(msg: str) -> Optional[str]:
        m = _IPV4.search(msg)
        if m:
            tok = m.group(0)
            try:
                if "/" in tok:
                    ipaddress.ip_network(tok, strict=False)
                else:
                    ipaddress.ip_address(tok)
                return tok
            except ValueError:
                return None
        d = _DOMAIN.search(msg)
        if d:
            return d.group(0)
        return None

    @staticmethod
    def is_capability_query(message: str) -> bool:
        low = message.lower()
        return any(k in low for k in ("do you have access", "are you connected", "check if you have",
                                      "what can you do", "capabilities", "which tools", "can you access"))


# ============================================================================
# Authorization guard + scope enforcement
# ============================================================================

@dataclass
class ScopeDecision:
    allowed: bool
    reason: str


class AuthorizationGuard:
    def check(self, target: Optional[str], ctx: AuthorizationContext) -> ScopeDecision:
        if not ctx.authorized:
            return ScopeDecision(False, "No authorization was provided for this request.")
        if not target:
            return ScopeDecision(False, "No target could be identified in the request.")
        if not ctx.targets:
            return ScopeDecision(False, "Authorization lists no in-scope targets.")
        # excluded first
        for ex in ctx.excluded_targets:
            if self._matches(target, ex):
                return ScopeDecision(False, "Target %s is explicitly excluded from scope." % target)
        for allowed in ctx.targets:
            if self._matches(target, allowed):
                return ScopeDecision(True, "Target %s is within the authorized scope." % target)
        return ScopeDecision(False, "Target %s is not in the authorized scope." % target)

    @staticmethod
    def _matches(target: str, scope_entry: str) -> bool:
        # exact string match (domains) or IP-in-network / exact IP (never silently widen)
        if target == scope_entry:
            return True
        try:
            t_is_net = "/" in target
            s_is_net = "/" in scope_entry
            if not t_is_net:
                ip = ipaddress.ip_address(target)
                if s_is_net:
                    return ip in ipaddress.ip_network(scope_entry, strict=False)
                return False  # single IP vs single IP already handled by ==
            else:
                # a requested network must be fully contained in an authorized network
                tnet = ipaddress.ip_network(target, strict=False)
                if s_is_net:
                    snet = ipaddress.ip_network(scope_entry, strict=False)
                    return tnet.subnet_of(snet)
                return False
        except ValueError:
            return False  # domains: only exact match counts


# ============================================================================
# Tool selection + argument building
# ============================================================================

class ToolSelector:
    """Selects a real registered tool for an intent. Never invents a tool id."""

    def __init__(self, registry_adapter: ToolRegistryAdapter) -> None:
        self._reg = registry_adapter

    def select(self, intent: ToolIntent) -> Optional[ToolCandidate]:
        # Only an explicitly named, registered tool is honoured here. There is NO
        # generic recon fallback (Phase 10.5 Fix #4): an unresolved action must never
        # silently become an nmap/recon scan. Capability resolution + the planner's
        # UNKNOWN clarification handle everything else.
        tid = intent.keyword
        if tid and self._reg.has(tid):
            return self._reg.candidate(tid)
        return None

    def validate_proposed(self, tool_id: str) -> Optional[ToolCandidate]:
        """Validate a tool id proposed by a model: must resolve to a real tool."""
        return self._reg.candidate(tool_id) if self._reg.has(tool_id) else None


class ArgumentValidationError(Exception):
    pass


class ToolArgumentBuilder:
    """Builds and validates a ToolInvocation. Never passes raw shell text."""

    _TARGET_PARAMS = ("target", "url", "domain", "host", "ip", "address")

    def build(self, candidate: ToolCandidate, intent: ToolIntent,
              target: str, extra: Optional[Dict[str, Any]] = None) -> ToolInvocation:
        params: Dict[str, Any] = {}
        # place the target into the tool's primary target-like parameter
        target_param = None
        for name in (candidate.required_params + candidate.optional_params):
            if name.lower() in self._TARGET_PARAMS:
                target_param = name
                break
        if target_param is None and candidate.required_params:
            target_param = candidate.required_params[0]
        if target_param is None:
            target_param = "target"
        params[target_param] = target
        # merge only known, whitelisted extra params (by spec name); reject unknown
        known = set(candidate.required_params) | set(candidate.optional_params)
        for k, v in (extra or {}).items():
            if k in known and self._safe_scalar(v):
                params[k] = v
        # required-field validation
        missing = [p for p in candidate.required_params if p not in params]
        if missing:
            raise ArgumentValidationError("Missing required parameters: %s" % ", ".join(missing))
        return ToolInvocation(tool_id=candidate.tool_id, path=candidate.path,
                              params=params, action_class=candidate.action_class)

    @staticmethod
    def _safe_scalar(v: Any) -> bool:
        # only simple scalars; no dict/list/None injection, no shell metacharacters smuggled as structure
        return isinstance(v, (str, int, float, bool))


# ============================================================================
# Execution adapter (injectable; wraps the existing RedVector tool layer)
# ============================================================================

ExecuteFn = Callable[[str, str, Dict[str, Any]], Dict[str, Any]]  # (tool_id, path, params) -> result dict


class ToolExecutorAdapter:
    """Executes a validated ToolInvocation through the EXISTING RedVector tool
    layer via the injected ``execute_fn``. Tests inject a deterministic fake;
    production wires this to the existing /api/tools/* execution path."""

    def __init__(self, execute_fn: ExecuteFn) -> None:
        self._execute = execute_fn

    def run(self, inv: ToolInvocation) -> ToolExecutionResult:
        try:
            data = self._execute(inv.tool_id, inv.path, dict(inv.params))
        except Exception as e:  # noqa: BLE001
            return ToolExecutionResult(inv.tool_id, False, "failed", error="%s: %s" % (type(e).__name__, e))
        if not isinstance(data, dict):
            return ToolExecutionResult(inv.tool_id, False, "failed", error="tool returned non-dict result")
        ok = bool(data.get("success", data.get("return_code", 0) == 0))
        status = "completed" if ok else ("timeout" if data.get("timed_out") else "failed")
        return ToolExecutionResult(inv.tool_id, ok, status, data=data,
                                   error=None if ok else (data.get("error") or data.get("stderr") or "tool failed"))


# ============================================================================
# Provider-agnostic chat adapter (thin per-provider translation)
# ============================================================================

class ChatProvider:
    """Thin provider-agnostic chat completion over the existing provider
    metadata + credential store + injectable transport. The agent core only
    calls ``complete`` and never knows which provider is active."""

    def __init__(self, provider_id: str, model: str, credentials, transport,
                 endpoints: Optional[Dict[str, str]] = None, timeout: int = 60) -> None:
        self.provider_id = provider_id
        self.model = model
        self._cred = credentials
        self._transport = transport
        self._endpoints = endpoints or {}
        self._timeout = timeout

    def _endpoint(self) -> str:
        try:
            d = _ai.PROVIDER_DEFINITIONS[_ai.AIProviderId(self.provider_id)]
            return self._endpoints.get(self.provider_id, d.default_endpoint).rstrip("/")
        except Exception:
            return self._endpoints.get(self.provider_id, "").rstrip("/")

    def _key(self) -> Optional[str]:
        try:
            d = _ai.PROVIDER_DEFINITIONS[_ai.AIProviderId(self.provider_id)]
            return self._cred.retrieve(d.credential_key)
        except Exception:
            return None

    def complete(self, system: str, user: str) -> str:
        pid = self.provider_id
        base = self._endpoint()
        key = self._key()
        if pid in ("ollama", "deepseek"):  # OpenAI-compatible
            headers = {"content-type": "application/json"}
            if key:
                headers["authorization"] = "Bearer %s" % key
            url = base + "/v1/chat/completions"
            resp = self._transport("POST", url, headers, self._timeout)
            return _extract_openai(resp)
        if pid == "claude":
            headers = {"content-type": "application/json", "anthropic-version": "2023-06-01"}
            if key:
                headers["x-api-key"] = key
            resp = self._transport("POST", base + "/v1/messages", headers, self._timeout)
            return _extract_claude(resp)
        if pid == "gemini":
            url = base + "/v1beta/models/%s:generateContent" % (self.model or "gemini-pro")
            resp = self._transport("POST", url, {"content-type": "application/json"}, self._timeout)
            return _extract_gemini(resp)
        resp = self._transport("POST", base + "/v1/chat/completions", {"content-type": "application/json"}, self._timeout)
        return _extract_openai(resp)


def _extract_openai(resp) -> str:
    if resp is None or getattr(resp, "status", 0) < 200 or resp.status >= 300 or not isinstance(resp.json, dict):
        raise ProviderError("provider returned HTTP %s" % getattr(resp, "status", "?"))
    try:
        return resp.json["choices"][0]["message"]["content"]
    except Exception:
        raise ProviderError("malformed provider response")


def _extract_claude(resp) -> str:
    if resp is None or getattr(resp, "status", 0) < 200 or resp.status >= 300 or not isinstance(resp.json, dict):
        raise ProviderError("provider returned HTTP %s" % getattr(resp, "status", "?"))
    try:
        parts = resp.json["content"]
        return "".join(p.get("text", "") for p in parts)
    except Exception:
        raise ProviderError("malformed provider response")


def _extract_gemini(resp) -> str:
    if resp is None or getattr(resp, "status", 0) < 200 or resp.status >= 300 or not isinstance(resp.json, dict):
        raise ProviderError("provider returned HTTP %s" % getattr(resp, "status", "?"))
    try:
        return resp.json["candidates"][0]["content"]["parts"][0]["text"]
    except Exception:
        raise ProviderError("malformed provider response")


class ProviderError(Exception):
    pass


# ============================================================================
# Result interpreter (provider summary with deterministic fallback)
# ============================================================================

class ResultInterpreter:
    def interpret(self, question: str, result: ToolExecutionResult,
                  provider: Optional[ChatProvider]) -> str:
        summary_input = _summarize_result(result)
        if provider is not None:
            try:
                system = ("You are RedVector's assistant. Summarize the security-tool output for a "
                          "pentester in clear language. Only use the provided data.")
                return provider.complete(system, "Question: %s\n\nTool output:\n%s" % (question, summary_input))
            except ProviderError:
                pass  # fall through to deterministic summary
        return self.deterministic(result)

    @staticmethod
    def deterministic(result: ToolExecutionResult) -> str:
        if not result.ok:
            return "The %s action did not complete (%s: %s)." % (
                result.tool_id, result.status, result.error or "unknown error")
        out = (result.data.get("stdout") or result.data.get("parsed") or "")
        text = out if isinstance(out, str) else str(out)
        text = text.strip()
        if not text:
            return "%s completed successfully with no notable output." % result.tool_id
        return "%s completed. Output:\n%s" % (result.tool_id, text[:1500])


def _summarize_result(result: ToolExecutionResult) -> str:
    d = result.data or {}
    keep = {k: d[k] for k in ("stdout", "parsed", "return_code", "success", "command") if k in d}
    s = str(_ai.scrub(keep))
    return s[:4000]


# ============================================================================
# Conversation manager (per-session state; not one global blob)
# ============================================================================

class ConversationManager:
    def __init__(self) -> None:
        self._sessions: Dict[str, AgentSession] = {}

    def get_or_create(self, session_id: Optional[str]) -> AgentSession:
        if session_id and session_id in self._sessions:
            return self._sessions[session_id]
        sid = session_id or ("sess-" + uuid.uuid4().hex[:12])
        sess = AgentSession(session_id=sid)
        self._sessions[sid] = sess
        return sess

    def get(self, session_id: str) -> Optional[AgentSession]:
        """Read-only lookup; does not create a session."""
        return self._sessions.get(session_id)

    def count(self) -> int:
        return len(self._sessions)


# ============================================================================
# Observability (structured, secret-free, no chain-of-thought)
# ============================================================================

def build_audit_event(session_id: str, provider: Optional[str], model: Optional[str],
                      tool: Optional[str], target: Optional[str], authorized: bool,
                      status: str, duration_ms: float, error_class: Optional[str]) -> Dict[str, Any]:
    return {
        "session_id": session_id, "provider": provider, "model": model,
        "tool": tool, "target": target, "authorized": authorized,
        "status": status, "duration_ms": round(duration_ms, 1), "error_class": error_class,
    }


# ============================================================================
# The agent core
# ============================================================================

class RedVectorAgent:
    def __init__(self, registry, executor: ToolExecutorAdapter,
                 provider_factory: Optional[Callable[[], Optional[ChatProvider]]] = None,
                 conversation: Optional[ConversationManager] = None,
                 audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
                 resolver: Optional[Any] = None,
                 installer: Optional[Any] = None,
                 planner: Optional[Any] = None,
                 stage_refiner: Optional[Callable[[str], Optional[str]]] = None) -> None:
        self.reg = ToolRegistryAdapter(registry)
        self.selector = ToolSelector(self.reg)
        self.argbuilder = ToolArgumentBuilder()
        self.guard = AuthorizationGuard()
        self.parser = IntentParser()
        self.interpreter = ResultInterpreter()
        # Structured planner (stage classification) + dynamic capability->tool
        # resolver. The resolver reuses the live registry + optional MCP availability
        # check; no tool id/target/provider is hard-coded. ``stage_refiner`` lets the
        # active provider optionally inform stage classification.
        self.planner = planner or _planner.Planner(
            classifier=_planner.StageClassifier(refine_fn=stage_refiner))
        self.capresolver = _planner.CapabilityResolver(
            self.reg, _classify_category, resolver,
            action_classifier=_classify_action, confirm_classes=CONFIRM_REQUIRED)
        self.executor = executor
        self.provider_factory = provider_factory or (lambda: None)
        self.conv = conversation or ConversationManager()
        self.audit_sink = audit_sink or (lambda e: None)
        # Optional MCP-first tool resolution/installation. When absent, behaviour
        # is exactly as before (no availability gate): existing callers/tests are
        # unaffected. redvector_toolmanager.ToolResolver / ToolInstallationManager.
        self.resolver = resolver
        self.installer = installer

    def capabilities(self) -> Dict[str, Any]:
        ids = self.reg.tool_ids()
        return {"connected": True, "security_integrations": len(ids),
                "example_categories": sorted({_classify_category(t) for t in ids})}

    def handle(self, req: AgentRequest) -> AgentResponse:
        t0 = time.time()
        sess = self.conv.get_or_create(req.session_id)
        # Session-level authorization (Phase 10.5 Fix #4). Scope belongs to the
        # engagement/session, not to a single message:
        #   * authorization is None  -> no update supplied -> reuse session scope;
        #   * authorized + targets   -> validate/replace the session scope;
        #   * authorized=False       -> explicit revoke -> clear the session scope;
        #   * authorized + no targets-> ambiguous no-op -> reuse (never silently wipe).
        auth = req.authorization
        if auth is not None:
            if not auth.authorized:
                sess.authorization = AuthorizationContext()
            elif auth.targets:
                sess.authorization = auth
        ctx = sess.authorization
        sess.messages.append(AgentMessage("user", req.message))
        events: List[str] = ["Understanding request"]
        prov = None
        prov_id = prov_model = None
        try:
            prov = self.provider_factory()
            if prov is not None:
                prov_id, prov_model = prov.provider_id, prov.model
        except Exception:
            prov = None

        # capability / connectivity query -> no tool execution
        if self.parser.is_capability_query(req.message):
            cap = self.capabilities()
            msg = ("Connected to RedVector. %d security-tool integrations are available across "
                   "categories: %s. Tell me an authorized target to begin." %
                   (cap["security_integrations"], ", ".join(cap["example_categories"])))
            events.append("Completed")
            return self._finish(sess, msg, prov_id, prov_model, [], events, t0, None, None, "read_only", True)

        # structured follow-up to an install / alternative offer
        if req.choice and sess.pending_resolution is not None:
            return self._handle_choice(sess, req, prov, prov_id, prov_model, events, t0, ctx)

        # pending confirmation path
        if sess.pending_invocation is not None and req.confirm:
            inv = sess.pending_invocation
            sess.pending_invocation = None
            events += ["Running %s" % inv.tool_id, "Analyzing results"]
            return self._execute_and_answer(sess, inv, req.message, prov, prov_id, prov_model, events, t0, ctx)

        intent = self.parser.parse(req.message)

        # STRUCTURED PLAN: classify the lifecycle stage + dynamic capability, using
        # grouped signals and session context (not a single-keyword->tool shortcut).
        plan = self.planner.plan(req.message, sess, intent)
        events.append("Planning: %s" % plan.stage)

        # ---- unknown intent: ask for clarification; NEVER silently run recon ----
        if plan.stage == _planner.Stage.UNKNOWN:
            events.append("Completed")
            return self._finish(sess, "I could not determine a safe RedVector action from that request. "
                                "Tell me the action you want (for example: reconnaissance, service "
                                "enumeration, vulnerability discovery, validation, or exploitation) and "
                                "an authorized target, and I will plan it.",
                                prov_id, prov_model, [{"status": "needs_clarification", "stage": plan.stage}],
                                events, t0, None, sess.current_target or sess.last_target,
                                ctx.authorized, "read_only", False)

        # ---- follow-up: summarize / report from session, no re-execution ----
        if plan.stage in (_planner.Stage.SUMMARY, _planner.Stage.REPORT):
            if sess.last_result is not None:
                events.append("Analyzing prior results")
                answer = self.interpreter.interpret(req.message, sess.last_result, prov)
                events.append("Completed")
                return self._finish(sess, answer, prov_id, prov_model,
                                    [{"tool": sess.last_result.tool_id, "status": "recalled",
                                      "stage": plan.stage}], events, t0,
                                    sess.last_result.tool_id, sess.current_target or sess.last_target,
                                    ctx.authorized, "read_only", True)
            events.append("Completed")
            return self._finish(sess, "There are no results from this session yet, so there is nothing "
                                "to %s. Give me an authorized target and an action to begin." %
                                ("summarize" if plan.stage == _planner.Stage.SUMMARY else "report on"),
                                prov_id, prov_model, [{"status": "no_prior_context", "stage": plan.stage}],
                                events, t0, None, None, ctx.authorized, "read_only", True)

        # ---- exploitation without a validated finding: route to validation, never
        #      run blind recon and never fabricate exploitability ----
        if plan.reason_code == "exploit_requires_validated_finding":
            events.append("Completed")
            ncand = len(sess.candidate_findings)
            if ncand:
                tail = ("I have %d candidate/inconclusive finding(s) on record but none are VALIDATED. "
                        "I can run a validation step against an authorized target to establish evidence "
                        "first; say which to validate (or 'validate the findings') and I will proceed." % ncand)
            else:
                tail = ("There are no findings on record yet. Run a vulnerability discovery step first, "
                        "then validation, and I will have evidence to work from.")
            msg = ("No VALIDATED exploitable finding has been established for this engagement, so I will "
                   "not attempt exploitation or assume the target is exploitable. " + tail)
            return self._finish(sess, msg, prov_id, prov_model,
                                [{"status": "exploitation_blocked_no_validated_finding",
                                  "stage": plan.stage}], events, t0, None,
                                sess.current_target or sess.last_target, ctx.authorized,
                                ActionClass.VALIDATION.value, True)

        # ---- retest: reuse the last tool against the session target ----
        if plan.stage == _planner.Stage.RETEST and plan.reason_code == "retest_last_action":
            return self._run_retest(sess, intent, req.message, prov, prov_id, prov_model,
                                    events, t0, ctx, req.confirm, plan)

        # ---- action stages: dynamic capability -> real tool ----
        return self._run_action(sess, plan, intent, req.message, prov, prov_id, prov_model,
                                events, t0, ctx, req.confirm)

    # ---- intent execution (shared by the normal path and alternative selection) ----
    def _run_intent(self, sess, intent, question, prov, prov_id, prov_model, events, t0, ctx,
                    confirm) -> AgentResponse:
        # select a real tool
        events.append("Selecting tool")
        candidate = self.selector.select(intent)
        if candidate is None:
            events.append("Completed")
            return self._finish(sess, "I could not map that request to a RedVector tool. Try naming the "
                                "action (for example a port scan) and an authorized target.",
                                prov_id, prov_model, [], events, t0, None, intent.target, ctx.authorized,
                                "read_only", False)

        # scope check
        decision = self.guard.check(intent.target, ctx)
        if not decision.allowed:
            self._audit(sess, prov_id, prov_model, candidate.tool_id, intent.target, ctx.authorized,
                        "rejected_scope", t0, "ScopeError")
            events.append("Completed")
            return self._finish(sess, decision.reason + " I did not run anything.", prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "blocked_out_of_scope"}], events, t0,
                                candidate.tool_id, intent.target, ctx.authorized, candidate.action_class.value,
                                False)

        # availability gate (MCP-first): never run a tool that is not installed/ready
        if self.resolver is not None:
            gate = self._resolution_gate(sess, candidate, intent.target,
                                         getattr(intent, "raw_message", None),
                                         prov_id, prov_model, events, t0, ctx)
            if gate is not None:
                return gate

        # build + validate arguments
        try:
            inv = self.argbuilder.build(candidate, intent, intent.target)
        except ArgumentValidationError as e:
            events.append("Completed")
            return self._finish(sess, "I could not build valid arguments: %s" % e, prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "invalid_arguments"}], events, t0,
                                candidate.tool_id, intent.target, ctx.authorized, candidate.action_class.value,
                                False)
        sess.last_target = intent.target

        # confirmation for higher-impact actions
        if candidate.action_class in CONFIRM_REQUIRED and not confirm:
            sess.pending_invocation = inv
            msg = ("This action (%s) is classified as %s against %s. Reply to confirm before I run it." %
                   (candidate.tool_id, candidate.action_class.value, intent.target))
            events.append("Awaiting confirmation")
            return self._finish(sess, msg, prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "awaiting_confirmation"}], events, t0,
                                candidate.tool_id, intent.target, ctx.authorized, candidate.action_class.value,
                                True, needs_confirmation=True)

        events.append("Running %s" % candidate.tool_id)
        events.append("Analyzing results")
        return self._execute_and_answer(sess, inv, question, prov, prov_id, prov_model, events, t0, ctx)

    # ---- plan-driven action execution (dynamic capability -> real tool) ----
    def _run_action(self, sess, plan, intent, question, prov, prov_id, prov_model, events, t0, ctx,
                    confirm) -> AgentResponse:
        # 1) resolve the target dynamically: explicit message > current session.
        target = intent.target
        if target is None and plan.target_source == "session":
            target = sess.current_target or sess.last_target
        if target is None:
            events.append("Completed")
            return self._finish(sess, "I need an authorized target for this %s step. Tell me which "
                                "in-scope host or domain to use." % plan.stage.replace("_", " "),
                                prov_id, prov_model, [{"status": "needs_target", "stage": plan.stage}],
                                events, t0, None, None, ctx.authorized, "read_only", False)

        # 2) dynamic capability search -> a REAL registered tool (capability match +
        #    action-class preference + registry order); nothing is hard-coded.
        events.append("Selecting tool")
        terms = _query_terms(getattr(intent, "raw_message", None) or question)
        candidate = self.capresolver.resolve(plan.capability_categories, query_terms=terms,
                                             prefer_active=plan.requires_confirmation)
        if candidate is None:
            events.append("Completed")
            return self._finish(sess, "I could not find a registered tool providing the %s capability." %
                                (plan.capability_query or plan.stage), prov_id, prov_model,
                                [{"status": "no_capability_tool", "stage": plan.stage}], events, t0,
                                None, target, ctx.authorized, "read_only", False)

        # 3) scope / authorization
        decision = self.guard.check(target, ctx)
        if not decision.allowed:
            self._audit(sess, prov_id, prov_model, candidate.tool_id, target, ctx.authorized,
                        "rejected_scope", t0, "ScopeError")
            events.append("Completed")
            return self._finish(sess, decision.reason + " I did not run anything.", prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "blocked_out_of_scope",
                                  "stage": plan.stage}], events, t0, candidate.tool_id, target,
                                ctx.authorized, candidate.action_class.value, False)

        # Persist the active engagement target NOW (authorized + in scope), before the
        # availability gate / confirmation. A follow-up must keep working even if this
        # first tool turns out to be uninstalled or needs confirmation.
        sess.current_target = target
        sess.last_target = target

        # 4) availability gate (MCP-first)
        if self.resolver is not None:
            gate = self._resolution_gate(sess, candidate, target, getattr(intent, "raw_message", None),
                                         prov_id, prov_model, events, t0, ctx)
            if gate is not None:
                return gate

        # 5) build + validate arguments
        try:
            inv = self.argbuilder.build(candidate, intent, target)
        except ArgumentValidationError as e:
            events.append("Completed")
            return self._finish(sess, "I could not build valid arguments: %s" % e, prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "invalid_arguments",
                                  "stage": plan.stage}], events, t0, candidate.tool_id, target,
                                ctx.authorized, candidate.action_class.value, False)
        sess.last_target = target

        # 6) confirmation for higher-impact actions (tool's own action class decides)
        if candidate.action_class in CONFIRM_REQUIRED and not confirm:
            sess.pending_invocation = inv
            sess.last_stage = plan.stage
            msg = ("This action (%s) is classified as %s against %s. Reply to confirm before I run it." %
                   (candidate.tool_id, candidate.action_class.value, target))
            events.append("Awaiting confirmation")
            return self._finish(sess, msg, prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "awaiting_confirmation",
                                  "stage": plan.stage}], events, t0, candidate.tool_id, target,
                                ctx.authorized, candidate.action_class.value, True, needs_confirmation=True)

        events.append("Running %s" % candidate.tool_id)
        events.append("Analyzing results")
        return self._execute_and_answer(sess, inv, question, prov, prov_id, prov_model, events, t0, ctx,
                                        stage=plan.stage)

    def _run_retest(self, sess, intent, question, prov, prov_id, prov_model, events, t0, ctx,
                    confirm, plan) -> AgentResponse:
        """Re-run the SAME tool as the last action against the SAME session target
        (a new explicit target overrides it and triggers a fresh scope check)."""
        tool_id = sess.last_tool
        target = intent.target or sess.current_target or sess.last_target
        candidate = self.reg.candidate(tool_id) if tool_id and self.reg.has(tool_id) else None
        if candidate is None or target is None:
            events.append("Completed")
            return self._finish(sess, "There is no previous action to repeat yet.", prov_id, prov_model,
                                [{"status": "nothing_to_retest"}], events, t0, None, target,
                                ctx.authorized, "read_only", False)

        decision = self.guard.check(target, ctx)
        if not decision.allowed:
            self._audit(sess, prov_id, prov_model, candidate.tool_id, target, ctx.authorized,
                        "rejected_scope", t0, "ScopeError")
            events.append("Completed")
            return self._finish(sess, decision.reason + " I did not run anything.", prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "blocked_out_of_scope"}], events, t0,
                                candidate.tool_id, target, ctx.authorized, candidate.action_class.value, False)

        if self.resolver is not None:
            gate = self._resolution_gate(sess, candidate, target, getattr(intent, "raw_message", None),
                                         prov_id, prov_model, events, t0, ctx)
            if gate is not None:
                return gate
        try:
            inv = self.argbuilder.build(candidate, intent, target)
        except ArgumentValidationError as e:
            events.append("Completed")
            return self._finish(sess, "I could not build valid arguments: %s" % e, prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "invalid_arguments"}], events, t0,
                                candidate.tool_id, target, ctx.authorized, candidate.action_class.value, False)
        sess.last_target = target
        if candidate.action_class in CONFIRM_REQUIRED and not confirm:
            sess.pending_invocation = inv
            sess.last_stage = sess.last_stage or _planner.Stage.RETEST
            msg = ("Re-running %s (classified %s) against %s. Reply to confirm before I run it." %
                   (candidate.tool_id, candidate.action_class.value, target))
            events.append("Awaiting confirmation")
            return self._finish(sess, msg, prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "awaiting_confirmation"}], events, t0,
                                candidate.tool_id, target, ctx.authorized, candidate.action_class.value,
                                True, needs_confirmation=True)
        events.append("Re-running %s" % candidate.tool_id)
        events.append("Analyzing results")
        return self._execute_and_answer(sess, inv, question, prov, prov_id, prov_model, events, t0, ctx,
                                        stage=sess.last_stage or _planner.Stage.RETEST)

    # ---- MCP-first tool resolution ----
    def _resolution_gate(self, sess, candidate, target, message, prov_id, prov_model, events, t0, ctx):
        """Return a resolution response if the tool is not runnable, else None."""
        from redvector.toolmanager import AvailabilityState
        resolved = self.resolver.resolve(candidate.tool_id)
        if resolved.state == AvailabilityState.INSTALLED:
            return None

        events.append("Resolving tool availability")
        sess.pending_resolution = {"tool": candidate.tool_id, "target": target,
                                   "message": message,
                                   "alternatives": list(resolved.alternatives)}
        alts = resolved.alternatives

        if resolved.state == AvailabilityState.INSTALLED_NOT_CONFIGURED:
            choices = (["USE_ALTERNATIVE"] if alts else []) + ["CANCEL"]
            msg = ("%s is installed but not configured yet, so I did not run it. %s "
                   "You can configure it, pick a registered alternative, or cancel." %
                   (candidate.tool_id, resolved.detail))
            return self._finish(sess, msg, prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "not_configured"}], events, t0,
                                candidate.tool_id, target, ctx.authorized, "installation", True,
                                tool_state=resolved.state.value, choices=choices, alternatives=alts)

        if resolved.state == AvailabilityState.UNAVAILABLE_ON_THIS_PLATFORM:
            choices = (["USE_ALTERNATIVE"] if alts else []) + ["CANCEL"]
            msg = ("%s is not available on this platform, so I did not run it. %s" %
                   (candidate.tool_id, resolved.detail))
            return self._finish(sess, msg, prov_id, prov_model,
                                [{"tool": candidate.tool_id, "status": "unavailable_on_platform"}], events, t0,
                                candidate.tool_id, target, ctx.authorized, "installation", True,
                                tool_state=resolved.state.value, choices=choices, alternatives=alts)

        # AVAILABLE_TO_INSTALL (or UNSUPPORTED, defensively)
        options = self.installer.install_options(candidate.tool_id) if self.installer else {
            "choices": (["USE_ALTERNATIVE"] if alts else []) + ["CANCEL"], "alternatives": alts}
        msg = ("%s is not installed, so I did not run anything. %s You can install it (with your "
               "confirmation), use a registered alternative, or cancel." %
               (candidate.tool_id, resolved.detail))
        return self._finish(sess, msg, prov_id, prov_model,
                            [{"tool": candidate.tool_id, "status": "not_installed"}], events, t0,
                            candidate.tool_id, target, ctx.authorized, "installation", True,
                            tool_state=resolved.state.value, choices=options.get("choices", []),
                            install_options=options, alternatives=alts)

    def _handle_choice(self, sess, req, prov, prov_id, prov_model, events, t0, ctx) -> AgentResponse:
        pending = sess.pending_resolution or {}
        action = (req.choice or {}).get("action", "").lower()
        orig_tool = pending.get("tool")
        target = pending.get("target")

        if action == "cancel":
            sess.pending_resolution = None
            events.append("Completed")
            return self._finish(sess, "Cancelled. Nothing was installed and nothing was run.",
                                prov_id, prov_model, [{"tool": orig_tool, "status": "cancelled"}], events, t0,
                                orig_tool, target, ctx.authorized, "installation", True)

        if action == "use_alternative":
            alt = (req.choice or {}).get("tool") or (req.choice or {}).get("alternative")
            valid = set(pending.get("alternatives") or [])
            if not alt or alt not in valid or not self.reg.has(alt):
                events.append("Completed")
                return self._finish(sess, "That is not one of the offered registered alternatives. "
                                    "Choose one of: %s." % ", ".join(sorted(valid)) if valid else
                                    "No registered alternatives are available.",
                                    prov_id, prov_model, [{"tool": orig_tool, "status": "invalid_alternative"}],
                                    events, t0, orig_tool, target, ctx.authorized, "installation", False,
                                    alternatives=sorted(valid))
            sess.pending_resolution = None
            alt_intent = ToolIntent(raw_message=pending.get("message") or "", action="use %s" % alt,
                                    category_hint=None, target=target, references_prior=False, keyword=alt)
            return self._run_intent(sess, alt_intent, pending.get("message") or ("Use %s" % alt),
                                    prov, prov_id, prov_model, events, t0, ctx,
                                    bool((req.choice or {}).get("confirm", False)))

        if action == "install":
            if not self.installer:
                events.append("Completed")
                return self._finish(sess, "Installation is not available in this deployment.",
                                    prov_id, prov_model, [{"tool": orig_tool, "status": "install_unavailable"}],
                                    events, t0, orig_tool, target, ctx.authorized, "installation", False)
            confirmed = bool((req.choice or {}).get("confirm", False)) or bool(req.confirm)
            events.append("Installing %s" % orig_tool)
            result = self.installer.install(orig_tool, confirmed=confirmed)
            self._audit(sess, prov_id, prov_model, orig_tool, target, ctx.authorized,
                        "install_%s" % result.status, t0, None if result.ok else "InstallError")
            if result.ok and result.verified_state == "installed":
                # tool is now installed -> continue the original request
                sess.pending_resolution = None
                intent = self.parser.parse(pending.get("message") or "")
                if intent.target is None:
                    intent = ToolIntent(raw_message=pending.get("message") or "", action="run %s" % orig_tool,
                                        category_hint=None, target=target, references_prior=False,
                                        keyword=orig_tool)
                events.append("Completed install")
                return self._run_intent(sess, intent, pending.get("message") or "", prov, prov_id,
                                        prov_model, events, t0, ctx, bool(req.confirm))
            # not confirmed / manual / failed -> report; keep pending for a retry
            events.append("Completed")
            return self._finish(sess, result.message, prov_id, prov_model,
                                [{"tool": orig_tool, "status": result.status}], events, t0, orig_tool,
                                target, ctx.authorized, "installation", result.ok,
                                needs_confirmation=(result.status == "not_confirmed"),
                                tool_state=result.verified_state, install_options={"install_result": result.to_dict()})

        events.append("Completed")
        return self._finish(sess, "Unrecognized choice. Use install, use_alternative, or cancel.",
                            prov_id, prov_model, [{"tool": orig_tool, "status": "unknown_choice"}], events, t0,
                            orig_tool, target, ctx.authorized, "installation", False)

    # ---- helpers ----
    def _execute_and_answer(self, sess, inv, question, prov, prov_id, prov_model, events, t0, ctx,
                            stage: Optional[str] = None) -> AgentResponse:
        result = self.executor.run(inv)
        sess.last_result = result
        stage = stage or sess.last_stage
        self._record_evidence(sess, inv, result, stage)
        answer = self.interpreter.interpret(question, result, prov)
        events.append("Completed")
        self._audit(sess, prov_id, prov_model, inv.tool_id, sess.last_target, ctx.authorized,
                    result.status, t0, None if result.ok else "ToolError")
        return self._finish(sess, answer, prov_id, prov_model,
                            [{"tool": inv.tool_id, "status": result.status, "stage": stage}], events, t0,
                            inv.tool_id, sess.last_target, ctx.authorized, inv.action_class.value, result.ok,
                            stage=stage, findings=self._findings_snapshot(sess))

    @staticmethod
    def _findings_snapshot(sess) -> List[Dict[str, Any]]:
        """Compact, UI-ready view of the session's findings for the current target
        (validated first). Raw evidence stays in the session; this is a summary view."""
        tgt = sess.current_target or sess.last_target
        out = []
        for f in (sess.validated_findings + sess.candidate_findings):
            if tgt is None or f.get("target") == tgt:
                out.append({"finding_id": f.get("finding_id"), "title": f.get("title"),
                            "tool": f.get("tool"), "status": f.get("status"),
                            "evidence": (f.get("evidence") or "")[:160]})
        return out

    @staticmethod
    def _has_output(result) -> bool:
        """True when a completed result carries substantive output (used ONLY to
        decide whether a discovery produced a CANDIDATE - never to mark VALIDATED)."""
        if not result.ok:
            return False
        d = result.data or {}
        for k in ("findings", "finding", "vulnerabilities", "vulns"):
            if k in d:
                return bool(d.get(k))
        if d.get("parsed"):
            return True
        out = d.get("stdout")
        return isinstance(out, str) and bool(out.strip())

    def _record_evidence(self, sess, inv, result, stage: Optional[str]) -> None:
        """Update the single session evidence store from REAL tool data only.

        Lifecycle (Phase 10.5 Fix #4):
          * VULN_DISCOVERY output -> CANDIDATE findings (never auto-promoted);
          * VULN_VALIDATION -> a DETERMINISTIC verdict (evidence.derive_verdict):
              CONFIRMED  -> finding VALIDATED (provenance recorded) -> unlocks exploit;
              REJECTED   -> finding REJECTED;
              INCONCLUSIVE (incl. mere non-empty stdout) -> NOT validated.
        Execution completing is NOT equivalent to a confirmed vulnerability, and the
        user calling something "validated" never mutates this state."""
        sess.current_target = sess.last_target
        sess.last_tool = inv.tool_id
        if stage:
            sess.last_stage = stage
        sess.completed_actions.append({"stage": stage, "tool": inv.tool_id,
                                       "target": sess.last_target, "status": result.status})

        if stage == _planner.Stage.VULN_DISCOVERY and self._has_output(result):
            f = _evidence.new_finding("Candidate from %s" % inv.tool_id, inv.tool_id,
                                      sess.last_target, stage, _evidence.FindingStatus.CANDIDATE)
            sess.candidate_findings.append(f)
        elif stage == _planner.Stage.VULN_VALIDATION:
            ev = _evidence.derive_verdict(inv.tool_id, result, sess.last_target)
            if ev.verdict == _evidence.Verdict.CONFIRMED:
                f = _evidence.new_finding("Validated by %s" % inv.tool_id, inv.tool_id,
                                          sess.last_target, stage,
                                          _evidence.FindingStatus.VALIDATED, ev.evidence_excerpt)
                f["provenance"].append(ev.to_dict())
                sess.validated_findings.append(f)
            elif ev.verdict == _evidence.Verdict.REJECTED:
                sess.candidate_findings.append(_evidence.new_finding(
                    "Rejected by %s" % inv.tool_id, inv.tool_id, sess.last_target, stage,
                    _evidence.FindingStatus.REJECTED, ev.evidence_excerpt))
            else:  # INCONCLUSIVE: execution completed, no deterministic positive proof
                sess.candidate_findings.append(_evidence.new_finding(
                    "Inconclusive from %s" % inv.tool_id, inv.tool_id, sess.last_target, stage,
                    _evidence.FindingStatus.INCONCLUSIVE, ev.evidence_excerpt))

    def _finish(self, sess, msg, prov_id, prov_model, actions, events, t0=None, tool=None,
                target=None, authorized=None, action_class=None, success=True,
                needs_confirmation=False, tool_state=None, choices=None,
                install_options=None, alternatives=None, stage=None, findings=None) -> AgentResponse:
        sess.messages.append(AgentMessage("agent", msg))
        dur = (time.time() - t0) * 1000.0 if t0 else 0.0
        return AgentResponse(success=success, session_id=sess.session_id, message=msg,
                             provider=prov_id, model=prov_model, actions=actions,
                             status_events=events, needs_confirmation=needs_confirmation,
                             tool_state=tool_state, choices=choices or [],
                             install_options=install_options, alternatives=alternatives or [],
                             findings=findings or [], stage=stage,
                             target=target, duration_ms=round(dur, 1))

    def _audit(self, sess, prov_id, prov_model, tool, target, authorized, status, t0, error_class) -> None:
        try:
            self.audit_sink(build_audit_event(sess.session_id, prov_id, prov_model, tool, target,
                                               authorized, status, (time.time() - t0) * 1000.0, error_class))
        except Exception:
            pass
