#!/usr/bin/env python3
"""
RedVector structured offensive planner (Phase 10.5 Fix #2).

The historical agent collapsed every request into one generic recon path because
tool selection was a flat keyword->tool table plus an ``nmap`` fallback. This
module replaces that with a *structured* two-stage decision:

    1. StageClassifier  -> which lifecycle STAGE the request belongs to
                           (recon / enumeration / vuln-discovery / vuln-validation
                            / exploitation / summary / report / retest), derived
                           from grouped lexical + session-context signals, not a
                           single ``if "exploit" in msg`` shortcut, and optionally
                           refined by the active AI provider.
    2. CapabilityResolver -> which REAL registered tool satisfies that stage's
                           capability, discovered DYNAMICALLY from the existing
                           security-tool registry by capability category and live
                           availability. No tool id / target / provider / model /
                           natural-language phrase is hard-coded to a tool here.

Hard invariants (enforced by the agent that consumes the Plan):
  * The word "exploit" classifies *intent*; it is never treated as evidence that a
    target is exploitable. Exploitation is gated on a real validated finding held
    in the session; absent that, the planner routes to validation and the agent
    explains - it never runs blind recon and never fabricates exploitability.
  * Stages that only read prior results (summary / report / retest) set
    ``requires_execution=False`` / ``requires_previous_context=True`` so the agent
    answers from session state instead of re-running tools.
  * Targets are never produced here; the planner only reports where a target
    should come from (explicit message / current session / none).

Everything is deterministic and offline-testable; provider refinement is an
optional injected callable so tests need no live provider.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional


# ============================================================================
# Lifecycle stages
# ============================================================================

class Stage:
    RECON = "recon"
    ENUMERATION = "enumeration"
    VULN_DISCOVERY = "vuln_discovery"
    VULN_VALIDATION = "vuln_validation"
    EXPLOITATION = "exploitation"
    SUMMARY = "summary"
    REPORT = "report"
    RETEST = "retest"

    ACTION_STAGES = {RECON, ENUMERATION, VULN_DISCOVERY, VULN_VALIDATION, EXPLOITATION}
    FOLLOWUP_STAGES = {SUMMARY, REPORT, RETEST}


# Per-stage specification: capability categories (resolved dynamically against the
# registry, in preference order), a capability-search query phrase, whether the
# stage normally needs confirmation, and whether it leans on prior session context.
# Categories are intrinsic tool classifications, NOT hard-coded tool ids.
_STAGE_SPEC = {
    Stage.RECON:           (["net"],                "network host and port reconnaissance", False, False),
    Stage.ENUMERATION:     (["ad", "net"],          "service and share enumeration",        False, False),
    Stage.VULN_DISCOVERY:  (["vuln", "web"],        "vulnerability discovery scanning",     False, False),
    Stage.VULN_VALIDATION: (["web", "auth", "vuln"], "vulnerability validation / proof",    True,  False),
    Stage.EXPLOITATION:    (["exploit"],            "exploitation framework",               True,  True),
    Stage.SUMMARY:         ([],                     "",                                     False, True),
    Stage.REPORT:          ([],                     "",                                     False, True),
    Stage.RETEST:          ([],                     "",                                     False, True),
}

# Coarse offensive-intent family per stage (second reported dimension).
_STAGE_INTENT = {
    Stage.RECON: "reconnaissance",
    Stage.ENUMERATION: "enumeration",
    Stage.VULN_DISCOVERY: "vulnerability_discovery",
    Stage.VULN_VALIDATION: "vulnerability_validation",
    Stage.EXPLOITATION: "exploitation",
    Stage.SUMMARY: "summary",
    Stage.REPORT: "report",
    Stage.RETEST: "retest",
}


# ============================================================================
# Structured classification signals (grouped features, not tool mappings)
# ============================================================================

def _words(groups: List[str]) -> List[re.Pattern]:
    # match as whole stems (word-boundary) so "ports" matches "port" cue "port\b?"
    pats = []
    for g in groups:
        pats.append(re.compile(r"(?<![a-z])" + re.escape(g), re.IGNORECASE))
    return pats


# Each stage carries several independent cue groups. Classification SCORES every
# stage by how many distinct cue groups fire, then applies lifecycle precedence -
# it is not a first-keyword-wins shortcut.
_CUES = {
    Stage.RETEST: _words([
        "run it again", "again", "re-run", "rerun", "re run", "retest",
        "redo", "repeat", "once more", "same scan", "same test",
    ]),
    Stage.SUMMARY: _words([
        "summar", "recap", "what did you find", "what was found", "what have you found",
        "what ports", "what services", "what vuln", "results so far", "findings so far",
        "show me the result", "show me the finding", "what do we have", "where are we",
    ]),
    Stage.REPORT: _words([
        "report", "write up", "write-up", "writeup", "document the", "deliverable",
        "generate a report", "produce a report",
    ]),
    Stage.EXPLOITATION: _words([
        "exploit", "gain a shell", "get a shell", "get shell", "pop a shell", "pop shell",
        "reverse shell", "remote code execution", "rce", "compromise", "take over",
        "takeover", "foothold", "payload", "meterpreter", "gain access", "break in",
    ]),
    Stage.VULN_VALIDATION: _words([
        "validate", "verify", "confirm", "is it vulnerable", "is it exploitable",
        "actually vulnerable", "prove", "check whether", "check if", "test the vuln",
        "test whether", "proof of concept", "poc",
        # specific active attack-type requests are validation / active tests
        "sql injection", "sqli", "injection", "xss", "cross-site", "lfi", "rfi",
        "ssrf", "xxe", "path traversal", "directory traversal", "command injection",
        "csrf", "idor", "deserialization",
    ]),
    Stage.VULN_DISCOVERY: _words([
        "vuln", "vulnerab", "cve", "weakness", "security hole", "security issue",
        "misconfig", "find flaws", "flaw", "outdated", "known issue", "security scan",
    ]),
    Stage.ENUMERATION: _words([
        "enumerate", "enum", "what services", "which services", "service version",
        "versions", "what is running", "what's running", "whats running", "fingerprint",
        "list shares", "shares", "banner grab", "list users",
    ]),
    Stage.RECON: _words([
        "recon", "reconnais", "scan", "port", "discover", "map the", "map out",
        "probe", "inspect", "footprint", "sweep", "ping", "look at",
    ]),
}

# Highest lifecycle precedence first. Follow-up stages are considered only when the
# message carries no new explicit target (handled in ``classify``).
_PRECEDENCE = [
    Stage.RETEST, Stage.SUMMARY, Stage.REPORT,
    Stage.EXPLOITATION, Stage.VULN_VALIDATION, Stage.VULN_DISCOVERY,
    Stage.ENUMERATION, Stage.RECON,
]

# Imperative action verbs that signal "do a NEW action now" rather than "tell me
# about what you already found". Used to separate a referential question
# ("which services look outdated?") from a fresh command ("scan it for CVEs").
_ACTION_VERB_RE = re.compile(
    r"(?<![a-z])(scan|re-?run|run a|run the|check|test|find a|find the|enumerate|enum\b|"
    r"exploit|probe|attack|validate|verify|sweep|fuzz|brute|discover|launch|execute|"
    r"perform|map out|map the)(?![a-z])", re.IGNORECASE)


class StageClassifier:
    """Scores and ranks lifecycle stages from grouped signals + session context.

    An optional ``refine_fn(message) -> Optional[str]`` lets the active AI provider
    propose a stage; a valid proposal is accepted (provider-informed planning),
    otherwise the deterministic result stands. Kept injectable so tests are offline.
    """

    def __init__(self, refine_fn: Optional[Callable[[str], Optional[str]]] = None) -> None:
        self._refine = refine_fn

    def scores(self, message: str) -> dict:
        low = message.lower()
        out = {}
        for stage, pats in _CUES.items():
            out[stage] = sum(1 for p in pats if p.search(low))
        return out

    def classify(self, message: str, has_explicit_target: bool,
                 references_prior: bool) -> str:
        scores = self.scores(message)

        # Provider refinement (optional, best-effort, never fabricates a stage).
        if self._refine is not None:
            try:
                hinted = self._refine(message)
            except Exception:
                hinted = None
            if hinted in _STAGE_SPEC:
                # provider may only pick a follow-up stage when context allows it
                if hinted in Stage.FOLLOWUP_STAGES and has_explicit_target:
                    pass
                else:
                    return hinted

        fired = [s for s in _PRECEDENCE if scores.get(s, 0) > 0]

        # Follow-up stages apply only when the user did not give a NEW explicit
        # target (a new target means "do something to this", not "summarize").
        if has_explicit_target:
            fired = [s for s in fired if s not in Stage.FOLLOWUP_STAGES]

        top = fired[0] if fired else None

        # An explicitly fired follow-up stage (retest / summary / report) wins by
        # precedence - e.g. "run it again" is a retest, not a summary.
        if top in Stage.FOLLOWUP_STAGES:
            return top

        # Recall override: a referential QUESTION with no new target and no action
        # verb is a request to interpret prior results, not to run a new tool - even
        # if it mentions "services" or "outdated".
        has_action_verb = bool(_ACTION_VERB_RE.search(message))
        if references_prior and not has_explicit_target and not has_action_verb:
            return Stage.SUMMARY

        if top is None:
            if references_prior and not has_explicit_target:
                return Stage.SUMMARY
            return Stage.RECON

        return top


# ============================================================================
# Dynamic capability -> tool resolution (no hard-coded tool id)
# ============================================================================

class CapabilityResolver:
    """Resolves a stage's capability categories to a REAL registered tool,
    discovered live from the registry adapter. Selection order within the
    stage's categories (preference order) is:

        1. a tool whose id lexically matches a capability term the user used
           (e.g. "sql" -> sqlmap) - this is a capability search, not a stored
           phrase->tool table;
        2. for active-testing stages, a tool whose action class needs confirmation
           (active-test / exploitation / validation) over a passive recon tool;
        3. plain registry order within the category.

    Availability is checked through the optional MCP ToolResolver when present, so
    an unavailable preferred tool still surfaces (the agent then offers install /
    alternative). Nothing is hard-coded to a specific tool id."""

    def __init__(self, adapter, classify_category: Callable[[str], str],
                 resolver: Optional[Any] = None,
                 action_classifier: Optional[Callable[[str], Any]] = None,
                 confirm_classes: Optional[set] = None) -> None:
        self._adapter = adapter
        self._cat = classify_category
        self._resolver = resolver
        self._action = action_classifier
        self._confirm = confirm_classes or set()

    def _available(self, tool_id: str) -> bool:
        if self._resolver is None:
            return True
        try:
            from redvector.toolmanager import AvailabilityState
            return self._resolver.resolve(tool_id).state == AvailabilityState.INSTALLED
        except Exception:
            return True

    @staticmethod
    def _normalize(tool_id: str) -> str:
        return tool_id.lower().replace("-", " ").replace("_", " ")

    def resolve(self, categories: List[str], query_terms: Optional[List[str]] = None,
                prefer_active: bool = False):
        """Return a ToolCandidate per the ordering above, or None if no category
        matches. A preferred tool that is unavailable is still returned so the
        agent's availability gate can offer install / an alternative."""
        if not categories:
            return None
        ids = self._adapter.tool_ids()
        terms = [t for t in (query_terms or []) if len(t) >= 3]
        fallback_id = None
        for cat in categories:
            in_cat = [t for t in ids if self._cat(t) == cat]
            if not in_cat:
                continue
            if fallback_id is None:
                fallback_id = in_cat[0]

            # 1) lexical capability match against the tool id. When the user names a
            #    specific capability/tool (e.g. "nuclei"), honour it: prefer an
            #    available match, but if the named tool is NOT installed, still return
            #    it so the agent's availability gate can offer install / alternative -
            #    never silently substitute a different available tool for a named one.
            if terms:
                matches = [t for t in in_cat
                           if any(term in self._normalize(t) for term in terms)]
                if matches:
                    for t in matches:
                        if self._available(t):
                            return self._adapter.candidate(t)
                    return self._adapter.candidate(matches[0])

            # 2) action-class preference for active-testing stages
            if prefer_active and self._action is not None:
                for t in in_cat:
                    try:
                        if self._action(t) in self._confirm and self._available(t):
                            return self._adapter.candidate(t)
                    except Exception:
                        pass

            # 3) plain registry order within the category
            for t in in_cat:
                if self._available(t):
                    return self._adapter.candidate(t)
        return self._adapter.candidate(fallback_id) if fallback_id else None


# ============================================================================
# Plan
# ============================================================================

@dataclass
class Plan:
    intent: str                        # offensive-intent family
    stage: str                         # lifecycle stage (Stage.*)
    requires_execution: bool           # does this stage run a tool?
    requires_previous_context: bool    # does it lean on prior session results?
    target_source: str                 # "explicit" | "session" | "none"
    capability_query: str              # capability-search phrase (never a tool id)
    requires_confirmation: bool        # advisory; agent re-checks tool action class
    reason_code: str                   # machine-readable routing reason
    capability_categories: List[str] = field(default_factory=list)
    source: str = "deterministic"      # "deterministic" | "provider"

    def to_dict(self) -> dict:
        return {
            "intent": self.intent,
            "stage": self.stage,
            "requires_execution": self.requires_execution,
            "requires_previous_context": self.requires_previous_context,
            "target_source": self.target_source,
            "capability_query": self.capability_query,
            "requires_confirmation": self.requires_confirmation,
            "reason_code": self.reason_code,
            "capability_categories": list(self.capability_categories),
            "source": self.source,
        }


# ============================================================================
# Planner
# ============================================================================

class Planner:
    """Produces a structured Plan from a message + session + parsed intent."""

    def __init__(self, classifier: Optional[StageClassifier] = None) -> None:
        self.classifier = classifier or StageClassifier()

    def plan(self, message: str, session, intent) -> Plan:
        has_target = getattr(intent, "target", None) is not None
        references_prior = bool(getattr(intent, "references_prior", False))

        stage = self.classifier.classify(message, has_target, references_prior)
        source = "provider" if self.classifier._refine is not None else "deterministic"

        # ---- target source (targets themselves are resolved by the agent) ----
        if has_target:
            target_source = "explicit"
        elif getattr(session, "current_target", None) or getattr(session, "last_target", None):
            target_source = "session"
        else:
            target_source = "none"

        categories, cap_query, needs_confirm, needs_prev = _STAGE_SPEC[stage]
        intent_family = _STAGE_INTENT[stage]

        # ---- follow-up stages that need prior context ----
        if stage in (Stage.SUMMARY, Stage.REPORT):
            has_prior = getattr(session, "last_result", None) is not None
            return Plan(
                intent=intent_family, stage=stage,
                requires_execution=False, requires_previous_context=True,
                target_source=target_source, capability_query="",
                requires_confirmation=False,
                reason_code=("%s_from_session" % stage) if has_prior else "no_prior_context",
                capability_categories=[], source=source,
            )

        if stage == Stage.RETEST:
            can_retest = bool(getattr(session, "last_tool", None)) and (
                getattr(session, "current_target", None) or getattr(session, "last_target", None))
            if can_retest:
                return Plan(
                    intent=intent_family, stage=stage,
                    requires_execution=True, requires_previous_context=True,
                    target_source="session" if not has_target else "explicit",
                    capability_query="rerun last action",
                    requires_confirmation=False, reason_code="retest_last_action",
                    capability_categories=[], source=source,
                )
            # nothing to retest -> reclassify ignoring the retest cue
            fresh = self._reclassify_without_retest(message, has_target, references_prior)
            return self._action_plan(fresh, session, has_target, target_source, source,
                                     reason_suffix="_no_prior_retest")

        # ---- exploitation gate: never treat the word "exploit" as evidence ----
        if stage == Stage.EXPLOITATION:
            validated = list(getattr(session, "validated_findings", []) or [])
            if not validated:
                # route to validation; the agent explains and offers to validate.
                vcats, vquery, _, _ = _STAGE_SPEC[Stage.VULN_VALIDATION]
                return Plan(
                    intent="exploitation", stage=Stage.VULN_VALIDATION,
                    requires_execution=False, requires_previous_context=True,
                    target_source=target_source, capability_query=vquery,
                    requires_confirmation=True,
                    reason_code="exploit_requires_validated_finding",
                    capability_categories=vcats, source=source,
                )

        return self._action_plan(stage, session, has_target, target_source, source)

    # ---- helpers ----
    def _reclassify_without_retest(self, message: str, has_target: bool,
                                   references_prior: bool) -> str:
        scores = self.classifier.scores(message)
        fired = [s for s in _PRECEDENCE
                 if s != Stage.RETEST and scores.get(s, 0) > 0]
        if has_target:
            fired = [s for s in fired if s not in Stage.FOLLOWUP_STAGES]
        if not fired:
            return Stage.RECON
        return fired[0]

    def _action_plan(self, stage: str, session, has_target: bool,
                     target_source: str, source: str, reason_suffix: str = "") -> Plan:
        categories, cap_query, needs_confirm, needs_prev = _STAGE_SPEC[stage]
        reason = stage + reason_suffix
        if target_source == "none":
            reason = "needs_target"
        return Plan(
            intent=_STAGE_INTENT[stage], stage=stage,
            requires_execution=True, requires_previous_context=needs_prev,
            target_source=target_source, capability_query=cap_query,
            requires_confirmation=needs_confirm, reason_code=reason,
            capability_categories=list(categories), source=source,
        )
