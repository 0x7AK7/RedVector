#!/usr/bin/env python3
"""
RedVector finding evidence + validation verdict model (Phase 10.5 Fix #4).

A completed validation command is NOT automatically a confirmed vulnerability.
This module separates *execution completion* from *evidentiary verdict* and gives
findings an explicit lifecycle so exploitation can be gated on real, provenance-
tracked evidence - never on "stdout is non-empty" and never on the user asserting
something is "validated".

Finding lifecycle:
    CANDIDATE   -> discovered by a scanner, not yet proven
    VALIDATING  -> a validation action is in progress
    VALIDATED   -> a validation step produced a deterministic positive verdict
    REJECTED    -> a validation step produced a deterministic negative verdict
    INCONCLUSIVE-> validation completed but no deterministic verdict could be derived

Verdicts come from DETERMINISTIC adapters over the real tool result (structured
result keys first; a small, extensible per-tool parser registry second). When no
adapter can establish a positive result the verdict is INCONCLUSIVE - the AI never
imagines a CONFIRMED. No tool/target/finding is hard-coded for routing here; the
per-tool parsers interpret evidence only (provenance is recorded).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional


class FindingStatus:
    CANDIDATE = "CANDIDATE"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class Verdict:
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class ValidationEvidence:
    """A structured, provenance-tracked verdict derived from a real tool result."""
    tool: str
    target: Optional[str]
    verdict: str                       # Verdict.*
    confidence: float                  # 0.0 - 1.0 (deterministic buckets, not AI)
    provenance: str                    # how the verdict was derived
    execution_success: bool
    evidence_excerpt: str = ""         # short, real excerpt of the actual output
    finding_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id, "tool": self.tool, "target": self.target,
            "verdict": self.verdict, "confidence": round(self.confidence, 2),
            "provenance": self.provenance, "execution_success": self.execution_success,
            "evidence_excerpt": self.evidence_excerpt,
        }


# Explicit, structured positive/negative result keys an integration may set.
_POSITIVE_KEYS = ("vulnerable", "validated", "exploitable", "confirmed", "is_vulnerable")
_NEGATIVE_KEYS = ("not_vulnerable", "safe")

# Per-tool deterministic stdout parsers (evidence interpretation, NOT selection).
# Each returns Verdict.* or None (None -> fall through to INCONCLUSIVE). The map is
# keyed by registered tool id; adding support for a tool is an evidence adapter, not
# a routing decision. Kept intentionally conservative - no prose "guessing".
def _parse_generic(_stdout: str) -> Optional[str]:
    return None


_TOOL_PARSERS: Dict[str, Callable[[str], Optional[str]]] = {}


def register_parser(tool_id: str, parser: Callable[[str], Optional[str]]) -> None:
    """Register a deterministic validation-output parser for a supported tool."""
    _TOOL_PARSERS[tool_id] = parser


def _excerpt(result_data: Dict[str, Any], limit: int = 200) -> str:
    out = result_data.get("stdout") or result_data.get("parsed") or ""
    text = out if isinstance(out, str) else str(out)
    return text.strip()[:limit]


def derive_verdict(tool_id: str, result, target: Optional[str]) -> ValidationEvidence:
    """Deterministically classify a validation result. Returns INCONCLUSIVE unless a
    structured key or a registered per-tool parser establishes a verdict. Never
    promotes merely-non-empty stdout to CONFIRMED."""
    ok = bool(getattr(result, "ok", False))
    data = getattr(result, "data", None) or {}
    excerpt = _excerpt(data)

    if not ok:
        return ValidationEvidence(tool_id, target, Verdict.INCONCLUSIVE, 0.0,
                                  "execution_failed", False, excerpt)

    # 1) explicit structured verdict keys (strongest, deterministic)
    for k in _POSITIVE_KEYS:
        if k in data:
            if data.get(k):
                return ValidationEvidence(tool_id, target, Verdict.CONFIRMED, 0.99,
                                          "structured_result_key:%s" % k, True, excerpt)
            return ValidationEvidence(tool_id, target, Verdict.REJECTED, 0.99,
                                      "structured_result_key:%s=false" % k, True, excerpt)
    for k in _NEGATIVE_KEYS:
        if data.get(k):
            return ValidationEvidence(tool_id, target, Verdict.REJECTED, 0.9,
                                      "structured_result_key:%s" % k, True, excerpt)

    # 2) deterministic per-tool stdout parser (evidence interpretation)
    parser = _TOOL_PARSERS.get(tool_id)
    if parser is not None:
        try:
            v = parser(data.get("stdout") or "")
        except Exception:
            v = None
        if v == Verdict.CONFIRMED:
            return ValidationEvidence(tool_id, target, Verdict.CONFIRMED, 0.85,
                                      "tool_parser:%s" % tool_id, True, excerpt)
        if v == Verdict.REJECTED:
            return ValidationEvidence(tool_id, target, Verdict.REJECTED, 0.85,
                                      "tool_parser:%s" % tool_id, True, excerpt)

    # 3) completed, but no deterministic positive proof -> INCONCLUSIVE (never CONFIRMED)
    return ValidationEvidence(tool_id, target, Verdict.INCONCLUSIVE, 0.3,
                              "execution_completed_no_deterministic_verdict", True, excerpt)


def new_finding(title: str, tool: str, target: Optional[str], stage: str,
                status: str = FindingStatus.CANDIDATE, evidence: str = "") -> Dict[str, Any]:
    """Create a finding record with a stable id + lifecycle status + provenance."""
    fid = "F-%s" % format(int(time.time() * 1000) % 0xFFFFFFFF, "08x")
    return {"finding_id": fid, "title": title, "tool": tool, "target": target,
            "stage": stage, "status": status, "evidence": evidence,
            "provenance": [], "ts": time.time()}
