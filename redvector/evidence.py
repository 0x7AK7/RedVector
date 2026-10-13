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

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


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


_FID_SEQ = [0]


def _fid() -> str:
    _FID_SEQ[0] += 1
    return "F-%08x%03d" % (int(time.time() * 1000) % 0xFFFFFFFF, _FID_SEQ[0] % 1000)


def new_finding(title: str, tool: str, target: Optional[str], stage: str,
                status: str = FindingStatus.CANDIDATE, evidence: str = "",
                **extra: Any) -> Dict[str, Any]:
    """Create a finding record with a stable id + lifecycle status + provenance.
    ``extra`` carries optional structured metadata (severity, service, port, url,
    cve, cwe, template_id, technology, matched_at, source_tool); absent values stay
    absent (never inferred)."""
    rec = {"finding_id": _fid(), "title": title, "tool": tool, "target": target,
           "stage": stage, "status": status, "evidence": evidence,
           "provenance": [], "ts": time.time()}
    for k, v in extra.items():
        if v is not None:
            rec[k] = v
    return rec


# ============================================================================
# ATOMIC parsers (Phase 10.5 result-UX fix): each observation/finding is one
# record parsed from a SINGLE line, so a port is never separated from its own
# service/version by zipping independent lists.
# ============================================================================

# Nmap-style port line: "22/tcp open ssh OpenSSH 8.2p1 Ubuntu" (version optional).
_PORT_LINE = re.compile(
    r"^[ \t]*(\d{1,5})/(tcp|udp)[ \t]+(open\|filtered|open|closed|filtered)[ \t]+(\S+)"
    r"(?:[ \t]+([^\n]*\S))?[ \t]*$",
    re.IGNORECASE | re.MULTILINE)


def parse_service_observations(stdout: str) -> List[Dict[str, Any]]:
    """Parse nmap-style port records atomically. Returns a list of
    {port, protocol, state, service, version} dicts - port/service/version always
    come from the SAME matched line (never zipped from separate arrays). Lines
    between port records (script output, banners) are ignored, and a port with no
    version yields version=None."""
    out: List[Dict[str, Any]] = []
    if not isinstance(stdout, str) or not stdout:
        return out
    seen = set()
    for m in _PORT_LINE.finditer(stdout):
        port = int(m.group(1))
        proto = m.group(2).lower()
        key = (port, proto)
        if key in seen:
            continue
        seen.add(key)
        version = (m.group(5) or "").strip() or None
        out.append({"port": port, "protocol": proto, "state": m.group(3).lower(),
                    "service": m.group(4).lower(), "version": version})
    return out


# Nuclei-style finding line: "[template-id] [http] [high] http://host/path [extracted]".
_NUCLEI_LINE = re.compile(
    r"\[([^\]]+)\][ \t]*\[([^\]]+)\][ \t]*\[(critical|high|medium|low|info|unknown)\][ \t]*(\S+)"
    r"(?:[ \t]*\[([^\]]*)\])?", re.IGNORECASE)
# Generic "[SEVERITY] title" fallback line.
_SEV_LINE = re.compile(r"^\s*\[(critical|high|medium|low|info)\]\s+(.*\S)\s*$",
                       re.IGNORECASE | re.MULTILINE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def parse_findings(tool: str, stdout: str, target: Optional[str] = None,
                   stage: str = "vuln_discovery") -> List[Dict[str, Any]]:
    """Parse structured findings from real scanner output - one record per real
    finding. Recognises the nuclei bracket format first, then a generic
    "[SEVERITY] title" line. Severities/titles/urls/CVEs come only from the actual
    output; nothing is fabricated. Returns [] when no finding line is present (the
    caller then records a single evidence-bearing candidate)."""
    findings: List[Dict[str, Any]] = []
    if not isinstance(stdout, str) or not stdout:
        return findings
    seen = set()
    for m in _NUCLEI_LINE.finditer(stdout):
        template_id = m.group(1).strip()
        proto = m.group(2).strip().lower()
        severity = m.group(3).upper()
        matched_at = m.group(4).strip()
        line = m.group(0).strip()
        key = (template_id, matched_at)
        if key in seen:
            continue
        seen.add(key)
        cve = None
        cm = _CVE_RE.search(template_id) or _CVE_RE.search(line)
        if cm:
            cve = cm.group(0).upper()
        findings.append(new_finding(
            title=template_id, tool=tool, target=target, stage=stage,
            status=FindingStatus.CANDIDATE, evidence=line[:200],
            source_tool=tool, template_id=template_id, severity=severity,
            protocol=proto, matched_at=matched_at, url=matched_at, cve=cve))
    if findings:
        return findings
    # fallback: generic "[SEVERITY] title" lines
    for m in _SEV_LINE.finditer(stdout):
        severity = m.group(1).upper()
        title = m.group(2).strip()
        key = (severity, title)
        if key in seen:
            continue
        seen.add(key)
        cm = _CVE_RE.search(title)
        findings.append(new_finding(
            title=title, tool=tool, target=target, stage=stage,
            status=FindingStatus.CANDIDATE, evidence=m.group(0).strip()[:200],
            source_tool=tool, severity=severity, cve=(cm.group(0).upper() if cm else None)))
    return findings
