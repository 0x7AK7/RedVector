"""Professional, severity-aware security-assessment report — the default compact operator view.

Renders on the existing Panel/Terminal architecture (no new dependency) in a fixed layout:
SECURITY ASSESSMENT (target, profile, coverage, status, duration), DISCOVERY (ports requested /
completed / open), NATIVE TOOL EXECUTION (engine, actual binary, status, duration), DISCOVERED
SERVICES, VULNERABILITIES and NEXT STEPS. It NEVER dumps flattened internal keys or raw JSON. Colors
follow the finding class / evidence confidence, not only a CVSS label; provider CVSS severity is shown
separately from validation status. Raw evidence stays complete and unchanged in archival storage and
is reached only by explicit request. Missing sections render as explicit "none" lines — never
fabricated.
"""
from redvector_ollama_panels import Panel
from redvector_cve_correlation import CLASSIFICATION_ORDER as CLASS_ORDER

# Finding class -> color kind (evidence strength, not provider severity).
_CLASS_KIND = {"Demonstrated Impact": "critical", "Validated Vulnerability": "critical",
               "Scanner-Detected Vulnerability": "high", "Candidate CVE": "medium",
               "Observed Exposure": "info", "Informational": "meta",
               # legacy labels (kept readable for older saved evidence)
               "Confirmed": "critical", "Strongly supported": "high",
               "Candidate CVE (requires validation)": "medium", "Unsupported/untested": "meta"}
_NATIVE_TRUE = ("true", "yes", "1")
_OK = ("ok", "success", "completed", "complete")


def _status_kind(status):
    s = str(status).lower()
    return "success" if s == "complete" else "error" if s == "failed" else "warning"


def _duration(value):
    return (format(value, ".2f") + " s") if isinstance(value, (int, float)) and value else "-"


def _coverage_text(cov):
    requested, completed = int(cov.get("requested") or 0), int(cov.get("completed") or 0)
    if not requested:
        return "not recorded"
    text = format(completed, ",") + " of " + format(requested, ",") + " requested TCP ports completed"
    if requested < 65535:
        text += " (not all 65,535 ports)"
    state = cov.get("state")
    return text + (" — " + str(state) if state and state != "complete" else "")


def normalize_class(classification, cve=""):
    """Map legacy labels from older saved evidence onto the current finding classes; never upgrades
    evidence strength (a legacy 'Strongly supported' CVE stays a candidate, not a vulnerability)."""
    c = str(classification or "")
    if c in CLASS_ORDER:
        return c
    if c == "Confirmed":
        return "Validated Vulnerability"
    if c in ("Candidate CVE (requires validation)",) or (c == "Strongly supported" and cve):
        return "Candidate CVE"
    if c == "Strongly supported":
        return "Observed Exposure"
    return "Informational"


def build_report(result):
    """Normalize a staged task result or a run_assessment-style dict into the report structure."""
    result = result or {}
    coverage = dict(result.get("coverage") or {})
    open_ports = result.get("open_ports", []) or []
    if not coverage and open_ports:
        coverage = {"requested": 0, "completed": 0, "open": len(open_ports), "state": "not recorded"}
    coverage.setdefault("open", len(open_ports))
    services = []
    for svc in result.get("services", []) or []:
        if isinstance(svc, dict):
            services.append({"port": str(svc.get("port", "")), "service": svc.get("service", "unknown"),
                             "product": svc.get("product", ""), "version": svc.get("version", ""),
                             "confidence": svc.get("confidence", "inconclusive")})
    findings = []
    for f in result.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        findings.append({"severity": str(f.get("cvss_severity") or f.get("provider_severity") or "") or "-",
                         "finding": f.get("title") or f.get("cve") or f.get("service") or "-",
                         "cve": f.get("cve") or "-", "classification": normalize_class(f.get("classification"), f.get("cve")),
                         "validation": f.get("validation") or f.get("applicability") or f.get("classification", ""),
                         "source": f.get("source") or f.get("tool") or "-", "port": str(f.get("port", "") or "")})
    execution = []
    for row in (result.get("execution") or result.get("audit_trail") or []):
        if isinstance(row, dict):
            execution.append({"engine": row.get("engine", row.get("tool", "")),
                              "binary": row.get("binary") or ("not executed (internal engine)" if str(row.get("native_executed", "")).lower() not in _NATIVE_TRUE else "not recorded"),
                              "native": str(row.get("native_executed", row.get("native", ""))).lower() in _NATIVE_TRUE,
                              "status": row.get("status", ""), "duration": row.get("duration", "")})
    counts = {name: sum(1 for f in findings if f["classification"] == name) for name in CLASS_ORDER}
    status = result.get("status") or ("Complete" if result.get("success") else "Partial")
    return {"target": result.get("target", "unspecified"), "profile": result.get("profile_label") or result.get("profile") or "detection",
            "status": status, "duration": result.get("execution_time", result.get("duration", 0)) or 0,
            "coverage": coverage, "services": services, "findings": findings, "execution": execution,
            "counts": counts, "native_tools": sum(1 for e in execution if e["native"] and str(e["status"]).lower() in _OK),
            "unavailable": [e["engine"] for e in execution if str(e["status"]).lower() not in _OK],
            "next_steps": result.get("next_steps", [])}


def render_report(term, report, width=None):
    """Draw the default compact SECURITY ASSESSMENT view. Width-aware, NO_COLOR/non-TTY safe."""
    panel = Panel(term, width)
    cov = report["coverage"]
    panel.section("REDVECTOR AI — SECURITY ASSESSMENT")
    panel.fields([("Target", str(report["target"])), ("Profile", str(report["profile"])),
                  ("Coverage", _coverage_text(cov)), ("Status", str(report["status"])),
                  ("Duration", _duration(report["duration"]))])
    panel.line("Status: " + str(report["status"]), _status_kind(report["status"]))
    panel.section("DISCOVERY")
    panel.fields([("Ports requested", format(int(cov.get("requested") or 0), ",")),
                  ("Ports completed", format(int(cov.get("completed") or 0), ",")),
                  ("Open ports", str(cov.get("open", 0)))])
    panel.section("NATIVE TOOL EXECUTION")
    if report["execution"]:
        panel.grid(["ENGINE", "ACTUAL BINARY", "STATUS", "DURATION"],
                   [[e["engine"], e["binary"], e["status"], _duration(e["duration"])] for e in report["execution"]],
                   ["success" if str(e["status"]).lower() in _OK else "warning" for e in report["execution"]])
    else:
        panel.line("No engine execution recorded.", "meta")
    panel.section("DISCOVERED SERVICES")
    if report["services"]:
        panel.grid(["PORT", "SERVICE", "PRODUCT", "VERSION", "CONFIDENCE"],
                   [[s["port"], s["service"], s["product"] or "-", s["version"] or "-", s["confidence"]] for s in report["services"]])
    else:
        panel.line("No services identified.", "meta")
    panel.section("VULNERABILITIES")
    c = report["counts"]
    panel.line("Validated " + str(c["Validated Vulnerability"]) + " | Scanner-detected " + str(c["Scanner-Detected Vulnerability"]) +
               " | Candidate CVEs " + str(c["Candidate CVE"]) + " | Observed exposures " + str(c["Observed Exposure"]), "info")
    vulns = [f for f in report["findings"] if f["classification"] not in ("Observed Exposure", "Informational")]
    if vulns:
        panel.grid(["SEVERITY", "FINDING", "CVE", "VALIDATION", "EVIDENCE SOURCE"],
                   [[f["severity"], f["finding"], f["cve"], f["validation"], f["source"]] for f in vulns],
                   [_CLASS_KIND.get(f["classification"], "info") for f in vulns])
        panel.line("Provider CVSS severity is shown separately from validation status; candidates are not confirmed.", "meta")
    else:
        panel.line("No vulnerabilities validated or detected by the engines that ran. This is not proof the target "
                   "is free of vulnerabilities" + (" — detection coverage is incomplete." if report["unavailable"] or
                   str(report["status"]).lower() != "complete" else "."), "meta")
    panel.section("NEXT STEPS")
    for step in (report["next_steps"] or _default_next_steps(report))[:5]:
        panel.line("- " + str(step))
    panel.line("Ask for detailed findings, the evidence overview, the raw JSON payload, or a JSON export.", "meta")


def _default_next_steps(report):
    steps = []
    if report["unavailable"]:
        steps.append("Coverage is incomplete: " + ", ".join(sorted(set(report["unavailable"])))[:200] + " did not run successfully.")
    if report["counts"]["Candidate CVE"]:
        steps.append("Validate candidate CVEs against the exact product and version before acting; they are not confirmed.")
    if int(report["coverage"].get("requested") or 0) and int(report["coverage"].get("requested")) < 65535:
        steps.append("Request all 65535 TCP ports for full discovery coverage.")
    if report["services"]:
        steps.append("Review exposed services and restrict or patch those not required.")
    return steps or ["No evidence-based action required from this assessment."]
