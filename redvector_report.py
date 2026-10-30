"""Professional, severity-aware security-assessment report — the default compact operator view.

Renders on the existing Panel/Terminal architecture (no new dependency). It shows only a useful
summary plus aligned tables; it NEVER dumps flattened internal keys. Colors reflect evidence
confidence / validation status, not only a CVSS label. Raw evidence stays complete and unchanged in
archival storage; detailed findings, raw evidence, full tool output and JSON export are reached by
natural-language request, not shown here by default.

build_report(result) normalizes an assessment/scan result into the report structure; render_report
draws it. Missing sections render as explicit "none" lines — never fabricated.
"""
from redvector_ollama_panels import Panel

# classification (evidence confidence/validation) -> color kind; distinct from provider CVSS severity.
_CLASS_KIND = {"Confirmed": "critical", "Strongly supported": "high",
               "Candidate CVE (requires validation)": "medium", "Informational": "info",
               "Unsupported/untested": "meta"}
_SEV_KIND = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
             "informational": "info", "info": "info", "none": "meta", "unknown": "meta"}


def _status_kind(status):
    s = str(status).lower()
    return "success" if s == "complete" else "error" if s == "failed" else "warning"


def build_report(result):
    """Normalize a run_assessment-style dict (or a staged result) into the report structure.
    Recognized keys: target, status, execution_time/duration, open_ports, services[], findings[]
    (evidence records), execution/audit_trail[]. Everything missing defaults safely."""
    result = result or {}
    services = []
    for svc in result.get("services", []) or []:
        if not isinstance(svc, dict):
            continue
        services.append({"port": str(svc.get("port", "")), "protocol": svc.get("protocol", "tcp"),
                         "service": svc.get("service", "unknown"), "product": svc.get("product", ""),
                         "version": svc.get("version", ""),
                         "confidence": svc.get("confidence", "inconclusive")})
    findings = []
    for f in result.get("findings", []) or []:
        if not isinstance(f, dict):
            continue
        classification = f.get("classification", "Informational")
        findings.append({"severity": str(f.get("cvss_severity", f.get("provider_severity", "")) or ""),
                         "title": f.get("title", "") or f.get("cve", "") or f.get("service", ""),
                         "host": f.get("host", f.get("target", "")), "port": str(f.get("port", "") or ""),
                         "cve": f.get("cve", ""), "classification": classification,
                         "validation": f.get("validation", f.get("applicability", "")),
                         "source": f.get("source", f.get("tool", "")),
                         "cvss": f.get("cvss", "")})
    execution = []
    for row in (result.get("execution") or result.get("audit_trail") or []):
        if not isinstance(row, dict):
            continue
        execution.append({"engine": row.get("engine", row.get("tool", "")),
                          "native": row.get("native_executed", row.get("native", "")),
                          "status": row.get("status", ""), "duration": row.get("duration", ""),
                          "evidence": row.get("evidence", row.get("evidence_ref", ""))})
    confirmed = sum(1 for f in findings if f["classification"] == "Confirmed")
    candidates = sum(1 for f in findings if f["classification"] == "Candidate CVE (requires validation)")
    informational = sum(1 for f in findings if f["classification"] == "Informational")
    native_ok = sum(1 for e in execution if str(e["native"]).lower() in ("true", "yes", "1") and str(e["status"]).lower() in ("ok", "success", "completed", "complete"))
    return {"target": result.get("target", "unspecified"),
            "status": result.get("status") or ("Complete" if result.get("success") else "Partial"),
            "duration": result.get("execution_time", result.get("duration", 0)) or 0,
            "open_ports": result.get("open_ports", []) or [],
            "services": services, "findings": findings, "execution": execution,
            "summary": {"open_ports": len(result.get("open_ports", []) or []),
                        "services": len(services), "confirmed": confirmed, "candidates": candidates,
                        "informational": informational, "native_tools": native_ok},
            "next_steps": result.get("next_steps", [])}


def render_report(term, report, width=None):
    """Draw the default compact SECURITY ASSESSMENT view. Width-aware, NO_COLOR/non-TTY safe."""
    panel = Panel(term, width)
    panel.section("REDVECTOR AI — SECURITY ASSESSMENT")
    panel.fields([("Target", str(report["target"])), ("Status", str(report["status"])),
                  ("Execution time", (format(report["duration"], ".2f") + " s") if isinstance(report["duration"], (int, float)) else str(report["duration"]))])
    panel.line("Status: " + str(report["status"]), _status_kind(report["status"]))
    s = report["summary"]
    panel.section("SUMMARY")
    panel.fields([("Open TCP ports", str(s["open_ports"])), ("Identified services", str(s["services"])),
                  ("Confirmed vulnerabilities", str(s["confirmed"])),
                  ("Unvalidated CVE candidates", str(s["candidates"])),
                  ("Informational observations", str(s["informational"])),
                  ("Native tools successfully executed", str(s["native_tools"]))])
    panel.section("SERVICES")
    if report["services"]:
        panel.grid(["PORT", "PROTOCOL", "SERVICE", "PRODUCT", "VERSION", "CONFIDENCE"],
                   [[r["port"], r["protocol"], r["service"], r["product"], r["version"], r["confidence"]] for r in report["services"]])
    else:
        panel.line("No services identified.", "meta")
    panel.section("SECURITY FINDINGS")
    if report["findings"]:
        rows, kinds = [], []
        for f in report["findings"]:
            rows.append([f["severity"] or "-", f["title"], f["host"], f["cve"] or "-", f["validation"] or f["classification"], f["source"] or "-"])
            kinds.append(_CLASS_KIND.get(f["classification"], "info"))
        panel.grid(["SEVERITY", "TITLE", "HOST", "CVE", "VALIDATION", "SOURCE"], rows, kinds)
        panel.line("Provider CVSS severity is shown separately from evidence confidence and validation status.", "meta")
    else:
        panel.line("No confirmed vulnerabilities; service identification is not a vulnerability.", "meta")
    panel.section("EXECUTION EVIDENCE")
    if report["execution"]:
        panel.grid(["ENGINE", "NATIVE EXECUTED?", "STATUS", "DURATION", "EVIDENCE"],
                   [[e["engine"], str(e["native"]), e["status"], (format(e["duration"], ".2f") + " s") if isinstance(e["duration"], (int, float)) and e["duration"] else str(e["duration"] or "-"), str(e["evidence"] or "-")] for e in report["execution"]])
    else:
        panel.line("No native engine execution recorded.", "meta")
    panel.section("NEXT STEPS")
    steps = report["next_steps"] or _default_next_steps(report)
    for step in steps[:5]:
        panel.line("- " + str(step))
    panel.line("Ask to show detailed findings, the original evidence, or to export the report as JSON.", "meta")


def _default_next_steps(report):
    steps = []
    if report["summary"]["candidates"]:
        steps.append("Validate candidate CVEs against the exact product and version before acting; they are not confirmed.")
    if report["summary"]["services"]:
        steps.append("Review exposed services and restrict or patch those not required.")
    if str(report["status"]).lower() == "partial":
        steps.append("Re-run the unavailable stages once their native engines are verified; coverage is incomplete.")
    return steps or ["No evidence-based action required from this assessment."]
