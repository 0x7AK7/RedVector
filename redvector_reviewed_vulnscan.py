"""Staged reviewed vulnerability-assessment orchestrator (ollama-assessment-v1).

Chains ONLY already-reviewed backend profiles — native nmap discovery and -sV service
versioning, RedVector's passive HTTP-response collector, the reviewed offline Nuclei
header profile when its verified binary is configured, and the fixed NVD advisory
provider. It never executes an unreviewed scanner, never claims native Nikto/Jaeles/
Masscan/RustScan execution, and never manufactures findings or exploitability. Each stage
records a real audit entry; a missing dependency is reported accurately, not faked.
"""
import ipaddress
import time
import redvector_reviewed_profiles as nmapp
import redvector_reviewed_assessment as http

PROFILE = "ollama-assessment-v1"
_DISCOVERY_RANGE = "1-10000"      # bounded default; full 1-65535 is its own explicit nmap stage
_VERSION_CHUNK = 128              # reviewed service-version profile cap
_MAX_WEB = 6
_WEB_PORTS = {"80", "81", "443", "591", "2082", "8000", "8008", "8080", "8180", "8443", "8888"}
_ORDER = ["Confirmed", "Strongly supported", "Candidate CVE (requires validation)",
          "Informational", "Unsupported/untested"]

def _numeric_host(value):
    address = ipaddress.ip_address(value)
    if address.is_multicast or address.is_unspecified or str(address) != value:
        raise ValueError("A canonical unicast numeric host is required")
    return str(address)

def run_assessment(params):
    started = time.monotonic()
    audit = []
    def record(stage, tool, engine, ok, detail=""):
        audit.append({"stage": stage, "tool": tool, "engine": engine,
                      "status": "ok" if ok else "unavailable", "detail": str(detail)[:200]})
    try:
        if not isinstance(params, dict) or set(params) - {"target", "focus_areas"}:
            raise ValueError("Unexpected assessment arguments")
        target = _numeric_host(str(params.get("target", "")))
    except ValueError as exc:
        return {"success": False, "profile": PROFILE,
                "error": "A single numeric authorized host is required for the staged assessment",
                "detail": str(exc)[:200], "audit_trail": audit}
    focus = str(params.get("focus_areas", "all"))
    findings = []
    services = []

    # Stage A — bounded native TCP discovery (real nmap -sT, XML parsed)
    disc = nmapp.run_discovery("nmap_scan", {"target": target, "ports": _DISCOVERY_RANGE,
        "scan_type": nmapp.DISCOVERY_PROFILE, "additional_args": "", "use_recovery": False})
    disc_ok = bool(disc.get("success"))
    record("discovery", "nmap_scan", "native nmap -sT connect discovery", disc_ok, disc.get("error", ""))
    open_ports = [e["port"] for e in disc.get("parsed", {}).get("open_ports", [])] if disc_ok else []

    # Stage B — native service/version on discovered open ports (chunked <=128)
    for index in range(0, len(open_ports), _VERSION_CHUNK):
        chunk = ",".join(open_ports[index:index + _VERSION_CHUNK])
        if not chunk:
            continue
        version = nmapp.run_profile("nmap_scan", {"target": target, "ports": chunk,
            "scan_type": nmapp.NMAP_PROFILE, "additional_args": "--version-intensity 2", "use_recovery": False})
        ok = bool(version.get("success"))
        record("service-version", "nmap_scan", "native nmap -sV reviewed profile", ok, version.get("error", ""))
        if ok:
            for service in version.get("parsed", {}).get("services", []):
                services.append(service)
                identified = service.get("confidence") == "identified"
                findings.append({
                    "classification": "Strongly supported" if identified else "Informational",
                    "host": target, "port": service.get("port"), "service": service.get("service"),
                    "product": service.get("product", ""), "version": service.get("version", ""),
                    "confidence": service.get("confidence", "inconclusive"),
                    "evidence": "nmap -sV method=" + str(service.get("method", "")),
                    "references": [],
                    "remediation": "Confirm the exact product/version and restrict or patch exposed services."})

    # Stage C — reviewed PASSIVE HTTP assessment (+ reviewed offline Nuclei when configured)
    web = [port for port in open_ports if port in _WEB_PORTS][:_MAX_WEB]
    if focus in ("all", "web", "http"):
        for port in web:
            url = "http://" + target + ":" + port + "/"
            passive = http.run_http_assessment("nikto_scan", {"target": url, "additional_args": http.HTTP_ASSESS_MARKER})
            ok = bool(passive.get("success"))
            record("http-config", "nikto_scan", "RedVector passive HTTP collector (NOT native Nikto)", ok, passive.get("error", ""))
            if ok:
                for item in passive.get("findings", []):
                    findings.append({"classification": "Informational", "host": target, "port": port,
                        "service": "http", "title": item.get("title"), "evidence": item.get("evidence"),
                        "confidence": "observed", "references": [],
                        "remediation": "Set the missing/weak security header or correct the server configuration."})
            nuclei = http.run_nuclei({"target": url, "severity": "", "tags": "",
                "template": http.NUCLEI_PROFILE, "use_recovery": False})
            nok = bool(nuclei.get("success"))
            record("nuclei-passive", "nuclei_scan",
                   "native reviewed Nuclei v3.11.1 (offline header profile)" if nok else "unavailable",
                   nok, nuclei.get("error", ""))
            if nok:
                for item in nuclei.get("findings", []):
                    findings.append({"classification": "Informational", "host": target, "port": port,
                        "service": "http", "title": item.get("title"),
                        "evidence": item.get("evidence"), "confidence": "observed", "references": [],
                        "remediation": "Address the missing response-header configuration."})

    # Stage D — candidate CVEs from the fixed NVD provider for identified products (best-effort, labeled)
    try:
        import redvector_reviewed_advisories as advisories
        keywords = sorted({service.get("product", "") for service in services if service.get("product")})[:3]
        for keyword in keywords:
            result = advisories.run({"hours": 168, "severity_filter": "HIGH,CRITICAL", "keywords": keyword.lower()})
            ok = bool(result.get("success"))
            record("advisory-nvd", "monitor_cve_feeds", "NVD CVE API 2.0", ok, result.get("error", ""))
            if ok:
                for row in result.get("advisories", [])[:5]:
                    findings.append({"classification": "Candidate CVE (requires validation)", "host": target,
                        "service": keyword, "cve": row.get("id"), "cvss": row.get("provider_cvss_score"),
                        "provider_severity": row.get("provider_severity"),
                        "evidence": "NVD keyword match on product '" + keyword + "'; applicability not established",
                        "confidence": "candidate",
                        "references": [row.get("reference")] if row.get("reference") else [],
                        "remediation": "Validate the CVE applies to the exact product and version before acting."})
    except Exception as exc:  # advisory stage is best-effort; never fail the whole assessment
        record("advisory-nvd", "monitor_cve_feeds", "NVD CVE API 2.0", False, str(exc)[:160])

    findings.sort(key=lambda finding: _ORDER.index(finding["classification"]) if finding.get("classification") in _ORDER else len(_ORDER))
    return {"success": disc_ok, "profile": PROFILE, "target": target, "focus_areas": focus,
            "open_ports": open_ports, "services": services, "findings": findings,
            "classification_legend": _ORDER, "audit_trail": audit,
            "execution_time": time.monotonic() - started,
            "limitations": ("Staged reviewed assessment over reviewed profiles only: native nmap -sT discovery "
                "(bounded " + _DISCOVERY_RANGE + ") and -sV service versioning, RedVector's passive HTTP-response "
                "collector (not native Nikto/Jaeles), the reviewed offline Nuclei header profile when its verified "
                "binary is configured, and NVD advisories. No native Nikto/Jaeles/Masscan/RustScan execution; no "
                "fabricated findings; candidate CVEs require validation and do not establish exploitability.")}
