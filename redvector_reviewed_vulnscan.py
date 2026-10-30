"""Staged reviewed vulnerability-assessment orchestrator (ollama-assessment-v1).

Chains ONLY already-reviewed backend profiles — native nmap discovery and -sV service versioning,
RedVector's passive HTTP-response collector, the reviewed offline Nuclei header profile when its
verified binary is configured, and the fixed NVD advisory provider. It never executes an unreviewed
scanner, never claims native Nikto/Jaeles/Masscan/RustScan execution, and never manufactures findings
or exploitability. Findings use the shared evidence schema with CPE/version-aware CVE correlation and
cross-engine deduplication: provider CVSS severity is kept separate from evidence confidence and
validation status, service identification is never a confirmed vulnerability, and incomplete coverage
is reported as Partial, not a false Success. Each stage records a real, honestly-labeled audit entry.
"""
import ipaddress
import time
import redvector_reviewed_profiles as nmapp
import redvector_reviewed_assessment as http
import redvector_evidence as ev
import redvector_cve_correlation as corr

PROFILE = "ollama-assessment-v1"
_DISCOVERY_RANGE = "1-10000"      # bounded default; full 1-65535 is its own explicit nmap stage
_VERSION_CHUNK = 128              # reviewed service-version profile cap
_MAX_WEB = 6
_WEB_PORTS = {"80", "81", "443", "591", "2082", "8000", "8008", "8080", "8180", "8443", "8888"}
_ORDER = corr.CLASSIFICATION_ORDER


def _numeric_host(value):
    address = ipaddress.ip_address(value)
    if address.is_multicast or address.is_unspecified or str(address) != value:
        raise ValueError("A canonical unicast numeric host is required")
    return str(address)


def _nvd_applies(product, version, cpes, description):
    """Applicability of an NVD advisory to a service, from the advisory's own text and the service's
    exact product/version/CPE. The exact product (or its CPE product) must appear — a broad vendor
    word like 'Apache' alone is not enough. 'applicable' only when the version also appears; product
    present but version absent -> 'candidate'; product absent -> 'not_applicable' (dropped). Never
    'confirmed'."""
    description = (description or "").lower()
    names = set()
    product_l = (product or "").strip().lower()
    if product_l:
        names.add(product_l)
    for cpe in cpes or []:
        parsed = corr.parse_cpe(cpe)
        if parsed and parsed["product"]:
            names.add(parsed["product"])
            names.add(parsed["product"].replace("_", " "))
    names = {n for n in names if n and len(n) >= 3}
    if not names or not any(n in description for n in names):
        return "not_applicable"
    version_l = (version or "").strip().lower()
    if version_l and version_l in description:
        return "applicable"
    return "candidate"


def run_assessment(params):
    started = time.monotonic()
    audit = []

    def record(stage, tool, engine, ok, native=False, detail="", duration=""):
        audit.append({"stage": stage, "tool": tool, "engine": engine, "native_executed": bool(native),
                      "status": "ok" if ok else "unavailable", "detail": str(detail)[:200], "duration": duration})

    try:
        if not isinstance(params, dict) or set(params) - {"target", "focus_areas"}:
            raise ValueError("Unexpected assessment arguments")
        target = _numeric_host(str(params.get("target", "")))
    except ValueError as exc:
        return {"success": False, "status": "Failed", "profile": PROFILE,
                "error": "A single numeric authorized host is required for the staged assessment",
                "detail": str(exc)[:200], "audit_trail": audit, "execution": audit, "findings": []}

    focus = str(params.get("focus_areas", "all"))
    findings = []
    services = []
    unavailable = False

    # Stage A — bounded native TCP discovery (real nmap -sT, XML parsed)
    disc = nmapp.run_discovery("nmap_scan", {"target": target, "ports": _DISCOVERY_RANGE,
        "scan_type": nmapp.DISCOVERY_PROFILE, "additional_args": "", "use_recovery": False})
    disc_ok = bool(disc.get("success"))
    record("discovery", "nmap_scan", "native nmap -sT connect discovery", disc_ok, native=True,
           detail=disc.get("error", ""), duration=disc.get("execution_time", ""))
    if not disc_ok:
        unavailable = True
    open_ports = [e["port"] for e in disc.get("parsed", {}).get("open_ports", [])] if disc_ok else []

    # Stage B — native service/version on discovered open ports (chunked <=128)
    for index in range(0, len(open_ports), _VERSION_CHUNK):
        chunk = ",".join(open_ports[index:index + _VERSION_CHUNK])
        if not chunk:
            continue
        version = nmapp.run_profile("nmap_scan", {"target": target, "ports": chunk,
            "scan_type": nmapp.NMAP_PROFILE, "additional_args": "--version-intensity 2", "use_recovery": False})
        ok = bool(version.get("success"))
        record("service-version", "nmap_scan", "native nmap -sV reviewed profile", ok, native=True,
               detail=version.get("error", ""), duration=version.get("execution_time", ""))
        if not ok:
            unavailable = True
            continue
        for service in version.get("parsed", {}).get("services", []):
            services.append(service)
            identified = service.get("confidence") == "identified"
            findings.append(ev.evidence(
                target=target, host=target, port=str(service.get("port", "")), protocol=service.get("protocol", "tcp"),
                service=service.get("service", ""), product=service.get("product", ""), version=service.get("version", ""),
                tool="nmap -sV", source="nmap -sV", verification_method="nmap -sV method=" + str(service.get("method", "")),
                classification="Strongly supported" if identified else "Informational",
                applicability="observed", confidence=service.get("confidence", "inconclusive"),
                evidence_ref="nmap-sV:" + str(service.get("port", "")), execution_status="completed",
                remediation="Confirm the exact product/version and restrict or patch exposed services."))

    # Stage C — reviewed PASSIVE HTTP assessment (+ reviewed offline Nuclei when configured)
    web = [port for port in open_ports if port in _WEB_PORTS][:_MAX_WEB]
    if focus in ("all", "web", "http"):
        for port in web:
            url = "http://" + target + ":" + port + "/"
            passive = http.run_http_assessment("nikto_scan", {"target": url, "additional_args": http.HTTP_ASSESS_MARKER})
            ok = bool(passive.get("success"))
            record("http-config", "nikto_scan", "RedVector passive HTTP collector (NOT native Nikto)", ok, native=False, detail=passive.get("error", ""))
            if not ok:
                unavailable = True
            for item in (passive.get("findings", []) if ok else []):
                findings.append(ev.evidence(target=target, host=target, port=str(port), protocol="tcp", service="http",
                    title=item.get("title"), source="passive-http", tool="passive-http", classification="Informational",
                    applicability="observed", confidence="observed", evidence_ref="passive-http:" + str(port),
                    remediation="Set the missing/weak security header or correct the server configuration."))
            nuclei = http.run_nuclei({"target": url, "severity": "", "tags": "",
                "template": http.NUCLEI_PROFILE, "use_recovery": False})
            nok = bool(nuclei.get("success"))
            record("nuclei-passive", "nuclei_scan",
                   "native reviewed Nuclei (offline header profile)" if nok else "unavailable",
                   nok, native=nok, detail=nuclei.get("error", ""))
            if not nok:
                unavailable = True
            for item in (nuclei.get("findings", []) if nok else []):
                findings.append(ev.evidence(target=target, host=target, port=str(port), protocol="tcp", service="http",
                    title=item.get("title"), source="nuclei", tool="nuclei", classification="Informational",
                    applicability="observed", confidence="observed", evidence_ref="nuclei:" + str(port),
                    remediation="Address the missing response-header configuration."))

    # Stage D — candidate CVEs from the fixed NVD provider, correlated to the EXACT product/version
    try:
        import redvector_reviewed_advisories as advisories
        by_product = {}
        for svc in services:
            product = (svc.get("product") or "").strip()
            if product:
                by_product.setdefault(product, []).append(svc)
        for product in sorted(by_product)[:3]:
            result = advisories.run({"hours": 168, "severity_filter": "HIGH,CRITICAL", "keywords": product.lower()[:80]})
            ok = bool(result.get("success"))
            record("advisory-nvd", "monitor_cve_feeds", "NVD CVE API 2.0", ok, native=False, detail=result.get("error", ""))
            if not ok:
                unavailable = True
                continue
            for svc in by_product[product]:
                version = svc.get("version", "")
                cpes = svc.get("cpe", [])
                port = str(svc.get("port", ""))
                for row in result.get("advisories", [])[:10]:
                    applic = _nvd_applies(product, version, cpes, row.get("description", ""))
                    if applic == "not_applicable":
                        continue
                    findings.append(ev.evidence(
                        target=target, host=target, port=port, protocol="tcp", service=svc.get("service", ""),
                        product=product, version=version, cve=row.get("id"),
                        cvss=row.get("provider_cvss_score"), cvss_severity=row.get("provider_severity"), cvss_source="NVD",
                        source="nvd", tool="nvd", title=row.get("id"),
                        classification="Strongly supported" if applic == "applicable" else "Candidate CVE (requires validation)",
                        applicability=applic, confidence=applic,
                        evidence_ref=row.get("reference", ""), references=[row.get("reference")] if row.get("reference") else [],
                        remediation="Validate the CVE applies to the exact product and version before acting."))
    except Exception as exc:  # advisory stage is best-effort; never fail the whole assessment
        record("advisory-nvd", "monitor_cve_feeds", "NVD CVE API 2.0", False, native=False, detail=str(exc)[:160])
        unavailable = True

    merged = ev.merge(findings)
    status = "Failed" if not disc_ok else ("Partial" if unavailable else "Complete")
    return {"success": disc_ok, "status": status, "profile": PROFILE, "target": target, "focus_areas": focus,
            "open_ports": open_ports, "services": services, "findings": merged,
            "summary": ev.summarize(merged), "classification_legend": _ORDER,
            "audit_trail": audit, "execution": audit, "execution_time": time.monotonic() - started,
            "limitations": ("Staged reviewed assessment over reviewed profiles only: native nmap -sT discovery "
                "(bounded " + _DISCOVERY_RANGE + ") and -sV service versioning, RedVector's passive HTTP-response "
                "collector (not native Nikto/Jaeles), the reviewed offline Nuclei header profile when its verified "
                "binary is configured, and NVD advisories correlated to the exact product/version. No native "
                "Nikto/Jaeles/Masscan/RustScan execution and no fabricated findings; candidate CVEs require "
                "validation and do not establish exploitability; service identification is not a confirmed "
                "vulnerability. Incomplete stages are reported as Partial.")}
