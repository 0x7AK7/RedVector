"""Deterministic CPE / product-version to CVE applicability logic (no network, no execution).

Correlates a discovered service (its nmap -sV product/version and any CPE evidence) against a
candidate advisory (its CPE list and/or affected product/versions). It decides *applicability*
conservatively and never asserts exploitability:

  * ``applicable``      — product matches AND the discovered version is in the advisory's affected
                          set (maps to "Strongly supported": evidence is strong, not exploit-proven).
  * ``candidate``       — product matches but version applicability is not established
                          (maps to "Candidate CVE (requires validation)").
  * ``not_applicable``  — product does not match (the advisory is dropped for this service).

Installed software is never confused with confirmed exploitability; a high-severity candidate is
always kept visible. This module is pure and fully unit-testable without Kali.
"""
import re

# Taxonomy shared with the orchestrator; order is strongest-first.
CLASSIFICATION_ORDER = ["Confirmed", "Strongly supported", "Candidate CVE (requires validation)",
                        "Informational", "Unsupported/untested"]
_VERSION_TOKEN = re.compile(r"[0-9]+(?:\.[0-9]+)*[a-z0-9._-]*", re.I)


def parse_cpe(cpe):
    """Parse a CPE 2.2 (cpe:/part:vendor:product:version) or 2.3
    (cpe:2.3:part:vendor:product:version:...) URI into its fields, or None if unrecognized."""
    if not isinstance(cpe, str):
        return None
    text = cpe.strip()
    if text.startswith("cpe:2.3:"):
        parts = text[len("cpe:2.3:"):].split(":")
    elif text.startswith("cpe:/"):
        parts = text[len("cpe:/"):].split(":")
    else:
        return None
    parts += [""] * (4 - len(parts))
    norm = lambda value: "" if value in ("*", "-", "") else value.lower().replace("\\", "")
    return {"part": norm(parts[0]), "vendor": norm(parts[1]), "product": norm(parts[2]), "version": norm(parts[3])}


def _products(entity):
    """Return the lowercase product tokens an entity (service or advisory) describes, from its CPEs
    and any plain product field. vendor and product are both included so e.g. 'nginx' matches
    cpe:/a:f5:nginx and a plain product 'nginx'."""
    names = set()
    for cpe in entity.get("cpe", []) or []:
        parsed = parse_cpe(cpe)
        if parsed:
            names.update(x for x in (parsed["product"], parsed["vendor"]) if x)
    product = entity.get("product")
    if isinstance(product, str) and product.strip():
        names.add(product.strip().lower())
    return names


def _service_version(service):
    version = str(service.get("version", "") or "").strip().lower()
    if version:
        match = _VERSION_TOKEN.match(version)
        if match:
            return match.group(0)
    for cpe in service.get("cpe", []) or []:
        parsed = parse_cpe(cpe)
        if parsed and parsed["version"]:
            return parsed["version"]
    return ""


def _advisory_versions(advisory):
    versions = set()
    for cpe in advisory.get("cpe", []) or []:
        parsed = parse_cpe(cpe)
        if parsed and parsed["version"]:
            versions.add(parsed["version"])
    for value in advisory.get("versions", []) or []:
        if isinstance(value, str) and value.strip():
            versions.add(value.strip().lower())
    return versions


def applicability(service, advisory):
    """Return (applicability, reason) for one service vs one candidate advisory."""
    service_products = _products(service)
    advisory_products = _products(advisory)
    if not service_products or not advisory_products:
        return "candidate", "insufficient product evidence to establish applicability"
    if service_products.isdisjoint(advisory_products):
        return "not_applicable", "advisory product does not match the discovered service"
    service_version = _service_version(service)
    advisory_versions = _advisory_versions(advisory)
    if service_version and advisory_versions:
        if service_version in advisory_versions:
            return "applicable", "product matches and discovered version is in the advisory's affected set"
        return "candidate", "product matches but the discovered version is not in the listed affected versions"
    return "candidate", "product matches; version applicability not established"


def classify(applic, source):
    """Map (applicability, evidence source) to the shared taxonomy. Active-check tools that assert
    VULNERABLE are Strongly supported (tool-asserted, not exploit-proven); CVE correlation is
    Strongly supported only on an exact version match, else a Candidate requiring validation."""
    if source == "active-check":
        return "Strongly supported"
    if applic == "applicable":
        return "Strongly supported"
    if applic == "not_applicable":
        return "Unsupported/untested"
    return "Candidate CVE (requires validation)"


def correlate(service, advisories):
    """Correlate one service against many candidate advisories. Returns the applicable/candidate
    ones (dropping product mismatches), each annotated with applicability, reason and taxonomy
    classification. High-severity candidates are retained, never hidden."""
    results = []
    for advisory in advisories or []:
        applic, reason = applicability(service, advisory)
        if applic == "not_applicable":
            continue
        results.append(dict(advisory, applicability=applic, applicability_reason=reason,
                            classification=classify(applic, advisory.get("source", "cve-correlation"))))
    return results
