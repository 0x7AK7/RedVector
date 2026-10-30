"""Deterministic CPE / product-version to CVE applicability logic (no network, no execution).

Correlates a discovered service (its nmap -sV product/version and any CPE evidence) against a
candidate advisory (its CPE list and/or affected product/versions). It decides *applicability*
conservatively and never asserts exploitability:

  * ``applicable``      — product matches AND the discovered version is in the advisory's affected
                          set (still a Candidate CVE: version-matched, not validated).
  * ``candidate``       — product matches but version applicability is not established
                          (a Candidate CVE: product match only).
  * ``not_applicable``  — product does not match (the advisory is dropped for this service).

Finding classes (strongest first) are shared by every report: Demonstrated Impact, Validated
Vulnerability, Scanner-Detected Vulnerability, Candidate CVE, Observed Exposure, Informational.
Installed software is never confused with confirmed exploitability; correlation alone never yields a
validated vulnerability; a high-severity candidate is always kept visible. Pure and unit-testable.
"""
import re

# Finding taxonomy shared by the client report, the backend orchestrator and the evidence merge;
# order is strongest-first. Only real validation/impact evidence may use the first two classes.
CLASSIFICATION_ORDER = ["Demonstrated Impact", "Validated Vulnerability", "Scanner-Detected Vulnerability",
                        "Candidate CVE", "Observed Exposure", "Informational"]
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
    """Map (applicability, evidence source) to the shared taxonomy. A verified native scanner that
    reports a detection is a Scanner-Detected Vulnerability (tool-asserted, not exploit-proven); CVE
    correlation — even an exact version match — is only a Candidate CVE requiring validation."""
    if source == "active-check":
        return "Scanner-Detected Vulnerability"
    if applic == "not_applicable":
        return "Informational"
    return "Candidate CVE"


def validation_label(applic):
    """Human-readable validation status for a correlated CVE (never 'confirmed')."""
    return {"applicable": "version-matched; not validated", "candidate": "product match only; not validated"}.get(
        applic, "not applicable")


def description_applicability(product, version, cpes, description):
    """Applicability of a provider advisory to a service from the advisory's own text and the
    service's exact product/version/CPE. The exact product (or its CPE product) must appear — a broad
    vendor word such as 'Apache' alone is not enough. 'applicable' only when the version also appears;
    product present without version -> 'candidate'; product absent -> 'not_applicable' (dropped)."""
    text = (description or "").lower()
    names = set()
    product_l = (product or "").strip().lower()
    if product_l:
        names.add(product_l)
    for cpe in cpes or []:
        parsed = parse_cpe(cpe)
        if parsed and parsed["product"]:
            names.add(parsed["product"])
            names.add(parsed["product"].replace("_", " "))
    names = {n for n in names if n and len(n) >= 3}
    if not names or not any(n in text for n in names):
        return "not_applicable"
    version_l = (version or "").strip().lower()
    if version_l and version_l in text:
        return "applicable"
    return "candidate"


_CVE_ID = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}", re.I)


def exploit_reference_applicability(product, version, title):
    """Applicability of an offline exploit-database reference (e.g. Searchsploit) to a service. The
    exact product must appear in the reference title; 'applicable' when the version also appears.
    A reference is never proof that the host is vulnerable."""
    return description_applicability(product, version, [], title)


def cve_ids(text):
    """CVE identifiers mentioned in free text (upper-cased, de-duplicated, ordered)."""
    return sorted({m.upper() for m in _CVE_ID.findall(text or "")})


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
