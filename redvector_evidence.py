"""Unified vulnerability-evidence schema and cross-engine deduplication (pure, no execution).

Produces the per-finding evidence record required by the Kali-first spec (§7) and merges findings
from multiple engines (Nmap -sV, Nmap NSE, native Nikto, Nuclei, Searchsploit, NVD) without
duplicates. Dedup is by the real-world defect: the same CVE on the same host/port collapses to one
record even when several tools report it, keeping the strongest classification, the highest CVSS
and the union of sources/references. Confirmed counts are never inflated: classification is carried
verbatim from the contributing evidence, never upgraded by merging.
"""
from redvector_cve_correlation import CLASSIFICATION_ORDER

# §7 evidence fields; every record carries all of them (empty when a source does not provide one).
# cvss_severity is the PROVIDER severity label, kept deliberately separate from `confidence`,
# `applicability` and `classification` (evidence confidence / validation status) so a high-CVSS
# candidate is never presented as an established risk.
FIELDS = ("target", "service", "port", "protocol", "product", "version", "cve", "cvss",
          "cvss_severity", "cvss_source", "tool", "tool_version", "verification_method",
          "execution_status", "evidence_ref", "confidence", "applicability", "classification",
          "validation", "source", "title", "references", "remediation")


def evidence(**values):
    """Build one normalized evidence record with every §7 field present (defaults for the rest)."""
    record = {field: "" for field in FIELDS}
    record["references"] = []
    record["classification"] = "Informational"
    record["execution_status"] = "completed"
    record["applicability"] = "candidate"
    for key, value in values.items():
        if key in record:
            record[key] = value
    if not isinstance(record["references"], list):
        record["references"] = [record["references"]] if record["references"] else []
    return record


def _rank(classification):
    return CLASSIFICATION_ORDER.index(classification) if classification in CLASSIFICATION_ORDER else len(CLASSIFICATION_ORDER)


def _cvss(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return -1.0


def _key(record):
    """Dedup identity: the same CVE on the same host/port/proto is one defect regardless of how
    many tools found it; without a CVE, dedup within a tool by its port + signature/title."""
    base = (str(record.get("target", "")), str(record.get("port", "")), str(record.get("protocol", "")))
    cve = str(record.get("cve", "")).strip().upper()
    if cve:
        return base + (cve,)
    return base + (str(record.get("tool", "")), str(record.get("evidence_ref", "") or record.get("service", "")))


def merge(records):
    """Deduplicate evidence across engines. For each defect identity keep the strongest
    classification, the highest reported CVSS (and its source), and the union of tools/references;
    the surviving record is the strongest-classified contributor, enriched with merged sources."""
    merged = {}
    for raw in records:
        record = evidence(**{k: v for k, v in raw.items() if k in FIELDS})
        key = _key(record)
        if key not in merged:
            record["tools"] = sorted({record["tool"]}) if record["tool"] else []
            merged[key] = record
            continue
        current = merged[key]
        # union of references and contributing tools
        refs = list(dict.fromkeys(list(current.get("references", [])) + list(record.get("references", []))))
        tools = sorted(set(current.get("tools", [])) | ({record["tool"]} if record["tool"] else set()))
        # keep the higher CVSS and its source
        if _cvss(record["cvss"]) > _cvss(current["cvss"]):
            current["cvss"], current["cvss_source"] = record["cvss"], record["cvss_source"]
        # the stronger classification wins the surviving record's identity fields
        if _rank(record["classification"]) < _rank(current["classification"]):
            keep_cvss, keep_source, keep_refs = current["cvss"], current["cvss_source"], refs
            current = evidence(**{k: v for k, v in record.items() if k in FIELDS})
            current["cvss"], current["cvss_source"] = keep_cvss, keep_source
            refs = keep_refs
        current["references"] = refs
        current["tools"] = tools
        merged[key] = current
    ordered = sorted(merged.values(), key=lambda r: (_rank(r["classification"]), -_cvss(r["cvss"])))
    return ordered


def summarize(records):
    """Classification counts plus confirmed/candidate tallies for a report header. Confirmed counts
    only records explicitly classified Confirmed — never inferred from merging or severity."""
    counts = {name: 0 for name in CLASSIFICATION_ORDER}
    for record in records:
        counts[record.get("classification", "Informational")] = counts.get(record.get("classification", "Informational"), 0) + 1
    return {"classification_counts": counts,
            "confirmed": counts.get("Validated Vulnerability", 0) + counts.get("Demonstrated Impact", 0),
            "scanner_detected": counts.get("Scanner-Detected Vulnerability", 0),
            "candidate_cves": counts.get("Candidate CVE", 0),
            "total": len(records)}
