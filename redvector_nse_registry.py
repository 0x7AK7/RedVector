"""Dynamic Nmap NSE 'vuln' script discovery and risk classification (pure; no execution, no network).

RedVector discovers the NSE vulnerability scripts actually installed on the native Kali runtime by
parsing ``nmap --script-help vuln`` (ALL scripts in the ``vuln`` category, not only ``safe`` ones) and
classifies each by its real NSE categories into an execution-risk tier. Discovery and classification
are read-only and NEVER authorize execution: only the default-eligible tier is run by the default
detection workflow, and even then only after the normal profile attestation, target authorization and
per-script integrity checks in redvector_reviewed_profiles.

Risk tiers (classification is by actual categories + a small reviewed name override, never by the
``safe`` tag alone — ``safe`` is explicitly NOT treated as a guarantee of harmless execution):

  * ``A`` — Low-impact detection: ``vuln`` AND ``safe`` with NONE of the sensitive categories below.
            Read-only / low-impact checks suitable for an explicitly authorized non-destructive
            assessment. These are the ONLY scripts the default nse-vuln-v1 workflow runs.
  * ``B`` — Active vulnerability testing: ``vuln`` without ``safe`` (more extensive / sensitive
            probing). Requires a separately reviewed execution profile and explicit approval; NOT run
            by the default workflow.
  * ``C`` — Intrusive / potentially disruptive: ``intrusive``/``dos``/``exploit``/``brute``/
            ``fuzzer``/``malware`` (may modify data, disrupt services or attack auth). Discovered and
            reported, but NEVER executed by the default workflow.
  * ``D`` — External advisory lookups: ``external`` (e.g. ``vulners``) — contact third-party services.
            Disclosed; require explicit operator approval before any service data leaves the host.
  * ``U`` — Unknown / unclassifiable: never eligible for execution until reviewed.
"""
import re

# Categories that make a script intrusive / potentially disruptive (tier C) — never auto-run.
_C_CATS = frozenset({"intrusive", "dos", "exploit", "brute", "fuzzer", "malware"})
# Categories that mark external/third-party contact (tier D).
_D_CATS = frozenset({"external"})
# Any of these present disqualifies a script from the low-impact tier A, even with a 'safe' tag.
_NOT_A = _C_CATS | _D_CATS | frozenset({"auth", "broadcast"})
# Reviewed name-based overrides: force a script to a stricter tier regardless of its advertised tags
# (behavioural review can override metadata; 'safe' is not a guarantee). Kept conservative/minimal.
_FORCE_RISKY = frozenset()          # e.g. a script known disruptive despite a 'safe' tag
_FORCE_EXTERNAL = frozenset({"vulners", "http-virustotal"})

_CATS_RE = re.compile(r"Categories:\s*(.+)", re.IGNORECASE)
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$", re.IGNORECASE)


def classify(name, categories):
    """Return (tier, reason) for a script from its name and NSE categories. Order is strictly
    most-restrictive-first so a script that is both intrusive and external is tier C, and an
    external-but-otherwise-safe script (vulners) is tier D, never tier A."""
    cats = {str(c).strip().lower() for c in (categories or []) if str(c).strip()}
    name_l = str(name or "").strip().lower()
    if name_l in _FORCE_RISKY or (cats & _C_CATS):
        return "C", "intrusive/disruptive category or reviewed-risky name"
    if name_l in _FORCE_EXTERNAL or (cats & _D_CATS):
        return "D", "contacts external/third-party services"
    if "vuln" in cats and "safe" in cats and not (cats & _NOT_A):
        return "A", "vuln+safe with no sensitive category: read-only/low-impact detection"
    if "vuln" in cats:
        return "B", "vuln without safe: more extensive/sensitive probing"
    return "U", "not a recognized vuln-category script"


def parse(text):
    """Parse ``nmap --script-help vuln`` output into classified records. The script name is the line
    immediately preceding its ``Categories:`` line (Nmap's stable --script-help layout). Returns a
    list of {script, categories, risk, reason}. Pure: no side effects."""
    lines = str(text or "").splitlines()
    records = []
    seen = set()
    for index, line in enumerate(lines):
        match = _CATS_RE.match(line.strip())
        if not match or index == 0:
            continue
        name = lines[index - 1].strip()
        if not name or not _NAME_RE.match(name) or name in seen:
            continue
        categories = sorted(c.strip().lower() for c in match.group(1).split() if c.strip())
        risk, reason = classify(name, categories)
        records.append({"script": name, "categories": categories, "risk": risk, "reason": reason})
        seen.add(name)
    return records


def eligible(records, limit=64):
    """The default-executable script names: tier A only, sorted and bounded. These are the ONLY
    scripts the default nse-vuln-v1 workflow may run (still subject to per-script integrity checks
    and attestation downstream)."""
    names = sorted({r["script"] for r in records if r.get("risk") == "A"})
    return names[:max(0, int(limit))]


def summary(records):
    """Per-tier counts and the tier-A names, for honest capability/inventory reporting."""
    counts = {tier: 0 for tier in ("A", "B", "C", "D", "U")}
    for record in records:
        counts[record.get("risk", "U")] = counts.get(record.get("risk", "U"), 0) + 1
    return {"total": len(records), "counts": counts, "category_a": eligible(records),
            "category_b": sorted(r["script"] for r in records if r.get("risk") == "B"),
            "category_c": sorted(r["script"] for r in records if r.get("risk") == "C"),
            "category_d": sorted(r["script"] for r in records if r.get("risk") == "D")}
