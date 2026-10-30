"""Inc B: professional SECURITY ASSESSMENT report. Compact by default, aligned tables, colors by
evidence confidence, width/NO_COLOR/non-TTY safe, and never a flattened internal-key dump. No target
or version is hardcoded (fixtures only)."""
import io
import pytest
from redvector_ollama_setup import Terminal
import redvector_report as rr


class TTY(io.StringIO):
    def isatty(self):
        return True


_RESULT = {
    "target": "198.51.100.10", "success": True, "execution_time": 12.5,
    "open_ports": ["22", "80", "443"],
    "services": [
        {"port": "80", "protocol": "tcp", "service": "http", "product": "nginx", "version": "1.18.0", "confidence": "identified"},
        {"port": "22", "protocol": "tcp", "service": "ssh", "product": "", "version": "", "confidence": "inconclusive"},
    ],
    "findings": [
        {"cve": "CVE-2021-23017", "title": "nginx resolver off-by-one", "host": "198.51.100.10", "port": "80",
         "classification": "Candidate CVE", "provider_severity": "HIGH", "cvss": "7.7",
         "validation": "candidate", "source": "nvd"},
    ],
    "execution": [
        {"engine": "native nmap -sT discovery", "native_executed": True, "status": "ok", "duration": 8.0, "evidence": "ev1"},
        {"engine": "native nmap -sV", "native_executed": True, "status": "ok", "duration": 4.0, "evidence": "ev2"},
        {"engine": "native nikto", "native_executed": False, "status": "unavailable", "duration": "", "evidence": ""},
    ],
}


def test_build_report_counts_are_evidence_based_not_inflated():
    report = rr.build_report(_RESULT)
    c = report["counts"]
    assert report["coverage"]["open"] == 3 and len(report["services"]) == 2
    assert c["Validated Vulnerability"] == 0 and c["Demonstrated Impact"] == 0   # a candidate is never confirmed
    assert c["Scanner-Detected Vulnerability"] == 0
    assert c["Candidate CVE"] == 1
    assert report["native_tools"] == 2                       # nikto did not execute -> not counted
    assert report["unavailable"] == ["native nikto"]         # the failed stage is reported, not hidden


def test_legacy_labels_never_upgrade_evidence():
    assert rr.normalize_class("Candidate CVE (requires validation)", "CVE-1") == "Candidate CVE"
    assert rr.normalize_class("Strongly supported", "CVE-1") == "Candidate CVE"    # version match is still a candidate
    assert rr.normalize_class("Strongly supported", "") == "Observed Exposure"
    assert rr.normalize_class("Unsupported/untested") == "Informational"


def test_render_is_compact_with_no_flattened_internal_keys():
    term = Terminal(io.StringIO())
    rr.render_report(term, rr.build_report(_RESULT), width=100)
    out = term.stream.getvalue()
    assert "REDVECTOR AI — SECURITY ASSESSMENT" in out
    for heading in ("DISCOVERY", "NATIVE TOOL EXECUTION", "DISCOVERED SERVICES", "VULNERABILITIES", "NEXT STEPS"):
        assert heading in out
    for label in ("Profile", "Coverage", "Ports requested", "Ports completed", "Open ports", "ACTUAL BINARY"):
        assert label in out
    assert "result.findings[" not in out and "audit_trail[" not in out and ".classification" not in out
    assert "{" not in out                                    # no raw JSON
    assert "nginx" in out and "CVE-2021-23017" in out
    assert "native nikto" in out and "not executed (internal engine)" in out   # honest engine identity


def test_findings_colored_by_confidence_not_only_cvss(monkeypatch):
    monkeypatch.setenv("TERM", "xterm-256color"); monkeypatch.delenv("NO_COLOR", raising=False)
    term = Terminal(TTY())
    rr.render_report(term, rr.build_report(_RESULT), width=120)
    out = term.stream.getvalue()
    # a HIGH-CVSS *candidate* is rendered with the candidate (medium/yellow) confidence color,
    # not the orange high-severity color — confidence drives the color, not the CVSS label.
    assert "33m" in out                                   # medium/yellow present for the candidate row
    assert "\x1b" in out                                   # colored on a TTY


def test_status_partial_when_not_success():
    report = rr.build_report(dict(_RESULT, success=False))
    assert report["status"] == "Partial"
    term = Terminal(io.StringIO())
    rr.render_report(term, report, width=100)
    assert "Status: Partial" in term.stream.getvalue()


def test_no_findings_states_not_a_vulnerability():
    term = Terminal(io.StringIO())
    rr.render_report(term, rr.build_report(dict(_RESULT, findings=[])), width=100)
    out = " ".join(term.stream.getvalue().split())          # sentences may wrap across lines
    assert "No vulnerabilities validated or detected" in out
    assert "not proof the target is free of vulnerabilities" in out
    assert "detection coverage is incomplete" in out         # nikto did not run -> incompleteness stated
    assert "Validated 0" in out and "Candidate CVEs 0" in out


@pytest.mark.parametrize("width", [40, 60, 80, 120])
def test_width_safe_and_no_ansi_in_non_tty(width):
    term = Terminal(io.StringIO())
    rr.render_report(term, rr.build_report(_RESULT), width=width)
    out = term.stream.getvalue()
    assert "\x1b" not in out                               # non-TTY: never leak ANSI
    assert all(len(line) <= width for line in out.splitlines())


def test_no_color_env_disables_ansi(monkeypatch):
    monkeypatch.setenv("TERM", "xterm-256color"); monkeypatch.setenv("NO_COLOR", "1")
    term = Terminal(TTY())
    rr.render_report(term, rr.build_report(_RESULT), width=100)
    assert "\x1b" not in term.stream.getvalue()
