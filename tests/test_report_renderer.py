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
         "classification": "Candidate CVE (requires validation)", "provider_severity": "HIGH", "cvss": "7.7",
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
    s = report["summary"]
    assert s["open_ports"] == 3 and s["services"] == 2
    assert s["confirmed"] == 0                      # a candidate is never counted confirmed
    assert s["candidates"] == 1
    assert s["native_tools"] == 2                   # nikto did not execute -> not counted


def test_render_is_compact_with_no_flattened_internal_keys():
    term = Terminal(io.StringIO())
    rr.render_report(term, rr.build_report(_RESULT), width=100)
    out = term.stream.getvalue()
    assert "REDVECTOR AI — SECURITY ASSESSMENT" in out
    for heading in ("SUMMARY", "SERVICES", "SECURITY FINDINGS", "EXECUTION EVIDENCE", "NEXT STEPS"):
        assert heading in out
    assert "result.findings[" not in out and "audit_trail[" not in out and ".classification" not in out
    assert "nginx" in out and "CVE-2021-23017" in out
    assert "native nikto" in out and "False" in out        # honest native-executed? column


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
    out = term.stream.getvalue()
    assert "No confirmed vulnerabilities" in out and "service identification is not a vulnerability" in out


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
