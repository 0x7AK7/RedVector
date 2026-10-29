"""Dynamic tool-discovery / capability compatibility layer. Pure + injectable: a fake runner and a
monkeypatched shutil.which stand in for real Kali, so every path is testable on any OS. No operator
version is a global requirement — compatibility is decided by capability, not exact version."""
import redvector_tool_registry as tr


# ---- version parsing across differing banners -------------------------------------------------

def test_parse_version_per_tool_and_generic_fallback():
    assert tr.parse_version("nmap", b"Nmap version 7.991 ( https://nmap.org )") == "7.991"
    assert tr.parse_version("nmap", "Nmap version 7.95") == "7.95"
    assert tr.parse_version("nuclei", b"v3.11.0") == "3.11.0"
    assert tr.parse_version("nikto", "- Nikto v2.6.0") == "2.6.0"
    assert tr.parse_version("sqlmap", "1.8.3#stable") == "1.8.3"
    assert tr.parse_version("nmap", b"no version") == ""


def test_capabilities_supported_reads_help_flags():
    caps = tr.capabilities_supported("nikto", "Options:\n -Format json\n -Tuning\n -maxtime\n -nointeractive\n")
    assert caps == {"-Format": True, "-Tuning": True, "-maxtime": True, "-nointeractive": True}
    partial = tr.capabilities_supported("nikto", "-Format only")
    assert partial["-Format"] is True and partial["-maxtime"] is False


# ---- discovery with an injected runner (no real binaries) -------------------------------------

def _runner_factory(version_out, help_out):
    def runner(path, args):
        # the version call uses the tool's version_args; everything else is treated as the help call
        return 0, (version_out if args and args[0] in ("--version", "-version", "-Version") else help_out), b""
    return runner


def test_discover_present_tool_reports_version_and_caps(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda name: "/usr/bin/nmap" if name == "nmap" else None)
    runner = _runner_factory(b"Nmap version 7.991", b"-oX -sV -sT --script")
    rec = tr.discover("nmap", runner=runner)
    assert rec["installed"] is True and rec["version"] == "7.991" and rec["source"] == "PATH"
    assert all(rec["capabilities"].values())
    assert tr.status(rec)[0] == "Ready"


def test_discover_missing_tool_is_missing_dependency(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda name: None)
    rec = tr.discover("nikto")
    assert rec["installed"] is False
    state, detail = tr.status(rec)
    assert state == "Missing Dependency" and "never substituted" in detail


def test_installed_but_missing_capability_is_incompatible(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda name: "/usr/bin/nikto" if name == "nikto" else None)
    # old build whose help lacks -Format (changed/absent CLI argument)
    runner = _runner_factory(b"- Nikto v2.1.5", b"-Tuning -maxtime -nointeractive")
    rec = tr.discover("nikto", runner=runner)
    state, detail = tr.status(rec)
    assert state == "Incompatible" and "-Format" in detail and "2.1.5" in detail


def test_capability_present_but_version_undetected_is_still_ready(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda name: "/usr/bin/nuclei" if name == "nuclei" else None)
    runner = _runner_factory(b"banner with no version", b"-u -t -jsonl")
    rec = tr.discover("nuclei", runner=runner)
    assert rec["version"] == ""
    assert tr.status(rec)[0] == "Ready"          # capability, not version, decides usability


def test_openvas_multiple_candidate_names(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda name: "/usr/bin/gvm-cli" if name == "gvm-cli" else None)
    rec = tr.discover("openvas", runner=_runner_factory(b"gvm-cli 23.1.0", b""))
    assert rec["installed"] is True and rec["path"] == "/usr/bin/gvm-cli"


def test_unknown_tool_is_reported_not_crash():
    rec = tr.discover("definitely-not-a-tool")
    assert rec["installed"] is False and rec["error"] == "unknown tool"


def test_engine_report_covers_all_tools(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda name: None)  # nothing installed
    report = tr.engine_report()
    assert set(report) == set(tr.TOOLS)
    assert all(v["state"] == "Missing Dependency" for v in report.values())
