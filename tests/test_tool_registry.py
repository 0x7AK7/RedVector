"""Dynamic tool-discovery / capability compatibility layer, repaired against REAL VMware Kali output
formats. Pure + injectable: fake runners and a monkeypatched shutil.which stand in for Kali, so every
path is testable on any OS. No operator version is a global requirement; capability — not version —
decides usability, and presence never implies execution readiness."""
import redvector_tool_registry as tr

# Real abbreviated `nmap -h`: scan types are grouped as "-sS/sT/sA" (dash dropped on later flags),
# which defeats naive literal matching of "-sT".
NMAP_HELP = (
    "Nmap 7.991 ( https://nmap.org )\n"
    "SCAN TECHNIQUES:\n  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans\n  -sU: UDP Scan\n"
    "SERVICE/VERSION DETECTION:\n  -sV: Probe open ports to determine service/version info\n"
    "SCRIPT SCAN:\n  --script=<Lua scripts>: comma separated list of directories/files\n"
    "OUTPUT:\n  -oN/-oX/-oS/-oG <file>: Output scan in Normal, XML, s|<rIpt, and Grepable format\n")
# Real WPScan help documents the toggle as "--[no-]update".
WPSCAN_HELP = ("--url URL  The URL of the blog to scan\n--format FORMAT  Output format\n"
               "--[no-]update  Whether or not to update the Database\n")


def _runner(version=b"", help=b"", probe=(0, b"", b"")):
    def run(path, args):
        if args and args[0] in ("--version", "-version", "-Version"):
            return 0, version, b""
        if args and args[0] in ("-h", "-hh", "-Help", "--help"):
            return 0, help, b""
        return probe
    return run


def _dpkg(mapping):
    def query(package):
        return (0, mapping[package].encode(), b"") if package in mapping else (1, b"", b"no packages found")
    return query


# ---- notation-aware flag matching (the nmap false-negative + WPScan --[no-]update) -------------

def test_match_flag_handles_nmap_grouped_scan_types():
    assert tr.match_flag("-sT", NMAP_HELP) is True        # appears only as "/sT" in "-sS/sT/sA"
    assert tr.match_flag("-sV", NMAP_HELP) is True
    assert tr.match_flag("-oX", NMAP_HELP) is True
    assert tr.match_flag("--script", NMAP_HELP) is True
    assert tr.match_flag("-sZ", NMAP_HELP) is False       # genuinely absent


def test_match_flag_recognizes_no_update_notation():
    assert tr.match_flag("--no-update", WPSCAN_HELP) is True
    assert tr.match_flag("--update", WPSCAN_HELP) is True
    assert tr.match_flag("--url", WPSCAN_HELP) is True
    assert tr.match_flag("--no-banner", WPSCAN_HELP) is False


# ---- version parsing across real banners ------------------------------------------------------

def test_parse_version_real_banners():
    assert tr.parse_version("nmap", b"Nmap version 7.991 ( https://nmap.org )") == "7.991"
    assert tr.parse_version("nikto", "- Nikto v2.6.0") == "2.6.0"
    assert tr.parse_version("nuclei", b"Nuclei Engine Version: v3.11.0") == "3.11.0"


# ---- nmap discovery now succeeds via notation-aware help --------------------------------------

def test_nmap_capabilities_detected_from_grouped_help(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda n: "/usr/bin/nmap" if n == "nmap" else None)
    rec = tr.discover("nmap", runner=_runner(version=b"Nmap version 7.991", help=NMAP_HELP.encode()),
                      dpkg_runner=_dpkg({}))
    assert rec["installed"] and rec["version"] == "7.991"
    assert all(rec["capabilities"].values())              # the former -sT false-negative is fixed
    assert tr.status(rec)[0] == "Installed"               # capability ok, execution not yet verified
    assert rec["execution_ready"] is False


def test_nmap_probe_fallback_confirms_flag_absent_from_help(monkeypatch):
    # help text omits -sT entirely; the side-effect-aware probe (no target) confirms it is accepted.
    monkeypatch.setattr(tr.shutil, "which", lambda n: "/usr/bin/nmap" if n == "nmap" else None)
    thin_help = b"OUTPUT:\n  -oX <file>\nSCRIPT:\n  --script=<...>\nVERSION:\n  -sV\n"
    probe = (0, b"", b"WARNING: No targets were specified, so 0 hosts scanned.")
    rec = tr.discover("nmap", runner=_runner(version=b"Nmap version 7.95", help=thin_help, probe=probe),
                      dpkg_runner=_dpkg({}))
    assert rec["capabilities"]["-sT"] is True             # recovered by the probe, not by help
    assert rec["capability_supported"] is True


def test_interpret_option_probe_distinguishes_recognized_from_unknown():
    assert tr.interpret_option_probe("-sT", 0, b"", b"WARNING: No targets were specified") is True
    assert tr.interpret_option_probe("-zz", 1, b"", b"nmap: unrecognized option '-zz'") is False
    assert tr.interpret_option_probe("--script", 1, b"", b"'redvector-nonexistent-sentinel' did not match any script") is True


# ---- searchsploit dpkg version fallback -------------------------------------------------------

def test_searchsploit_version_from_dpkg_fallback(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda n: "/usr/bin/searchsploit" if n == "searchsploit" else None)
    rec = tr.discover("searchsploit", runner=_runner(help=b"--json  Output results in JSON"),
                      dpkg_runner=_dpkg({"exploitdb": "20260709-0kali1"}))
    assert rec["version"] == "20260709-0kali1" and rec["version_source"] == "dpkg:exploitdb"
    assert rec["capabilities"]["--json"] is True and tr.status(rec)[0] == "Installed"


# ---- GVM modeled as separate components; scanner not ready from presence ----------------------

def test_gvm_components_modeled_separately(monkeypatch):
    present = {"gvmd": "/usr/sbin/gvmd", "openvas": "/usr/sbin/openvas", "ospd-openvas": "/usr/bin/ospd-openvas"}
    monkeypatch.setattr(tr.shutil, "which", lambda n: present.get(n))   # gvm-cli -> None
    report = tr.gvm_report(runner=_runner(version=b"gvmd 23.0.1"), dpkg_runner=_dpkg({}))
    comps = report["components"]
    assert comps["gvm-manager"]["installed"] and comps["gvm-scanner"]["installed"] and comps["gvm-ospd"]["installed"]
    assert comps["gvm-client"]["state"] == "Optional — Not Installed"
    assert report["execution_ready"] is False                          # never from presence
    assert "not execution-ready" in comps["gvm-scanner"]["detail"].lower() or "not implied by presence" in comps["gvm-scanner"]["detail"].lower()


# ---- missing / incompatible -------------------------------------------------------------------

def test_missing_tool_is_missing_dependency(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda n: None)
    state, detail = tr.status(tr.discover("nikto", runner=_runner(), dpkg_runner=_dpkg({})))
    assert state == "Missing Dependency" and "never substituted" in detail


def test_incompatible_when_required_capability_absent(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda n: "/usr/bin/nikto" if n == "nikto" else None)
    rec = tr.discover("nikto", runner=_runner(version=b"- Nikto v2.1.0", help=b"-Tuning -maxtime -nointeractive"),
                      dpkg_runner=_dpkg({}))
    state, detail = tr.status(rec)
    assert state == "Incompatible" and "-Format" in detail and "2.1.0" in detail


# ---- four-state model + detected version is only an observation -------------------------------

def test_engine_report_exposes_four_states(monkeypatch):
    monkeypatch.setattr(tr.shutil, "which", lambda n: None)
    report = tr.engine_report(dpkg_runner=_dpkg({}))
    assert set(report) == set(tr.TOOLS)
    for entry in report.values():
        assert set(entry["states"]) == {"installed", "capability_supported", "integrity_verified", "execution_ready"}
        assert entry["states"]["execution_ready"] is False   # discovery never asserts execution readiness
