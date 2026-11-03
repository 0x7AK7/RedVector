"""Reviewed native Searchsploit adapter — strict validation, structured JSON parsing, and
accurate A/D/E/R execution-mode labeling. No target or path is hardcoded. These run on any OS:
the native-executed (mode A) and missing-dependency (mode D) paths are exercised by substituting
the runtime/subprocess boundary, so no real searchsploit binary or exploit DB is required. Real
native Kali execution evidence is produced by tests/test_reviewed_searchsploit_live.py."""
import json
import sys
import pytest
import redvector_reviewed_searchsploit as ss

MARKER = ss.SEARCHSPLOIT_MARKER

_SAMPLE = json.dumps({
    "SEARCH": "apache 2.4",
    "DB_PATH": "/opt/exploitdb",
    "RESULTS_EXPLOIT": [
        {"Title": "Apache 2.4.49 - Path Traversal", "EDB-ID": "50383", "Date_Published": "2021-10-05",
         "Type": "webapps", "Platform": "multiple", "Path": "/opt/exploitdb/exploits/multiple/webapps/50383.sh"},
        {"Title": "Apache 2.4.50 - RCE", "EDB-ID": "50406", "Date_Published": "2021-10-07",
         "Type": "webapps", "Platform": "multiple", "Path": "/opt/exploitdb/exploits/multiple/webapps/50406.py"},
    ],
    "RESULTS_SHELLCODE": [],
})


def _ok(params):
    return dict({"additional_args": MARKER}, **params)


# ---- strict validation -> mode R (nothing executed) -------------------------------------------

@pytest.mark.parametrize("params,needle", [
    ({"query": "apache"}, "marker required"),                                    # missing marker
    (_ok({}), "query or CVE is required"),                                       # no query/cve
    (_ok({"query": "apache; rm -rf /"}), "unsupported characters"),             # shell metachars
    (_ok({"query": "`id`"}), "unsupported characters"),                          # backticks
    (_ok({"query": "-m 50383"}), "begin with"),                                  # option-injection
    (_ok({"query": "apache", "mirror": "50383"}), "read-only"),                 # mirror disabled
    (_ok({"query": "apache", "json_output": False}), "structured JSON"),        # json always on
    (_ok({"query": "apache", "exact": "yes"}), "must be a boolean"),            # non-bool flag
    (_ok({"cve": "not-a-cve"}), "CVE must look like"),                           # malformed CVE
    (_ok({"query": "apache", "unknown": 1}), "Unexpected"),                      # extra arg
    (_ok({"query": "apache", "exclude": "dos|evil"}), "Exclude terms"),         # bad exclude char
])
def test_invalid_input_is_rejected_mode_R_without_execution(params, needle, monkeypatch):
    # Guard: even if a binary were present, validation must reject before any execution.
    monkeypatch.setattr(ss, "_runtime", lambda: (_ for _ in ()).throw(AssertionError("must not run")))
    result = ss.run_searchsploit(params)
    assert result["success"] is False
    assert result["execution_mode"] == "R"
    assert result["execution_mode"] != "A"
    assert needle.lower() in result["error"].lower()


def test_valid_cve_is_normalized_and_marker_not_in_argv():
    spec = ss._validate("searchsploit_lookup", _ok({"cve": "2021-44228"}))
    assert spec["cve"] == "CVE-2021-44228"
    command = ss._command("/usr/bin/searchsploit", spec)
    assert command[:3] == ["/usr/bin/searchsploit", "--json", "--disable-colour"]
    assert "--cve" in command and "CVE-2021-44228" in command
    assert MARKER not in command                      # the reserved marker never reaches argv
    assert not any(tok == "-m" or tok.startswith("--mirror") for tok in command)


def test_query_terms_become_separate_argv_tokens_no_shell():
    spec = ss._validate("searchsploit_lookup", _ok({"query": "apache 2.4", "exact": True, "title_only": True}))
    command = ss._command("/usr/bin/searchsploit", spec)
    assert "--exact" in command and "--title" in command
    assert command[-2:] == ["apache", "2.4"]          # terms are argv tokens, not a shell string


# ---- structured JSON parsing ------------------------------------------------------------------

def test_parse_json_extracts_bounded_rows():
    parsed = ss.parse_json(_SAMPLE)
    assert parsed["search"] == "apache 2.4"
    assert len(parsed["results"]) == 2
    assert parsed["results"][0]["edb_id"] == "50383"
    assert parsed["results"][0]["path"].endswith("50383.sh")
    assert parsed["shellcode"] == []


def test_parse_json_tolerates_banner_prefix():
    parsed = ss.parse_json("Exploit Database search\n" + _SAMPLE)
    assert len(parsed["results"]) == 2


def test_parse_json_empty_is_no_results_not_error():
    parsed = ss.parse_json("   ")
    assert parsed["results"] == [] and "Empty" in parsed["note"]


def test_parse_json_unrecognized_raises_unsupported():
    with pytest.raises(ss.SearchsploitError):
        ss.parse_json("this is not json at all")
    with pytest.raises(ss.SearchsploitError):
        ss.parse_json("[1,2,3]")                       # JSON, but not the expected object


# ---- execution-mode labeling (A / D / E) ------------------------------------------------------

def test_mode_A_only_when_native_binary_actually_ran(monkeypatch):
    monkeypatch.setattr(ss, "_runtime", lambda: "/usr/bin/searchsploit")
    monkeypatch.setattr(ss, "_trusted", lambda path: "deadbeef")
    captured = {}
    def fake_execute(command, directory, timeout=ss._DEADLINE):
        captured["command"] = command
        return 0, _SAMPLE, ""
    monkeypatch.setattr(ss, "_execute", fake_execute)
    result = ss.run_searchsploit(_ok({"query": "apache 2.4"}))
    assert result["success"] is True
    assert result["execution_mode"] == "A" and result["execution_mode_detail"] == "native binary executed"
    assert result["results_count"] == 2
    assert result["query"] == "apache 2.4"
    assert result["engine"].startswith("native searchsploit")
    assert captured["command"][0] == "/usr/bin/searchsploit"   # real argv, fixed executable


def test_mode_D_when_binary_missing(monkeypatch):
    monkeypatch.setattr(ss, "_runtime",
                        lambda: (_ for _ in ()).throw(ss.SearchsploitError("Missing Dependency: native searchsploit binary unavailable")))
    result = ss.run_searchsploit(_ok({"query": "apache"}))
    assert result["success"] is False
    assert result["execution_mode"] == "D" and result["execution_mode_detail"] == "missing dependency"
    assert "Missing Dependency" in result["error"]


def test_mode_E_on_integrity_change_never_claims_native(monkeypatch):
    monkeypatch.setattr(ss, "_runtime", lambda: "/usr/bin/searchsploit")
    calls = iter(["before", "after-changed"])
    monkeypatch.setattr(ss, "_trusted", lambda path: next(calls))
    monkeypatch.setattr(ss, "_execute", lambda command, directory, timeout=ss._DEADLINE: (0, _SAMPLE, ""))
    result = ss.run_searchsploit(_ok({"query": "apache"}))
    assert result["success"] is False
    assert result["execution_mode"] == "E"
    assert result["execution_mode"] != "A"


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="Non-Linux host path")
def test_non_linux_host_reports_unsupported():
    result = ss.run_searchsploit(_ok({"query": "apache"}))
    assert result["success"] is False
    assert result["execution_mode"] == "E"
    assert "native Linux" in result["error"]


def test_capabilities_reports_a_single_profile_state():
    caps = ss.capabilities()
    assert set(caps) == {ss.PROFILE}
    assert caps[ss.PROFILE]["state"] in ("Ready", "Missing Dependency", "Unsupported")
