"""Reviewed native Nikto adapter — strict URL validation, non-destructive argv, JSON parsing and
honest A/D/E/R execution-mode labeling. No target is hardcoded; the mode-A path is exercised by
substituting the runtime/subprocess boundary, so no real nikto binary is required on this host.
Real native Kali execution evidence is produced by tests/test_reviewed_nikto_live.py."""
import json
import sys
from pathlib import Path
import pytest
import redvector_reviewed_nikto as nk

MARKER = nk.NIKTO_MARKER

_SAMPLE = json.dumps({
    "host": "127.0.0.1", "ip": "127.0.0.1", "port": "80",
    "vulnerabilities": [
        {"id": "999957", "method": "GET", "url": "/", "msg": "Missing X-Frame-Options header"},
        {"id": "999103", "method": "GET", "url": "/icons/", "msg": "Directory indexing found"},
    ],
})


def _ok(url="http://127.0.0.1:80/"):
    return {"target": url, "additional_args": MARKER}


@pytest.mark.parametrize("params,needle", [
    ({"target": "http://127.0.0.1/"}, "marker required"),                       # missing marker
    (_ok("https://127.0.0.1/admin"), "without credentials"),                    # path present
    (_ok("http://127.0.0.1/?q=1"), "without credentials"),                      # query present
    (_ok("http://user:pw@127.0.0.1/"), "without credentials"),                  # credentials
    (_ok("ftp://127.0.0.1/"), "root HTTP"),                                      # bad scheme
    (_ok("http://example.com/"), "numeric pinned host"),                        # not numeric (policy pins)
    ({"target": "http://127.0.0.1/", "additional_args": MARKER, "x": 1}, "Unexpected"),
])
def test_invalid_input_is_rejected_mode_R(params, needle, monkeypatch):
    monkeypatch.setattr(nk, "_runtime", lambda: (_ for _ in ()).throw(AssertionError("must not run")))
    result = nk.run_nikto(params)
    assert result["success"] is False
    assert result["execution_mode"] == "R" and result["execution_mode"] != "A"
    assert needle.lower() in result["error"].lower()


def test_command_is_non_destructive_fixed_argv():
    spec = nk._validate("nikto_scan", _ok("https://127.0.0.1:8443/"))
    assert spec == {"host": "127.0.0.1", "port": "8443", "ssl": True, "version": 4}
    cmd = nk._command("/usr/bin/nikto", spec, "/tmp/out.json")
    assert cmd[0] == "/usr/bin/nikto" and "-h" in cmd and "127.0.0.1" in cmd
    assert "-nointeractive" in cmd and "-ssl" in cmd
    assert cmd[cmd.index("-Tuning") + 1] == "123b"      # DoS/cmd-exec/injection/SQLi/upload excluded
    assert MARKER not in cmd                             # reserved marker never reaches argv


def test_default_ports_follow_scheme():
    assert nk._validate("nikto_scan", _ok("http://127.0.0.1/"))["port"] == "80"
    assert nk._validate("nikto_scan", _ok("https://127.0.0.1/"))["port"] == "443"


def test_parse_json_object_and_list_forms():
    parsed = nk.parse_json(_SAMPLE)
    assert parsed["host"] == "127.0.0.1" and parsed["port"] == "80"
    assert len(parsed["findings"]) == 2 and parsed["findings"][0]["id"] == "999957"
    parsed_list = nk.parse_json("[" + _SAMPLE + "]")
    assert len(parsed_list["findings"]) == 2


def test_parse_json_empty_is_no_findings():
    assert nk.parse_json("  ")["findings"] == []


def test_parse_json_unrecognized_raises():
    with pytest.raises(nk.NiktoError):
        nk.parse_json("not json")


def test_mode_A_only_when_native_ran(monkeypatch, tmp_path):
    monkeypatch.setattr(nk, "_runtime", lambda: "/usr/bin/nikto")
    monkeypatch.setattr(nk, "_trusted", lambda path: "cafef00d")
    captured = {}

    def fake_execute(command, directory, timeout=nk._DEADLINE):
        captured["command"] = command
        (Path(directory) / "nikto.json").write_text(_SAMPLE, encoding="utf-8")
        return 0, "", ""
    monkeypatch.setattr(nk, "_execute", fake_execute)
    result = nk.run_nikto(_ok("http://127.0.0.1:80/"))
    assert result["success"] is True
    assert result["execution_mode"] == "A" and result["execution_mode_detail"] == "native binary executed"
    assert result["findings_count"] == 2
    assert result["engine"].startswith("native nikto")
    assert captured["command"][0] == "/usr/bin/nikto"


def test_mode_D_when_binary_missing(monkeypatch):
    monkeypatch.setattr(nk, "_runtime",
                        lambda: (_ for _ in ()).throw(nk.NiktoError("Missing Dependency: native nikto binary unavailable")))
    result = nk.run_nikto(_ok())
    assert result["success"] is False and result["execution_mode"] == "D"
    assert "Missing Dependency" in result["error"]


def test_mode_E_on_integrity_change(monkeypatch):
    monkeypatch.setattr(nk, "_runtime", lambda: "/usr/bin/nikto")
    seq = iter(["before", "after-changed"])
    monkeypatch.setattr(nk, "_trusted", lambda path: next(seq))
    monkeypatch.setattr(nk, "_execute", lambda command, directory, timeout=nk._DEADLINE: (0, _SAMPLE, ""))
    result = nk.run_nikto(_ok())
    assert result["success"] is False and result["execution_mode"] == "E" and result["execution_mode"] != "A"


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="Non-Linux host path")
def test_non_linux_reports_unsupported():
    result = nk.run_nikto(_ok())
    assert result["success"] is False and result["execution_mode"] == "E"
    assert "native Linux" in result["error"]


def test_capabilities_single_profile():
    caps = nk.capabilities()
    assert set(caps) == {nk.PROFILE}
    assert caps[nk.PROFILE]["state"] in ("Ready", "Missing Dependency", "Unsupported")
