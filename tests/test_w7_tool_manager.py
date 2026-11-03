"""W7-A: Unified native-tool status layer (redvector_tool_manager).

Tests that:
  - discover_tools() returns the expected structure on any platform
  - unavailability_reason() maps adapter states to precise human-readable explanations
  - status taxonomy: Ready / Missing Dependency / Unsupported / Disabled / Restricted
  - install_hint is present and actionable for every tool
  - the four known profiles (tcp-discovery-v1, http-headers-v1, nikto-native-v1,
    searchsploit-v1) are covered
  - on Windows the tool manager does not crash and returns non-Ready states for Linux-only tools
  - discover_tools() is idempotent and pure (no side effects)
"""
import unittest
from unittest.mock import patch
import redvector_tool_manager as tm


# Synthetic capabilities() returns for unit-testing unavailability_reason() in isolation.
def _tool_status(overrides):
    """Build a minimal tool_status dict with given per-profile state/detail overrides."""
    base = {
        "nmap":        {"display": "native Nmap",              "execution_class": "detection",  "install_hint": "sudo apt-get install nmap",       "profiles": {}},
        "nuclei":      {"display": "native Nuclei",            "execution_class": "web-scan",   "install_hint": "python3 tools/install_reviewed_nuclei.py  (reviewed build required)", "profiles": {}},
        "nikto":       {"display": "native Nikto",             "execution_class": "web-scan",   "install_hint": "sudo apt-get install nikto",       "profiles": {}},
        "searchsploit":{"display": "native Searchsploit",      "execution_class": "exploit-db", "install_hint": "sudo apt-get install exploitdb",   "profiles": {}},
    }
    for profile_id, info in overrides.items():
        for spec in tm._TOOLS:
            if profile_id in spec["profiles"]:
                base[spec["name"]]["profiles"][profile_id] = info
                break
    return base


class DiscoverToolsStructure(unittest.TestCase):

    def test_returns_all_four_tools(self):
        result = tm.discover_tools()
        assert set(result.keys()) == {"nmap", "nuclei", "nikto", "searchsploit"}

    def test_each_entry_has_required_fields(self):
        result = tm.discover_tools()
        for name, entry in result.items():
            assert "display" in entry, name
            assert "execution_class" in entry, name
            assert "install_hint" in entry, name
            assert "profiles" in entry and isinstance(entry["profiles"], dict), name

    def test_install_hints_are_non_empty(self):
        result = tm.discover_tools()
        for name, entry in result.items():
            assert entry["install_hint"], "empty install_hint for {}".format(name)

    def test_known_profiles_present(self):
        result = tm.discover_tools()
        assert "tcp-discovery-v1" in result["nmap"]["profiles"]
        assert "service-version-v1" in result["nmap"]["profiles"]
        assert "nse-vuln-v1" in result["nmap"]["profiles"]
        assert "--redvector-profile=http-headers-v1" in result["nuclei"]["profiles"]
        assert "nikto-native-v1" in result["nikto"]["profiles"]
        assert "searchsploit-v1" in result["searchsploit"]["profiles"]

    def test_each_profile_has_state_and_detail(self):
        result = tm.discover_tools()
        for name, entry in result.items():
            for pid, info in entry["profiles"].items():
                assert "state" in info, "missing state for {} / {}".format(name, pid)
                assert "detail" in info, "missing detail for {} / {}".format(name, pid)

    def test_nikto_not_ready_on_windows(self):
        import sys
        if sys.platform.startswith("linux"):
            return  # only meaningful on non-Linux
        result = tm.discover_tools()
        state = result["nikto"]["profiles"].get("nikto-native-v1", {}).get("state", "")
        assert state != tm.READY

    def test_idempotent(self):
        first = tm.discover_tools()
        second = tm.discover_tools()
        assert first == second


class UnavailabilityReason(unittest.TestCase):

    def test_ready_returns_ready(self):
        status = _tool_status({"nikto-native-v1": {"state": tm.READY, "detail": ""}})
        assert tm.unavailability_reason("nikto-native-v1", status) == "ready"

    def test_missing_dependency_includes_install_hint(self):
        status = _tool_status({"nikto-native-v1": {"state": tm.MISSING, "detail": "native nikto binary unavailable"}})
        reason = tm.unavailability_reason("nikto-native-v1", status)
        assert reason.startswith("not installed:")
        assert "apt-get" in reason or "install" in reason.lower()

    def test_linux_required_says_not_enabled(self):
        status = _tool_status({"nikto-native-v1": {"state": "Unsupported", "detail": "reviewed native Nikto requires native Linux"}})
        reason = tm.unavailability_reason("nikto-native-v1", status)
        assert reason.startswith("not enabled:")
        assert "linux" in reason.lower() or "kali" in reason.lower()

    def test_nse_empty_allowlist_says_not_run(self):
        status = _tool_status({"nse-vuln-v1": {"state": "Unsupported", "detail": "NSE vuln script allowlist not yet curated from live nmap --script-help; nse-vuln-v1 disabled"}})
        reason = tm.unavailability_reason("nse-vuln-v1", status)
        assert reason.startswith("not run:")
        assert "allowlist" in reason.lower()

    def test_nuclei_sha256_mismatch_says_attestation_failed(self):
        status = _tool_status({"--redvector-profile=http-headers-v1": {"state": "Unsupported", "detail": "Nuclei SHA256 not in approved builds registry"}})
        reason = tm.unavailability_reason("--redvector-profile=http-headers-v1", status)
        assert "not enabled" in reason

    def test_unknown_profile_returns_no_approved_adapter(self):
        status = _tool_status({})
        reason = tm.unavailability_reason("nonexistent-profile-v99", status)
        assert "no approved adapter" in reason

    def test_disabled_state(self):
        status = _tool_status({"searchsploit-v1": {"state": tm.DISABLED, "detail": "disabled by operator policy"}})
        reason = tm.unavailability_reason("searchsploit-v1", status)
        assert reason.startswith("disabled:")

    def test_restricted_state(self):
        status = _tool_status({"tcp-discovery-v1": {"state": tm.RESTRICTED, "detail": "backend upgrade required"}})
        reason = tm.unavailability_reason("tcp-discovery-v1", status)
        assert reason.startswith("restricted:")

    def test_searchsploit_missing_dep(self):
        status = _tool_status({"searchsploit-v1": {"state": tm.MISSING, "detail": "searchsploit binary not found"}})
        reason = tm.unavailability_reason("searchsploit-v1", status)
        assert "not installed" in reason
        assert "exploitdb" in reason or "searchsploit" in reason.lower()


class ExecutionClasses(unittest.TestCase):

    def test_execution_classes_are_valid(self):
        valid = {"detection", "web-scan", "exploit-db", "exploitation"}
        result = tm.discover_tools()
        for name, entry in result.items():
            assert entry["execution_class"] in valid, "{}:{}".format(name, entry["execution_class"])

    def test_exploitation_class_not_in_default_tools(self):
        # No default tool is in the exploitation class — that class requires separate activation
        result = tm.discover_tools()
        exploit_class_tools = [n for n, e in result.items() if e["execution_class"] == "exploitation"]
        assert exploit_class_tools == [], "unexpected exploitation-class tools: {}".format(exploit_class_tools)


class FormatToolReport(unittest.TestCase):

    def test_returns_list_of_strings(self):
        result = tm.discover_tools()
        lines = tm.format_tool_report(result)
        assert isinstance(lines, list)
        assert all(isinstance(l, str) for l in lines)

    def test_at_least_one_line_per_tool(self):
        result = tm.discover_tools()
        lines = tm.format_tool_report(result)
        assert len(lines) >= len(result)
