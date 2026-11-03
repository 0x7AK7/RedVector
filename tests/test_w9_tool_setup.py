"""W9 TASK 1 & 2: native-tool discovery surfacing + guided install/fallback workflow.

Covers:
  * NL routing of install/setup/discovery phrasing to the new ``tool_setup`` intent, without
    disturbing the existing read-only tools-catalog intent or scan routing.
  * The reviewed apt install adapter guards: no silent install (approval required), non-apt tools
    refused, non-Linux host reported Unsupported, and the fixed-argv apt command on the success path.
  * The guided flow: missing -> install (approve) -> re-discover; missing -> decline -> internal
    fallback; missing -> decline -> skip; and the critical rule that an INSTALLED-BUT-BLOCKED tool
    is never treated as missing or offered for install.

Pure/injected throughout, so it runs on any OS; it does NOT prove a real apt install (that is the
operator's native-Kali step)."""
import unittest
from unittest.mock import patch

from redvector_nl_router import classify
import redvector_reviewed_install as installer
import redvector_tool_setup as setup


# --------------------------------------------------------------------------- #
# NL routing                                                                  #
# --------------------------------------------------------------------------- #
class Routing(unittest.TestCase):
    def test_install_and_setup_phrasing_routes_to_tool_setup(self):
        for text in ("Install native nikto.", "Set up the native Kali tools.",
                     "Is nikto installed?", "Discover my kali security tools.",
                     "Install the missing tools."):
            self.assertEqual(classify(text)[0], "tool_setup", text)

    def test_plain_tools_catalog_still_routes_to_tools(self):
        # Read-only catalog queries must NOT be captured by the setup intent.
        for text in ("Show available tools.", "What security tools can scan web apps?",
                     "List the tool catalog."):
            self.assertEqual(classify(text)[0], "tools", text)

    def test_scan_requests_are_untouched(self):
        self.assertEqual(classify("Scan my authorized target for open TCP ports.")[0], "task")
        self.assertEqual(classify("Find critical and high vulnerabilities on my target.")[0], "assess")


# --------------------------------------------------------------------------- #
# Reviewed apt install adapter                                                #
# --------------------------------------------------------------------------- #
class InstallAdapter(unittest.TestCase):
    def test_plan_official_package_and_non_apt_tool(self):
        self.assertEqual(installer.plan("nikto")["package"], "nikto")
        self.assertEqual(installer.plan("searchsploit")["package"], "exploitdb")
        self.assertTrue(installer.plan("nmap")["installable"])
        nuclei = installer.plan("nuclei")
        self.assertFalse(nuclei["installable"])        # reviewed build required, never apt here
        self.assertIn("reviewed", nuclei["note"].lower())
        self.assertFalse(installer.plan("totally-unknown")["installable"])

    def test_no_silent_install_without_approval(self):
        res = installer.run_install("nikto", approved=False)
        self.assertEqual(res["execution_mode"], "R")   # rejected: nothing executed
        self.assertIn("approval", res["error"].lower())

    def test_non_apt_tool_refused_even_with_approval(self):
        res = installer.run_install("nuclei", approved=True)
        self.assertEqual(res["execution_mode"], "R")

    def test_success_path_uses_fixed_apt_argv(self):
        calls = {}

        def runner(argv):
            calls["argv"] = argv
            return 0, "Setting up nikto ...", ""

        with patch.object(installer.sys, "platform", "linux"), \
             patch.object(installer.shutil, "which", return_value="/usr/bin/apt-get"):
            res = installer.run_install("nikto", approved=True, runner=runner)

        self.assertEqual(res["execution_mode"], "A")
        self.assertTrue(res["success"])
        self.assertEqual(calls["argv"], ["/usr/bin/apt-get", "install", "-y",
                                         "--no-install-recommends", "nikto"])
        self.assertTrue(res["verification_required"])   # never auto-authorized

    def test_non_linux_host_is_unsupported(self):
        with patch.object(installer.sys, "platform", "win32"):
            res = installer.run_install("nikto", approved=True, runner=lambda a: (0, "", ""))
        self.assertEqual(res["execution_mode"], "E")


# --------------------------------------------------------------------------- #
# Guided discovery + install/fallback flow                                    #
# --------------------------------------------------------------------------- #
_MISSING = {"installed": False}
_INSTALLED = {"installed": True, "capability_supported": True, "version": "2.5.0",
              "capabilities": {"-Format": True}}
_BLOCKED = {"installed": True, "capability_supported": False, "version": "2.5.0",
            "capabilities": {"-Format": True, "-Tuning": False}}


def _driver(discover_fn, install_calls, confirm_answers, approve_answers):
    """Build injected confirm/approve/message/install/discover for run_setup and capture output."""
    messages = []
    confirms = list(confirm_answers)
    approves = list(approve_answers)

    def confirm(_label):
        return confirms.pop(0) if confirms else False

    def approve(_op):
        return approves.pop(0) if approves else False

    def message(kind, line):
        messages.append((kind, line))

    def install(tool, approved=False):
        install_calls.append((tool, approved))
        return {"execution_mode": "A", "success": True, "tool": tool, "package": "nikto"}

    return messages, confirm, approve, install


class SetupFlow(unittest.TestCase):
    def test_missing_then_install_approved_rediscovers(self):
        states = iter([_MISSING, _INSTALLED])          # before install, then after
        install_calls = []
        messages, confirm, approve, install = _driver(
            lambda t: next(states), install_calls, confirm_answers=[True], approve_answers=[True])
        result = setup.run_setup("set up native nikto", confirm=confirm, approve=approve,
                                 message=message_of(messages), discover=lambda t: next(states),
                                 install=install)
        # install was called with approved=True exactly once
        self.assertEqual(install_calls, [("nikto", True)])
        self.assertEqual(result["outcomes"][0]["action"], "installed")

    def test_missing_decline_then_internal_fallback(self):
        install_calls = []
        messages = []
        result = setup.run_setup(
            "install native nikto",
            confirm=_scripted([False, True]),          # decline install, accept fallback
            approve=_scripted([]),
            message=message_of(messages),
            discover=lambda t: _MISSING, install=_record_install(install_calls))
        self.assertEqual(install_calls, [])            # never installed
        self.assertEqual(result["outcomes"][0]["action"], "fallback_internal")
        self.assertTrue(any("internal alternative" in line.lower() for _, line in messages))

    def test_missing_decline_all_skips_with_coverage_note(self):
        install_calls = []
        messages = []
        result = setup.run_setup(
            "install native nikto",
            confirm=_scripted([False, False]),         # decline install AND fallback
            approve=_scripted([]), message=message_of(messages),
            discover=lambda t: _MISSING, install=_record_install(install_calls))
        self.assertEqual(install_calls, [])
        self.assertEqual(result["outcomes"][0]["action"], "skipped")
        self.assertTrue(any("coverage limitation" in line.lower() for _, line in messages))

    def test_installed_but_blocked_is_not_offered_install(self):
        install_calls = []
        messages = []
        asked = []
        result = setup.run_setup(
            "set up native nikto",
            confirm=lambda label: asked.append(label) or True,   # would say yes if asked
            approve=_scripted([True]), message=message_of(messages),
            discover=lambda t: _BLOCKED, install=_record_install(install_calls))
        self.assertEqual(install_calls, [])            # blocked != missing: never install
        self.assertEqual(asked, [])                    # never prompted to install a blocked tool
        self.assertEqual(result["outcomes"][0]["action"], "none")
        self.assertTrue(any("installed but blocked" in line.lower() for _, line in messages))

    def test_install_declined_at_approval_does_not_install(self):
        install_calls = []
        messages = []
        result = setup.run_setup(
            "install native nikto",
            confirm=_scripted([True]),                 # yes to install...
            approve=_scripted([False]),                # ...but decline the system change
            message=message_of(messages), discover=lambda t: _MISSING,
            install=_record_install(install_calls))
        self.assertEqual(install_calls, [])
        self.assertEqual(result["outcomes"][0]["action"], "install_declined")

    def test_nuclei_missing_has_no_apt_path_and_no_fallback(self):
        install_calls = []
        messages = []
        result = setup.run_setup(
            "install nuclei",
            confirm=_scripted([True, True]),           # even if operator says yes, no apt path exists
            approve=_scripted([True]), message=message_of(messages),
            discover=lambda t: _MISSING, install=_record_install(install_calls))
        self.assertEqual(install_calls, [])            # never apt-installed
        self.assertEqual(result["outcomes"][0]["action"], "skipped_no_fallback")


def message_of(sink):
    def message(kind, line):
        sink.append((kind, line))
    return message


def _scripted(answers):
    box = list(answers)

    def fn(_label):
        return box.pop(0) if box else False
    return fn


def _record_install(calls):
    def install(tool, approved=False):
        calls.append((tool, approved))
        return {"execution_mode": "A", "success": True, "tool": tool}
    return install


if __name__ == "__main__":
    unittest.main()
