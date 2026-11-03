"""W9 TASK D: dynamic NSE 'vuln' discovery + risk classification (A/B/C/D) and its integration into
the reviewed profile's capability/inventory path.

Pure classification/parse tests run anywhere. The profile-integration tests inject the runtime and
the ``nmap --script-help vuln`` output, so they verify discovery -> classification -> eligibility
without a native nmap; a non-Linux guard test proves the stage stays Unsupported on Windows. Real
NSE execution against a lab target is the operator's native-Kali acceptance step."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import redvector_nse_registry as registry
import redvector_reviewed_profiles as profiles


_SCRIPT_HELP = """Starting Nmap 7.95 ( https://nmap.org )

http-vuln-cve2017-5638
Categories: exploit vuln intrusive
https://nmap.org/nsedoc/scripts/http-vuln-cve2017-5638.html
  Detects Apache Struts ...

smb-vuln-ms17-010
Categories: vuln intrusive
https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html
  Checks MS17-010 ...

ssl-heartbleed
Categories: vuln safe
https://nmap.org/nsedoc/scripts/ssl-heartbleed.html
  Detects CVE-2014-0160 ...

http-csrf
Categories: vuln
https://nmap.org/nsedoc/scripts/http-csrf.html
  Finds CSRF ...

vulners
Categories: safe external vuln
https://nmap.org/nsedoc/scripts/vulners.html
  Queries the Vulners database ...

ftp-vsftpd-backdoor
Categories: vuln safe
https://nmap.org/nsedoc/scripts/ftp-vsftpd-backdoor.html
  Detects the vsftpd 2.3.4 backdoor ...

http-slowloris-check
Categories: vuln dos
https://nmap.org/nsedoc/scripts/http-slowloris-check.html
  Tests for Slowloris DoS ...
"""


class Classification(unittest.TestCase):
    def test_tiers_by_category(self):
        self.assertEqual(registry.classify("ssl-heartbleed", ["vuln", "safe"])[0], "A")
        self.assertEqual(registry.classify("http-csrf", ["vuln"])[0], "B")
        self.assertEqual(registry.classify("smb-vuln-ms17-010", ["vuln", "intrusive"])[0], "C")
        self.assertEqual(registry.classify("http-slowloris-check", ["vuln", "dos"])[0], "C")

    def test_external_overrides_safe_to_tier_d(self):
        # vulners is tagged 'safe' but contacts a third-party service: must be D, never A.
        self.assertEqual(registry.classify("vulners", ["safe", "external", "vuln"])[0], "D")

    def test_intrusive_external_is_c_not_d(self):
        # Most-restrictive-first: a script both intrusive and external is C (never run), not D.
        self.assertEqual(registry.classify("x", ["vuln", "external", "intrusive"])[0], "C")

    def test_name_override_forces_external(self):
        # A reviewed external name is D even if its advertised categories omit 'external'.
        self.assertEqual(registry.classify("vulners", ["vuln", "safe"])[0], "D")

    def test_non_vuln_is_unknown(self):
        self.assertEqual(registry.classify("banner", ["discovery", "safe"])[0], "U")

    def test_safe_is_not_sufficient_alone(self):
        # 'safe' without 'vuln' is not a vuln-tier-A script.
        self.assertEqual(registry.classify("whatever", ["safe"])[0], "U")


class Parsing(unittest.TestCase):
    def test_parse_and_eligibility(self):
        records = registry.parse(_SCRIPT_HELP)
        by_name = {r["script"]: r for r in records}
        self.assertEqual(by_name["ssl-heartbleed"]["risk"], "A")
        self.assertEqual(by_name["ftp-vsftpd-backdoor"]["risk"], "A")
        self.assertEqual(by_name["http-csrf"]["risk"], "B")
        self.assertEqual(by_name["smb-vuln-ms17-010"]["risk"], "C")
        self.assertEqual(by_name["vulners"]["risk"], "D")
        # Eligibility is tier A only — the two safe detection scripts, never the intrusive/external.
        self.assertEqual(registry.eligible(records), ["ftp-vsftpd-backdoor", "ssl-heartbleed"])
        summary = registry.summary(records)
        self.assertEqual(summary["counts"], {"A": 2, "B": 1, "C": 3, "D": 1, "U": 0})

    def test_parse_ignores_junk_and_dedupes(self):
        text = "header line\nnot-a-script\nssl-heartbleed\nCategories: vuln safe\nssl-heartbleed\nCategories: vuln safe\n"
        records = registry.parse(text)
        self.assertEqual([r["script"] for r in records], ["ssl-heartbleed"])   # deduped

    def test_eligible_is_bounded(self):
        many = [{"script": "s%02d" % i, "categories": ["vuln", "safe"], "risk": "A", "reason": ""}
                for i in range(200)]
        self.assertEqual(len(registry.eligible(many, limit=64)), 64)


class ProfileIntegration(unittest.TestCase):
    def _runtime_double(self):
        return ("/usr/bin/nmap", Path("/usr/share/nmap"), [], {"/usr/bin/nmap": "sha-abc"})

    def test_discover_nse_parses_and_caches(self):
        calls = []

        def fake_execute(command, directory, timeout=0):
            calls.append(list(command))
            return 0, _SCRIPT_HELP, ""

        profiles._NSE_DISCOVERY_CACHE.clear()
        with patch.object(profiles, "_execute", fake_execute):
            recs = profiles._discover_nse("/usr/bin/nmap", Path("/usr/share/nmap"), "sha-abc", Path("."))
            self.assertTrue(any(r["script"] == "ssl-heartbleed" and r["risk"] == "A" for r in recs))
            self.assertIn("--script-help", calls[0])
            self.assertIn("vuln", calls[0])
            # Second call with the same integrity digest is served from cache (no second subprocess).
            profiles._discover_nse("/usr/bin/nmap", Path("/usr/share/nmap"), "sha-abc", Path("."))
            self.assertEqual(len(calls), 1)

    def test_nse_inventory_classifies_with_injected_runtime(self):
        profiles._NSE_DISCOVERY_CACHE.clear()
        with patch.object(profiles, "_runtime", return_value=self._runtime_double()), \
             patch.object(profiles, "_execute", return_value=(0, _SCRIPT_HELP, "")):
            inv = profiles.nse_inventory()
        self.assertEqual(inv["state"], "ok")
        self.assertGreaterEqual(inv["summary"]["counts"]["A"], 2)
        self.assertEqual(inv["summary"]["category_a"], ["ftp-vsftpd-backdoor", "ssl-heartbleed"])

    @unittest.skipIf(sys.platform.startswith("linux"), "native Linux may legitimately report Ready")
    def test_capabilities_nse_unsupported_off_linux(self):
        # On Windows the NSE stage must stay Unsupported (native-Linux guard) — never Ready.
        caps = profiles.capabilities()
        self.assertIn("nse-vuln-v1", caps)
        self.assertNotEqual(caps["nse-vuln-v1"]["state"], "Ready")


if __name__ == "__main__":
    unittest.main()
