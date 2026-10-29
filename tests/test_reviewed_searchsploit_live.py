"""Native reviewed Searchsploit evidence against the local Exploit-DB.

Offline and read-only: it runs the real ``searchsploit --json`` binary over the locally installed
Exploit-DB and asserts mode A (native binary executed) with a parsed, bounded result. No network,
no mirroring, no target. If the exploitdb package is not installed the reviewed capability is not
Ready and the test is skipped (that absence is reported accurately as mode D at runtime, never as
a native success). No query is a production constant; 'afd' is a stable historical Exploit-DB term."""
import os
import shutil
import sys
import unittest
import redvector_reviewed_searchsploit as ss


@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE") == "1" and shutil.which("searchsploit"),
                     "Requires native Linux, native searchsploit and REDVECTOR_RUN_SMOKE=1")
class NativeSearchsploit(unittest.TestCase):
    def setUp(self):
        state = ss.capabilities()[ss.PROFILE]["state"]
        if state != "Ready":
            self.skipTest("Reviewed searchsploit capability not Ready (mode " +
                          ("D" if state == "Missing Dependency" else "E") + "): " + state)

    def _run(self, params):
        return ss.run_searchsploit(dict({"additional_args": ss.SEARCHSPLOIT_MARKER}, **params))

    def test_native_query_lookup_reports_mode_A_with_parsed_results(self):
        result = self._run({"query": "afd"})
        self.assertTrue(result["success"], result)
        self.assertEqual(result["execution_mode"], "A", result)              # native binary really ran
        self.assertEqual(result["execution_mode_detail"], "native binary executed")
        self.assertEqual(result["profile"], "searchsploit-v1")
        self.assertIn("results", result["parsed"])
        self.assertIsInstance(result["parsed"]["results"], list)
        self.assertEqual(result["results_count"], len(result["parsed"]["results"]))
        self.assertTrue(result.get("runtime_sha256"))
        print("REAL SEARCHSPLOIT PASS: native searchsploit --json executed (mode A), " +
              str(result["results_count"]) + " exploit row(s) parsed; read-only, no network/mirroring.")

    def test_native_cve_lookup_executes(self):
        result = self._run({"cve": "CVE-2021-44228"})
        self.assertTrue(result["success"], result)
        self.assertEqual(result["execution_mode"], "A", result)
        self.assertIsInstance(result["parsed"]["results"], list)

    def test_option_injection_is_rejected_before_execution(self):
        # A query term that looks like an option must be rejected (mode R), never executed.
        result = self._run({"query": "-m 50383"})
        self.assertFalse(result["success"])
        self.assertEqual(result["execution_mode"], "R", result)


if __name__ == "__main__":
    unittest.main()
