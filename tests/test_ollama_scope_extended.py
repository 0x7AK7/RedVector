"""Scope and destination confinement regressions; DNS is injected, never live."""
import unittest
from redvector_ollama_policy import Policy, PolicyError

FIXED = "-n -Pn --unprivileged --max-retries 1 --host-timeout 60s"

class ExtendedScopeTests(unittest.TestCase):
    def test_scope_is_atomic_canonical_and_immutable(self):
        source = ["10.2.3.9/24", "2001:db8::1", "LAB.example"]
        policy = Policy(source, resolver=lambda _: ["10.2.3.8"])
        source.append("8.8.8.8")
        self.assertEqual(policy.snapshot(), ("10.2.3.0/24", "2001:db8::1", "lab.example"))
        self.assertIsInstance(policy.scope, tuple)
        revision, pins = policy.revision, policy.dns_snapshot()
        for invalid in (["8.8.8.8", "*"], ["other.example", "-bad"], "10.0.0.1"):
            with self.subTest(invalid=invalid), self.assertRaises(PolicyError):
                policy.replace_scope(invalid)
            self.assertEqual(policy.revision, revision)
            self.assertEqual(policy.dns_snapshot(), pins)
            self.assertEqual(policy.snapshot()[0], "10.2.3.0/24")
        pins["lab.example"] = ("8.8.8.8",)
        self.assertEqual(policy.dns_snapshot()["lab.example"], ("10.2.3.8",))
        policy.replace_scope(["8.8.8.8"])
        self.assertGreater(policy.revision, revision)
        self.assertFalse(policy.contains("10.2.3.8"))
        policy.replace_scope([])
        self.assertEqual(policy.snapshot(), ())

    def test_network_membership_fixed_options_and_ipv6(self):
        policy = Policy(["10.0.0.0/8", "2001:db8::/32", "8.8.8.8"])
        for address, scan in [("10.2.3.4","-sT"), ("8.8.8.8","-sT"),
                              ("2001:db8::9","-sT")]:
            with self.subTest(address=address):
                approved = []
                result = policy.authorize("nmap_scan", {"target":address,"scan_type":scan,"ports":"80,443"}, lambda call: approved.append(call) or True)
                self.assertEqual(result, {"target":address, "scan_type":("-6 " if ":" in address else "") + scan,
                                          "ports":"80,443", "additional_args":FIXED, "use_recovery":False})
                self.assertEqual(approved, [{"tool":"nmap_scan","arguments":result}])
        for address in ["11.0.0.1", "2001:db9::9", "10.0.0.0/8"]:
            with self.subTest(address=address), self.assertRaises(PolicyError):
                policy.authorize("nmap_scan", {"target":address}, lambda _: True)

    def test_dns_is_explicit_pinned_and_all_answers_rechecked(self):
        answers = ["10.0.0.8", "2001:db8::8"]
        policy = Policy(["lab.example"], resolver=lambda _: answers[:])
        result = policy.authorize("nmap_scan", {"target":"LAB.example"}, lambda _: True)
        self.assertEqual(result["target"], "10.0.0.8")
        self.assertEqual(policy.dns_snapshot(), {"lab.example":("10.0.0.8", "2001:db8::8")})
        answers.append("8.8.8.8")
        with self.assertRaises(PolicyError):
            policy.authorize("nmap_scan", {"target":"lab.example"}, lambda _: True)
        policy = Policy(["10.0.0.0/8"], resolver=lambda _: ["10.0.0.8"])
        with self.assertRaises(PolicyError):
            policy.authorize("nmap_scan", {"target":"unapproved.example"}, lambda _: True)

    def test_dns_and_scope_changes_during_approval_block_execution(self):
        answers = ["10.0.0.8"]
        policy = Policy(["lab.example"], resolver=lambda _: answers[:])
        def change_dns(_):
            answers[:] = ["10.0.0.9"]
            return True
        with self.assertRaises(PolicyError):
            policy.authorize("nmap_scan", {"target":"lab.example"}, change_dns)
        policy = Policy(["10.0.0.8"])
        def change_scope(_):
            policy.replace_scope(["10.0.0.8"])
            return True
        with self.assertRaises(PolicyError):
            policy.authorize("nmap_scan", {"target":"10.0.0.8"}, change_scope)

    def test_approval_cannot_mutate_execution_or_reuse_prior_approval(self):
        policy = Policy(["10.0.0.8"])
        def mutate(call):
            call["arguments"]["target"] = "8.8.8.8"
            return True
        self.assertEqual(policy.authorize("nmap_scan", {"target":"10.0.0.8"}, mutate)["target"], "10.0.0.8")
        with self.assertRaises(PolicyError):
            policy.authorize("nmap_scan", {"target":"10.0.0.8"}, lambda _: False)

    def test_no_secondary_destination_options_shell_or_recovery(self):
        policy = Policy(["10.0.0.8"])
        bad = [{"target":x} for x in ["10.0.0.8;id","10.0.0.8 8.8.8.8","https://10.0.0.8","-iL","10.0.0.*"]]
        bad += [{"target":"10.0.0.8", field:value} for field,value in [
            ("additional_args","--script safe"),("additional_args","-D 8.8.8.8"),("additional_args","-oN out"),
            ("scan_type","-sT -sC"),("scan_type","-sT -sV --version-light"),("scan_type","-sT --dns-servers 8.8.8.8"),("use_recovery",True),
            ("use_recovery",0),("proxy","8.8.8.8"),("url","http://8.8.8.8"),("ports","80;id")]]
        for args in bad:
            with self.subTest(args=args), self.assertRaises(PolicyError):
                policy.authorize("nmap_scan", args, lambda _: True)
        self.assertFalse(policy.authorize("nmap_scan", {"target":"10.0.0.8","additional_args":FIXED,"use_recovery":False}, lambda _: True)["use_recovery"])

    def test_nonunicast_and_malformed_scope_refused(self):
        for value in ["::","ff02::1","0.0.0.0","224.0.0.1","255.255.255.255","fe80::1%eth0","*.example","https://example.com","127.1","0x7f000001"]:
            with self.subTest(value=value), self.assertRaises(PolicyError):
                Policy([value], resolver=lambda _: ["10.0.0.8"])
        for answers in ([], ["224.0.0.1"], ["10.0.0.8","::"]):
            with self.subTest(answers=answers), self.assertRaises(PolicyError):
                Policy(["lab.example"], resolver=lambda _: answers)

    def test_whois_disabled_and_diagnostics_preserved(self):
        with self.assertRaisesRegex(PolicyError, "(?i)(referral|registr)"):
            Policy(["10.0.0.8"]).authorize("whois_lookup", {"target":"10.0.0.8"}, lambda _: True)
        self.assertEqual(Policy().authorize("server_health", {}, lambda _: False), {})
        with self.assertRaises(PolicyError):
            Policy().authorize("clear_cache", {}, lambda _: False)

    def test_numeric_destination_from_hostname_pin_checks_current_dns(self):
        answers = ["10.0.0.8"]
        policy = Policy(["lab.example"], resolver=lambda _: answers[:])
        def change_dns(_):
            answers[:] = ["10.0.0.9"]
            return True
        with self.assertRaises(PolicyError):
            policy.authorize("nmap_scan", {"target":"10.0.0.8"}, change_dns)

    def test_failed_resolution_replacement_preserves_old_authorization(self):
        def resolve(name):
            if name == "broken.example":
                raise OSError("lookup failed")
            return ["10.0.0.8"]
        policy = Policy(["lab.example"], resolver=resolve)
        previous = policy.snapshot(), policy.dns_snapshot(), policy.revision
        with self.assertRaises(PolicyError):
            policy.replace_scope(["8.8.8.8", "broken.example"])
        self.assertEqual((policy.snapshot(), policy.dns_snapshot(), policy.revision), previous)
        self.assertEqual(policy.authorize("nmap_scan", {"target":"lab.example"}, lambda _: True)["target"], "10.0.0.8")

    def test_default_dns_timeout_preserves_scope_even_after_late_completion(self):
        import threading
        import time
        from unittest.mock import patch
        release, finished = threading.Event(), threading.Event()
        worker_threads = []
        def lookup(*args, **kwargs):
            worker_threads.append(threading.current_thread())
            release.wait(0.5)
            finished.set()
            return [(2, 1, 6, "", ("10.0.0.9", 0))]
        policy = Policy(["10.0.0.8"])
        previous = policy.snapshot(), policy.dns_snapshot(), policy.revision
        with patch("redvector_ollama_policy.DNS_LOOKUP_TIMEOUT", 0.02, create=True), patch("redvector_ollama_policy.socket.getaddrinfo", lookup):
            started = time.monotonic()
            try:
                with self.assertRaises(PolicyError):
                    policy.replace_scope(["late.example"])
                self.assertLess(time.monotonic() - started, 0.3)
                self.assertEqual((policy.snapshot(), policy.dns_snapshot(), policy.revision), previous)
            finally:
                release.set()
                self.assertTrue(finished.wait(1))
                worker_threads[0].join(1)
                self.assertFalse(worker_threads[0].is_alive())
        self.assertEqual((policy.snapshot(), policy.dns_snapshot(), policy.revision), previous)

    def test_stalled_default_dns_workers_are_bounded_and_daemonic(self):
        import threading
        from unittest.mock import patch
        release, finished = threading.Event(), threading.Event()
        worker_threads = []
        def lookup(*args, **kwargs):
            worker_threads.append(threading.current_thread())
            release.wait(0.5)
            finished.set()
            return [(2, 1, 6, "", ("10.0.0.9", 0))]
        with patch("redvector_ollama_policy.DNS_LOOKUP_TIMEOUT", 0.02, create=True), patch("redvector_ollama_policy._DNS_WORKER_SLOTS", threading.BoundedSemaphore(1), create=True), patch("redvector_ollama_policy.socket.getaddrinfo", lookup):
            try:
                for _ in range(2):
                    with self.assertRaises(PolicyError):
                        Policy(["late.example"])
                self.assertEqual(len(worker_threads), 1)
                self.assertTrue(worker_threads[0].daemon)
            finally:
                release.set()
                self.assertTrue(finished.wait(1))
                worker_threads[0].join(1)
                self.assertFalse(worker_threads[0].is_alive())
            restored = Policy(["ready.example"])
            self.assertEqual(restored.dns_snapshot(), {"ready.example":("10.0.0.9",)})

    def test_default_dns_errors_do_not_expose_resolver_exception_secrets(self):
        import traceback
        from unittest.mock import patch
        with patch("redvector_ollama_policy.socket.getaddrinfo", side_effect=OSError("secret-resolver-token")):
            try:
                Policy(["broken.example"])
            except PolicyError as error:
                self.assertNotIn("secret-resolver-token", "".join(traceback.format_exception(error)))
            else:
                self.fail("Resolver failure must reject scope")
