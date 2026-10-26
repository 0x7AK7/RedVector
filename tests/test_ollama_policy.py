"""Policy regressions: no network assessments are executed."""
import unittest
from redvector_ollama_policy import Policy, PolicyError, validate_arguments

class PolicyTests(unittest.TestCase):
    def test_diagnostics_without_scope(self):
        self.assertEqual(Policy(auto_discovery=False).authorize("server_health", {}, lambda _: False), {})
    def test_unreviewed_and_commands_denied(self):
        for name in ("execute_command", "autonomous_recon_to_shell", "made_up"):
            with self.subTest(name=name), self.assertRaises(PolicyError):
                Policy(["127.0.0.1"], auto_discovery=False).authorize(name, {}, lambda _: True)
    def test_scope_required_and_exact(self):
        for target in ("example.org", "127.0.0.2", "example.com.evil", "https://example.com"):
            with self.subTest(target=target), self.assertRaises(PolicyError):
                Policy(["example.com"],resolver=lambda _:["192.0.2.10"], auto_discovery=False).authorize("nmap_scan", {"target":target}, lambda _:True)
        with self.assertRaises(PolicyError):
            Policy(auto_discovery=False).authorize("nmap_scan", {"target":"127.0.0.1"}, lambda _:True)
    def test_safe_scan_is_scoped_approved_and_fixed(self):
        args=Policy(["127.0.0.0/30"], auto_discovery=False).authorize("nmap_scan", {"target":"127.0.0.1","ports":"80,443"}, lambda _:True)
        self.assertEqual(args, {"target":"127.0.0.1","ports":"80,443","scan_type":"-sT","additional_args":"-n -Pn --unprivileged --max-retries 1 --host-timeout 60s","use_recovery":False})
    def test_injection_and_bypass_rejected(self):
        for args in ({"target":"127.0.0.1;id"}, {"target":"127.0.0.1","additional_args":"-oN /tmp/x"},
                     {"target":"127.0.0.1","scan_type":"-sC"}, {"target":"127.0.0.1","ports":"0"},
                     {"target":"127.0.0.1","ports":"90-80"}, {"target":"127.0.0.1","ports":"65536"}):
            with self.subTest(args=args), self.assertRaises(PolicyError):
                Policy(["127.0.0.0/8"], auto_discovery=False).authorize("nmap_scan", args, lambda _:True)
    def test_approval_is_per_call(self):
        for name,args in (("nmap_scan",{"target":"127.0.0.1"}), ("clear_cache",{})):
            with self.subTest(name=name), self.assertRaises(PolicyError):
                Policy(["127.0.0.1"], auto_discovery=False).authorize(name,args,lambda _:False)
    def test_schema_rejects_extra_fields_wrong_types_and_required(self):
        schema={"type":"object","properties":{"target":{"type":"string"}},"required":["target"]}
        for args in ({}, {"target":3}, {"target":"x","command":"id"}):
            with self.subTest(args=args), self.assertRaises(PolicyError):
                validate_arguments(schema,args)
    def test_invalid_scope_rejected(self):
        for scope in ("*", "example.com;id", "-example.com", "https://example.com", "127.0.0.1/999"):
            with self.subTest(scope=scope), self.assertRaises(PolicyError):
                Policy([scope], auto_discovery=False)
