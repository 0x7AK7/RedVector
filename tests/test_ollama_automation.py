import unittest
from unittest.mock import Mock
from redvector_ollama_policy import Policy,PolicyError,FIXED_NMAP_ARGS

class Automatic(unittest.TestCase):
    def policy(self):return Policy(["192.0.2.8"],clock=lambda:100)
    def test_reviewed_small_scan_needs_no_repetitive_approval(self):
        policy=self.policy();approve=Mock(side_effect=AssertionError("Low-impact scan must not prompt"))
        args=policy.authorize("nmap_scan",{"target":"192.0.2.8","ports":"22,80"},approve)
        self.assertTrue(policy.last_automatic)
        self.assertIn("--max-rate 50",args["additional_args"])
        self.assertIn("--scan-delay 20ms",args["additional_args"])
        self.assertIn("--max-parallelism 8",args["additional_args"])
        self.assertFalse(args["use_recovery"])
    def test_full_range_and_state_change_still_require_exact_approval(self):
        # Full-range discovery now runs the attested reviewed discovery profile, which must be
        # Ready; it still requires one explicit operator approval (never silent auto-run).
        for tool,args in [("nmap_scan",{"target":"192.0.2.8","ports":"1-65535"}),("clear_cache",{})]:
            policy=self.policy();policy.profile_status={"tcp-discovery-v1":{"state":"Ready"}};approve=Mock(return_value=False)
            with self.assertRaises(PolicyError):policy.authorize(tool,args,approve)
            approve.assert_called_once()
        p=self.policy();p.profile_status={"tcp-discovery-v1":{"state":"Ready"}}
        p.authorize("nmap_scan",{"target":"192.0.2.8","ports":"1-65535"},lambda operation:True)
        self.assertFalse(p.last_automatic)
    def test_scope_and_malformed_destinations_cannot_be_automated(self):
        for policy,args in [(Policy(),{"target":"192.0.2.8"}),(self.policy(),{"target":"192.0.2.9"}),
                            (self.policy(),{"target":"192.0.2.8","additional_args":"--script default"}),
                            (self.policy(),{"target":"192.0.2.8","ports":"1-1001;id"})]:
            approve=Mock(return_value=True)
            with self.assertRaises(PolicyError):policy.authorize("nmap_scan",args,approve)
            approve.assert_not_called()
    def test_session_and_cooldown_limits_fall_back_to_operator_gate(self):
        p=self.policy();args={"target":"192.0.2.8","ports":"80"}
        p.authorize("nmap_scan",args,lambda operation:False)
        with self.assertRaises(PolicyError):p.authorize("nmap_scan",args,lambda operation:False)
        p.last_auto=-1000;p.auto_count=5
        with self.assertRaises(PolicyError):p.authorize("nmap_scan",args,lambda operation:False)
    def test_explicit_legacy_manual_mode_and_unreviewed_tools_stay_blocked(self):
        p=Policy(["192.0.2.8"],auto_discovery=False)
        with self.assertRaises(PolicyError):p.authorize("nmap_scan",{"target":"192.0.2.8","ports":"80"},lambda operation:False)
        for name in ("execute_command","exploit","whois_lookup"):
            with self.assertRaises(PolicyError):p.authorize(name,{},lambda operation:True)
    def test_dns_and_scope_revalidated_even_on_automatic_path(self):
        answers=iter([["192.0.2.8"],["192.0.2.8"],["192.0.2.9"]])
        p=Policy(["scope.example"],resolver=lambda name:next(answers))
        with self.assertRaises(PolicyError):p.authorize("nmap_scan",{"target":"scope.example","ports":"80"},lambda operation:True)
