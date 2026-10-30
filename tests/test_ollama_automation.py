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
    def test_state_change_still_requires_exact_approval(self):
        # clear_cache is state-changing and still requires an explicit approval each time.
        policy=self.policy();approve=Mock(return_value=False)
        with self.assertRaises(PolicyError):policy.authorize("clear_cache",{},approve)
        approve.assert_called_once()
    def test_full_range_discovery_needs_task_authorization_not_scope_alone(self):
        p=self.policy();p.profile_status={"tcp-discovery-v1":{"state":"Ready"}}
        # scope alone does not authorize full-range discovery: it prompts
        calls=[]
        p.authorize("nmap_scan",{"target":"192.0.2.8","ports":"1-65535"},lambda op:calls.append(op) or True)
        self.assertEqual(len(calls),1)
        # a full-range task asks ONCE, then its discovery stage runs without a repeated prompt
        confirmations=[]
        p.begin_task("192.0.2.8",65535,{"discovery"},lambda op:confirmations.append(op) or True,"full-range detection task")
        self.assertEqual(len(confirmations),1)
        out=p.authorize("nmap_scan",{"target":"192.0.2.8","ports":"1-65535"},Mock(side_effect=AssertionError("must not re-prompt")))
        self.assertTrue(p.last_automatic and p.last_task_id)
        self.assertEqual(out["scan_type"],"--redvector-profile=tcp-discovery-v1")
        # the task ends with the task
        p.end_task()
        calls2=[]
        p.authorize("nmap_scan",{"target":"192.0.2.8","ports":"1-65535"},lambda op:calls2.append(op) or True)
        self.assertEqual(len(calls2),1)
    def test_declined_task_runs_nothing(self):
        p=self.policy()
        with self.assertRaises(PolicyError):p.begin_task("192.0.2.8",65535,{"discovery"},lambda op:False,"full-range task")
        self.assertIsNone(p.task)
    def test_task_never_covers_other_target_stage_or_scope_change(self):
        p=Policy(["192.0.2.8","192.0.2.9"],clock=lambda:100);p.profile_status={"tcp-discovery-v1":{"state":"Ready"},"service-version-v1":{"state":"Ready"}}
        p.begin_task("192.0.2.8",1000,{"discovery"},lambda op:True,"bounded task")
        calls=[]
        p.authorize("nmap_scan",{"target":"192.0.2.9","ports":"1-1000","scan_type":"--redvector-profile=tcp-discovery-v1"},lambda op:calls.append(op) or True)
        self.assertEqual(len(calls),1)                                  # no cross-target reuse
        p.authorize("nmap_scan",{"target":"192.0.2.8","ports":"80","scan_type":"-sV"},lambda op:calls.append(op) or True)
        self.assertEqual(len(calls),2)                                  # service-version not in this task's stages
        p.authorize("nmap_scan",{"target":"192.0.2.8","ports":"1-5000","scan_type":"--redvector-profile=tcp-discovery-v1"},lambda op:calls.append(op) or True)
        self.assertEqual(len(calls),3)                                  # beyond the task's port bound
        p.replace_scope(["192.0.2.8"])
        p.authorize("nmap_scan",{"target":"192.0.2.8","ports":"1-1000","scan_type":"--redvector-profile=tcp-discovery-v1"},lambda op:calls.append(op) or True)
        self.assertEqual(len(calls),4)                                  # scope change invalidates the task
        with self.assertRaises(PolicyError):p.begin_task("192.0.2.8",10,{"exploitation"},lambda op:True,"x")   # never exploitation
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
