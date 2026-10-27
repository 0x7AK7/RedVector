import unittest
from unittest.mock import patch
import redvector_reviewed_profiles as p
class Profiles(unittest.TestCase):
    def params(self, **kw):
        args=dict(target="127.0.0.1",ports="22,80",scan_type=p.NMAP_PROFILE,additional_args="--version-intensity 1",use_recovery=False)
        args.update(kw);return args
    def test_invalid_never_reaches_runtime(self):
        with patch.object(p,"_runtime",side_effect=AssertionError("must validate first")):
            for kw in [dict(target="example.com"),dict(target="127.0.0.1/24"),dict(ports="1-129"),dict(ports="9100"),dict(ports=""),dict(ports="U:53"),dict(use_recovery=True),dict(additional_args="--script safe"),dict(additional_args="--version-intensity 9"),dict(scan_type="-sV"),dict(unexpected=True)]:
                with self.subTest(kw=kw):self.assertFalse(p.run_profile("nmap_scan",self.params(**kw))["success"])
    def test_evidence(self):
        xml='<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.9" method="probed" conf="10"/></port><port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table" conf="3"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
        result=p.parse_xml(xml)["open_ports"]
        self.assertEqual(result[0]["version"],"9.9")
        self.assertEqual(result[0]["confidence"],"identified")
        self.assertEqual(result[1]["confidence"],"inconclusive")
        self.assertEqual(result[1]["version"],"")
    def test_missing_is_not_ready(self):
        with patch.object(p,"_runtime",side_effect=p.ProfileError("Missing native scanner")):
            self.assertNotEqual(p.capabilities()["service-version-v1"]["state"],"Ready")
    def test_unknown_tool(self):self.assertFalse(p.run_profile("nuclei_scan",self.params())["success"])

    def test_entity_and_external_dtd_are_rejected(self):
        for xml in ['<!DOCTYPE nmaprun SYSTEM "http://example.invalid/data"><nmaprun/>',
                    '<!DOCTYPE nmaprun [<!ENTITY x "unsafe">]><nmaprun>&x;</nmaprun>']:
            with self.subTest(xml=xml),self.assertRaises(p.ProfileError):p.parse_xml(xml)
    def test_incomplete_output_never_has_complete_flag(self):
        for xml in ['<nmaprun/>','<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>',
                    '<nmaprun><host timedout="true"/><runstats><finished exit="success"/></runstats></nmaprun>']:
            self.assertFalse(p.parse_xml(xml)["scan_complete"])
    def test_ipv6_numeric_canonicalization(self):
        result=p.parse_xml('<nmaprun><host><address addr="0:0:0:0:0:0:0:1"/></host></nmaprun>')
        self.assertEqual(result["hosts"],["::1"])
    def test_foreign_version_script_selection_is_rejected(self):
        with patch.object(p,"_execute",return_value=(0,"Unexpected installed version scripts","")):
            with self.assertRaises(p.ProfileError):p._verify_scripts("nmap",".")
    def test_intensity_boundaries_and_no_default_ports(self):
        for intensity in range(3):
            result=p._validate("nmap_scan",self.params(additional_args=f"--version-intensity {intensity}"))
            self.assertEqual(result[2],str(intensity))
        for address in ["0.0.0.0","224.0.0.1","::","ff02::1","fe80::1%eth0"]:
            with self.assertRaises(p.ProfileError):p._validate("nmap_scan",self.params(target=address))
