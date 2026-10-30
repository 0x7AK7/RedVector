"""W7-C: Product-aware and version-aware Searchsploit correlation.

Tests that exploit_reference_applicability:
  - matches known product aliases (Apache httpd / Apache HTTP Server)
  - requires version presence for bare single-word vendor names
  - drops unrelated products from the same vendor family
  - correctly returns 'applicable' when product AND version both appear in the title
  - never labels a reference 'applicable' when the product is not present
  - does not change description_applicability (used for NVD advisories)
"""
import unittest
from redvector_cve_correlation import exploit_reference_applicability, description_applicability


class ExploitReferenceApplicability(unittest.TestCase):

    # --- Apache httpd aliases ---

    def test_apache_httpd_exact_match_with_version(self):
        assert exploit_reference_applicability(
            "Apache httpd", "2.4.49", "Apache httpd 2.4.49 - Path Traversal and RCE") == "applicable"

    def test_apache_http_server_alias_with_version(self):
        # Searchsploit titles often say "Apache HTTP Server" not "Apache httpd"
        assert exploit_reference_applicability(
            "Apache httpd", "2.4.49", "Apache HTTP Server 2.4.49 - Path Traversal (CVE-2021-41773)") == "applicable"

    def test_apache_http_server_alias_no_version(self):
        assert exploit_reference_applicability(
            "Apache httpd", "2.4.49", "Apache HTTP Server - mod_rewrite Open Redirect") == "candidate"

    def test_apache_httpd_no_version_in_title(self):
        assert exploit_reference_applicability(
            "Apache httpd", "2.4.49", "Apache httpd - Directory Traversal") == "candidate"

    # --- Vendor-only match without version is too broad ---

    def test_apache_vendor_only_no_version_drops(self):
        # Product "Apache" (bare) matching "Apache Log4j" is unrelated to the HTTP server
        assert exploit_reference_applicability(
            "Apache", "", "Apache Log4j 2.x - Log4Shell RCE") == "not_applicable"

    def test_apache_vendor_only_with_version_kept(self):
        # Version present in title → applicable even for bare vendor name
        assert exploit_reference_applicability(
            "Apache", "2.4.49", "Apache 2.4.49 - Path Traversal") == "applicable"

    def test_apache_vendor_only_wrong_version_drops(self):
        # Version "2.4.49" not in "Apache Log4j 2.16.0" → version check fails,
        # and matched name "apache" is a vendor-only word → not_applicable
        assert exploit_reference_applicability(
            "Apache", "2.4.49", "Apache Log4j 2.16.0 - RCE") == "not_applicable"

    # --- Unrelated products from same vendor are dropped ---

    def test_apache_struts_not_apache_httpd(self):
        # "apache httpd" is not in "Apache Struts", and "apache http server" is not either
        assert exploit_reference_applicability(
            "Apache httpd", "2.4.49", "Apache Struts 2.4.49 - Remote Code Execution") == "not_applicable"

    def test_apache_tomcat_not_apache_httpd(self):
        assert exploit_reference_applicability(
            "Apache httpd", "2.4.49", "Apache Tomcat 8.5 - Arbitrary File Upload") == "not_applicable"

    # --- OpenSSH ---

    def test_openssh_applicable_with_version(self):
        assert exploit_reference_applicability(
            "OpenSSH", "7.2p2", "OpenSSH 7.2p2 - Username Enumeration (CVE-2016-6210)") == "applicable"

    def test_openssh_candidate_different_version(self):
        # Product present but this version is not the same
        assert exploit_reference_applicability(
            "OpenSSH", "7.2p2", "OpenSSH 6.9 - Remote Code Execution") == "candidate"

    def test_dropbear_not_openssh(self):
        assert exploit_reference_applicability(
            "OpenSSH", "7.2p2", "Dropbear SSH 2016 - Remote Code Execution") == "not_applicable"

    # --- No match ---

    def test_completely_unrelated_title(self):
        assert exploit_reference_applicability(
            "Apache httpd", "2.4.49", "Windows RDP BlueKeep - Remote Code Execution") == "not_applicable"

    def test_empty_product_is_not_applicable(self):
        assert exploit_reference_applicability("", "2.4.49", "Apache httpd 2.4.49 - X") == "not_applicable"

    def test_empty_title_is_not_applicable(self):
        assert exploit_reference_applicability("Apache httpd", "2.4.49", "") == "not_applicable"

    # --- description_applicability is unchanged (NVD path) ---

    def test_description_applicability_unchanged(self):
        # The NVD advisory path uses description_applicability directly; it must still work
        assert description_applicability("OpenSSH", "7.2p2", [],
                                         "sshd in OpenSSH before 7.3 allows remote attackers") == "candidate"
        assert description_applicability("OpenSSH", "7.2p2", [],
                                         "OpenSSH 7.2p2 contains a vulnerability") == "applicable"
        assert description_applicability("nginx", "1.14.0", [],
                                         "Apache httpd path traversal") == "not_applicable"

    # --- Aliases: other products ---

    def test_samba_smbd_alias(self):
        assert exploit_reference_applicability(
            "Samba smbd", "4.6.0", "Samba 4.6.0 - RCE") == "applicable"

    def test_microsoft_iis_alias_httpd(self):
        assert exploit_reference_applicability(
            "Microsoft IIS", "7.5", "Microsoft IIS 7.5 - Remote Code Execution") == "applicable"
