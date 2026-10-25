"""Offline regression tests; no security tools or backend are executed."""
import contextlib
import importlib.util
import io
import logging
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_client():
    # SDK/network are external boundaries. The actual client, logging and main run.
    sdk = types.ModuleType('mcp.server.fastmcp')
    sdk.FastMCP = object
    # Restore only the SDK keys we replace. patch.dict(sys.modules) also
    # removes unrelated dependencies imported inside its scope, splitting the
    # Requests/CookieJar identities when later real integration tests import SDKs.
    stubs = {'mcp': types.ModuleType('mcp'),
             'mcp.server': types.ModuleType('mcp.server'),
             'mcp.server.fastmcp': sdk}
    previous = {name: sys.modules.get(name) for name in stubs}
    sys.modules.update(stubs)
    try:
        spec = importlib.util.spec_from_file_location('health_test_client', ROOT / 'redvector_mcp.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        for name, original in previous.items():
            if original is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original


class HealthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = load_client()

    def run_main(self, details):
        module = self.client
        paths = []
        health = {'status': 'healthy', 'version': '8.0.0'}

        class Response:
            def raise_for_status(self):
                pass

            def json(self):
                if paths[-1].endswith('/health/details'):
                    if isinstance(details, Exception):
                        raise details
                    return details
                return health

        class Session:
            headers = {}

            def get(self, url, **kwargs):
                paths.append(url)
                return Response()

        class MCP:
            transport = None

            def run(self, transport):
                self.transport = transport

        mcp = MCP()
        stdout, logs = io.StringIO(), io.StringIO()
        handler = logging.StreamHandler(logs)
        with contextlib.redirect_stdout(stdout), patch.object(module.requests, 'Session', Session), \
                patch.object(sys, 'argv', ['redvector_mcp.py']), \
                patch.object(module, 'setup_mcp_server', return_value=mcp), \
                patch.object(module.logger, 'handlers', [handler]), \
                patch.object(module.logger, 'level', logging.INFO), \
                patch.object(module.logger, 'propagate', False):
            module.main()
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(mcp.transport, 'stdio')
        self.assertTrue(any(p.endswith('/health') for p in paths))
        self.assertTrue(any(p.endswith('/health/details') for p in paths))
        return logs.getvalue()

    def test_eight_of_eight_with_missing_external_tools(self):
        logs = self.run_main({'all_essential_tools_available': True,
                              'category_stats': {'essential': {'available': 8, 'total': 8}},
                              'tools_status': {'nmap': True, 'nuclei': False}})
        self.assertIn('Essential tools: 8/8', logs)
        self.assertNotIn('Not all essential', logs)
        self.assertNotIn('Missing tools', logs)

    def test_seven_of_eight(self):
        logs = self.run_main({'all_essential_tools_available': False,
                              'category_stats': {'essential': {'available': 7, 'total': 8}}})
        self.assertIn('Essential tools: 7/8', logs)
        self.assertIn('Not all essential', logs)

    def test_missing_and_invalid_details_are_unknown(self):
        for details in ({}, [], None, ValueError('invalid JSON'),
                        {'error': '404'}, {'all_essential_tools_available': 'false'},
                        {'category_stats': {'essential': {'available': True, 'total': 8}}}):
            with self.subTest(details=details):
                logs = self.run_main(details)
                self.assertIn('Essential tools: Unknown', logs)
                self.assertNotIn('Not all essential', logs)
                self.assertNotIn('Missing tools', logs)

    def test_security_checks_preserved(self):
        with self.assertRaises(ValueError):
            self.client.RedVectorClient('http://example.com:8888')
        self.assertEqual(self.client._redact_sensitive_mapping({'token': 'secret'}),
                         {'token': '***REDACTED***'})


if __name__ == '__main__':
    unittest.main()
