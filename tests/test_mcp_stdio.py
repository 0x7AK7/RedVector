"""Wire-level smoke test when the project's real MCP SDK is installed."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(importlib.util.find_spec('mcp'), 'Real MCP SDK is not installed')
class MCPStdioTests(unittest.TestCase):
    def test_initialize_and_list_tools_over_stdio(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = {'status': 'healthy', 'version': '8.0.0'}
                if self.path == '/health/details':
                    body.update(all_essential_tools_available=True,
                                category_stats={'essential': {'available': 8, 'total': 8}})
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        process = subprocess.Popen([sys.executable, str(ROOT / 'redvector_mcp.py'),
                                    '--server', f'http://127.0.0.1:{server.server_port}'],
                                   cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, encoding='utf8')
        output = queue.Queue()
        diagnostics = []
        reader = threading.Thread(target=lambda: [output.put(line) for line in process.stdout], daemon=True)
        errors = threading.Thread(target=lambda: diagnostics.extend(process.stderr), daemon=True)
        reader.start()
        errors.start()

        def send(message):
            process.stdin.write(json.dumps(message) + '\n')
            process.stdin.flush()

        try:
            send({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                  'params': {'protocolVersion': '2024-11-05', 'capabilities': {},
                             'clientInfo': {'name': 'regression', 'version': '1.0'}}})
            response = json.loads(output.get(timeout=20))
            self.assertEqual(response['id'], 1)
            self.assertIn('result', response)
            send({'jsonrpc': '2.0', 'method': 'notifications/initialized'})
            send({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}})
            response = json.loads(output.get(timeout=20))
            self.assertEqual(response['id'], 2)
            self.assertEqual(len(response['result']['tools']), 328)
        finally:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.terminate()  # Only this test's child, never an existing backend.
                process.wait(timeout=5)
            reader.join(timeout=2)
            errors.join(timeout=2)
            process.stdout.close()
            process.stderr.close()
            server.shutdown()
            server.server_close()
        self.assertIn('Essential tools: 8/8', ''.join(diagnostics))


if __name__ == '__main__':
    unittest.main()
