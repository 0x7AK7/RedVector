"""Native staged reviewed vulnerability assessment against an owned loopback web service."""
import os,shutil,socket,sys,threading,unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import redvector_reviewed_vulnscan as v

def _bind_web():
    for port in (8080,8000,8888,8180,8008):
        try:
            srv=ThreadingHTTPServer(("127.0.0.1",port),_Owned);return srv,port
        except OSError:continue
    return None,None

class _Owned(BaseHTTPRequestHandler):
    server_version="OwnedHTTP/1.2";sys_version=""
    def log_message(self,*a):pass
    def do_GET(self):
        self.send_response(200);self.send_header("Content-Type","text/html")
        self.send_header("X-Powered-By","PHP/8.2.1");self.end_headers()
        self.wfile.write(b"<html><head><title>Owned Lab</title></head><body>It works!</body></html>")

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE")=="1" and shutil.which("nmap"),
                     "Requires native Linux, native nmap and REDVECTOR_RUN_SMOKE=1")
class NativeVulnScan(unittest.TestCase):
    def test_staged_assessment_against_owned_web_service(self):
        srv,port=_bind_web()
        if srv is None:self.skipTest("no free loopback web port in the reviewed web-port set")
        thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start()
        try:
            out=v.run_assessment({"target":"127.0.0.1","focus_areas":"all"})
            self.assertTrue(out["success"],out)
            self.assertIn(str(port),out["open_ports"])
            stages={a["stage"]:a["status"] for a in out["audit_trail"]}
            self.assertEqual(stages.get("discovery"),"ok")
            self.assertIn("service-version",stages)
            self.assertIn("http-config",stages)
            # honesty: no fabricated findings; every finding carries a classification from the legend
            self.assertTrue(all(f.get("classification") in out["classification_legend"] for f in out["findings"]))
            self.assertIn("no fabricated findings",out["limitations"].lower())
            print("REAL STAGED ASSESSMENT PASS: discovery->service-version->passive HTTP on owned loopback; audit trail; ranked legend; no fabrication.")
        finally:srv.shutdown();srv.server_close();thread.join(timeout=2)
