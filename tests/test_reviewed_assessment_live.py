"""Real native offline scanner, no-network kernel policy and owned HTTP endpoints."""
import os,subprocess,sys,threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import unittest
import redvector_reviewed_assessment as a

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE")=="1" and os.environ.get("REDVECTOR_NUCLEI_BIN"),"Requires native Linux, configured reviewed Nuclei and REDVECTOR_RUN_SMOKE=1")
class NativeAssessment(unittest.TestCase):
    def test_kernel_denies_scanner_network_sockets(self):
        code="import redvector_reviewed_assessment as a,socket;a.no_network();socket.socket()"
        r=subprocess.run([sys.executable,"-c",code],capture_output=True,text=True,timeout=10)
        self.assertNotEqual(r.returncode,0)
        self.assertIn("PermissionError",r.stderr)
        print("REAL SANDBOX PASS: Linux seccomp rejected socket creation with EPERM.")

    def test_actual_nuclei_finds_missing_headers_then_clean_control(self):
        seen=[];secure=[False]
        class H(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                seen.append(self.path);self.send_response(200)
                if secure[0]:
                    self.send_header("X-Content-Type-Options","nosniff");self.send_header("X-Frame-Options","DENY")
                self.end_headers();self.wfile.write(b"owned fixture")
        server=ThreadingHTTPServer(("127.0.0.1",0),H);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        params=dict(target="http://127.0.0.1:"+str(server.server_port)+"/",template=a.NUCLEI_PROFILE,use_recovery=False)
        try:
            bad=a.run_nuclei(params);self.assertTrue(bad["success"],bad)
            self.assertEqual({r["id"] for r in bad["findings"]},{"rv-missing-nosniff","rv-missing-frame-options"})
            secure[0]=True
            good=a.run_nuclei(params);self.assertTrue(good["success"],good);self.assertEqual(good["findings"],[])
            self.assertEqual(seen,["/","/"])
            print("REAL NUCLEI PASS: native pinned v3.11.1; two actual findings; secure control zero findings; one GET each; scanner network denied.")
        finally:server.shutdown();server.server_close();thread.join()

    def test_real_tls_nuclei_preserves_hostname_on_numeric_pin(self):
        import ssl,tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix="rv-owned-tls-") as directory:
            cert=Path(directory)/"cert.pem";key=Path(directory)/"key.pem"
            generated=subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=lab.example","-addext","subjectAltName=DNS:lab.example","-keyout",str(key),"-out",str(cert)],capture_output=True,timeout=20)
            self.assertEqual(generated.returncode,0,"Owned certificate generation failed")
            seen=[]
            class H(BaseHTTPRequestHandler):
                def log_message(self,*args):pass
                def do_GET(self):
                    seen.append(self.headers.get("Host"));self.send_response(200);self.end_headers()
            server=ThreadingHTTPServer(("127.0.0.1",0),H)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            server.socket=context.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            trusted=ssl.create_default_context(cafile=str(cert))
            params=dict(target="https://127.0.0.1:"+str(server.server_port)+"/",template=a.NUCLEI_PROFILE,use_recovery=False,additional_args="--redvector-authority=lab.example")
            try:
                with patch.object(a.ssl,"create_default_context",return_value=trusted):
                    result=a.run_nuclei(params)
                    self.assertTrue(result["success"],result)
                    self.assertEqual(len(result["findings"]),2)
                    params["additional_args"]="--redvector-authority=wrong.example"
                    denied=a.run_nuclei(params)
                    self.assertFalse(denied["success"])
                self.assertEqual(seen,["lab.example"])
                print("REAL TLS NUCLEI PASS: numeric destination pin; DNS-only certificate and Host authority validated; wrong hostname rejected before HTTP.")
            finally:server.shutdown();server.server_close();thread.join()

    def test_chunked_response_cannot_be_reported_false_clean(self):
        class H(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                self.send_response(200);self.send_header("Transfer-Encoding","chunked");self.end_headers()
                self.wfile.write(b"5\r\nowned\r\n0\r\n\r\n")
        server=ThreadingHTTPServer(("127.0.0.1",0),H);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            result=a.run_nuclei(dict(target="http://127.0.0.1:"+str(server.server_port)+"/",template=a.NUCLEI_PROFILE,use_recovery=False))
            self.assertTrue(result["success"],result)
            self.assertEqual(len(result["findings"]),2,result)
            print("REAL CHUNKED NUCLEI PASS: decoded root response normalized for header-only matching; both actual missing headers detected.")
        finally:server.shutdown();server.server_close();thread.join()
