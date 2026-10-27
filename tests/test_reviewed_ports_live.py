"""Real 128-port profile boundary; every endpoint is owned by this test."""
import os,socketserver,sys,threading,unittest
import redvector_reviewed_profiles as p

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE")=="1","Requires native Linux and explicit smoke mode")
class NativeExpandedPorts(unittest.TestCase):
    def test_128_owned_ftp_banner_endpoints(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:self.request.sendall(b"220 ProFTPD 1.3.8e Server Ready\r\n")
                except OSError:pass
        class Server(socketserver.ThreadingTCPServer):
            daemon_threads=True
        servers=[];threads=[]
        try:
            for _ in range(128):
                server=Server(("127.0.0.1",0),Handler);servers.append(server)
                thread=threading.Thread(target=server.serve_forever,kwargs={"poll_interval":.02},daemon=True)
                thread.start();threads.append(thread)
            ports={s.server_address[1] for s in servers}
            result=p.run_profile("nmap_scan",dict(target="127.0.0.1",ports=",".join(map(str,sorted(ports))),scan_type=p.NMAP_PROFILE,additional_args="--version-intensity 1",use_recovery=False))
            self.assertTrue(result["success"],result)
            rows=result["parsed"]["open_ports"]
            self.assertEqual({int(r["port"]) for r in rows},ports)
            self.assertTrue(all(r["product"]=="ProFTPD" and r["version"]=="1.3.8e" for r in rows),rows)
            print("REAL 128-PORT PASS: all 128 test-owned listeners discovered; all 128 ProFTPD versions verified; bounded profile completed.")
        finally:
            for server in servers:server.shutdown();server.server_close()
            for thread in threads:thread.join(timeout=2)
