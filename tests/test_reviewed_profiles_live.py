"""Opt-in real native scanner tests. All listeners are test-owned loopback."""
import os
import socket
import sys
import threading
import unittest
from pathlib import Path
import redvector_reviewed_profiles as p

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE")=="1",
                     "Requires native Linux and REDVECTOR_RUN_SMOKE=1")
class NativeReviewedProfile(unittest.TestCase):
    def test_real_versions_and_no_redirect_or_extra_payload(self):
        stop=threading.Event();seen=[];secondary=[]
        sockets=[];threads=[]
        def listener(response,records):
            server=socket.socket();server.bind(("127.0.0.1",0));server.listen();server.settimeout(.1)
            sockets.append(server)
            def loop():
                while not stop.is_set():
                    try:client,_=server.accept()
                    except socket.timeout:continue
                    except OSError:break
                    with client:
                        client.settimeout(1.3)
                        if not response.startswith(b"HTTP"):
                            try:client.sendall(response)
                            except ConnectionError:continue
                        try:data=client.recv(4096)
                        except (socket.timeout,ConnectionError):data=b""
                        records.append(data)
                        if response.startswith(b"HTTP") and data:
                            try:client.sendall(response)
                            except ConnectionError:pass
            thread=threading.Thread(target=loop,daemon=True);thread.start();threads.append(thread)
            return server.getsockname()[1]
        trap=listener(b"",secondary)
        http=listener(("HTTP/1.0 302 Found\r\nServer: ReviewHTTP/1.2.3\r\nLocation: http://127.0.0.1:"+str(trap)+"/\r\nContent-Length: 0\r\n\r\n").encode(),seen)
        sshseen=[];ssh=listener(b"SSH-2.0-OpenSSH_9.9p1\r\n",sshseen)
        ftpseen=[];ftp=listener(b"220 ProFTPD 1.3.8e Server Ready\r\n",ftpseen)
        smtpseen=[];smtp=listener(b"220 owned ESMTP Postfix\r\n",smtpseen)
        try:
            capability=p.capabilities()[p.PROFILE]
            self.assertEqual(capability["state"],"Ready",capability)
            result=p.run_profile("nmap_scan",dict(target="127.0.0.1",ports=f"{http},{ssh},{ftp},{smtp}",
                scan_type=p.NMAP_PROFILE,additional_args="--version-intensity 1",use_recovery=False))
            self.assertTrue(result["success"],result)
            services={int(x["port"]):x for x in result["parsed"]["open_ports"]}
            self.assertEqual(services[http]["product"],"ReviewHTTP",result)
            self.assertEqual(services[http]["version"],"1.2.3",result)
            self.assertEqual(services[ssh]["product"],"OpenSSH",result)
            self.assertEqual(services[ssh]["version"],"9.9p1",result)
            self.assertEqual(services[ftp]["product"],"ProFTPD",result)
            self.assertEqual(services[ftp]["version"],"1.3.8e",result)
            self.assertEqual(services[smtp]["product"],"Postfix",result)
            self.assertEqual(services[smtp]["version"],"",result)
            self.assertEqual(secondary,[],"A redirect destination was contacted")
            self.assertTrue(any(x==b"GET / HTTP/1.0\r\n\r\n" for x in seen),seen)
            self.assertTrue(all(x in (b"",b"GET / HTTP/1.0\r\n\r\n") for x in seen+sshseen),(seen,sshseen))
            self.assertEqual(result["reviewed_profile"]["probes"],["NULL","RVHttp"])
            print("REAL REVIEWED NMAP: owned loopback HTTP/SSH/FTP versions and SMTP product verified; exact HTTP bytes; redirect trap untouched.")
        finally:
            stop.set()
            for server in sockets:server.close()
            for thread in threads:thread.join(timeout=2)
