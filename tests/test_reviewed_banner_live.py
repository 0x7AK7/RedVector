"""Native Nmap identifies only bytes reported by owned greeting fixtures."""
import os,socket,sys,threading,unittest
import redvector_reviewed_profiles as p

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE")=="1","Requires native Linux smoke")
class NativeGreetingProfiles(unittest.TestCase):
    def test_additional_passive_protocol_greetings(self):
        payload=b"\x0a8.0.40\x00"+(1).to_bytes(4,"little")+b"abcdefgh\x00\xff\xf7\x21\x02\x00\xff\x81\x15"+b"\x00"*10+b"123456789012\x00caching_sha2_password\x00"
        mysql=len(payload).to_bytes(3,"little")+b"\x00"+payload
        fixtures=[(b"220 (vsFTPd 3.0.5)\r\n","vsFTPd","3.0.5"),(b"220 owned ESMTP Exim 4.98.2 ready\r\n","Exim","4.98.2"),(b"+OK Dovecot ready.\r\n","Dovecot",""),(b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n","Dovecot",""),(mysql,"MySQL","8.0.40")]
        stop=threading.Event();servers=[];threads=[];expected={}
        def loop(server,banner):
            while not stop.is_set():
                try:client,_=server.accept()
                except socket.timeout:continue
                except OSError:break
                with client:
                    try:client.sendall(banner)
                    except OSError:pass
        try:
            for banner,product,version in fixtures:
                server=socket.socket();server.bind(("127.0.0.1",0));server.listen();server.settimeout(.1);servers.append(server)
                expected[server.getsockname()[1]]=(product,version)
                thread=threading.Thread(target=loop,args=(server,banner),daemon=True);thread.start();threads.append(thread)
            result=p.run_profile("nmap_scan",dict(target="127.0.0.1",ports=",".join(map(str,expected)),scan_type=p.NMAP_PROFILE,additional_args="--version-intensity 1",use_recovery=False))
            self.assertTrue(result["success"],result)
            rows={int(row["port"]):row for row in result["parsed"]["open_ports"]}
            for port,(product,version) in expected.items():
                self.assertEqual(rows[port]["product"],product,(port,rows[port]))
                self.assertEqual(rows[port]["version"],version,(port,rows[port]))
            print("REAL GREETING PROFILE PASS: native Nmap identified vsFTPd/Exim versions, Dovecot POP3/IMAP products and MySQL greeting version from owned TCP fixtures; no additional probes.")
        finally:
            stop.set()
            for server in servers:server.close()
            for thread in threads:thread.join(timeout=2)
