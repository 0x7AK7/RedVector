"""Native full-range reviewed TCP discovery against an owned loopback listener."""
import os,shutil,socket,sys,threading,unittest
import redvector_reviewed_profiles as p

@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("REDVECTOR_RUN_SMOKE")=="1" and shutil.which("nmap"),
                     "Requires native Linux, native nmap and REDVECTOR_RUN_SMOKE=1")
class NativeDiscovery(unittest.TestCase):
    def test_full_range_discovery_parses_states_and_open_port(self):
        srv=socket.socket();srv.bind(("127.0.0.1",0));srv.listen(16);srv.settimeout(0.5)
        open_port=str(srv.getsockname()[1])
        stop=threading.Event()
        def serve():
            while not stop.is_set():
                try:conn,_=srv.accept();conn.close()
                except (socket.timeout,OSError):pass
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        try:
            res=p.run_discovery("nmap_scan",{"target":"127.0.0.1","ports":"1-65535",
                "scan_type":p.DISCOVERY_PROFILE,"additional_args":"","use_recovery":False})
            self.assertTrue(res["success"],res)
            parsed=res["parsed"]
            self.assertEqual(parsed["host_state"],"up")
            states={e["port"]:e["state"] for e in parsed["ports"]}
            self.assertEqual(states.get(open_port),"open",parsed["state_counts"])
            self.assertEqual(res["reviewed_profile"]["engine"],"native nmap -sT connect discovery")
            self.assertEqual(res["reviewed_profile"]["ports_count"],65535)
            print("REAL FULL-RANGE DISCOVERY PASS: native nmap -sT 1-65535, XML states parsed, owned open port found.")
        finally:stop.set();srv.close();thread.join(timeout=2)
