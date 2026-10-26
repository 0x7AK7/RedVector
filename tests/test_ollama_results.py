"""Actual MCP shapes as fixtures; no fabricated live scan successes."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from redvector_ollama_results import findings, ResultsStore, analysis_page
from redvector_ollama_presentation import render_scan
from redvector_ollama_setup import Terminal

def response(rows=None,**extra):
    payload={"success":True,"return_code":0,"execution_time":20.16,
             "parsed":{"open_ports":rows if rows is not None else [
                 {"port":"80","protocol":"tcp","state":"open","service":"http"},
                 {"port":"22","protocol":"tcp","state":"open","service":"ssh"},
                 {"port":"23","protocol":"tcp","state":"closed","service":"telnet"}]},
             "stdout":"Not shown: 99 closed tcp ports (reset)\n"}
    payload.update(extra)
    return {"source":"mcp","isError":False,"content":[{"type":"text","text":json.dumps(payload)}],
            "structuredContent":{"result":copy.deepcopy(payload)}}

class Results(unittest.TestCase):
    def test_structured_first_exact_states_and_no_guessed_versions(self):
        value=findings(response(),"fixture-target",1)
        self.assertEqual(value["status"],"COMPLETED")
        self.assertEqual([r["port"] for r in value["ports"]],[22,23,80])
        self.assertEqual(value["open_count"],2)
        self.assertEqual(value["closed_count"],100)
        self.assertTrue(all(r["version"]=="Not verified" for r in value["ports"]))
        self.assertEqual(value["duration"],20.16)

    def test_status_partial_failed_unknown_and_conflict(self):
        for data,status in [(response(partial_results=True),"PARTIAL"),(response(success=False,return_code=1),"FAILED"),
                            ({"isError":True,"execution_status":"unknown"},"UNKNOWN"),
                            (response(stdout="Skipping host fixture due to host timeout"),"PARTIAL"),
                            (response(timed_out=True,partial_results=False),"PARTIAL")]:
            self.assertEqual(findings(data,"fixture",1)["status"],status)
        data=response();data["structuredContent"]["result"]["success"]=False
        self.assertNotEqual(findings(data,"fixture",1)["status"],"COMPLETED")

    def test_fallback_tcp_udp_version_and_ambiguous_state(self):
        data=response([]);payload=data["structuredContent"]["result"]
        payload["stdout"]="PORT STATE SERVICE VERSION\n53/udp open domain\n22/tcp open ssh OpenSSH 9.0\n99/tcp open|filtered unknown\n"
        data["content"]=[]
        value=findings(data,"fixture",1)
        self.assertEqual(value["open_count"],2)
        self.assertEqual(value["ports"][0]["version"],"OpenSSH 9.0")
        self.assertEqual(value["ports"][1]["protocol"],"udp")
        self.assertIsNone(value["closed_count"])

    def test_bad_rows_cannot_invent_ports_or_versions(self):
        data=response([{"port":"80;id","protocol":"tcp","state":"open","service":"http"},
                       {"port":"1","protocol":"evil","state":"open","service":"x"},
                       {"port":65536,"protocol":"tcp","state":"open","service":"x"}])
        value=findings(data,"fixture",1)
        self.assertEqual(value["ports"],[])
        self.assertTrue(value["warnings"])

    def test_store_preserves_original_unknown_fields_and_export(self):
        with tempfile.TemporaryDirectory() as d:
            store=ResultsStore(Path(d)/"results");raw=response();raw["unknown"]={"keep":[1,2]}
            record=store.save("nmap_scan","fixture",{},raw,{"wire_extension":True},1)
            loaded=store.load(record["id"])
            self.assertEqual(loaded["mcp"],raw)
            self.assertEqual(loaded["wire"],{"wire_extension":True})
            exported=store.export(record["id"])
            self.assertEqual(json.loads(exported.read_text()),loaded)
            self.assertTrue(record["persisted"])
            if hasattr(os,"geteuid"):self.assertEqual(exported.stat().st_mode & 0o777,0o600)

    def test_disk_failure_keeps_memory_and_never_claims_durable(self):
        with tempfile.TemporaryDirectory() as d:
            store=ResultsStore(Path(d)/"results");store.ensure()
            with patch.object(store,"_write",side_effect=OSError("disk full")):
                record=store.save("nmap_scan","fixture",{},response(),{},1)
            self.assertFalse(record["persisted"])
            self.assertEqual(store.load(record["id"])["mcp"],response())

    def test_path_traversal_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            store=ResultsStore(Path(d)/"results");store.ensure()
            for bad in ("../secret","/etc/passwd","a"*31,"x"*32):
                with self.assertRaises(ValueError):store.load(bad)
            if hasattr(os,"geteuid"):
                outside=Path(d)/"outside";outside.write_text("{}")
                (store.directory/("a"*32+".json")).symlink_to(outside)
                with self.assertRaises(ValueError):store.load("a"*32)

    def test_private_directory_not_repaired_automatically(self):
        if not hasattr(os,"geteuid"):self.skipTest("Unix permission semantics")
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"results";path.mkdir(mode=0o777);path.chmod(0o777)
            with self.assertRaises(ValueError):ResultsStore(path).ensure()
            self.assertEqual(path.stat().st_mode & 0o777,0o777)

    def test_all_ports_rendered_sorted_narrow_and_no_color(self):
        rows=[{"port":str(p),"protocol":"tcp","state":"open","service":"long-service-name"*3} for p in range(40,0,-1)]
        value=findings(response(rows),"fixture",1)
        term=Terminal(io.StringIO())
        render_scan(term,value,"abc",width=24)
        output=term.stream.getvalue()
        self.assertNotIn("\x1b",output)
        for p in range(1,41):self.assertIn(str(p)+"/tcp",output)
        self.assertTrue(all(len(line)<=24 for line in output.splitlines()))
        self.assertLess(output.index("1/tcp"),output.index("40/tcp"))
        self.assertIn("Not verified",output)

    def test_analysis_budget_no_duplicate_raw_and_explicit_paging(self):
        rows=[{"port":p,"protocol":"tcp","state":"open","service":"ssh"} for p in range(1,1001)]
        value=findings(response(rows,stdout="secret raw banner"*10000),"fixture",1)
        page=analysis_page(value,1,1200)
        self.assertLessEqual(len(json.dumps(page,ensure_ascii=True,separators=(",",":")).encode()),1200)
        self.assertNotIn("secret raw",json.dumps(page))
        self.assertGreater(page["pages"],1)
        ports=[]
        for n in range(1,page["pages"]+1):ports+=analysis_page(value,n,1200)["open_ports"]
        self.assertEqual(len(ports),1000)
        self.assertEqual(len(set(ports)),1000)

    def test_windows_shared_directory_is_rejected_without_repair(self):
        if os.name!="nt":self.skipTest("Windows DACL semantics")
        import subprocess
        from redvector_ollama_private import secure_new_directory
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d)/"shared";directory.mkdir()
            secure_new_directory(directory)
            result=subprocess.run(["icacls",str(directory),"/grant","*S-1-1-0:(OI)(CI)R"],capture_output=True)
            self.assertEqual(result.returncode,0)
            with self.assertRaises(ValueError):ResultsStore(directory).ensure()

    def test_color_errors_and_versions_are_fact_based(self):
        data=response([{"port":"80","protocol":"tcp","state":"open","service":"http","version":"1.2","product":"ExplicitProduct"}],success=False,return_code=1)
        value=findings(data,"fixture",1)
        self.assertEqual(value["ports"][0]["version"],"ExplicitProduct 1.2")
        term=Terminal(io.StringIO());term.color=True
        render_scan(term,value,"id",width=80)
        text=term.stream.getvalue()
        self.assertIn("\x1b[92m",text);self.assertIn("\x1b[91m",text)
        self.assertNotIn("CVE-",text)

    def test_large_duplicate_evidence_stays_exact_but_analysis_is_compact(self):
        data=response([{"port":p,"protocol":"tcp","state":"open","service":"service"} for p in range(1,32)],
                      stdout="actual fixture banner "*50000)
        with tempfile.TemporaryDirectory() as d:
            store=ResultsStore(Path(d)/"results")
            record=store.save("nmap_scan","fixture",{},data,{"original":data},20.16)
            self.assertEqual(store.load()["mcp"],data)
            compact=analysis_page(record["findings"])
            self.assertEqual(len(compact["open_ports"]),31)
            self.assertLess(len(json.dumps(compact)),1800)
            self.assertNotIn("banner",json.dumps(compact))

    def test_windows_owner_rights_cannot_hide_another_owner(self):
        from redvector_ollama_private import _verify_sddl
        user="S-1-5-21-111-222-333-1001";other="S-1-5-21-111-222-333-1002"
        for text in ("O:"+other+"D:P(A;;FA;;;"+user+")(A;;FA;;;OW)",
                     "D:P(A;;FA;;;"+user+")",
                     "O:"+user+"D:P(A;;FA;;;WD)"):
            with self.assertRaises(ValueError):_verify_sddl(text,user)
        _verify_sddl("O:"+user+"D:P(A;;FA;;;"+user+")(A;;FA;;;SY)",user)

    def test_oversized_managed_evidence_is_not_falsely_marked_durable(self):
        with tempfile.TemporaryDirectory() as d:
            store=ResultsStore(Path(d)/"results")
            with patch("redvector_ollama_results.MAX_EVIDENCE_BYTES",100):
                record=store.save("nmap_scan","fixture",{},response(),{"all":response()},1)
            self.assertFalse(record["persisted"])
            self.assertEqual(store.load()["wire"],{"all":response()})
            self.assertFalse((store.directory/(record["id"]+".json")).exists())
            exported=store.export()
            self.assertEqual(json.loads(exported.read_text())["wire"],{"all":response()})

    def test_open_state_green_and_unknown_fields_amber(self):
        value=findings(response([{"port":"12345","protocol":"tcp","state":"open","service":"unknown"}]),"fixture",1)
        term=Terminal(io.StringIO());term.color=True
        render_scan(term,value,"id",width=80)
        text=term.stream.getvalue()
        self.assertIn("\x1b[92mOPEN",text)
        self.assertIn("\x1b[33munknown",text)
        self.assertIn("\x1b[33mNot verified",text)
