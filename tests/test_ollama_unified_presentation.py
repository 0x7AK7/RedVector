"""Presentation fixtures are not real exploitation, escalation or pivoting tests."""
import io
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
import pytest
from redvector_ollama_setup import Terminal, OllamaTimeout
from redvector_ollama_results import ResultsStore
from redvector_ollama_agent import Agent
from redvector_ollama_policy import Policy, REVIEWED

def data(payload):
    return {"source":"mcp","isError":False,"structuredContent":payload,
            "content":[{"type":"text","text":json.dumps(payload)}]}

def view(tool,payload):
    from redvector_ollama_views import normalize
    return normalize(tool,"fixture-target",{},data(payload),1.25)

@pytest.mark.parametrize("tool,category",[
    ("nuclei_scan","Vulnerability Assessment"),("exploit_select","Exploit Selection"),
    ("metasploit_run","Exploit Execution"),("linpeas_scan","Privilege Escalation"),
    ("chisel_tunnel","Pivoting"),("impacket_psexec","Lateral Movement"),
    ("post_exploit_playbook","Post-Exploitation"),("list_active_processes","Session Management"),
    ("nikto_scan","Web Security"),("api_fuzzer","API Security"),
    ("prowler_scan","Cloud Security"),("wireless_observer","Wireless Security"),
    ("volatility_analyze","Digital Forensics"),("shodan_search","OSINT"),
    ("server_health","MCP Diagnostics"),("llm_list_models","AI Model Compatibility"),
    ("unknown_custom","Tool Results")])
def test_categories_never_grant_execution(tool,category):
    result=view(tool,{"success":True,"observation":"source evidence"})
    assert result["category"]==category
    assert REVIEWED=={"server_health","get_cache_stats","clear_cache","nmap_scan"}
    assert result["status"]=="COMPLETED"

@pytest.mark.parametrize("payload,status",[
    ({"success":True},"COMPLETED"),({"success":False},"FAILED"),
    ({"success":True,"partial_results":True},"PARTIAL"),
    ({"success":True,"timed_out":True},"PARTIAL"),
    ({"status":"healthy"},"COMPLETED"),({"status":"unsupported"},"UNSUPPORTED"),
    ({"status":"running"},"RUNNING"),({"status":"pending approval"},"PENDING APPROVAL"),
    ({"status":"cancelled"},"CANCELLED"),({"observation":"only"},"UNKNOWN"),
    ({"success":True,"error":"failure"},"FAILED")])
def test_evidence_states(payload,status):
    assert view("custom",payload)["status"]==status

def test_severity_and_validation_are_source_only():
    result=view("nuclei_scan",{"success":True,"findings":[
        {"title":"Candidate CVE","severity":"high","cve":"CVE-fixture","validation":"unverified"},
        {"title":"Config","severity":"weird","type":"configuration weakness"},
        {"title":"Confirmed by scanner","severity":"critical","validation":"confirmed"}]})
    assert result["severity"]=={"Critical":1,"High":1,"Medium":0,"Low":0,"Informational":0,"Unknown":1}
    assert result["confirmed"]==1
    assert any(row[0].endswith(".validation") and row[1]=="unverified" for row in result["fields"])
    assert view("nmap_custom",{"success":True,"ports":[{"port":80,"state":"open"}]})["confirmed"]==0

def test_conflicts_and_missing_malformed_fields_remain_unknown():
    from redvector_ollama_views import normalize
    value=data({"success":True})
    value["content"][0]["text"]='{"success":false}'
    assert normalize("x",None,{},value,0)["status"]=="UNKNOWN"
    for payload in ({}, {"findings":None}, {"findings":[None,"text",{"severity":None}]}):
        assert view("nuclei_scan",payload)["status"]=="UNKNOWN"

@pytest.mark.parametrize("width",[12,24,64,100])
def test_width_controls_no_raw_duplicates_and_complete_fields(width):
    from redvector_ollama_presentation import render_result
    payload={"success":True,"findings":[{"title":"row-"+str(i),"severity":"low"} for i in range(55)],
             "evidence":"\x1b[31mUNTRUSTED\x1b[0m\x07"}
    record={"id":"a"*32,"tool":"nikto_scan","findings":view("nikto_scan",payload)}
    stream=io.StringIO();term=Terminal(stream)
    render_result(term,record,width=width)
    output=stream.getvalue()
    assert "structuredContent" not in output and "\x1b" not in output and "\x07" not in output
    assert all(len(line)<=width for line in output.splitlines())
    assert "row-54" in output
    assert "VERIFIED TOOL" in output or width==12

def test_no_color_and_redirected_output(monkeypatch):
    from redvector_ollama_presentation import Panel
    class TTY(io.StringIO):
        def isatty(self):return True
    monkeypatch.setenv("TERM","xterm");monkeypatch.setenv("NO_COLOR","")
    stream=TTY();term=Terminal(stream);Panel(term,40).section("Heading",["Success"],"success")
    assert "\x1b" not in stream.getvalue()
    monkeypatch.delenv("NO_COLOR")
    stream=TTY();term=Terminal(stream);Panel(term,40).section("Heading",["Success"],"success")
    assert "\x1b[" in stream.getvalue()
    assert not Terminal(io.StringIO()).color

def test_all_evidence_and_export_retained(tmp_path):
    store=ResultsStore(tmp_path/"evidence")
    source=data({"success":True,"sessions":[{"id":"s","privilege":"user"}]})
    record=store.save("list_active_processes",None,{},source,{"extra":"exact wire"},1)
    assert record["findings"]["category"]=="Session Management"
    assert store.load(record["id"])["mcp"]==source
    assert json.loads(store.export().read_text())["wire"]=={"extra":"exact wire"}

def test_generic_success_then_ai_timeout_preserves_evidence_no_retry(tmp_path):
    import asyncio
    asyncio.run(_generic_recovery(tmp_path))

async def _generic_recovery(tmp_path):
    tool=SimpleNamespace(name="server_health",description="health",inputSchema={"type":"object","properties":{}})
    result=SimpleNamespace(isError=False,content=[],structuredContent={"status":"healthy","version":"8.0.0"},
                           model_dump=lambda **kwargs:{"original":"wire"})
    session=Mock();session.call_tool=AsyncMock(return_value=result)
    api=Mock();api.async_chat=AsyncMock(side_effect=[
        {"content":"","tool_calls":[{"function":{"name":"server_health","arguments":{}}}]},
        OllamaTimeout("private failure")])
    term=Terminal(io.StringIO())
    agent=Agent(api,"installed",session,{"server_health":tool},Policy(),lambda _:False,lambda _:None,
                results=ResultsStore(tmp_path/"evidence"),terminal=term)
    answer=await agent.turn("Check server_health")
    assert "COMPLETED" in answer and "Unavailable" in answer
    assert agent.results.load()["findings"]["status"]=="COMPLETED"
    assert "healthy" in term.stream.getvalue()
    assert "structuredContent" not in term.stream.getvalue()
    api.async_chat.side_effect=OllamaTimeout("again")
    await agent.summarize_saved()
    assert session.call_tool.await_count==1
    assert api.async_chat.call_args.args[2]==[]
