"""Client proof and saved-evidence tests; network calls are isolated here."""
import asyncio,copy,json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,AsyncMock,patch
import pytest
from redvector_ollama_backend import BackendProof,BackendReuseError
from redvector_ollama_profiles import attest
from redvector_ollama_agent import Agent,tool_schema
from redvector_ollama_policy import Policy,PolicyError
from redvector_ollama_reporting import report_arguments,report_complete,source_record

def proof():
    return BackendProof(1,2.0,Path("python"),Path("other/redvector_server.py"),Path("other"))

def test_capability_requires_real_matching_process_and_source():
    p=proof();metadata={"profiles":{"service-version-v1":{"state":"Ready"}},"module_sha256":b"source".hex()}
    with patch("redvector_ollama_profiles.inspect_backend",return_value=p),patch("redvector_ollama_profiles._source_start_limit",return_value=2),patch("redvector_ollama_profiles._script_path",side_effect=lambda p,s:p),patch("redvector_ollama_profiles._source",return_value=b"source"):
        assert attest(p,metadata,Path("."),8888)["service-version-v1"]["state"]=="Ready"
        with pytest.raises(BackendReuseError):attest(None,metadata,Path("."),8888)
        with pytest.raises(BackendReuseError):attest(p,dict(metadata,module_sha256="wrong"),Path("."),8888)
    with patch("redvector_ollama_profiles.inspect_backend",return_value=None):
        with pytest.raises(BackendReuseError):attest(p,metadata,Path("."),8888)

def test_original_schema_unchanged_and_reports_only_accept_saved_marker():
    original={"type":"object","properties":{"target":{"type":"string"},"findings":{"type":"string"}}}
    tool=SimpleNamespace(name="create_scan_summary",description="",inputSchema=original)
    before=copy.deepcopy(original)
    schema=tool_schema(tool)["function"]["parameters"]
    assert schema["properties"]=={"target":{"type":"string","enum":["saved"]}}
    assert original==before
    policy=Policy();policy.report_provider=lambda n:{"target":"example.invalid","tools_used":"nmap_scan","vulnerabilities_found":0,"execution_time":1.0,"findings":"{}"}
    assert policy.authorize(tool.name,{"target":"saved"},Mock(side_effect=AssertionError))["vulnerabilities_found"]==0
    with pytest.raises(PolicyError):policy.authorize(tool.name,{"target":"invented"},lambda _:True)

def test_report_preserves_actual_findings_without_inferred_vulnerabilities():
    record={"tool":"nmap_scan","created":"now","target":"example.invalid","mcp":{"source":"mcp","content":[{"text":json.dumps({"success":True,"parsed":{"open_ports":[{"port":80,"state":"open"}]}})}]},"findings":{"status":"COMPLETED","duration":1,"ports":[]}}
    store=Mock();store.ids.return_value=["id"];store.load.return_value=record
    report=report_arguments(store,"create_scan_summary")
    assert report["vulnerabilities_found"]==0
    assert json.loads(report["findings"])["source_findings"]==[]
    record["mcp"]["source"]="application"
    with pytest.raises(ValueError):source_record(store)

def test_empty_formatter_is_not_success():
    args={"vulnerabilities":"[]"}
    assert not report_complete("create_vulnerability_report",{"isError":False,"content":[{"text":"{}"}]},args)
    assert report_complete("create_vulnerability_report",{"isError":False,"content":[{"text":json.dumps({"summary_report":"No source vulnerabilities","vulnerability_cards":[]})}]},args)

def test_unverified_health_claim_does_not_enable_profile():
    session=SimpleNamespace(call_tool=AsyncMock(return_value=SimpleNamespace(isError=False,content=[SimpleNamespace(type="text",text=json.dumps({"status":"healthy","reviewed_capabilities":{"profiles":{"service-version-v1":{"state":"Ready"}}}}))])))
    policy=Policy()
    agent=Agent(Mock(),"optional",session,{},policy,lambda _:True,lambda _:None)
    asyncio.run(agent.refresh_profiles())
    assert not agent.runtime_verified
    assert policy.profile_status["service-version-v1"]["state"]=="Restricted"
    assert policy.profile_status["--redvector-profile=http-headers-v1"]["state"]=="Restricted"
    assert "proof" in policy.profile_status["--redvector-profile=http-headers-v1"]["detail"].lower()


def test_summary_and_visual_formatter_require_actual_nonempty_output():
    for name,args in [("create_scan_summary",{}),("format_tool_output_visual",{})]:
        assert not report_complete(name,{"isError":False,"content":[{"text":'{"success":true}'}]},args)

def test_new_assessment_capabilities_require_matching_module_attestation():
    p=proof();metadata={"profiles":{"redvector-http-read-v1":{"state":"Ready"}},"module_sha256":b"source".hex(),"modules_sha256":{"redvector_reviewed_assessment.py":"wrong"}}
    with patch("redvector_ollama_profiles.inspect_backend",return_value=p),patch("redvector_ollama_profiles._source_start_limit",return_value=2),patch("redvector_ollama_profiles._script_path",side_effect=lambda p,s:p),patch("redvector_ollama_profiles._source",return_value=b"source"):
        with pytest.raises(BackendReuseError,match="Assessment profile source"):attest(p,metadata,Path("."),8888)
        metadata["modules_sha256"]["redvector_reviewed_assessment.py"]=b"source".hex()
        assert attest(p,metadata,Path("."),8888)["redvector-http-read-v1"]["state"]=="Ready"

def test_advanced_no_version_task_is_refused_before_mcp():
    from types import SimpleNamespace
    catalog={"nmap_advanced_scan":SimpleNamespace(name="nmap_advanced_scan",description="",inputSchema={"type":"object","properties":{"target":{"type":"string"},"ports":{"type":"string"},"scan_type":{"type":"string"}},"required":["target"]})}
    session=SimpleNamespace(call_tool=AsyncMock())
    agent=Agent(Mock(),"optional",session,catalog,Policy(["192.0.2.15"]),lambda _:True,lambda _:None)
    agent.assessment_target="192.0.2.15"
    result=asyncio.run(agent.execute("nmap_advanced_scan",{"target":"192.0.2.15","ports":"80","scan_type":"-sT"},{"nmap_advanced_scan"}))
    assert result["isError"] and "Explicitly request service versions" in result["error"]
    session.call_tool.assert_not_called()

def test_completed_advanced_scan_is_attributed_to_its_real_name():
    catalog={"nmap_advanced_scan":SimpleNamespace(name="nmap_advanced_scan",description="",inputSchema={"type":"object","properties":{"target":{"type":"string"}}})}
    api=Mock();api.async_chat=AsyncMock(side_effect=[{"content":"","tool_calls":[{"function":{"name":"nmap_advanced_scan","arguments":{"target":"192.0.2.15"}}}]},{"content":"done"}])
    class BoundaryAgent(Agent):
        async def refresh_profiles(self,data=None):
            self.policy.profile_status={"service-version-v1":{"state":"Ready"}}
        async def execute(self,name,args,exposed):
            self.last_invocation=(name,args)
            return {"source":"mcp","isError":False}
    agent=BoundaryAgent(api,"boundary-double",Mock(),catalog,Policy(["192.0.2.15"]),lambda _:True,lambda _:None)
    answer=asyncio.run(agent.turn("Scan 192.0.2.15 using nmap_advanced_scan for service versions, ports 80."))
    assert "actual MCP nmap_advanced_scan" in answer and "No authorized Nmap scan" not in answer

def test_advanced_start_panel_uses_actual_tool_name(tmp_path):
    import io
    from redvector_ollama_setup import Terminal
    from redvector_ollama_results import ResultsStore
    fields={k:{"type":"boolean" if k in {"os_detection","version_detection","aggressive","stealth"} else "string"} for k in ("target","ports","scan_type","timing","nse_scripts","os_detection","version_detection","aggressive","stealth","additional_args")}
    tool=SimpleNamespace(name="nmap_advanced_scan",description="",inputSchema={"type":"object","properties":fields,"required":["target"]})
    session=SimpleNamespace(call_tool=AsyncMock(return_value=SimpleNamespace(isError=False,content=[SimpleNamespace(type="text",text='{"success":true,"parsed":{"open_ports":[]}}')])))
    stream=io.StringIO();policy=Policy(["192.0.2.15"]);policy.profile_status={"service-version-v1":{"state":"Ready"}}
    agent=Agent(Mock(),"boundary-double",session,{tool.name:tool},policy,lambda _:True,lambda _:None,results=ResultsStore(tmp_path/"results"),terminal=Terminal(stream))
    agent.version_task=True;agent.assessment_target="192.0.2.15";agent.runtime_verified=True
    result=asyncio.run(agent.execute(tool.name,{"target":"192.0.2.15","ports":"80","scan_type":"-sT -sV"},{tool.name}))
    assert not result["isError"],result
    assert "Tool: nmap_advanced_scan" in stream.getvalue() and "Tool: nmap_scan" not in stream.getvalue()
