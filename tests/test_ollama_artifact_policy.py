"""Trusted operator selection is distinct from network target authorization."""
import asyncio,hashlib
from pathlib import Path
from unittest.mock import Mock
import pytest
from redvector_ollama_policy import Policy,PolicyError
from redvector_ollama_artifacts import snapshot
from redvector_ollama_setup import SetupError

def test_model_cannot_choose_a_file_or_forge_a_selected_handle():
    policy=Policy();policy.profile_status={"artifact-read-v1:strings_extract":{"state":"Ready"}}
    for value in ["selected","/etc/passwd","rv-artifact-v1:forged"]:
        with pytest.raises(PolicyError):policy.authorize("strings_extract",{"file_path":value},lambda _:True)

def test_selected_read_needs_no_repeated_high_impact_approval():
    policy=Policy()
    policy.profile_status={"artifact-read-v1:strings_extract":{"state":"Ready"},"artifact-read-v1:objdump_analyze":{"state":"Ready"}}
    policy.artifact_provider=lambda:{"source":"operator-snapshot","token":"trusted-private-handle"}
    approve=Mock(side_effect=AssertionError)
    assert policy.authorize("strings_extract",{"file_path":"selected"},approve)["file_path"]=="trusted-private-handle"
    assert policy.authorize("objdump_analyze",{"binary":"selected"},approve)["disassemble"] is False

def test_operator_snapshot_preserves_real_file_bytes(tmp_path):
    path=tmp_path/"owned artifact.bin";data=b"owned evidence";path.write_bytes(data)
    metadata,actual=snapshot(str(path))
    assert actual==data and metadata["sha256"]==hashlib.sha256(data).hexdigest()
    assert path.read_bytes()==data
    with pytest.raises(SetupError):snapshot(str(tmp_path))

def test_runtime_pid_requires_prior_actual_discovery():
    policy=Policy();policy.profile_status={"runtime-read-v1":{"state":"Ready"}}
    with pytest.raises(PolicyError):policy.authorize("get_process_status",{"pid":123},lambda _:True)
    policy.observed_processes={123:1.0}
    assert policy.authorize("get_process_status",{"pid":123},lambda _:False)=={"pid":123}

def test_public_advisory_query_requires_exact_approval():
    policy=Policy();policy.profile_status={"nvd-advisory-v1":{"state":"Ready"}}
    for name,args in [("monitor_cve_feeds",{"hours":24,"severity_filter":"ALL","keywords":""}),("vulnerability_intelligence_dashboard",{})]:
        calls=[]
        with pytest.raises(PolicyError):policy.authorize(name,args,lambda op:calls.append(op) or False)
        assert len(calls)==1 and "NVD" in calls[0]["reason"]

def test_clear_revokes_local_artifact_even_when_backend_cleanup_fails():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock,patch
    from redvector_ollama_agent import Agent
    agent=Agent(None,"unused",SimpleNamespace(),{},Policy(),lambda _:False,lambda _:None)
    agent.artifact={"token":"private-selected-handle"}
    with patch("redvector_ollama_artifacts.control",side_effect=SetupError("Backend unavailable")):
        asyncio.run(agent.clear_artifact())
    assert agent.artifact is None

def test_actual_artifact_parser_failure_keeps_its_actionable_error(tmp_path):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock,patch
    from redvector_ollama_agent import Agent
    from redvector_ollama_results import ResultsStore,payloads
    tool=SimpleNamespace(name="strings_extract",description="",inputSchema={"type":"object","properties":{"file_path":{"type":"string"}},"required":["file_path"]})
    session=SimpleNamespace(call_tool=AsyncMock(return_value=SimpleNamespace(isError=False,content=[SimpleNamespace(type="text",text='{"success":false,"error":"Artifact output exceeds512 KiB"}')])))
    policy=Policy();policy.profile_status={"artifact-read-v1:strings_extract":{"state":"Ready"}}
    agent=Agent(None,"unused",session,{tool.name:tool},policy,lambda _:False,lambda _:None,results=ResultsStore(tmp_path/"evidence"))
    agent.artifact={"source":"operator-snapshot","token":"private","name":"owned","sha256":"a"*64};agent.runtime_verified=True
    with patch("redvector_ollama_artifacts.require_backend",return_value=None):
        result=asyncio.run(agent.execute(tool.name,{"file_path":"selected"},{tool.name}))
    assert result["isError"]
    assert "digest" not in result.get("error","").lower()
    assert "output" in payloads(result)[0]["error"].lower()
