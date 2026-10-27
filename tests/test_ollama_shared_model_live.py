"""Installed Ollama chooses real artifact/runtime/advisory tools and interprets their evidence."""
import asyncio,json,os,sys
from pathlib import Path
import pytest
from redvector_ollama_agent import Agent,bridge,tool_schema
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore,payloads
from redvector_ollama_setup import Ollama
from test_ollama_unified_live import _runtime

def test_real_model_shared_adapter_selection_and_interpretation(tmp_path):
    if not sys.platform.startswith("linux") or not os.environ.get("REDVECTOR_SHARED_LIVE_MODEL") or os.environ.get("REDVECTOR_RUN_PUBLIC_ADVISORY")!="1":
        pytest.skip("Requires existing operator-selected model and explicit native/public-provider acceptance; no downloads.")
    with _runtime(tmp_path):asyncio.run(run(tmp_path))

async def run(directory):
    artifact=directory/"owned-evidence.txt";marker="REDVECTOR_SELECTED_ARTIFACT_EVIDENCE_123"
    artifact.write_text(marker+"\n",encoding="ascii")
    api=Ollama();model=os.environ["REDVECTOR_SHARED_LIVE_MODEL"]
    assert "tools" in (await api.async_show(model)).get("capabilities",[])
    async with bridge() as (session,catalog):
        assert len(catalog)==328
        approvals=[]
        def approve(operation):
            approvals.append(operation)
            return operation["tool"]=="monitor_cve_feeds" and operation["arguments"].get("hours")==24 and operation["arguments"].get("severity_filter")=="ALL" and operation["arguments"].get("keywords","")==""
        agent=Agent(api,model,session,catalog,Policy(),approve,lambda _:None,results=ResultsStore(directory/"evidence"))
        selected=await agent.select_artifact(str(artifact))
        names={"strings_extract","display_system_metrics","monitor_cve_feeds"};remaining=set(names);evidence={}
        messages=[{"role":"user","content":"Use each of these tools exactly once: strings_extract with file_path selected; display_system_metrics with empty arguments; monitor_cve_feeds with hours24, severity_filter ALL and empty keywords. Make structured tool calls; do not invent evidence."}]
        for _ in range(4):
            schemas=[tool_schema(catalog[name]) for name in sorted(remaining)]
            message=await api.async_chat(model,messages,schemas)
            calls=message.get("tool_calls",[])
            assert isinstance(calls,list) and 1<=len(calls)<=3,message
            messages.append(dict(message,role="assistant"))
            for call in calls:
                function=call["function"];name=function["name"]
                assert name in remaining,(name,remaining)
                outcome=await agent.execute(name,function["arguments"],remaining)
                assert not outcome["isError"],(name,outcome,agent.policy.profile_status)
                value=payloads(outcome)[0]
                if name=="strings_extract":
                    assert marker in value["stdout"] and value["artifact_sha256"]==selected["sha256"]
                    facts={"tool":name,"observed_marker":marker,"engine":value["engine"],"artifact_executed":False}
                elif name=="display_system_metrics":
                    facts={"tool":name,"cpu_percent":value["metrics"]["cpu_percent"],"source":"actual psutil measurement"}
                else:
                    facts={"tool":name,"provider":value["provider"],"applicability":"Not assessed","sampled_records":value["sampled_records"]}
                evidence[name]=facts
                reply={"role":"tool","tool_name":name,"content":json.dumps(facts)}
                if call.get("id"):reply["tool_call_id"]=call["id"]
                messages.append(reply);remaining.remove(name)
            if not remaining:break
        assert not remaining,remaining
        messages.append({"role":"user","content":'Return only JSON with observed_marker, engine, artifact_executed, cpu_percent, provider and applicability copied from actual tool evidence. No other claims or text.'})
        interpretation=await api.async_chat(model,messages,[])
        text=interpretation.get("content","").strip()
        if text.startswith("```"):text=text.split("\n",1)[1].rsplit("```",1)[0].strip()
        result=json.loads(text)
        assert result["observed_marker"]==marker and result["engine"]=="strings" and result["artifact_executed"] is False,result
        assert result["cpu_percent"]==evidence["display_system_metrics"]["cpu_percent"],result
        assert result["provider"]=="NVD" and result["applicability"]=="Not assessed",result
        assert len(approvals)==1
        await agent.clear_artifact()
        print("REAL SHARED OLLAMA PASS:",model,"selected strings_extract/display_system_metrics/monitor_cve_feeds; all actual MCP paths; exact artifact marker, non-execution, CPU measurement and advisory provenance interpreted;328 tools.")
