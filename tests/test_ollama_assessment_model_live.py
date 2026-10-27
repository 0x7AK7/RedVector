"""Opt-in installed-model selection -> actual MCP Nuclei -> evidence interpretation."""
import asyncio,json,os,sys,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import pytest
from redvector_ollama_agent import Agent,bridge,tool_schema
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore,payloads
from redvector_ollama_setup import Ollama
from test_ollama_unified_live import _runtime

def test_real_model_selects_and_interprets_assessment(tmp_path):
    if not sys.platform.startswith("linux") or not os.environ.get("REDVECTOR_ASSESSMENT_LIVE_MODEL"):
        pytest.skip("Requires native existing operator-selected model and reviewed scanner; never downloads.")
    with _runtime(tmp_path):
        asyncio.run(run(tmp_path))

async def run(directory):
    class H(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            self.send_response(200);self.end_headers();self.wfile.write(b"Owned assessment fixture")
    server=ThreadingHTTPServer(("127.0.0.1",0),H);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    url="http://127.0.0.1:"+str(server.server_port)+"/"
    try:
        api=Ollama();model=os.environ["REDVECTOR_ASSESSMENT_LIVE_MODEL"]
        assert "tools" in (await api.async_show(model)).get("capabilities",[])
        async with bridge() as (session,catalog):
            assert len(catalog)==328
            schema=tool_schema(catalog["nuclei_scan"])
            messages=[{"role":"user","content":"Call nuclei_scan exactly once with target "+url+". Leave optional strings empty. Use a structured tool call, no prose."}]
            selected=await api.async_chat(model,messages,[schema])
            calls=selected.get("tool_calls",[])
            assert len(calls)==1,selected
            function=calls[0]["function"];assert function["name"]=="nuclei_scan"
            agent=Agent(api,model,session,catalog,Policy(["127.0.0.1"]),lambda _:False,lambda _:None,results=ResultsStore(directory/"evidence"))
            outcome=await agent.execute(function["name"],function["arguments"],{"nuclei_scan"})
            assert not outcome["isError"],{"outcome":outcome,"verified_capabilities":agent.policy.profile_status}
            findings=payloads(outcome)[0]["findings"]
            ids=sorted(row["id"] for row in findings);assert len(ids)==2
            messages.append(dict(selected,role="assistant"))
            reply={"role":"tool","tool_name":"nuclei_scan","content":json.dumps({"source":"actual MCP Nuclei result","success":True,"finding_ids":ids,"severity":"info","exploitability":"not assessed"})}
            if calls[0].get("id"):reply["tool_call_id"]=calls[0]["id"]
            messages.append(reply)
            messages.append({"role":"user","content":'Summarize only that real result as JSON with keys finding_ids, severity and exploitability. Copy the exact IDs and values. No other text.'})
            interpreted=await api.async_chat(model,messages,[])
            raw=interpreted.get("content","").strip()
            if raw.startswith("```"):raw=raw.split("\n",1)[1].rsplit("```",1)[0].strip()
            result=json.loads(raw)
            assert sorted(result["finding_ids"])==ids and result["severity"]=="info" and result["exploitability"]=="not assessed",result
            print("REAL OLLAMA ASSESSMENT PASS:",model,"selected nuclei_scan; actual MCP/backend/native Nuclei; two source-backed IDs correctly interpreted; 328 tools.")
    finally:server.shutdown();server.server_close();thread.join()
