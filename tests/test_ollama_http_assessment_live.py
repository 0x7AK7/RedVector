"""Four reviewed HTTP assessment MCP interfaces against one owned loopback web service."""
import asyncio,os,sys,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import pytest
from redvector_ollama_agent import Agent,bridge
from redvector_ollama_policy import Policy
from redvector_ollama_results import ResultsStore,payloads
from ollama_profile_runtime import owned_backend

@pytest.mark.skipif(not sys.platform.startswith("linux") or os.environ.get("REDVECTOR_RUN_SMOKE")!="1",reason="Requires native Linux and explicit smoke mode")
def test_real_http_assessment_mcp_workflows(tmp_path):
    requests=[]
    class Owned(BaseHTTPRequestHandler):
        server_version="OwnedHTTP/1.2";sys_version=""
        def log_message(self,*args):pass
        def do_GET(self):
            requests.append(self.path)
            body=b"<html><head><title>Owned Lab</title></head><body>It works!</body></html>"
            self.send_response(200)
            self.send_header("Content-Type","text/html")
            self.send_header("X-Powered-By","PHP/8.2.1")
            self.send_header("Set-Cookie","sid=abc; Path=/")
            self.end_headers();self.wfile.write(body)
    web=ThreadingHTTPServer(("127.0.0.1",0),Owned)
    thread=threading.Thread(target=web.serve_forever,daemon=True);thread.start()
    url="http://127.0.0.1:"+str(web.server_port)+"/"
    try:
        with owned_backend(tmp_path):asyncio.run(run(tmp_path,url))
    finally:web.shutdown();web.server_close();thread.join()
    assert requests==["/","/","/","/"]

async def run(directory,url):
    async with bridge() as (session,catalog):
        assert len(catalog)==328
        agent=Agent(None,"unused",session,catalog,Policy(["127.0.0.1"]),lambda _:True,lambda _:None,results=ResultsStore(directory/"evidence"))
        await agent.refresh_profiles()

        r=await agent.execute("httpx_probe",{"target":url},{"httpx_probe"});assert not r["isError"],r
        v=payloads(r)[0]
        assert v["success"] and v["probe"]["status_code"]==200 and v["probe"]["title"]=="Owned Lab"
        assert "PHP" in v["probe"]["powered_by"] and v["probe"]["redirect_followed"] is False
        assert v["scanner"]["name"]=="httpx" and "no external scanner" in v["scanner"]["mode"].lower()

        r=await agent.execute("wafw00f_scan",{"target":url},{"wafw00f_scan"});assert not r["isError"],r
        v=payloads(r)[0];assert v["success"] and v["waf"]["detected"] is False  # loopback fixture has no WAF headers

        r=await agent.execute("nikto_scan",{"target":url},{"nikto_scan"});assert not r["isError"],r
        v=payloads(r)[0];assert v["success"]
        ids={f["id"] for f in v["findings"]}
        assert {"rv-powered-by","rv-missing-x-frame-options","rv-cookie-httponly"}<=ids

        r=await agent.execute("jaeles_vulnerability_scan",{"url":url},{"jaeles_vulnerability_scan"});assert not r["isError"],r
        v=payloads(r)[0];assert v["success"]
        mids={m["id"] for m in v["matches"]}
        assert "rv-info-powered-by" in mids and "rv-default-page" in mids

        print("REAL FOUR-HTTP-ASSESSMENT MCP PASS: httpx/wafw00f/nikto/jaeles reviewed passive profiles; one confined GET each; actual response evidence; no external scanner binary; 328 tools.")
