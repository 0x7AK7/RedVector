"""Opt-in live model observation. No fake model, MCP or backend responses."""
import json
import os
from pathlib import Path
import time
from redvector_ollama_agent import Agent,verify_tools
from redvector_ollama_policy import Policy
from redvector_ollama_setup import Ollama

class ObservedOllama(Ollama):
    def __init__(self):
        super().__init__()
        self.exchanges=[]
    async def async_chat(self,model,messages,tools):
        started=time.monotonic()
        response=await super().async_chat(model,messages,tools)
        # Snapshot actual traffic rather than retaining mutable conversation lists.
        self.exchanges.append(json.loads(json.dumps({"messages":messages,"tools":tools,
            "response":response,"elapsed_seconds":round(time.monotonic()-started,3)})))
        destination=os.environ.get("REDVECTOR_LIVE_EVIDENCE")
        if destination:
            path=Path(destination).with_suffix(".partial.json")
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps(self.exchanges,indent=2,ensure_ascii=True),encoding="utf8")
        return response

async def live_model_roundtrip(session,catalog,model):
    api=ObservedOllama()
    if not api.healthy():raise AssertionError("Real Ollama API is unavailable.")
    metadata=await api.async_show(model)
    await verify_tools(api,model)
    observed=[]
    agent=Agent(api,model,session,catalog,Policy(),lambda _:False,observed.append)
    answer=await agent.turn(
        "Call the read-only server_health tool once. Then summarize the actual server status "
        "and exact version returned by that tool in one short English sentence. "
        "Do not scan a target, call other assessment tools, or invent results.")
    results=[json.loads(value) for value in observed]
    actual=[value for value in results if value.get("source")=="mcp"]
    if not actual:raise AssertionError("No real MCP tool execution occurred.")
    if any(value["isError"] for value in actual):raise AssertionError("A real MCP call returned an error.")
    payload=json.loads(actual[-1]["content"][0]["text"])
    if payload.get("status")!="healthy":raise AssertionError("Backend did not report healthy.")
    calls=[call for exchange in api.exchanges for call in exchange["response"].get("tool_calls",[])]
    real_calls=[call for call in calls if call.get("function",{}).get("name")!="connection_probe"]
    if not real_calls or any(call["function"]["name"]!="server_health" for call in real_calls):
        raise AssertionError("Model did not restrict real calls to server_health.")
    sent_back=[message for exchange in api.exchanges for message in exchange["messages"]
               if message.get("role")=="tool" and message.get("tool_name")=="server_health"]
    if not sent_back or not any(json.loads(message["content"]) in actual for message in sent_back):
        raise AssertionError("Actual MCP output was not returned to the model.")
    if payload["status"].lower() not in answer.lower() or str(payload.get("version")) not in answer:
        raise AssertionError("Model summary did not accurately include actual status and version: "+answer)
    evidence={"model":model,"capabilities":metadata.get("capabilities"),"tool_count":len(catalog),
              "tool_calls":real_calls,"actual_mcp_results":actual,"summary":answer,
              "returned_real_result_to_model":True,"exchanges":api.exchanges}
    destination=os.environ.get("REDVECTOR_LIVE_EVIDENCE")
    if destination:
        path=Path(destination);path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(evidence,indent=2,ensure_ascii=True),encoding="utf8")
    print("LIVE MODEL:",model)
    print("LIVE TOOL CALL:",json.dumps(real_calls,ensure_ascii=True))
    print("LIVE MCP RESULT:",json.dumps(actual,ensure_ascii=True))
    print("LIVE MODEL SUMMARY:",answer)
    print("LIVE E2E PASS: Ollama -> structured call -> MCP -> actual backend -> model summary.")
    return evidence
