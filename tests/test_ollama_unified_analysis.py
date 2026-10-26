import asyncio
from unittest.mock import AsyncMock,Mock
from redvector_ollama_analysis import summarize
from redvector_ollama_views import normalize

def test_only_grounded_analysis_ids_can_be_selected():
    asyncio.run(_analysis())

async def _analysis():
    facts=normalize("nuclei_scan","fixture",{},{"structuredContent":{"success":True,"findings":[
        {"title":"source issue","severity":"high","validation":"unverified","remediation":"source remediation"}]}},1)
    record={"findings":facts}
    api=Mock()
    def answer(model,messages,tools,**kwargs):
        import json
        source=json.loads(messages[-1]["content"])
        assert tools==[]
        assert kwargs["response_schema"]["properties"]["fields"]["enum"]==[source["fields"]]
        return {"content":json.dumps({"status":source["status"],"fields":source["fields"],"observations":["priority","validation"]})}
    api.async_chat=AsyncMock(side_effect=answer)
    result=await summarize(api,"installed",record)
    assert result["state"]=="verified"
    assert "1 High" in result["text"] and "Unverified" in result["text"]
    def invented(model,messages,tools,**kwargs):
        import json
        source=json.loads(messages[-1]["content"])
        return {"content":json.dumps({"status":source["status"],"fields":source["fields"],"observations":["compromised"]})}
    api.async_chat.side_effect=invented
    assert (await summarize(api,"installed",record))["state"]=="unavailable"


def test_diagnostic_explanation_copies_source_status_and_version():
    asyncio.run(_diagnostic())

async def _diagnostic():
    import json
    value=normalize("server_health",None,{},{"structuredContent":{"status":"healthy","version":"8.0.0"}},0)
    api=Mock()
    def echo(model,messages,tools,**kwargs):
        source=json.loads(messages[-1]["content"])
        return {"content":json.dumps({"status":source["status"],"fields":source["fields"]})}
    api.async_chat=AsyncMock(side_effect=echo)
    result=await summarize(api,"installed",{"findings":value})
    assert result["state"]=="verified"
    assert "healthy" in result["text"] and "8.0.0" in result["text"]
