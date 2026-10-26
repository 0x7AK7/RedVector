import io
from types import SimpleNamespace
import pytest
from redvector_ollama_views import normalize
from redvector_ollama_setup import Terminal
from redvector_ollama_presentation import render_result

def test_complementary_json_blocks_preserve_every_finding():
    value=normalize("nuclei_scan",None,{},{"isError":False,
        "structuredContent":{"success":True},
        "content":[{"text":'{"findings":[{"title":"Missing finding","severity":"high"}]}'},
                   {"text":'{"asset":"second evidence"}'}]},0)
    assert value["finding_count"]==1
    assert value["severity"]["High"]==1
    assert any(text=="Missing finding" for key,text in value["fields"])
    assert any(text=="second evidence" for key,text in value["fields"])

@pytest.mark.parametrize("content",[None,False,3,"invalid"])
def test_malformed_content_is_visible_unknown_not_a_crash(content):
    value=normalize("x",None,{},{"content":content},0)
    assert value["status"]=="UNKNOWN"
    assert value["warnings"]

def test_conflicting_fields_are_all_visible_and_never_successful():
    value=normalize("x",None,{},{"structuredContent":{"success":True,"user":"user"},
        "content":[{"text":'{"success":true,"user":"root"}'}]},0)
    assert value["status"]=="UNKNOWN"
    assert any(text=="user" for _,text in value["fields"])
    assert any(text=="root" for _,text in value["fields"])

def test_nested_json_array_is_readable_fields_not_raw_dump():
    value=normalize("x",None,{},{"content":[{"text":'[{"id":"session","privilege":"user"}]'}]},0)
    assert any(key.endswith(".privilege") and text=="user" for key,text in value["fields"])

def test_pending_and_partial_no_success_color():
    for state in ("pending approval","running","partial","unsupported","blocked","cancelled"):
        value=normalize("metasploit_run",None,{},{"structuredContent":{"status":state}},0)
        assert value["status"]!="COMPLETED"
