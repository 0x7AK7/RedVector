import json
from redvector_ollama_views import normalize,evidence_page

def test_conflicting_success_and_failure_signals_never_look_completed():
    value=normalize("x",None,{},{"structuredContent":{"success":True},
        "content":[{"text":'{"status":"failed"}'}]},0)
    assert value["status"]=="UNKNOWN"
    assert value["warnings"]

def test_unicode_long_paths_and_long_values_fit_every_page():
    value=normalize("x",None,{},{"structuredContent":{"success":True,"long"*100:"Ã©"*900}},0)
    first=evidence_page(value,budget=512)
    reconstructed=[]
    for number in range(1,first["pages"]+1):
        page=evidence_page(value,number,budget=512)
        assert page["fields"]
        assert len(json.dumps(page,ensure_ascii=True).encode())<=512
        reconstructed.extend(text for key,text in page["fields"])
    assert "Ã©"*900 in "".join(reconstructed)
    assert "long"*100 in "".join(reconstructed)


def test_all_supplied_execution_aliases_must_agree():
    for payload in (
        {"execution_status":"completed","status":"failed"},
        {"return_code":0,"returncode":1},
        {"success":False,"status":"complete"},
        {"status":"completed","returncode":1},
    ):
        value=normalize("x",None,{},{"structuredContent":payload},0)
        assert value["status"]=="UNKNOWN"
        assert value["warnings"]
