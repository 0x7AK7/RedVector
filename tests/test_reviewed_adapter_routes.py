"""Extract actual opt-in route bodies; do not import/start the full backend here."""
import ast,base64,hashlib,hmac
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
from flask import Flask,request,jsonify
import pytest
import psutil
import redvector_reviewed_artifacts as a

@pytest.fixture
def app(tmp_path):
    tree=ast.parse(Path("redvector_server.py").read_text(encoding="utf-8-sig"))
    names={"require_api_authentication","reviewed_artifact_control","reviewed_runtime_snapshot","reviewed_advisory_query"}
    nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in names]
    assert {n.name for n in nodes}==names
    app=Flask("new-adapter-routes")
    env={"app":app,"request":request,"jsonify":jsonify,"hmac":hmac,"API_TOKEN":"fixture-only",
         "AUTH_EXEMPT_PATHS":{"/health","/health/details"},"psutil":psutil,
         "ProcessManager":SimpleNamespace(list_active_processes=lambda:{}),"logger":Mock()}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),"redvector_server.py","exec"),env)
    with patch.object(a,"_STORE",a.ArtifactStore(tmp_path/"private")):yield app

def test_control_routes_require_existing_backend_auth(app):
    client=app.test_client()
    for method,path in [("post","/api/ollama/artifacts"),("delete","/api/ollama/artifacts"),("get","/api/ollama/runtime"),("post","/api/ollama/advisories")]:
        assert getattr(client,method)(path,json={}).status_code==401

def test_artifact_control_only_stages_exact_data_without_paths(app):
    client=app.test_client();headers={"Authorization":"Bearer fixture-only"};data=b"owned"
    payload={"session":"a"*32,"sha256":hashlib.sha256(data).hexdigest(),"data":base64.b64encode(data).decode()}
    value=client.post("/api/ollama/artifacts",headers=headers,json=payload)
    assert value.status_code==200 and a.store().read(value.json["token"])==data
    assert client.post("/api/ollama/artifacts",headers=headers,json=dict(payload,path="/arbitrary")).status_code==400
    assert client.delete("/api/ollama/artifacts",headers=headers,json={"token":value.json["token"]}).json["success"]
    with pytest.raises(a.ArtifactError):a.store().read(value.json["token"])

def test_runtime_pid_cannot_inspect_arbitrary_os_process(app):
    client=app.test_client();headers={"Authorization":"Bearer fixture-only"}
    assert client.get("/api/ollama/runtime?pid=not-a-pid",headers=headers).status_code==400
    value=client.get("/api/ollama/runtime?pid=123",headers=headers)
    assert value.status_code==404 and not value.json["success"]
