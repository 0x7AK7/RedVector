"""Actual route bodies extracted into Flask fixture; profile executor boundary isolated."""
import ast
import hmac
from pathlib import Path
from unittest.mock import Mock,patch
from flask import Flask,request,jsonify
import pytest
from redvector_reviewed_profiles import NMAP_PROFILE

@pytest.fixture
def route_app():
    source=ast.parse(Path("redvector_server.py").read_text(encoding="utf-8-sig"))
    wanted={"require_api_authentication","nmap","reviewed_ollama_profiles"}
    nodes=[n for n in source.body if isinstance(n,ast.FunctionDef) and n.name in wanted]
    assert {n.name for n in nodes}==wanted
    app=Flask("reviewed-route-test")
    env={"app":app,"request":request,"jsonify":jsonify,"hmac":hmac,
         "AUTH_EXEMPT_PATHS":{"/health","/health/details"},"API_TOKEN":"fixture-secret",
         "logger":Mock(),"Path":Path,"_get_tools_status_snapshot":lambda names:{name:False for name in names},
         "_parse_nmap_output":lambda text:{"legacy":True},
         "execute_command":Mock(return_value={"success":True,"stdout":"legacy"}),
         "execute_command_with_recovery":Mock(return_value={"success":True,"stdout":"legacy"})}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),"redvector_server.py","exec"),env)
    return app,env

def test_opt_in_profile_route_preserves_auth_and_bypasses_recovery(route_app):
    app,env=route_app
    payload={"target":"192.0.2.15","ports":"80","scan_type":NMAP_PROFILE,"additional_args":"--version-intensity 1","use_recovery":False}
    with patch("redvector_reviewed_profiles.run_profile",return_value={"success":True,"profile":"fixture"}) as execute:
        assert app.test_client().post("/api/tools/nmap",json=payload).status_code==401
        result=app.test_client().post("/api/tools/nmap",json=payload,headers={"Authorization":"Bearer fixture-secret"})
        assert result.json["profile"]=="fixture"
        execute.assert_called_once_with("nmap_scan",payload)
    env["execute_command"].assert_not_called();env["execute_command_with_recovery"].assert_not_called()

def test_legacy_nmap_path_unchanged(route_app):
    app,env=route_app
    result=app.test_client().post("/api/tools/nmap",json={"target":"fixture","scan_type":"-sT","use_recovery":False},
        headers={"Authorization":"Bearer fixture-secret"})
    assert result.json["parsed"]=={"legacy":True}
    env["execute_command"].assert_called_once()

def test_capabilities_route_requires_auth_and_real_runtime_state(route_app):
    app,env=route_app
    assert app.test_client().get("/api/ollama/profiles").status_code==401
    with patch("redvector_reviewed_profiles.capabilities",return_value={"service-version-v1":{"state":"Unsupported","detail":"fixture"}}):
        value=app.test_client().get("/api/ollama/profiles",headers={"Authorization":"Bearer fixture-secret"}).json
        assert value["profiles"]["service-version-v1"]["state"]=="Unsupported"
        assert value["tools_status"]["nuclei"] is False
        assert len(value["module_sha256"])==64
