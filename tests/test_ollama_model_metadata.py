"""Official metadata boundaries are fixtures; no model blobs are ever requested."""
import hashlib
import json
import unittest
from unittest.mock import Mock
from redvector_ollama_models import api_capabilities,canonical_model,registry_metadata,inspect_model

class Response:
    def __init__(self,body,status=200,headers=None):
        self.body=body;self.status_code=status;self.headers=headers or {}
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def iter_content(self,n):
        for start in range(0,len(self.body),n):yield self.body[start:start+n]

class Registry:
    def __init__(self,responses):self.responses=list(responses);self.calls=[];self.trust_env=True
    def get(self,url,**kwargs):
        self.calls.append((url,kwargs))
        if not self.responses:raise AssertionError("Unexpected metadata request")
        value=self.responses.pop(0)
        if isinstance(value,Exception):raise value
        return value
    def close(self):pass

def manifest(config):
    raw=json.dumps(config).encode()
    value={"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json",
           "config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":len(raw),
                     "digest":"sha256:"+hashlib.sha256(raw).hexdigest()},
           "layers":[{"mediaType":"application/vnd.ollama.image.model","size":5_000_000_000,"digest":"sha256:"+"1"*64},
                     {"mediaType":"application/vnd.ollama.image.template","size":25,"digest":"sha256:"+"2"*64}]}
    return json.dumps(value).encode(),raw

class Metadata(unittest.TestCase):
    def test_actual_api_capabilities_control_states_not_names(self):
        for model,info,state in [
            ("random-custom:q7",{"capabilities":["completion","tools"]},"SUPPORTED"),
            ("qwen3:8b",{"capabilities":["completion"]},"UNSUPPORTED"),
            ("coding-model:30b",{},"UNVERIFIED"),
            ("gpt-oss:20b",{"capabilities":"tools"},"UNVERIFIED"),
            ("anything:latest",{"capabilities":[]},"UNSUPPORTED"),
            ("anything:latest",{"capabilities":[3]},"UNVERIFIED")]:
            with self.subTest(model=model,info=info):
                self.assertEqual(api_capabilities(model,info).state,state)

    def test_exact_tags_and_custom_identifiers_are_not_allowlisted(self):
        self.assertEqual(canonical_model("new-owner/custom_model:Q4_K_M"),"new-owner/custom_model:Q4_K_M")
        self.assertEqual(canonical_model("library/custom"),"custom:latest")
        for bad in ("https://other/x","../x","-x","a;id","a b","a\n","a/b/c"):
            with self.subTest(bad=bad),self.assertRaises(ValueError):canonical_model(bad)

    def test_registry_fetches_only_bounded_manifest_and_config(self):
        body,config=manifest({"capabilities":["tools"],"model_family":"custom"})
        transport=Registry([Response(body),Response(config)])
        info=registry_metadata("custom:variant",transport)
        self.assertEqual(info.state,"UNVERIFIED")
        self.assertEqual(info.estimated_bytes,5_000_000_025)
        self.assertEqual(info.declared_capabilities,("tools",))
        self.assertEqual(len(transport.calls),2)
        self.assertFalse(transport.trust_env)
        for url,options in transport.calls:
            self.assertTrue(url.startswith("https://registry.ollama.ai/"))
            self.assertFalse(options["allow_redirects"])
            self.assertTrue(options["stream"])
            self.assertNotIn("1"*64,url)

    def test_missing_registry_tools_is_not_exhaustive_negative(self):
        for config in ({},{"capabilities":[]},{"capabilities":["completion"]}):
            body,raw=manifest(config)
            self.assertEqual(registry_metadata("custom",Registry([Response(body),Response(raw)])).state,"UNVERIFIED")

    def test_integrity_failure_remains_unknown(self):
        body,raw=manifest({"capabilities":["tools"]})
        info=registry_metadata("custom",Registry([Response(body),Response(b"wrong")]))
        self.assertEqual(info.state,"UNVERIFIED")
        self.assertIn("integrity",info.reason)

    def test_offline_redirect_unknown_schema_and_large_metadata(self):
        for response in (Response(b"",503),Response(b"",302,{"Location":"http://localhost/private"}),
                         Response(b"{}"),Response(b"x"*70000),OSError("secret-token")):
            transport=Registry([response])
            info=registry_metadata("custom:exact",transport)
            self.assertEqual(info.state,"UNVERIFIED")
            self.assertNotIn("secret-token",info.reason)
            self.assertEqual(len(transport.calls),1)

    def test_model_or_oversized_config_descriptor_never_fetched(self):
        for config in (None,{"mediaType":"application/vnd.ollama.image.model","size":1,"digest":"sha256:"+"a"*64},
                       {"mediaType":"application/vnd.docker.container.image.v1+json","size":70000,"digest":"sha256:"+"a"*64}):
            body,_=manifest({})
            data=json.loads(body);data["config"]=config
            transport=Registry([Response(json.dumps(data).encode())])
            self.assertEqual(registry_metadata("custom",transport).state,"UNVERIFIED")
            self.assertEqual(len(transport.calls),1)

    def test_computed_api_evidence_overrides_registry_and_installed_needs_no_registry(self):
        api=Mock();api.show.return_value={"capabilities":["completion"]}
        body,raw=manifest({"capabilities":["tools"]})
        api.registry_info.return_value=registry_metadata("custom",Registry([Response(body),Response(raw)]))
        self.assertEqual(inspect_model(api,"custom",False).state,"UNSUPPORTED")
        api.registry_info.reset_mock()
        api.show.return_value={"capabilities":["tools"]}
        self.assertEqual(inspect_model(api,"custom",True).state,"SUPPORTED")
        api.registry_info.assert_not_called()

    def test_missing_evidence_never_guesses_from_name(self):
        api=Mock();api.show.side_effect=OSError("credential");api.registry_info.side_effect=OSError("credential")
        for name in ("qwen3:8b","gpt-oss:20b","random-owner/custom:variant"):
            info=inspect_model(api,name,False)
            self.assertEqual(info.state,"UNVERIFIED")
            self.assertEqual(info.model,canonical_model(name))
            self.assertNotIn("credential",info.reason)
