"""Attest opt-in capabilities against the verified running backend, not HTTP claims."""
from pathlib import Path
from redvector_ollama_backend import (BackendProof,BackendReuseError,inspect_backend,
    _source,_script_path,_source_start_limit)

def attest(proof,metadata,root,port):
    if not isinstance(proof,BackendProof):
        raise BackendReuseError("Verified backend process proof is unavailable.")
    if inspect_backend(root,"127.0.0.1",port)!=proof:
        raise BackendReuseError("Backend process disappeared or changed; reconnect explicitly.")
    if not isinstance(metadata,dict):
        raise BackendReuseError("Backend capability response is malformed.")
    profiles=metadata.get("profiles")
    if not isinstance(profiles,dict):
        raise BackendReuseError("Backend capability profiles are malformed.")
    if profiles:
        limit=_source_start_limit(proof.pid,proof.started)
        path=_script_path(proof.script.parent/"redvector_reviewed_profiles.py",limit)
        actual=_source(path,limit)
        if actual!=_source(Path(root)/"redvector_reviewed_profiles.py") or actual.hex()!=metadata.get("module_sha256"):
            raise BackendReuseError("Running backend profile source does not match the reviewed module.")
    assessment_names={"redvector-http-read-v1","redvector-tcp-connect-v1","--redvector-profile=http-headers-v1"}
    if assessment_names.intersection(profiles):
        limit=_source_start_limit(proof.pid,proof.started)
        path=_script_path(proof.script.parent/"redvector_reviewed_assessment.py",limit)
        actual=_source(path,limit)
        if actual!=_source(Path(root)/path.name) or actual.hex()!=metadata.get("modules_sha256",{}).get(path.name):
            raise BackendReuseError("Assessment profile source differs from the reviewed module.")
    artifact_keys={"artifact-read-v1"}|{"artifact-read-v1:"+name for name in ("strings_extract","xxd_hexdump","objdump_analyze","checksec_analyze")}
    if artifact_keys.intersection(profiles):
        limit=_source_start_limit(proof.pid,proof.started)
        path=_script_path(proof.script.parent/"redvector_reviewed_artifacts.py",limit)
        actual=_source(path,limit)
        if actual!=_source(Path(root)/path.name) or actual.hex()!=metadata.get("modules_sha256",{}).get(path.name):
            raise BackendReuseError("Artifact profile source differs from the reviewed module.")
    runtime_keys={"runtime-read-v1"}
    if runtime_keys.intersection(profiles):
        limit=_source_start_limit(proof.pid,proof.started)
        path=_script_path(proof.script.parent/"redvector_reviewed_runtime.py",limit)
        actual=_source(path,limit)
        if actual!=_source(Path(root)/path.name) or actual.hex()!=metadata.get("modules_sha256",{}).get(path.name):
            raise BackendReuseError("Runtime profile source differs from the reviewed module.")
    advisory_keys={"nvd-advisory-v1"}
    if advisory_keys.intersection(profiles):
        limit=_source_start_limit(proof.pid,proof.started)
        path=_script_path(proof.script.parent/"redvector_reviewed_advisories.py",limit)
        actual=_source(path,limit)
        if actual!=_source(Path(root)/path.name) or actual.hex()!=metadata.get("modules_sha256",{}).get(path.name):
            raise BackendReuseError("Advisory profile source differs from the reviewed module.")
    searchsploit_keys={"searchsploit-v1"}
    if searchsploit_keys.intersection(profiles):
        limit=_source_start_limit(proof.pid,proof.started)
        path=_script_path(proof.script.parent/"redvector_reviewed_searchsploit.py",limit)
        actual=_source(path,limit)
        if actual!=_source(Path(root)/path.name) or actual.hex()!=metadata.get("modules_sha256",{}).get(path.name):
            raise BackendReuseError("Searchsploit profile source differs from the reviewed module.")
    states={}
    for name,value in profiles.items():
        if name not in {"service-version-v1","tcp-discovery-v1"}|assessment_names|artifact_keys|runtime_keys|advisory_keys|searchsploit_keys:continue
        if not isinstance(value,dict) or value.get("state") not in ("Ready","Missing Dependency","Unsupported","Restricted"):
            raise BackendReuseError("Backend profile status is invalid.")
        states[name]=dict(value)
    return states
