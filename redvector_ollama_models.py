"""Exact-tag capability evidence. Registry observations never fetch model layers."""
from dataclasses import dataclass
import hashlib
import json
import re
import requests

REGISTRY = "https://registry.ollama.ai"
METADATA_LIMIT = 64 * 1024
CONFIG_TYPES = {"application/vnd.docker.container.image.v1+json", "application/vnd.oci.image.config.v1+json"}

def model_id_value(value):
    if not isinstance(value, str) or len(value) > 160 or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]*(?:/[A-Za-z0-9][A-Za-z0-9_.-]*)?(?::[A-Za-z0-9][A-Za-z0-9_.-]*)?", value):
        raise ValueError("Invalid model identifier. Use name:tag or namespace/name:tag.")
    return value

def canonical_model(value):
    value = model_id_value(value)
    if value.startswith("library/"): value = value[8:]
    return value if ":" in value else value + ":latest"

@dataclass(frozen=True)
class ModelCompatibility:
    model: str
    state: str
    reason: str
    source: str
    estimated_bytes: int | None = None
    manifest_digest: str | None = None
    declared_capabilities: tuple | None = None

def capabilities(value):
    if not isinstance(value, list) or len(value) > 64 or any(
        not isinstance(item, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", item) for item in value):
        return None
    return tuple(value)

def api_capabilities(model, metadata):
    found = capabilities(metadata.get("capabilities")) if isinstance(metadata, dict) else None
    state = "UNVERIFIED" if found is None else "SUPPORTED" if "tools" in found else "UNSUPPORTED"
    reason = ("Computed native tools capability confirmed." if state == "SUPPORTED" else
              "Computed capabilities exclude native tools." if state == "UNSUPPORTED" else
              "Computed capabilities are missing or malformed.")
    return ModelCompatibility(canonical_model(model), state, reason, "Exact-model Ollama /api/show")

def _read(transport, url):
    with transport.get(url, headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json, application/json"},
                       timeout=(3, 8), allow_redirects=False, stream=True) as response:
        if response.status_code != 200: raise ValueError("Metadata unavailable")
        size = response.headers.get("Content-Length")
        if size is not None and (not str(size).isdecimal() or int(size) > METADATA_LIMIT):
            raise ValueError("Metadata too large")
        body = bytearray()
        for chunk in response.iter_content(4096):
            body.extend(chunk)
            if len(body) > METADATA_LIMIT: raise ValueError("Metadata too large")
        return bytes(body), response.headers

def registry_metadata(model, session=None):
    model = canonical_model(model)
    repository, tag = model.split(":")
    if "/" not in repository: repository = "library/" + repository
    transport = session if session is not None else requests.Session()
    transport.trust_env = False
    estimate = digest = declared = None
    reason = "Registry metadata is not a complete computed capability list."
    try:
        raw, headers = _read(transport, REGISTRY + "/v2/" + repository + "/manifests/" + tag)
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        if headers.get("Docker-Content-Digest", digest) != digest: raise ValueError("Integrity")
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("schemaVersion") != 2: raise ValueError("Schema")
        layers = data.get("layers")
        if not isinstance(layers, list) or not layers: raise ValueError("Layers")
        sizes = [item.get("size") if isinstance(item, dict) else None for item in layers]
        if any(not isinstance(n, int) or isinstance(n, bool) or n <= 0 for n in sizes): raise ValueError("Size")
        if sum(sizes) >= 2**63: raise ValueError("Size")
        estimate = sum(sizes)
        config = data.get("config")
        if not isinstance(config, dict): raise ValueError("Config")
        size, target = config.get("size"), config.get("digest")
        if (config.get("mediaType") not in CONFIG_TYPES or not isinstance(size, int) or isinstance(size, bool)
            or not 0 < size <= METADATA_LIMIT or not isinstance(target, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", target)): raise ValueError("Config")
        raw, _ = _read(transport, REGISTRY + "/v2/" + repository + "/blobs/" + target)
        if len(raw) != size or "sha256:" + hashlib.sha256(raw).hexdigest() != target: raise ValueError("Integrity")
        config = json.loads(raw)
        if not isinstance(config, dict): raise ValueError("Config")
        declared = capabilities(config.get("capabilities"))
        # Ollama also computes tools from GGUF, templates, parsers and model families.
        # Registry config alone is neither exhaustive negative nor sufficient positive proof.
    except (requests.RequestException, ValueError, TypeError, KeyError, OSError):
        reason = "Official metadata unavailable, incomplete or failed integrity checks; compatibility is unverified."
    finally:
        if session is None: transport.close()
    return ModelCompatibility(model, "UNVERIFIED", reason, "Official exact-tag registry metadata",
                              estimate, digest, declared)

def inspect_model(api, model, installed):
    try: info = api_capabilities(model, api.show(model))
    except Exception: info = api_capabilities(model, None)
    if installed: return info
    try: registry = api.registry_info(model, refresh=True)
    except Exception: registry = None
    if not isinstance(registry, ModelCompatibility):
        registry = ModelCompatibility(canonical_model(model), "UNVERIFIED",
            "Official metadata unavailable; compatibility is unverified.", "Official exact-tag registry metadata")
    if info.state != "UNVERIFIED":
        return ModelCompatibility(info.model, info.state, info.reason, info.source,
                                  registry.estimated_bytes, registry.manifest_digest)
    return registry
