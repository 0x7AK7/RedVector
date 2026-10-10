#!/usr/bin/env python3
"""
RedVector AI - MCP layer core architecture (Phase 2).

Independent, declarative backbone for the RedVector MCP layer. It replaces the
previously ad-hoc, duplicated transport/error-handling and the un-inspectable
"parse 328 function bodies" registration model with explicit, typed, testable
components - WITHOUT changing any externally-observable MCP behavior.

Components
----------
Typed domain models:
    MCPParameterSpec   - one tool parameter (name/required/default/annotation)
    MCPRouteSpec       - backend destination (method + path)
    MCPResultPolicy    - how a tool's result is shaped (passthrough today)
    MCPToolSpec        - a full declarative tool specification

Registration:
    MCPToolRegistry    - central, inspectable catalog of registered tools
    build_tool_spec    - introspect a wrapper fn -> MCPToolSpec
    instrument_registration - wrap a FastMCP instance's ``.tool`` so every
                         registration is recorded into the registry, in order,
                         while delegating to the real FastMCP unchanged

Transport / normalization (centralizes what used to be triplicated inside
``RedVectorClient.safe_get/safe_post/safe_delete``):
    MCPErrorMapper        - exception -> legacy ``{"error":..,"success":False}``
    MCPResultNormalizer   - response -> decoded JSON (passthrough)
    MCPTransportAdapter   - base-url + path + method + (json|params) + timeout +
                            raise_for_status + error mapping, byte-identical to
                            the legacy ``safe_*`` methods

Design rules for this phase:
  * No MCP tool is added, removed, renamed or re-schema'd.
  * Wrapper functions remain the tool handlers (their per-tool payload mapping
    is legitimately unique and is preserved verbatim); this module centralizes
    only the genuinely-shared transport/error/registration concerns.
  * Every transport/error branch reproduces the original behavior exactly,
    including the exact ``{"error": f"Request failed: {str(e)}", "success": False}``
    shapes and the debug log lines.
"""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import requests


# ============================================================================
# Typed domain models
# ============================================================================

@dataclass(frozen=True)
class MCPParameterSpec:
    name: str
    required: bool
    default: Any = None
    annotation: Optional[str] = None


@dataclass(frozen=True)
class MCPRouteSpec:
    method: str                 # "GET" | "POST" | "DELETE" | "CMD"
    path: Optional[str] = None  # backend endpoint (without leading slash)


@dataclass(frozen=True)
class MCPResultPolicy:
    """How the tool's backend result is shaped before returning to the caller.
    Every current tool is ``passthrough`` (returns the backend dict verbatim);
    the enum exists so genuinely-different policies can be made explicit later
    without changing today's behavior."""
    kind: str = "passthrough"


@dataclass
class MCPToolSpec:
    name: str
    description: str = ""
    parameters: List[MCPParameterSpec] = field(default_factory=list)
    route: Optional[MCPRouteSpec] = None
    result_policy: MCPResultPolicy = field(default_factory=MCPResultPolicy)
    handler_type: str = "wrapper"   # provenance: "wrapper" | "generic" | "local"
    source: str = "redvector_mcp"   # registration provenance

    def parameter_names(self) -> List[str]:
        return [p.name for p in self.parameters]

    def required_names(self) -> List[str]:
        return [p.name for p in self.parameters if p.required]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": [
                {"name": p.name, "required": p.required, "default": p.default, "annotation": p.annotation}
                for p in self.parameters
            ],
            "route": None if self.route is None else {"method": self.route.method, "path": self.route.path},
            "result_policy": self.result_policy.kind,
            "handler_type": self.handler_type,
            "source": self.source,
        }


# ============================================================================
# Registry + registrar
# ============================================================================

class MCPToolRegistry:
    """Central, inspectable catalog of registered MCP tools, preserving
    registration order. Does not change how tools are registered with the MCP
    framework - it records them as they are registered."""

    def __init__(self) -> None:
        self._specs: Dict[str, MCPToolSpec] = {}
        self._order: List[str] = []

    def record(self, spec: MCPToolSpec) -> None:
        if spec.name not in self._specs:
            self._order.append(spec.name)
        self._specs[spec.name] = spec

    def get(self, name: str) -> MCPToolSpec:
        return self._specs[name]

    def names(self) -> List[str]:
        return list(self._order)

    def specs(self) -> List[MCPToolSpec]:
        return [self._specs[n] for n in self._order]

    def count(self) -> int:
        return len(self._order)

    def to_list(self) -> List[Dict[str, Any]]:
        return [self._specs[n].to_dict() for n in self._order]

    def clear(self) -> None:
        self._specs.clear()
        self._order.clear()


def build_tool_spec(fn: Callable, route: Optional[MCPRouteSpec] = None,
                    handler_type: str = "wrapper") -> MCPToolSpec:
    """Introspect a decorated wrapper function into a declarative spec - exactly
    the signature/docstring surface the MCP framework itself introspects."""
    sig = inspect.signature(fn)
    params: List[MCPParameterSpec] = []
    for pname, pv in sig.parameters.items():
        if pname == "self":
            continue
        required = pv.default is inspect._empty
        default = None if required else pv.default
        annotation = None
        if pv.annotation is not inspect._empty:
            annotation = getattr(pv.annotation, "__name__", None) or str(pv.annotation)
        params.append(MCPParameterSpec(name=pname, required=required, default=default, annotation=annotation))
    return MCPToolSpec(
        name=fn.__name__,
        description=fn.__doc__ or "",
        parameters=params,
        route=route,
        handler_type=handler_type,
    )


def instrument_registration(mcp: Any, registry: MCPToolRegistry) -> Any:
    """Wrap ``mcp.tool`` so each ``@mcp.tool()`` registration is also recorded
    into ``registry`` (centralized, inspectable registration), while delegating
    to the real MCP framework unchanged - same decorator semantics, same
    registration order, same resulting tools. Returns the same ``mcp`` object
    (still a genuine FastMCP instance), so callers that use ``mcp.settings`` /
    ``mcp.run`` are unaffected."""
    original_tool = mcp.tool

    def tool(*args: Any, **kwargs: Any):
        decorator = original_tool(*args, **kwargs)

        def wrapper(fn: Callable):
            try:
                registry.record(build_tool_spec(fn))
            except Exception:
                # Recording is observability only; never break registration.
                pass
            return decorator(fn)

        return wrapper

    mcp.tool = tool
    return mcp


# ============================================================================
# Transport + error/result normalization
# ============================================================================

class MCPErrorMapper:
    """Maps transport exceptions to the exact legacy error dicts."""

    @staticmethod
    def request_exception(exc: Exception) -> Dict[str, Any]:
        return {"error": f"Request failed: {str(exc)}", "success": False}

    @staticmethod
    def unexpected(exc: Exception) -> Dict[str, Any]:
        return {"error": f"Unexpected error: {str(exc)}", "success": False}


class MCPResultNormalizer:
    """Decodes a backend response. Passthrough today: returns ``response.json()``
    exactly as the legacy ``safe_*`` methods did."""

    @staticmethod
    def decode(response) -> Dict[str, Any]:
        return response.json()


class MCPTransportAdapter:
    """Centralized backend transport. Reproduces the legacy
    ``RedVectorClient.safe_get/safe_post/safe_delete`` behavior byte-for-byte:
    URL construction, ``json=`` / ``params=`` placement, ``self.timeout``,
    ``raise_for_status``, the debug log lines (with redaction) and the two
    error-mapping branches."""

    def __init__(self, session, server_url: str, timeout: int,
                 logger=None, redact: Optional[Callable[[Any], Any]] = None,
                 error_mapper: Optional[MCPErrorMapper] = None,
                 normalizer: Optional[MCPResultNormalizer] = None) -> None:
        self.session = session
        self.server_url = server_url
        self.timeout = timeout
        self._logger = logger
        self._redact = redact or (lambda x: x)
        self._errors = error_mapper or MCPErrorMapper()
        self._normalize = normalizer or MCPResultNormalizer()

    def _url(self, endpoint: str) -> str:
        return f"{self.server_url}/{endpoint}"

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if params is None:
            params = {}
        url = self._url(endpoint)
        try:
            if self._logger:
                self._logger.debug(f"📡 GET {url} with params: {self._redact(params)}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return self._normalize.decode(response)
        except requests.exceptions.RequestException as e:
            if self._logger:
                self._logger.error(f"🚫 Request failed: {str(e)}")
            return self._errors.request_exception(e)
        except Exception as e:
            if self._logger:
                self._logger.error(f"💥 Unexpected error: {str(e)}")
            return self._errors.unexpected(e)

    def post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        url = self._url(endpoint)
        try:
            if self._logger:
                self._logger.debug(f"📡 POST {url} with data: {self._redact(json_data)}")
            response = self.session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return self._normalize.decode(response)
        except requests.exceptions.RequestException as e:
            if self._logger:
                self._logger.error(f"🚫 Request failed: {str(e)}")
            return self._errors.request_exception(e)
        except Exception as e:
            if self._logger:
                self._logger.error(f"💥 Unexpected error: {str(e)}")
            return self._errors.unexpected(e)

    def delete(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        url = self._url(endpoint)
        try:
            if self._logger:
                self._logger.debug(f"📡 DELETE {url} with data: {self._redact(json_data)}")
            response = self.session.delete(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return self._normalize.decode(response)
        except requests.exceptions.RequestException as e:
            if self._logger:
                self._logger.error(f"🚫 Request failed: {str(e)}")
            return self._errors.request_exception(e)
        except Exception as e:
            if self._logger:
                self._logger.error(f"💥 Unexpected error: {str(e)}")
            return self._errors.unexpected(e)
