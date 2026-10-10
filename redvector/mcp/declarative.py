#!/usr/bin/env python3
"""
RedVector AI - MCP layer declarative registration (Phase 2B).

Phase 2A made ``MCPToolRegistry`` / ``MCPToolSpec`` an inspectable catalog that
*recorded* the 328 hand-written ``@mcp.tool()`` wrappers. Phase 2B turns the
declarative specs into the real **source of truth** for the subset of tools
whose behavior is provably, exactly representable by a declarative spec: those
tools are generated from ``redvector_mcp_specs.json`` and registered through the
registrar, instead of through their legacy wrapper bodies.

Scope / invariants (identical externally-observable behavior):
  * No tool is added, removed, renamed, or re-schema'd.
  * Generated handlers reproduce, byte-for-byte, the wrapper they replace:
    the exact signature (names / annotations / defaults / return annotation),
    the cleaned docstring, the single backend call (method + path + payload
    mapping), the passthrough result, the error behavior, and the exact
    logging side effects (pre / success / fail).
  * Registration ORDER is unchanged: the substituting registrar swaps the
    generated handler in at the same ordinal position the legacy decorator
    fired, and never registers a migrated tool twice.
  * Tools that are NOT provably representable (e.g. a branch condition or a
    log message derived from the response body) stay as explicit custom
    handlers. ``DECLARATIVE_EXCLUSIONS`` lists the specced-but-retained tools
    with the reason; the Phase-2B test suite re-derives this set from a live
    differential proof and fails if it drifts.

Spec schema (one entry per tool in ``redvector_mcp_specs.json``):
    name, method (safe_get|safe_post|safe_delete), path, has_payload,
    mapping [[payload_key, param_name], ...], params [{name, annotation,
    required, default_repr}], ret_ann, docstring (raw), logpolicy
    {pre|success|fail: [{level, segs:[["c", const] | ["p", param], ...]}]}.
"""

from __future__ import annotations

import ast
import json
import os
from typing import Any, Callable, Dict, List

from redvector.mcp import core as _core

SPECS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "specs.json")


def load_tool_specs(path: str = SPECS_PATH) -> Dict[str, Dict[str, Any]]:
    """Load the declarative tool specs catalog (keyed by tool name)."""
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


TOOL_SPECS: Dict[str, Dict[str, Any]] = load_tool_specs()

# Specced tools deliberately RETAINED as custom handlers because their current
# behavior is not exactly representable by the declarative schema. Re-derived
# and asserted by tests/test_redvector_mcp_phase2b.py (live differential proof).
DECLARATIVE_EXCLUSIONS: "frozenset[str]" = frozenset({
    # get_live_dashboard branches on result.get("success", True) (default True),
    # so an empty/absent-"success" response logs SUCCESS in the wrapper but would
    # log FAILURE through the declarative success/fail policy. Not representable.
    "get_live_dashboard",
})

# The proven, conservatively-selected migration set: every specced tool except
# the retained exclusions. Driven by the specs catalog, not a magic list.
MIGRATED_TOOLS: "frozenset[str]" = frozenset(TOOL_SPECS) - DECLARATIVE_EXCLUSIONS


# ============================================================================
# Code generation: spec -> handler (genuine function w/ exact signature)
# ============================================================================

def _render_seg(seg: List[Any]) -> str:
    kind, val = seg[0], seg[1]
    if kind == "c":            # constant text
        return repr(val)
    if kind == "p":            # interpolated parameter value (f"{param}")
        return "str(%s)" % val
    raise ValueError("unknown log segment kind: %r" % (kind,))


def _render_msg(segs: List[List[Any]]) -> str:
    if not segs:
        return "''"
    return " + ".join(_render_seg(s) for s in segs)


def generate_handler_source(spec: Dict[str, Any]) -> str:
    """Generate the exact Python source for a tool's declarative handler.

    Mirrors the canonical wrapper shape: build ``data`` (payload tools), emit
    the pre log(s), make the one backend call, emit success/fail log(s) when
    the wrapper had them, and return the backend result verbatim.
    """
    name = spec["name"]
    sig_parts = []
    for p in spec["params"]:
        part = "%s: %s" % (p["name"], p["annotation"])
        if not p["required"]:
            part += " = " + p["default_repr"]
        sig_parts.append(part)
    header = "def %s(%s) -> %s:" % (name, ", ".join(sig_parts), spec["ret_ann"])

    body: List[str] = []
    if spec["has_payload"]:
        if spec["mapping"]:
            items = ", ".join("%r: %s" % (key, param) for key, param in spec["mapping"])
            body.append("data = {%s}" % items)
        else:
            body.append("data = {}")

    logpolicy = spec["logpolicy"]
    for stmt in logpolicy.get("pre", []):
        body.append("logger.%s(%s)" % (stmt["level"], _render_msg(stmt["segs"])))

    if spec["has_payload"]:
        call = "redvector_client.%s(%r, data)" % (spec["method"], spec["path"])
    else:
        call = "redvector_client.%s(%r)" % (spec["method"], spec["path"])
    body.append("result = " + call)

    success = logpolicy.get("success", [])
    fail = logpolicy.get("fail", [])
    if success or fail:
        body.append('if result.get("success"):')
        if success:
            for stmt in success:
                body.append("    logger.%s(%s)" % (stmt["level"], _render_msg(stmt["segs"])))
        else:
            body.append("    pass")
        if fail:
            body.append("else:")
            for stmt in fail:
                body.append("    logger.%s(%s)" % (stmt["level"], _render_msg(stmt["segs"])))
    body.append("return result")

    return header + "\n" + "\n".join("    " + line for line in body)


def build_declarative_handler(spec: Dict[str, Any], redvector_client: Any,
                              logger: Any) -> Callable:
    """Compile a spec into a genuine handler function closing over the given
    client + logger, with the exact signature/annotations/defaults/docstring."""
    namespace: Dict[str, Any] = {
        "Dict": Dict, "Any": Any, "List": List,
        "redvector_client": redvector_client, "logger": logger,
    }
    source = generate_handler_source(spec)
    # dont_inherit=True: do NOT inherit this module's ``from __future__ import
    # annotations`` (PEP 563) into the generated handler, so its annotations are
    # real objects (str/bool/int/Dict[...]) exactly like the wrappers it
    # replaces - required for byte-identical ``inspect.signature`` parity.
    code = compile(source, "<declarative:%s>" % spec["name"], "exec", dont_inherit=True)
    exec(code, namespace)
    fn = namespace[spec["name"]]
    fn.__doc__ = spec["docstring"]
    fn.__wrapped_spec__ = spec            # provenance
    fn._declarative = True                # marker: source-of-truth = spec
    return fn


def spec_to_toolspec(spec: Dict[str, Any]) -> _core.MCPToolSpec:
    """Build the registry's ``MCPToolSpec`` record for a declarative tool."""
    params: List[_core.MCPParameterSpec] = []
    for p in spec["params"]:
        required = bool(p["required"])
        default = None
        if not required and p.get("default_repr") is not None:
            try:
                default = ast.literal_eval(p["default_repr"])
            except Exception:
                default = None
        params.append(_core.MCPParameterSpec(
            name=p["name"], required=required, default=default,
            annotation=p.get("annotation")))
    return _core.MCPToolSpec(
        name=spec["name"],
        description=spec.get("docstring") or "",
        parameters=params,
        route=_core.MCPRouteSpec(method=spec["method"], path=spec.get("path")),
        handler_type="generic",
        source="redvector_mcp_specs",
    )


# ============================================================================
# Substituting registrar
# ============================================================================

def instrument_registration_declarative(mcp: Any, registry: "_core.MCPToolRegistry",
                                         specs: Dict[str, Dict[str, Any]],
                                         migrated: "frozenset[str]",
                                         redvector_client: Any, logger: Any) -> Any:
    """Wrap ``mcp.tool`` so that, as each ``@mcp.tool()`` fires in source order:

      * a MIGRATED tool is registered from its declarative spec (handler built
        here) and recorded with ``handler_type="generic"`` - the legacy wrapper
        body is NOT registered (source of truth = spec); and
      * a RETAINED tool is registered exactly as before (its wrapper fn) and
        recorded with ``handler_type="wrapper"``.

    Registration order and the one-registration-per-tool guarantee are
    preserved because the substitution happens in-place at the same decorator
    call. Returns the same ``mcp`` object.
    """
    original_tool = mcp.tool

    def tool(*args: Any, **kwargs: Any):
        def wrapper(fn: Callable):
            name = getattr(fn, "__name__", None)
            if name in migrated:
                handler = build_declarative_handler(specs[name], redvector_client, logger)
                # Register the generated handler through the real framework.
                original_tool(*args, **kwargs)(handler)
                try:
                    registry.record(spec_to_toolspec(specs[name]))
                except Exception:
                    pass
                # Return the (now unregistered) legacy fn unchanged; its binding
                # inside setup_mcp_server is never used elsewhere.
                return fn
            decorator = original_tool(*args, **kwargs)
            try:
                registry.record(_core.build_tool_spec(fn))
            except Exception:
                pass
            return decorator(fn)

        return wrapper

    mcp.tool = tool
    return mcp
