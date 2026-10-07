#!/usr/bin/env python3
"""
RedVector AI - declarative security-tool integration model (Phase 3).

Phase 3 replaces hand-written, duplicated command-construction in the Flask
security-tool routes with a RedVector-specific declarative tool model, WITHOUT
changing any externally-observable behavior.

Conceptual flow for a migrated tool:

    SecurityToolSpec            (declarative metadata = source of truth)
          |
    SecurityToolRegistry        (central, inspectable catalog + provenance)
          |
    CommandBuilder              (constructs the EXACT legacy command string)
          |
    (route) execute_command     (unchanged Phase-1 execution backend)
          |
    existing RedVector result   (unchanged public result/error schema)

Only the command-construction step is inverted to be spec-driven, and ONLY for
tools whose command is provably, byte-for-byte reproducible from the spec across
many argument probes (see tests/test_redvector_security_tools.py). Every other
tool keeps its explicit custom handler; all 134 tools are represented in the
registry for inventory/provenance.

Hard compatibility rules (this phase):
  * No tool added / removed / renamed / weakened.
  * Command construction is a FROZEN contract: same executable, same flags,
    same order, same quoting, same defaults, same optional inclusion/omission.
  * Execution, result shaping, and error shaping are untouched by this module;
    it only centralizes command building + typed provenance.
"""

from __future__ import annotations

import ast
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

SPECS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "security_tool_specs.json")


# ============================================================================
# Typed domain model
# ============================================================================

@dataclass(frozen=True)
class ToolParameterSpec:
    name: str
    required: bool = False
    default_repr: Optional[str] = None

    @property
    def default(self) -> Any:
        if self.default_repr is None:
            return None
        try:
            return ast.literal_eval(self.default_repr)
        except Exception:
            return self.default_repr


@dataclass(frozen=True)
class CommandSegment:
    """One appended command fragment. ``condition`` is the name of a parameter
    whose truthiness gates inclusion (None => always appended). ``template`` is
    a ``str.format`` template using positional ``{0},{1}...`` placeholders that
    map, in order, to ``params``."""
    condition: Optional[str]
    template: str
    params: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class CommandSpec:
    base_template: str
    base_params: List[str] = field(default_factory=list)
    segments: List[CommandSegment] = field(default_factory=list)


@dataclass(frozen=True)
class ExecutionPolicy:
    """How the command is executed. Phase 3 does not change execution; this
    records which Phase-1 backend the route uses."""
    backend: str = "execute_command"       # "execute_command" today for migrated tools
    use_cache: bool = True


@dataclass(frozen=True)
class OutputPolicy:
    kind: str = "passthrough"               # result returned verbatim by the route


@dataclass(frozen=True)
class ErrorPolicy:
    missing_required: str = "400"
    exception: str = "500"


@dataclass(frozen=True)
class ToolProvenance:
    canonical_id: str
    public_wrapper: str
    executable: Optional[str]
    spec_source: str
    execution_adapter: str
    result_policy: str


@dataclass(frozen=True)
class SecurityToolSpec:
    tool_name: str
    path: str
    wrapper: str
    handler_type: str                       # "declarative" | "custom"
    parameters: List[ToolParameterSpec]
    provenance: ToolProvenance
    command: Optional[CommandSpec] = None    # present for declarative tools
    param_var: str = "params"
    execution: ExecutionPolicy = field(default_factory=ExecutionPolicy)
    output: OutputPolicy = field(default_factory=OutputPolicy)
    error: ErrorPolicy = field(default_factory=ErrorPolicy)

    def parameter_names(self) -> List[str]:
        return [p.name for p in self.parameters]

    def defaults(self) -> Dict[str, Any]:
        return {p.name: p.default for p in self.parameters}


# ============================================================================
# Command builder (reproduces the exact legacy command string)
# ============================================================================

class CommandBuilder:
    """Builds the command string for a declarative tool exactly as the original
    hand-written wrapper did: start from the base template, then append each
    segment whose gating parameter is truthy (or unconditional). Parameter
    values come from the incoming request params, falling back to the spec
    default - identical to the wrappers' ``params.get(name, default)``."""

    @staticmethod
    def build(spec: SecurityToolSpec, params: Dict[str, Any]) -> str:
        if spec.command is None:
            raise ValueError("tool %r is not declarative (no command spec)" % spec.tool_name)
        defaults = spec.defaults()

        def value(name: str) -> Any:
            return params.get(name, defaults.get(name))

        cmd = spec.command.base_template.format(*[value(n) for n in spec.command.base_params])
        for seg in spec.command.segments:
            include = True if seg.condition is None else bool(value(seg.condition))
            if include:
                cmd += seg.template.format(*[value(n) for n in seg.params])
        return cmd


# ============================================================================
# Registry (source of truth + inventory/provenance for every tool)
# ============================================================================

class SecurityToolRegistry:
    def __init__(self) -> None:
        self._specs: Dict[str, SecurityToolSpec] = {}
        self._order: List[str] = []

    def register(self, spec: SecurityToolSpec) -> None:
        if spec.tool_name not in self._specs:
            self._order.append(spec.tool_name)
        self._specs[spec.tool_name] = spec

    def get(self, name: str) -> SecurityToolSpec:
        return self._specs[name]

    def names(self) -> List[str]:
        return list(self._order)

    def count(self) -> int:
        return len(self._order)

    def declarative_names(self) -> List[str]:
        return [n for n in self._order if self._specs[n].handler_type == "declarative"]

    def custom_names(self) -> List[str]:
        return [n for n in self._order if self._specs[n].handler_type == "custom"]

    def build_command(self, name: str, params: Dict[str, Any]) -> str:
        """Spec-driven command construction for a migrated tool. This is the
        source-of-truth entry point the Flask routes call."""
        return CommandBuilder.build(self._specs[name], params)


# ============================================================================
# Thin result/error normalizers + execution adapter (centralization points)
# ============================================================================

class ToolResultNormalizer:
    """Passthrough today: migrated routes return the ``execute_command`` result
    dict verbatim (plus any route-specific additions the route still performs).
    Exists as the single future seam for result normalization."""

    @staticmethod
    def normalize(result: Dict[str, Any]) -> Dict[str, Any]:
        return result


class ToolErrorMapper:
    """Documents the existing error contract (missing-required => 400,
    unexpected => 500). Not invoked by Phase-3 routes (their error handling is
    unchanged); provided for provenance/future centralization."""

    @staticmethod
    def missing_required(field_name: str) -> Dict[str, Any]:
        return {"error": "%s parameter is required" % field_name}


class ToolExecutionAdapter:
    """Optional centralized execution boundary that delegates to the injected
    Phase-1 ``execute_command`` without changing its behavior. Phase-3 routes
    continue to call ``execute_command`` directly; this adapter exists for
    provenance and future job-orchestration without broadening capability."""

    def __init__(self, execute_command) -> None:
        self._execute_command = execute_command

    def run(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        return self._execute_command(command, use_cache)


# ============================================================================
# Spec loading
# ============================================================================

def _spec_from_dict(d: Dict[str, Any]) -> SecurityToolSpec:
    params = [ToolParameterSpec(name=p["name"], required=bool(p["required"]),
                                default_repr=p.get("default_repr"))
              for p in d.get("parameters", [])]
    prov_d = d.get("provenance", {})
    provenance = ToolProvenance(
        canonical_id=prov_d.get("canonical_id", d["tool_name"]),
        public_wrapper=prov_d.get("public_wrapper", d.get("wrapper", "")),
        executable=prov_d.get("executable"),
        spec_source=prov_d.get("spec_source", "security_tool_specs.json"),
        execution_adapter=prov_d.get("execution_adapter", "execute_command"),
        result_policy=prov_d.get("result_policy", "passthrough"),
    )
    command = None
    if d.get("handler_type") == "declarative" and "command" in d:
        c = d["command"]
        command = CommandSpec(
            base_template=c["base_template"],
            base_params=list(c.get("base_params", [])),
            segments=[CommandSegment(condition=s["condition"], template=s["template"],
                                     params=list(s.get("params", [])))
                      for s in c.get("segments", [])],
        )
    return SecurityToolSpec(
        tool_name=d["tool_name"], path=d["path"], wrapper=d["wrapper"],
        handler_type=d["handler_type"], parameters=params, provenance=provenance,
        command=command, param_var=d.get("param_var", "params"),
    )


def load_specs(path: str = SPECS_PATH) -> Dict[str, Dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def build_registry(path: str = SPECS_PATH) -> SecurityToolRegistry:
    reg = SecurityToolRegistry()
    for name, d in load_specs(path).items():
        reg.register(_spec_from_dict(d))
    return reg


# Module-level registry: the runtime source of truth for security-tool command
# construction (migrated tools) and inventory/provenance (all tools).
SECURITY_TOOL_REGISTRY = build_registry()
