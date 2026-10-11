#!/usr/bin/env python3
"""
Opt-in session/runtime trace (Phase 10.5 Fix #5, Step 1).

Enabled ONLY when the environment variable ``REDVECTOR_DEBUG_SESSION`` is set to a
truthy value (1/true/yes/on). Default is OFF. It logs *safe metadata only* about how
a chat turn flows through chat -> backend -> ConversationManager -> AgentSession ->
planner -> resolver -> evidence, so the exact point where a target or scope is lost
is visible. It never logs secrets, API keys, credentials, raw tool output, or model
reasoning.

The facility is intentionally tiny and dependency-free so it can stay in the tree
as a permanent, opt-in diagnostic.
"""

from __future__ import annotations

import os
import sys
from typing import Any

_TRUTHY = {"1", "true", "yes", "on"}


def enabled() -> bool:
    return str(os.environ.get("REDVECTOR_DEBUG_SESSION", "")).strip().lower() in _TRUTHY


# keys that must never be emitted even if a caller passes them by mistake
_FORBIDDEN = {"token", "api_key", "apikey", "key", "secret", "password", "credential",
              "credentials", "authorization_header", "stdout", "raw", "output",
              "reasoning", "chain_of_thought", "prompt"}


def _safe(value: Any) -> Any:
    # scalars pass through; collections are reduced to lengths; anything else -> type
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= 120 else (value[:117] + "...")
    if isinstance(value, (list, tuple, set, dict)):
        return "<%s len=%d>" % (type(value).__name__, len(value))
    return "<%s>" % type(value).__name__


def trace(component: str, **fields: Any) -> None:
    """Emit one safe trace line for ``component`` when debug is enabled."""
    if not enabled():
        return
    parts = []
    for k, v in fields.items():
        if k.lower() in _FORBIDDEN:
            continue
        parts.append("%s=%s" % (k, _safe(v)))
    line = "[RV-TRACE %s] %s" % (component, " ".join(parts))
    try:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    except Exception:
        pass
