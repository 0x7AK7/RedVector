"""Unified three-dimension AI status model (Phase 10.2).

Every AI client / provider / harness reports three independent dimensions so the
dimensions are never conflated:

  Installation  - is the app/runtime actually present?   (config existing != installed)
  Configuration - is RedVector's integration set up?      (installed != configured)
  Connection    - is a live connection actually observed?  (configured != connected)

CONNECTED is only ever reported when real connectivity is observed; it is never
fabricated. Desktop clients own their own session, so their Connection is
NOT_OBSERVABLE, not CONNECTED.
"""
from __future__ import annotations

# Installation
INSTALLED = "INSTALLED"
NOT_INSTALLED = "NOT_INSTALLED"
UNKNOWN = "UNKNOWN"
NOT_APPLICABLE = "NOT_APPLICABLE"

# Configuration
CONFIGURED = "CONFIGURED"
NOT_CONFIGURED = "NOT_CONFIGURED"
INVALID = "INVALID"
STALE = "STALE"
SETUP_REQUIRED = "SETUP_REQUIRED"

# Connection
CONNECTED = "CONNECTED"
NOT_CONNECTED = "NOT_CONNECTED"
NOT_OBSERVABLE = "NOT_OBSERVABLE"
NOT_RUNNING = "NOT_RUNNING"
READY = "READY"

_DISPLAY = {
    "NOT_INSTALLED": "NOT INSTALLED", "NOT_APPLICABLE": "NOT APPLICABLE",
    "NOT_CONFIGURED": "NOT CONFIGURED", "SETUP_REQUIRED": "SETUP REQUIRED",
    "NOT_CONNECTED": "NOT CONNECTED", "NOT_OBSERVABLE": "NOT OBSERVABLE",
    "NOT_RUNNING": "NOT RUNNING",
}


def disp(value: str) -> str:
    """Human display tag for a status value (underscores -> spaces)."""
    return _DISPLAY.get(value, value)
