"""Authoritative RedVector version source.

Every runtime version consumer (startup banner, health/status output, MCP client
banner, package metadata, launcher display) reads from here. Do not hard-code the
version anywhere else.
"""

PRODUCT_NAME = "RedVector"
__version__ = "8.0.0"
VERSION = __version__


def version_string() -> str:
    """Human-readable product identity, e.g. 'RedVector 8.0.0'."""
    return "%s %s" % (PRODUCT_NAME, __version__)
