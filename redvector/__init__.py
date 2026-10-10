"""RedVector - AI-assisted offensive security platform.

This package intentionally keeps its top-level import light: it exposes only
version metadata and does NOT eagerly import the heavy runtime modules
(``server``, ``mcp.server``, ``agent``, ...). Import those explicitly, e.g.::

    from redvector import server
    from redvector import agent
    from redvector.mcp import server as mcp_server
"""

from redvector.version import PRODUCT_NAME, __version__, VERSION, version_string

__all__ = ["PRODUCT_NAME", "__version__", "VERSION", "version_string"]
