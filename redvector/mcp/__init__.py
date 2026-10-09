"""RedVector MCP subpackage (server, core, declarative registration).

Kept import-light on purpose: importing ``redvector.mcp`` does not pull in the
third-party ``mcp`` runtime or register tools. Import the modules you need, e.g.::

    from redvector.mcp import server, core, declarative
"""
