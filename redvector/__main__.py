"""Package entrypoint: ``python -m redvector``.

Starts the RedVector backend API server by delegating to the single
authoritative startup implementation in ``redvector.server.main``. It does not
reimplement any backend or MCP startup logic.

The MCP client has its own module entrypoint: ``python -m redvector.mcp.server``.
"""
from redvector.server import main

if __name__ == "__main__":
    main()
