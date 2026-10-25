#!/usr/bin/env bash
# Independent Ollama launcher; existing MCP/Claude launchers are unchanged.
set -euo pipefail
SOURCE="$(realpath -- "${BASH_SOURCE[0]}")"
PROJECT="$(cd -- "$(dirname -- "$SOURCE")" && pwd -P)"
PYTHON=python3
if [[ -x "$PROJECT/.venv/bin/python3" ]]; then
    PYTHON="$PROJECT/.venv/bin/python3"
elif [[ -x "$PROJECT/.venv/bin/python" ]]; then
    PYTHON="$PROJECT/.venv/bin/python"
fi
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    printf '%s\n' 'Error: Python 3 is required.' >&2
    exit 1
fi
if ! "$PYTHON" "$PROJECT/redvector_ollama_dependencies.py" >/dev/null 2>&1; then
    printf '%s\n' 'Error: Install dependencies in .venv: python -m pip install -r requirements.txt -r requirements-ollama.txt' >&2
    exit 1
fi
exec "$PYTHON" "$PROJECT/redvector_ollama_setup.py" "$@"
