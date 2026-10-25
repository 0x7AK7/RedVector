#!/usr/bin/env bash
# English terminal installer; leaves Claude Desktop configuration untouched.
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
trap 'printf "\nInstallation cancelled safely.\n" >&2; exit 130' INT TERM
if ! "$PYTHON" "$PROJECT/redvector_ollama_dependencies.py" >/dev/null 2>&1; then
    printf '%s\n' 'Python dependencies are missing.' 'Install backend and Ollama Python dependencies in the project .venv? [y/N]' >&2
    ANSWER=
    read -r ANSWER || true
    ANSWER="${ANSWER%$'\r'}"
    if [[ "$ANSWER" != y && "$ANSWER" != Y ]]; then
        printf '%s\n' 'Error: dependencies were not installed. Run this installer again to retry.' >&2
        exit 1
    fi
    if [[ "$PYTHON" == python3 ]]; then
        if [[ -e "$PROJECT/.venv" ]]; then
            printf '%s\n' 'Error: .venv exists without a usable interpreter. Repair it manually; it was not overwritten.' >&2
            exit 1
        fi
        if ! python3 -m venv "$PROJECT/.venv"; then
            printf '%s\n' 'Error: venv creation failed. Install python3-venv for your Python version, then retry.' >&2
            exit 1
        fi
        PYTHON="$PROJECT/.venv/bin/python3"
    fi
    "$PYTHON" -m pip install -r "$PROJECT/requirements.txt" -r "$PROJECT/requirements-ollama.txt"
    if ! "$PYTHON" "$PROJECT/redvector_ollama_dependencies.py" >/dev/null 2>&1; then
        printf '%s\n' 'Error: dependency verification failed. Review the installation output.' >&2
        exit 1
    fi
fi
exec "$PYTHON" "$PROJECT/redvector_ollama_setup.py" --install "$@"
