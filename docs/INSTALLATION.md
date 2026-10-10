# Installation

## Requirements

- Python **3.10+**
- An OS of Windows, macOS, or Linux
- External security binaries you intend to use (e.g. nmap, nuclei, trivy) installed and on `PATH` - RedVector invokes them but does not install them
- Optional: [Ollama](https://ollama.com) for local AI, or an API key for a cloud provider

## 1. Get the code and create a virtual environment

```bash
git clone <your-fork-url> redvector
cd redvector
python -m venv .venv
```

Activate it:

- **Linux/macOS:** `source .venv/bin/activate`
- **Windows (PowerShell):** `.\.venv\Scripts\Activate.ps1`

## 2. Install Python dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Start the backend

```bash
python -m redvector
```

Default address: `http://127.0.0.1:8888`.

## 4. Verify

```bash
curl http://127.0.0.1:8888/health
```

On Windows PowerShell:

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8888/health"
```

## 5. Connect an AI client (MCP)

Start the MCP server (stdio by default), pointing at the backend:

```bash
python -m redvector.mcp.server --server http://127.0.0.1:8888
```

Or use the launcher scripts (`start_redvector.sh` / `start_redvector.ps1`) which start the backend if needed and then launch MCP. See [AI_INTEGRATION.md](AI_INTEGRATION.md) for one-click client setup.

## 6. AI Integration Manager

With the backend running, the management API under `/api/ai/*` lets you list/test/switch AI providers and configure MCP clients without editing JSON by hand. See [AI_INTEGRATION.md](AI_INTEGRATION.md).

## Security-tool dependencies

Each security integration calls an external binary. If a required binary is missing, that tool returns a failure result; other tools are unaffected. Install only the tools you need.
