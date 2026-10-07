# ═══════════════════════════════════════════════════════════════════════════════
#  RedVector AI v8.0 - Windows Launcher (PowerShell)
#  Auto-starts the backend server (if not running) then launches the MCP client.
#  Used by Ollama / Claude Desktop / AI agents via mcp.json.
# ═══════════════════════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

# Resolve the directory where this script lives
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Configurable
$ServerPort = if ($env:REDVECTOR_PORT) { $env:REDVECTOR_PORT } else { "8888" }
$ServerHost = if ($env:REDVECTOR_HOST) { $env:REDVECTOR_HOST } else { "127.0.0.1" }
$Token = if ($env:REDVECTOR_API_TOKEN) { $env:REDVECTOR_API_TOKEN } else { "redvector-dev-token" }

$env:REDVECTOR_API_TOKEN = $Token

# Activate virtualenv if it exists
$VenvActivate = Join-Path $ScriptDir ".venv\Scripts\Activate.ps1"
if (Test-Path $VenvActivate) {
    & $VenvActivate
}

# Auto-start the backend server if not already running
$HealthUrl = "http://${ServerHost}:${ServerPort}/health"
$ServerRunning = $false
try {
    $response = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue
    if ($response.StatusCode -eq 200) { $ServerRunning = $true }
} catch {
    $ServerRunning = $false
}

if (-not $ServerRunning) {
    Write-Host "[RedVector] Backend not running - starting redvector_server.py on port $ServerPort ..." -ForegroundColor Yellow
    $ServerScript = Join-Path $ScriptDir "redvector_server.py"
    $StdoutLog = Join-Path $ScriptDir "server_stdout.log"
    $StderrLog = Join-Path $ScriptDir "server_stderr.log"
    Start-Process -FilePath "python" -ArgumentList $ServerScript, "--port", $ServerPort `
        -RedirectStandardOutput $StdoutLog -RedirectStandardError $StderrLog `
        -WindowStyle Hidden -PassThru | Out-Null

    # Wait up to 30 seconds for the server to become healthy
    $ServerHealthy = $false
    for ($i = 1; $i -le 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $response = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200) {
                Write-Host "[RedVector] Server is healthy after ${i}s" -ForegroundColor Green
                $ServerHealthy = $true
                break
            }
        } catch {}
    }
    if (-not $ServerHealthy) {
        Write-Host "[RedVector] ERROR: Server did not become healthy within 30s. Check server_stdout.log" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[RedVector] Backend already running on ${ServerHost}:${ServerPort}" -ForegroundColor Green
}

# Launch the MCP client - pass through any extra arguments
$McpScript = Join-Path $ScriptDir "redvector_mcp.py"
& python $McpScript --server "http://${ServerHost}:${ServerPort}" @args
