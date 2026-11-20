# ═══════════════════════════════════════════════════════════════════════════════
#  RedVector AI v8.1.0 - Windows Launcher (PowerShell)
#  Auto-starts the backend server (if not running) then launches the MCP client.
#  Used by Claude Desktop / AI agents via mcp.json.
# ═══════════════════════════════════════════════════════════════════════════════

$ErrorActionPreference = "Stop"

# Resolve the directory where this script lives
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# Configurable
$ServerPort = if ($env:REDVECTOR_PORT) { $env:REDVECTOR_PORT } else { "8888" }
$ServerHost = if ($env:REDVECTOR_HOST) { $env:REDVECTOR_HOST } else { "127.0.0.1" }

# Authentication token (CWE-798): no hard-coded default credential. An
# explicitly provided token is honoured and never rotated; the revoked published
# development token is rejected; otherwise a strong token is generated ONCE and
# PERSISTED by redvector_credentials.py so the backend and the MCP client share
# the SAME credential across restarts and reboots (no per-launch ephemeral
# token, which previously caused 401 / "Connection closed").
if ($env:REDVECTOR_API_TOKEN -eq "redvector-dev-token") {
    Write-Host "[RedVector] ERROR: REDVECTOR_API_TOKEN is set to the insecure published development token. Refusing to start. Unset it (the Claude Desktop manager migrates it automatically) or set a strong, unique token." -ForegroundColor Red
    exit 1
}
$PyExe = "python"
$VenvPy = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (Test-Path $VenvPy) { $PyExe = $VenvPy }
$Token = (& $PyExe (Join-Path $ScriptDir "redvector_credentials.py") ensure | Out-String).Trim()
if (-not $Token -or $Token -eq "redvector-dev-token") {
    Write-Host "[RedVector] ERROR: Unable to establish a secure API token. Set REDVECTOR_API_TOKEN explicitly or check the credential store." -ForegroundColor Red
    exit 1
}
if (-not $env:REDVECTOR_API_TOKEN) {
    Write-Host "[RedVector] Using a persisted per-user API token (generated automatically on first run). No manual token setup is required." -ForegroundColor Green
}

$env:REDVECTOR_API_TOKEN = $Token

# Activate virtualenv if it exists
$VenvActivate = Join-Path $ScriptDir ".venv\Scripts\Activate.ps1"
if (Test-Path $VenvActivate) {
    & $VenvActivate
}

# Auto-start the backend server if not already running
$HealthUrl = "http://${ServerHost}:${ServerPort}/health"
$ApiUrl    = "http://${ServerHost}:${ServerPort}/api/processes/list"

# Authenticated probe: confirms a RUNNING backend accepts THIS session's token.
# A healthy /health response (unauthenticated) is NOT proof the MCP connection
# will authenticate, so credential conflicts are detected here. No process is
# ever stopped to resolve a conflict.
function Test-RedVectorAuth {
    param([string]$Url, [string]$Tok)
    try {
        $r = Invoke-WebRequest -Uri $Url -Headers @{ Authorization = "Bearer $Tok" } `
            -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        return ($r.StatusCode -eq 200)
    } catch {
        return $false
    }
}

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

    # Wait up to 30 seconds for the server to become healthy AND authenticate.
    $ServerHealthy = $false
    for ($i = 1; $i -le 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $response = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 200 -and (Test-RedVectorAuth $ApiUrl $Token)) {
                Write-Host "[RedVector] Server is healthy and authenticating after ${i}s" -ForegroundColor Green
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
    if (-not (Test-RedVectorAuth $ApiUrl $Token)) {
        Write-Host "[RedVector] ERROR: A RedVector backend is already running on ${ServerHost}:${ServerPort}, but it does not accept this session's API token (credential conflict). No process was stopped. Stop that backend and relaunch, or set REDVECTOR_API_TOKEN to the credential it was started with." -ForegroundColor Red
        exit 1
    }
    Write-Host "[RedVector] Backend already running on ${ServerHost}:${ServerPort} (authenticated)" -ForegroundColor Green
}

# Launch the MCP client - pass through any extra arguments
$McpScript = Join-Path $ScriptDir "redvector_mcp.py"
& python $McpScript --server "http://${ServerHost}:${ServerPort}" @args
