# ===========================================================================
#  RedVector 8.0.0 - one-command first-run installer + launcher (Windows)
#
#  First run:   git clone ... ; cd RedVector ; .\start_redvector.ps1
#  Creates a .venv when needed, installs dependencies only when
#  requirements.txt changed, starts the backend, waits for health, then starts
#  the MCP client. No manual virtualenv activation is required.
#
#  If PowerShell blocks script execution, run it for this process only:
#     powershell -ExecutionPolicy Bypass -File .\start_redvector.ps1
#  (This launcher never changes the machine execution policy.)
# ===========================================================================

$ErrorActionPreference = "Stop"

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$Version    = "8.0.0"
$ServerHost = if ($env:REDVECTOR_HOST) { $env:REDVECTOR_HOST } else { "127.0.0.1" }
$ServerPort = if ($env:REDVECTOR_PORT) { $env:REDVECTOR_PORT } else { "8888" }
$Token      = if ($env:REDVECTOR_API_TOKEN) { $env:REDVECTOR_API_TOKEN } else { "redvector-dev-token" }
$env:REDVECTOR_API_TOKEN = $Token

$VenvDir   = Join-Path $ScriptDir ".venv"
$VenvPy    = Join-Path $VenvDir "Scripts\python.exe"
$ReqFile   = Join-Path $ScriptDir "requirements.txt"
$HashFile  = Join-Path $VenvDir ".requirements.sha256"
$HealthUrl = "http://${ServerHost}:${ServerPort}/health"

function Log  ([string]$m) { Write-Host "[RedVector] $m" -ForegroundColor Cyan }
function Die  ([string]$m) { Write-Host "[RedVector] ERROR: $m" -ForegroundColor Red; exit 1 }

# ---- 2. detect Python reliably ----
$PyCmd = $null
foreach ($c in @("python", "py")) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { $PyCmd = $c; break }
}
if (-not $PyCmd) { Die "Python was not found. Install Python 3.10+ and run the launcher again." }

# ---- 3. validate Python version (>= 3.10) ----
& $PyCmd -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)"
if ($LASTEXITCODE -ne 0) { Die "Python 3.10 or newer is required." }

# ---- 4. requirements present ----
if (-not (Test-Path $ReqFile)) { Die "requirements.txt not found next to the launcher." }

# ---- 5/6. create venv if missing ----
$FreshVenv = $false
if (-not (Test-Path $VenvPy)) {
    Log "[RedVector $Version] First-time setup detected"
    Log "Creating Python environment..."
    & $PyCmd -m venv $VenvDir
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPy)) { Die "Could not create the virtual environment (.venv)." }
    $FreshVenv = $true
} else {
    Log "[RedVector $Version] Environment ready"
}

# ---- 7. verify pip in the venv ----
& $VenvPy -m pip --version *> $null
if ($LASTEXITCODE -ne 0) {
    & $VenvPy -m ensurepip --upgrade *> $null
    if ($LASTEXITCODE -ne 0) { Die "pip is not available in the virtual environment." }
}

# ---- 8/9/10. requirements SHA-256 change detection ----
$CurHash = (Get-FileHash -Algorithm SHA256 -Path $ReqFile).Hash.ToLower()
$StoredHash = ""
if (Test-Path $HashFile) { $StoredHash = (Get-Content $HashFile -Raw).Trim().ToLower() }

function Verify-Deps {
    # Verify only the CORE backend runtime imports (see start_redvector.sh for why
    # the MCP SDK import is validated when the MCP client starts, not here).
    & $VenvPy -c "import importlib; [importlib.import_module(m) for m in ('flask','requests','psutil')]" *> $null
    return ($LASTEXITCODE -eq 0)
}

$NeedInstall = $false
if ($FreshVenv) { $NeedInstall = $true }
if ($CurHash -ne $StoredHash) { $NeedInstall = $true }
if (-not (Verify-Deps)) { $NeedInstall = $true }

if ($NeedInstall) {
    Log "Installing dependencies..."
    & $VenvPy -m pip install --upgrade pip *> $null
    & $VenvPy -m pip install -r $ReqFile
    if ($LASTEXITCODE -ne 0) { Die "Dependency installation failed. Check your network and the pip output above." }
    if (-not (Verify-Deps)) { Die "Dependencies installed but a critical import still fails." }
    Set-Content -Path $HashFile -Value $CurHash -NoNewline   # store only after a verified install
    Log "Dependencies ready"
} else {
    Log "Dependencies unchanged - skipping install"
}

# ---- Phase 10: delegate setup commands to the shared Python layer ----
$SetupFlags = @("--connect-claude","--connect-cursor","--disconnect-claude","--disconnect-cursor",
                "--setup-ai","--setup-harness","--install-dsh","--diagnostics","--status","--provider")
$IsSetupCmd = $false
foreach ($a in $args) { if ($SetupFlags -contains $a -or $a -like "--provider=*") { $IsSetupCmd = $true } }
if ($IsSetupCmd) {
    & $VenvPy -m redvector.setup @args
    exit $LASTEXITCODE
}

# First-run / interactive preflight. Exit 10 means "start RedVector normally".
& $VenvPy -m redvector.setup
$PreflightRc = $LASTEXITCODE
if ($PreflightRc -ne 10) { exit $PreflightRc }

# ---- 11/12/13. start backend if not already healthy ----
$Running = $false
try {
    $r = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue
    if ($r.StatusCode -eq 200) { $Running = $true }
} catch { $Running = $false }

if ($Running) {
    Log "Backend already running on ${ServerHost}:${ServerPort}"
} else {
    Log "Starting backend..."
    $out = Join-Path $ScriptDir "server_stdout.log"
    $err = Join-Path $ScriptDir "server_stderr.log"
    Start-Process -FilePath $VenvPy -ArgumentList "-m", "redvector", "--port", $ServerPort, "--host", $ServerHost `
        -WorkingDirectory $ScriptDir -RedirectStandardOutput $out -RedirectStandardError $err `
        -WindowStyle Hidden -PassThru | Out-Null
    $Healthy = $false
    for ($i = 1; $i -le 30; $i++) {
        Start-Sleep -Seconds 1
        try {
            $r = Invoke-WebRequest -Uri $HealthUrl -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
            if ($r.StatusCode -eq 200) { $Healthy = $true; break }
        } catch {}
    }
    if (-not $Healthy) { Die "backend did not become healthy within 30s. Check server_stderr.log" }
    Log "Backend ready on ${ServerHost}:${ServerPort}"
}

# ---- concise aggregated status (read-only) ----
& $VenvPy -m redvector.setup --status

# ---- 14. start the MCP client ----
Log "Starting MCP..."
& $VenvPy -m redvector.mcp.server --server "http://${ServerHost}:${ServerPort}" @args
