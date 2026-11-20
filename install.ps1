# ═══════════════════════════════════════════════════════════════════════════════
#  RedVector AI — One-command installer (Windows 11, PowerShell)
#  Creates a virtualenv, installs dependencies, ensures a secure API token, and
#  (with explicit consent) registers the RedVector MCP server in Claude Desktop
#  using the shared safe writer redvector_desktop_config.py.
#
#  Makes NO change to RedVector's tools, schemas, execution semantics or security
#  controls. Never grants tool permissions and never writes 'alwaysAllow'.
# ═══════════════════════════════════════════════════════════════════════════════
$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$VenvDir = Join-Path $ScriptDir ".venv"
$Req     = Join-Path $ScriptDir "requirements.txt"
$AssumeYes  = ($env:REDVECTOR_INSTALL_YES -eq "1")
$SkipConfig = ($env:REDVECTOR_SKIP_CLAUDE_CONFIG -eq "1")

function Info($m) { Write-Host "[RedVector] $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "[RedVector] ERROR: $m" -ForegroundColor Red; exit 1 }

# ── 1. Preflight: Python + pip (report version, do not arbitrarily cap it) ─────
# Support both `python` and the Windows launcher `py -3`, held as an executable
# plus an argument array so invocation is a single, direct PowerShell call.
$PyExe = $null; $PyArgs = @()
foreach ($cand in @("python", "py")) {
    if (Get-Command $cand -ErrorAction SilentlyContinue) {
        if ($cand -eq "py") { $PyExe = "py"; $PyArgs = @("-3") } else { $PyExe = "python"; $PyArgs = @() }
        break
    }
}
if (-not $PyExe) { Fail "Python 3 was not found on PATH. Install Python 3 and re-run." }

# Direct PowerShell invocation (no Windows command shell). Snippets avoid '%'
# so nothing is subject to shell percent-expansion. Python compatibility is not
# capped here — only a sane lower bound is enforced.
$PyVer = (& $PyExe @PyArgs -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $PyVer) { Fail "Could not run Python ($PyExe $PyArgs)." }
$PyVer = "$PyVer".Trim()
$verOk = (& $PyExe @PyArgs -c "import sys; print('ok' if sys.version_info[:2] >= (3, 9) else 'old')" 2>$null)
if ("$verOk".Trim() -ne "ok") { Fail "Python $PyVer is too old; RedVector needs Python 3.9 or newer." }
Info "Using Python $PyVer"
if (-not (Test-Path $Req)) { Fail "requirements.txt not found next to this installer." }

# ── 2. Virtualenv (idempotent: reuse if present) ──────────────────────────────
$VenvPy = Join-Path $VenvDir "Scripts\python.exe"
if (Test-Path $VenvPy) {
    Info "Reusing existing virtualenv at .venv"
} else {
    Info "Creating virtualenv at .venv ..."
    & $PyExe @PyArgs -m venv $VenvDir
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $VenvPy)) { Fail "Failed to create a virtualenv (.venv)." }
}

# ── 3. Dependencies (clear validation + error reporting) ──────────────────────
Info "Upgrading pip ..."
& $VenvPy -m pip install --upgrade pip *> $null

Info "Installing dependencies from requirements.txt ..."
$PipLog = Join-Path $ScriptDir ".install-pip.log"
& $VenvPy -m pip install -r $Req *> $PipLog
if ($LASTEXITCODE -ne 0) {
    Write-Host "[RedVector] ERROR: Dependency installation failed. Last 25 lines of the pip log:" -ForegroundColor Red
    Get-Content $PipLog -Tail 25 | Write-Host
    Write-Host "[RedVector] Common causes: no network/PyPI access (proxy/offline), or a dependency has" -ForegroundColor Red
    Write-Host "[RedVector] no wheel for Python $PyVer. Full log: $PipLog" -ForegroundColor Red
    exit 1
}
Info "Dependencies installed. Validating core imports ..."
$missing = (& $VenvPy -c @"
import importlib
missing = []
for mod in ('flask','requests','psutil','mcp.server.fastmcp'):
    try:
        importlib.import_module(mod)
    except Exception as exc:
        missing.append('%s (%s)' % (mod, exc.__class__.__name__))
print(';'.join(missing))
"@)
if ($missing) { Fail "Core dependencies did not import after installation: $missing (see $PipLog)." }
Info "Core dependencies verified (flask, requests, psutil, mcp)."

# ── 4. Secure API token (reuse redvector_credentials.py; never a dev token) ───
$Token = (& $VenvPy (Join-Path $ScriptDir "redvector_credentials.py") ensure | Out-String).Trim()
if (-not $Token -or $Token -eq "redvector-dev-token") { Fail "Could not establish a secure API token." }
Info "Secure per-user API token is in place (generated once, persisted, never shown here)."

# ── 5. Claude Desktop registration (EXPLICIT consent; safe merge; no alwaysAllow)
if ($SkipConfig) {
    Info "Skipping Claude Desktop registration (REDVECTOR_SKIP_CLAUDE_CONFIG=1)."
} else {
    $Cfg = if ($env:CLAUDE_CONFIG) { $env:CLAUDE_CONFIG } else { Join-Path $env:APPDATA "Claude\claude_desktop_config.json" }
    $DoConfig = $false
    if ($AssumeYes) {
        $DoConfig = $true
    } else {
        Write-Host "[RedVector] Register the RedVector MCP server in Claude Desktop config?" -ForegroundColor Yellow
        Write-Host "           File: $Cfg"
        Write-Host "           Other servers and your settings are preserved; no tool permissions are granted."
        $reply = Read-Host "           Proceed? [y/N]"
        if ($reply -match '^(y|yes)$') { $DoConfig = $true }
    }

    if ($DoConfig) {
        $claude = Get-Process -Name "claude" -ErrorAction SilentlyContinue
        if ($claude) { Fail "Claude Desktop is running. Fully quit it, then re-run the installer. No changes were made." }
        # Get-Process is a reliable Windows check; assert it to the writer so a
        # transient psutil 'unknown' cannot block an otherwise-verified install.
        & $VenvPy (Join-Path $ScriptDir "redvector_desktop_config.py") register `
            --project $ScriptDir --config $Cfg --platform windows --assume-stopped
        if ($LASTEXITCODE -ne 0) { Fail "Claude Desktop registration did not complete. No partial changes were written." }
    } else {
        Info "Claude Desktop was not modified. Re-run and consent to register, or edit the config manually."
    }
}

Info "Installation complete. Start Claude Desktop to use RedVector."
