<#
.SYNOPSIS
  ATOR DFIR agent deployment helper.

  Mode "package"  (run on HOST / repo):    builds scripts\out\ator-agent-deploy.zip
  Mode "endpoint" (run on ENDPOINT/VM):    installs, enrolls, verifies, optional scheduled task

.EXAMPLE (host)
  powershell -ExecutionPolicy Bypass -File scripts\deploy_agent.ps1 -Mode package

.EXAMPLE (endpoint; zip already copied + extracted)
  powershell -ExecutionPolicy Bypass -File scripts\deploy_agent.ps1 `
      -Mode endpoint -BaseUrl http://192.168.50.1:8000 `
      -AgentRoot C:\ator-agent-pkg -InstallDir C:\ator-agent -InstallScheduledTask
#>
param(
    [ValidateSet("package", "endpoint")]
    [string]$Mode = "package",
    [string]$BaseUrl = "http://127.0.0.1:8000",
    [string]$InstallDir = "C:\ator-agent",
    [string]$AgentRoot,
    [switch]$InstallScheduledTask
)
$ErrorActionPreference = "Stop"

function Get-RepoRoot {
    return Split-Path -Parent $PSScriptRoot
}

if ($Mode -eq "package") {
    $root = Get-RepoRoot
    $outDir = Join-Path $root "scripts\out"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $zipPath = Join-Path $outDir "ator-agent-deploy.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    $stage = Join-Path $env:TEMP ("ator_stage_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
    try {
        # Stage ONLY the agent package so the endpoint gets the real module layout:
        #   agent\__init__.py, agent\agent.py, agent\collectors\*, agent\requirements.txt
        Copy-Item (Join-Path $root "agent") -Destination $stage -Recurse
        Remove-Item (Join-Path $stage "__pycache__") -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $stage "config.json") -Force -ErrorAction SilentlyContinue
        Remove-Item (Join-Path $stage "spool") -Recurse -Force -ErrorAction SilentlyContinue
        Compress-Archive -Path $stage -DestinationPath $zipPath -CompressionLevel Optimal
    } finally {
        if (Test-Path $stage) { Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue }
    }
    Write-Host "Package written: $zipPath"
    Write-Host "Ship it to the endpoint, then:"
    Write-Host "  Expand-Archive <zip> -DestinationPath <extract-dir>"
    Write-Host "  ...\deploy_agent.ps1 -Mode endpoint -BaseUrl <server-url> -AgentRoot <extract-dir>"
    exit 0
}

# ---- endpoint mode ---------------------------------------------------------
if (-not $AgentRoot) { throw "Endpoint mode requires -AgentRoot (dir containing the extracted 'agent' folder)" }
$agentSrc = Join-Path $AgentRoot "agent"
if (-not (Test-Path (Join-Path $agentSrc "requirements.txt"))) {
    throw "Expected '$agentSrc\requirements.txt' not found. Extract the deploy zip first."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $agentSrc -Destination $InstallDir -Recurse -Force

# Python may be missing on a fresh VM (no winget per lab notes); give exact guidance.
$pyLauncher = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyLauncher) {
    throw "Python not on PATH. Install 3.12 silently: Invoke-WebRequest https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe -OutFile py-inst.exe; .\py-inst.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0"
}
& python --version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "python launcher present but not functional." }

Write-Host "[1/4] Creating venv at $InstallDir\.venv"
Push-Location $InstallDir
try {
    python -m venv .venv
    & ".\.venv\Scripts\pip.exe" install -q -r ".\agent\requirements.txt"

    Write-Host "[2/4] Enrolling against $BaseUrl (ATOR_SERVER_URL env has top precedence)"
    $env:ATOR_SERVER_URL = $BaseUrl
    & ".\.venv\Scripts\python.exe" -m agent.agent enroll

    Write-Host "[3/4] Verification collection"
    & ".\.venv\Scripts\python.exe" -m agent.agent once

    Write-Host "[4/4] Done. Verify in dashboard Endpoints page."

    if ($InstallScheduledTask) {
        $action = New-ScheduledTaskAction -Execute (Join-Path $InstallDir ".venv\Scripts\python.exe") `
            -Argument "-m agent.agent loop" -WorkingDirectory $InstallDir
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName "ATOR Agent Loop" -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName "ATOR Agent Loop"
        Write-Host "Scheduled task 'ATOR Agent Loop' registered (SYSTEM, at startup) and started."
        Write-Host "Manage: schtasks /query /tn 'ATOR Agent Loop' | Stop-/Unregister later."
    } else {
        Write-Host "Continuous mode later: $InstallDir\.venv\Scripts\python.exe -m agent.agent loop"
    }
} finally {
    Pop-Location
}
