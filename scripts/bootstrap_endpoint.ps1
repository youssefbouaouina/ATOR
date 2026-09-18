<#
.SYNOPSIS
    ATOR DFIR - Bare Windows Endpoint Automated Bootstrap & Token Enrollment
.DESCRIPTION
    Idempotent bootstrap for a FRESH / bare Windows endpoint that has nothing
    installed. It will:
      1. Check TLS 1.2 is enabled (required for python.org / server fetches).
      2. Install Python 3.12 if no usable Python 3.8+ is present.
      3. Deploy the ATOR agent package (copy from a local repo next to this
         script, or download ator-agent-deploy.zip from the server).
      4. Create an isolated virtual environment and install dependencies.
      5. Enroll using the admin-approved enrollment token.
      6. Run a one-time verification collection.
      7. Register a Task Scheduler job so the agent runs continuously.
      Every step logs to C:\enroll_debug.log and each step is idempotent.
    The Linux counterpart is scripts/bootstrap_endpoint.sh.
.PARAMETER ServerUrl
    URL of the ATOR DFIR server, e.g. http://192.168.1.50:8000
    Use the server's LAN IP - NEVER 127.0.0.1 on a remote endpoint.
.PARAMETER EnrollmentToken
    The enrollment token shown after the admin accepts the request.
.PARAMETER InstallDir
    Directory to install the agent into (default C:\ator-agent).
.PARAMETER EnablePersistence
    If provided, registers the Task Scheduler job for continuous collection.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\bootstrap_endpoint.ps1 `
        -ServerUrl "http://192.168.1.50:8000" `
        -EnrollmentToken "9f8c-...." -EnablePersistence
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,
    [Parameter(Mandatory = $true)]
    [string]$EnrollmentToken,
    [string]$InstallDir = "C:\ator-agent",
    [switch]$EnablePersistence = $true
)

$ErrorActionPreference = "Stop"
$LogFile = "C:\enroll_debug.log"
$ProgressPreference = "SilentlyContinue"
$TaskName = "ATOR Agent Loop"

function Log {
    param([string]$Message)
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Write-Host "[$ts] $Message"
    Add-Content -Path $LogFile -Value "[$ts] $Message" -Force
}

function Fail {
    param([string]$Message)
    Log "ERROR: $Message"
    throw $Message
}

function Test-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Run a native executable and capture stdout+stderr. Windows PowerShell 5.1
# turns every stderr line into a terminating error under
# $ErrorActionPreference=Stop (pip/python warnings would abort the bootstrap),
# so relax it for the call and judge success by the exit code instead.
function Invoke-Native {
    param([string]$FilePath, [string[]]$Arguments)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $FilePath @Arguments 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    return [pscustomobject]@{ ExitCode = $code; Output = ($output -join "`n") }
}

# Find a real Python 3.8+ interpreter. The "python.exe" in WindowsApps on a
# fresh Windows 10/11 is only a Microsoft Store stub, so every candidate is
# verified by actually running it.
function Find-Python {
    $candidates = @()
    foreach ($name in @("python", "python3")) {
        Get-Command $name -All -ErrorAction SilentlyContinue |
            Where-Object { $_.Source -notmatch "\\WindowsApps\\" } |
            ForEach-Object { $candidates += $_.Source }
    }
    $candidates += @(
        "$env:ProgramFiles\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
    )
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        $r = Invoke-Native $py.Source @("-3", "-c", "import sys; print(sys.executable)")
        if ($r.ExitCode -eq 0 -and $r.Output) { $candidates += $r.Output.Trim() }
    }
    foreach ($c in $candidates) {
        if (-not $c -or -not (Test-Path $c)) { continue }
        $r = Invoke-Native $c @("-c", "import sys, venv; sys.exit(0 if sys.version_info >= (3, 8) else 1)")
        if ($r.ExitCode -eq 0) { return $c }
    }
    return $null
}

# --- 0. Ensure admin rights (self-elevate once) -------------------------
if (-not (Test-Admin)) {
    Write-Warning "Administrator rights required. Re-launching elevated..."
    # -NoExit keeps the elevated window open so the result stays readable.
    $argList = "-NoProfile -NoExit -ExecutionPolicy Bypass -File `"$PSCommandPath`" " +
               "-ServerUrl `"$ServerUrl`" -EnrollmentToken `"$EnrollmentToken`" " +
               "-InstallDir `"$InstallDir`""
    if ($EnablePersistence) { $argList += " -EnablePersistence" }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

"=== ATOR Endpoint Bootstrap Started $(Get-Date -Format o) ===" | Out-File -FilePath $LogFile -Encoding utf8
Log "Target server : $ServerUrl"
Log "Install dir   : $InstallDir"

# --- 1. Enable TLS 1.2 (needed on older Win10/Server for HTTPS) ---------
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12
    Log "[OK] TLS 1.2 enabled."
} catch {
    Log "WARN: Could not force TLS 1.2: $($_.Exception.Message)"
}

# --- 2. Validate server URL (reject loopback unless it IS the server) ---
$server = $ServerUrl.TrimEnd('/')
if ($server -match "127\.0\.0\.1|localhost") {
    Log "WARN: ServerUrl uses loopback ($server). If this is a remote endpoint the server will NOT be reachable - use its LAN IP."
}
try {
    $h = Invoke-WebRequest -Uri "$server/health" -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    if ($h.StatusCode -ne 200) { throw "Server returned HTTP $($h.StatusCode)" }
    Log "[OK] Server reachable: $server/health"
} catch {
    Fail "Cannot reach $server/health. Check the server LAN IP and firewall (allow port 8000). Detail: $($_.Exception.Message)"
}

# --- 3. Install Python 3.12 if missing ----------------------------------
$python = Find-Python
if (-not $python) {
    Log "No usable Python 3.8+ found. Downloading Python 3.12 installer..."
    $installer = Join-Path $env:TEMP "python-3.12.10-amd64.exe"
    $pyUrl = "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe"
    try {
        Invoke-WebRequest -Uri $pyUrl -OutFile $installer -UseBasicParsing -TimeoutSec 300
    } catch {
        Fail "Failed to download Python ($pyUrl). Check outbound internet, then re-run. Detail: $($_.Exception.Message)"
    }
    Log "Installing Python silently (all users, add to PATH)..."
    $p = Start-Process -FilePath $installer -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0 Include_launcher=1" -PassThru -Wait
    if ($p.ExitCode -ne 0) { Fail "Python silent install failed (exit $($p.ExitCode))." }
    # Refresh PATH for this session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
                [System.Environment]::GetEnvironmentVariable("Path", "User")
    $python = Find-Python
    if (-not $python) { Fail "Python was installed but no working interpreter was found." }
    Log "[OK] Python installed."
}
$pyVersion = (Invoke-Native $python @("--version")).Output
Log "[OK] Python: $pyVersion ($python)"

# --- 4. Deploy agent package to InstallDir ------------------------------
# Stop a previous installation first so its files are not in use.
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Log "Stopping existing scheduled task '$TaskName' before upgrade..."
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$agentDest = Join-Path $InstallDir "agent"
$configPath = Join-Path $agentDest "config.json"
$scriptRoot = Split-Path -Parent $PSCommandPath

# Keep credentials from a previous enrollment across the package refresh.
$savedConfig = $null
if (Test-Path $configPath) { $savedConfig = [System.IO.File]::ReadAllBytes($configPath) }

$stage = Join-Path $env:TEMP ("ator_pkg_" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $stage | Out-Null
try {
    if (Test-Path (Join-Path $scriptRoot "agent\agent.py")) {
        Log "Using agent package from local repo ($scriptRoot)..."
        Copy-Item (Join-Path $scriptRoot "agent") -Destination (Join-Path $stage "agent") -Recurse -Force
        if (Test-Path (Join-Path $scriptRoot "rules\malware")) {
            New-Item -ItemType Directory -Force -Path (Join-Path $stage "rules") | Out-Null
            Copy-Item (Join-Path $scriptRoot "rules\malware") -Destination (Join-Path $stage "rules\malware") -Recurse -Force
        }
    } else {
        Log "Downloading agent package from server: $server/static/ator-agent-deploy.zip"
        $zip = Join-Path $stage "ator-agent-deploy.zip"
        try {
            Invoke-WebRequest -Uri "$server/static/ator-agent-deploy.zip" -OutFile $zip -UseBasicParsing -TimeoutSec 120
        } catch {
            Fail "Could not fetch agent archive from server. Detail: $($_.Exception.Message)"
        }
        Expand-Archive -Path $zip -DestinationPath $stage -Force
        Remove-Item $zip -Force
    }
    if (-not (Test-Path (Join-Path $stage "agent\agent.py"))) { Fail "Agent package is missing agent\agent.py." }

    if (Test-Path $agentDest) { Remove-Item $agentDest -Recurse -Force }
    Move-Item (Join-Path $stage "agent") $agentDest
    if (Test-Path (Join-Path $stage "rules")) {
        $rulesDest = Join-Path $InstallDir "rules"
        if (Test-Path $rulesDest) { Remove-Item $rulesDest -Recurse -Force }
        Move-Item (Join-Path $stage "rules") $rulesDest
    }
    Remove-Item (Join-Path $agentDest "config.json") -Force -ErrorAction SilentlyContinue
    if ($savedConfig) {
        [System.IO.File]::WriteAllBytes($configPath, $savedConfig)
        Log "[OK] Preserved existing agent config.json."
    }
} finally {
    Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
}
Log "[OK] Agent deployed to $agentDest"

# --- 5. Create isolated venv & install deps ------------------------------
$venv = Join-Path $InstallDir ".venv"
$venvPy = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    Log "Creating virtual environment..."
    $r = Invoke-Native $python @("-m", "venv", $venv)
    if ($r.ExitCode -ne 0) { Fail "venv creation failed (exit $($r.ExitCode)): $($r.Output)" }
}
Log "Installing agent dependencies..."
$req = Join-Path $agentDest "requirements.txt"
$r = Invoke-Native $venvPy @("-m", "pip", "install", "-q", "--disable-pip-version-check", "-r", $req)
if ($r.ExitCode -ne 0) {
    # Optional collectors (python-evtx, yara-python) must not block enrollment.
    Log "WARN: full requirements failed, installing core deps only: $($r.Output)"
    $r = Invoke-Native $venvPy @("-m", "pip", "install", "-q", "--disable-pip-version-check", "requests", "psutil")
    if ($r.ExitCode -ne 0) { Fail "pip install failed (exit $($r.ExitCode)): $($r.Output)" }
}
Log "[OK] Dependencies installed."

# --- 6. Token enrollment (idempotent) -----------------------------------
Log "Enrolling with token: $EnrollmentToken"
Push-Location $InstallDir
try {
    $r = Invoke-Native $venvPy @("-m", "agent.agent", "enroll", "--token", $EnrollmentToken, "--server", $server)
} finally {
    Pop-Location
}
Log "Enrollment output: $($r.Output)"
if ($r.ExitCode -ne 0) {
    Fail "Enrollment failed (exit $($r.ExitCode)). Check that the request was accepted and the token has not been used by another host."
}
Log "[OK] Enrollment complete. Credentials saved to $configPath"

# --- 7. Verification collection ------------------------------------------
Log "Running one-time verification collection..."
Push-Location $InstallDir
try {
    $r = Invoke-Native $venvPy @("-m", "agent.agent", "once")
} finally {
    Pop-Location
}
Log "Verification output: $($r.Output)"
if ($r.ExitCode -ne 0) { Log "WARN: verification collection exited with $($r.ExitCode)." }

# --- 8. Persistent background collection (Task Scheduler) ---------------
if ($EnablePersistence) {
    try {
        Log "Registering Task Scheduler job '$TaskName' (at startup, SYSTEM)..."
        $action = New-ScheduledTaskAction -Execute $venvPy -Argument "-m agent.agent loop" -WorkingDirectory $InstallDir
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
            -Settings $settings -Principal $principal -Force | Out-Null
        Start-ScheduledTask -TaskName $TaskName
        Log "[OK] Scheduled task '$TaskName' registered and started."
    } catch {
        Log "WARN: Could not register scheduled task: $($_.Exception.Message)"
    }
}

Log "=== ATOR Endpoint Bootstrap Completed Successfully ==="
Write-Host ""
Write-Host "[SUCCESS] Endpoint enrolled. Check /endpoints in the dashboard." -ForegroundColor Green
Write-Host "Full log: $LogFile"
