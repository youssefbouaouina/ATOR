<#
.SYNOPSIS
    Install the ATOR agent as a SYSTEM scheduled task, so Velociraptor works.

.DESCRIPTION
    The Velociraptor Windows binary embeds a manifest requesting
    'highestAvailable'. Under UAC that means it cannot launch from a normal
    process at all - it fails with WinError 740 - so artifact collection only
    works when the agent itself runs elevated.

    Running the agent by hand from an Administrator window solves that only for
    as long as the window stays open. Running it as a SYSTEM scheduled task
    solves it permanently: SYSTEM is above Administrator, there is no UAC
    prompt, and the task starts by itself at boot and restarts if it dies.

    This script also pins the server URL. The agent's LAN auto-discovery scans
    the subnet for anything answering /health, which on a network with more than
    one ATOR server can silently re-point the agent at the wrong one.

.PARAMETER ServerUrl
    Server the agent should report to. Pinned into the task's environment so
    auto-discovery cannot override it.

.PARAMETER InstallDir
    Where the agent is installed. Default C:\ator-agent.

.PARAMETER Uninstall
    Remove the scheduled task and stop the agent.

.EXAMPLE
    # from an Administrator PowerShell:
    .\install_agent_service.ps1 -ServerUrl http://127.0.0.1:8000

.EXAMPLE
    .\install_agent_service.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$ServerUrl = "http://127.0.0.1:8000",
    [string]$InstallDir = "C:\ator-agent",
    [string]$TaskName = "ATOR Agent Loop",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

# -- must be elevated: registering a SYSTEM principal requires it -------------
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principalCheck = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principalCheck.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error @"
This script must run from an Administrator PowerShell.

Right-click PowerShell -> 'Run as administrator', then run it again.
(Registering a task that runs as SYSTEM cannot be done without elevation.)
"@
    exit 1
}

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'." -ForegroundColor Green
    } else {
        Write-Host "No scheduled task named '$TaskName' found; nothing to do."
    }
    exit 0
}

# -- sanity checks before registering anything -------------------------------
$python = Join-Path $InstallDir ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "Agent python not found at $python. Deploy the agent first (scripts\deploy_agent.ps1)."
    exit 1
}
$configPath = Join-Path $InstallDir "agent\config.json"
if (-not (Test-Path $configPath)) {
    Write-Error "Agent config not found at $configPath. Enroll the agent first."
    exit 1
}

Write-Host "[1/5] Checking the agent is enrolled" -ForegroundColor Cyan
$config = Get-Content $configPath -Raw | ConvertFrom-Json
if (-not $config.api_key -or -not $config.client_id) {
    Write-Error "Agent at $InstallDir is not enrolled (no api_key/client_id in config.json)."
    exit 1
}
Write-Host "      client_id: $($config.client_id)"

Write-Host "[2/5] Pinning server URL to $ServerUrl" -ForegroundColor Cyan
# Written into the config as well as the task environment, so both agree.
$config.server_url = $ServerUrl
$config | ConvertTo-Json -Depth 10 | Set-Content $configPath -Encoding utf8

Write-Host "[3/5] Checking the Velociraptor binary" -ForegroundColor Cyan
$velo = Join-Path $InstallDir "tools\velociraptor.exe"
if (Test-Path $velo) {
    Write-Host "      found: $velo" -ForegroundColor Green
} else {
    Write-Warning "      not found at $velo"
    Write-Warning "      The agent will run fine, but artifact sweeps will report"
    Write-Warning "      'velociraptor binary not found' until you put it there."
}

Write-Host "[4/5] Stopping any agent started by hand" -ForegroundColor Cyan
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
    Where-Object { $_.CommandLine -like "*agent.agent*" } |
    ForEach-Object {
        Write-Host "      stopping PID $($_.ProcessId)"
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }

Write-Host "[5/5] Registering '$TaskName' to run as SYSTEM" -ForegroundColor Cyan
# ATOR_SERVER_URL short-circuits the agent's subnet auto-discovery, so the task
# cannot drift onto another ATOR server it happens to find on the LAN.
$inner = "`$env:ATOR_SERVER_URL='$ServerUrl'; & '$python' -m agent.agent loop"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))

$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded" `
    -WorkingDirectory $InstallDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Start-Sleep -Seconds 3
$task = Get-ScheduledTask -TaskName $TaskName
$info = Get-ScheduledTaskInfo -TaskName $TaskName

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host "  task    : $TaskName"
Write-Host "  runs as : SYSTEM (no UAC prompt, starts at boot, restarts on failure)"
Write-Host "  state   : $($task.State)"
Write-Host "  server  : $ServerUrl"
Write-Host "  last run: $($info.LastRunTime)  result: $($info.LastTaskResult)"
Write-Host ""
Write-Host "Check it worked: open the Artifacts page. The endpoint should say 'Ready'"
Write-Host "within about a minute (it reports on its next heartbeat)."
Write-Host ""
Write-Host "Manage:"
Write-Host "  Get-ScheduledTaskInfo -TaskName '$TaskName'"
Write-Host "  Stop-ScheduledTask    -TaskName '$TaskName'"
Write-Host "  .\install_agent_service.ps1 -Uninstall"
