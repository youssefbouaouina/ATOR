<#
.SYNOPSIS
    Register, inspect or remove the weekly ATOR ML update (Windows Task Scheduler).

.DESCRIPTION
    Creates the scheduled task "ATOR ML Weekly Update", which runs scripts\mlops_weekly.cmd
    once a week (docs/ML_MLOPS_PLAN.md). Paths are resolved from this script's location, so it
    works from any clone. Re-running it replaces the task in place (idempotent).

    Settings chosen for an unattended laptop or server:
      * StartWhenAvailable  - a machine that was off or asleep at the scheduled time runs the
                              job when it next can, instead of skipping a week. The pipeline's
                              own 6-day cadence guard stops that catch-up and the next regular
                              trigger from both running.
      * battery allowed     - a laptop unplugged at the time would otherwise never run it.
      * IgnoreNew           - never two runs at once (the pipeline also holds a lock).
      * 4 h time limit      - a hung run is stopped; the next run reclaims its lock.
      * 2 restarts, 30 min  - retries a transient failure (e.g. the database busy).

    By default the task runs as the current user, only while logged on, and no password is
    stored. -AsSystem runs it whether or not anyone is logged on; it needs an elevated shell.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1 -Day Wednesday -At 13:00
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1 -Status
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\install_mlops_schedule.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [ValidateSet("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")]
    [string]$Day = "Sunday",
    [string]$At = "03:00",
    [switch]$AsSystem,
    [switch]$Status,
    [switch]$Uninstall,
    [string]$TaskName = "ATOR ML Weekly Update"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$wrapper = Join-Path $repo "scripts\mlops_weekly.cmd"

function Show-Status {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $task) { Write-Host "Not installed."; return }
    $info = Get-ScheduledTaskInfo -TaskName $TaskName
    $meaning = @{ 0 = "ok"; 1 = "failed - models unchanged, see mlops\runs"; 2 = "completed, needs a look";
                  267011 = "has not run yet"; 267009 = "running now" }
    $result = [int]$info.LastTaskResult
    Write-Host "Task:        $TaskName ($($task.State))"
    Write-Host "Runs:        $($task.Actions[0].Execute)"
    Write-Host "Last run:    $($info.LastRunTime)  result $result ($($meaning[$result]))"
    Write-Host "Next run:    $($info.NextRunTime)"
    Write-Host "Pipeline:    .venv\Scripts\python.exe -m ml.mlops status   (for models, trials, runs)"
}

if ($Status) { Show-Status; exit 0 }

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed '$TaskName'. Models in service are unchanged; any running trial stays"
        Write-Host "recorded and resumes if the task is installed again."
    } else {
        Write-Host "'$TaskName' is not installed."
    }
    exit 0
}

if (-not (Test-Path $wrapper)) { throw "wrapper not found: $wrapper" }
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Warning "$python does not exist yet. The task will be registered, but each run will fail until the venv is rebuilt (docs/ML_PROGRESS.md)."
}

$action = New-ScheduledTaskAction -Execute $wrapper -WorkingDirectory $repo
$trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek $Day -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Hours 4) -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 30)

if ($AsSystem) {
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
} else {
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
}

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force `
    -Description "ATOR Layer 4.5: weekly retrieve, ETL, retrain, evaluate, shadow-trial and deploy of the ML models (docs/ML_MLOPS_PLAN.md). Safe to run late or twice." | Out-Null

Write-Host "Installed '$TaskName': every $Day at $At$(if ($AsSystem) {' as SYSTEM'} else {" as $user (while logged on)"})."
Show-Status
