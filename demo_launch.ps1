<#
.SYNOPSIS
    Backwards-compatible entry point for the ATOR DFIR endpoint demo.

.DESCRIPTION
    This file used to be a full copy of scripts\demo_windows_capabilities.ps1,
    which meant the two copies could drift apart. It is now a thin wrapper that
    forwards every argument to the canonical script. The demo automatically
    removes its temporary signals and demo-only collected data after 3 minutes.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\demo_launch.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\demo_launch.ps1 -Cleanup

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\demo_launch.ps1 -HoldSeconds 90

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\demo_launch.ps1 -CleanupAfterMinutes 20
#>
$ErrorActionPreference = "Stop"
$target = Join-Path $PSScriptRoot "scripts\demo_windows_capabilities.ps1"
if (-not (Test-Path $target)) {
    Write-Error "canonical demo script not found: $target"
    exit 1
}
& $target @args
exit $LASTEXITCODE
