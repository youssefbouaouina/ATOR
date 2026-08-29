param()
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $env:TEMP "Sysmon64.exe"
$config = Join-Path $PSScriptRoot "sysmon-config.xml"

if (-not (Test-Path $dest)) {
    Write-Host "Downloading Sysmon from Sysinternals Live..."
    Invoke-WebRequest -Uri "https://live.sysinternals.com/Sysmon64.exe" -OutFile $dest -UseBasicParsing
}
Write-Host "Installing/Updating Sysmon with ATOR DFIR config..."
& $dest -accepteula -i $config
Write-Host "Done."
# NOTE: the installed service is named Sysmon64 (not 'Sysmon').
Get-Service Sysmon64 | Select-Object Status, StartType, Name, DisplayName
Write-Host "Event check: Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5"
