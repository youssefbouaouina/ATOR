param(
    [string]$BaseUrl = "http://127.0.0.1:8000"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path (Join-Path $root ".venv\Scripts\python.exe"))) {
    python -m venv (Join-Path $root ".venv")
    & (Join-Path $root ".venv\Scripts\pip.exe") install -q -r (Join-Path $root "agent\requirements.txt")
}
$py = Join-Path $root ".venv\Scripts\python.exe"
Push-Location $root
try {
    $enroll = & $py -c "import sys; sys.path.insert(0,'.'); from agent import agent; cfg = agent.load_config(); cfg['server_url']='$BaseUrl'; print(agent.enroll(cfg))" | ConvertFrom-Json
    Write-Host "Enrolled client_id=$($enroll.client_id)"
    & $py -m agent.agent once
} finally {
    Pop-Location
}
