<#
  RAGSEC handover demo launcher (MOCK backend, synthetic data).

  Starts the FastAPI mock API + the Streamlit UI on loopback via the project venv, seeds the synthetic complaint
  document into an ISOLATED per-run demo index, waits until both respond, and prints the Chrome URL. Demo
  credentials only (never a real key). The efficacy pilot stays on HOLD (mock backend; no attack payloads).

  Default mode is NON-BLOCKING (servers are detached and keep running) so it works as a VS Code preLaunchTask;
  stop them with -Stop. Use -Foreground for a manual terminal run that stops on Enter.

  Usage:
    .\scripts\demo_launch.ps1                         # start on 127.0.0.1:8000 (API) / 127.0.0.1:8501 (UI)
    .\scripts\demo_launch.ps1 -Stop                   # stop the demo services
    .\scripts\demo_launch.ps1 -Foreground             # start, then press Enter to stop
    .\scripts\demo_launch.ps1 -ApiPort 8010 -UiPort 8511   # other ports (e.g. if 8000/8501 are reserved -> 10013)
#>
param([switch]$Stop, [switch]$Foreground, [int]$ApiPort = 8000, [int]$UiPort = 8501,
      [string]$Key = "demo-key-123456")

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$py = Join-Path $repo ".venv\Scripts\python.exe"
$pidFile = Join-Path $env:TEMP "ragsec-demo.pids"

function Test-PortInUse([int]$p) {
    return [bool](Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue)
}
function Stop-DemoPids {
    if (Test-Path $pidFile) {
        Get-Content $pidFile | ForEach-Object { if ($_) { Stop-Process -Id ([int]$_) -Force -ErrorAction SilentlyContinue } }
        Remove-Item $pidFile -ErrorAction SilentlyContinue
    }
}
function Wait-Ready([string]$url, $proc, [string]$log) {
    for ($i = 0; $i -lt 40; $i++) {
        if ($proc.HasExited) {
            Write-Host "FAIL: server exited during startup. Last log lines ($log):" -ForegroundColor Red
            Get-Content $log -Tail 20 -ErrorAction SilentlyContinue
            Write-Host "If you see WinError 10013 (socket access forbidden) the port is RESERVED on this machine:" -ForegroundColor Yellow
            Write-Host "  netsh int ipv4 show excludedportrange protocol=tcp"
            Write-Host "  then retry on free ports:  .\scripts\demo_launch.ps1 -ApiPort 8010 -UiPort 8511"
            return $false
        }
        try { Invoke-WebRequest -Uri $url -TimeoutSec 2 -UseBasicParsing | Out-Null; return $true }
        catch { Start-Sleep -Milliseconds 500 }
    }
    Write-Host "FAIL: no response from $url within timeout. Log: $log" -ForegroundColor Red
    Get-Content $log -Tail 20 -ErrorAction SilentlyContinue
    return $false
}

if ($Stop) {
    Stop-DemoPids
    foreach ($p in $ApiPort, $UiPort) {
        try { (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction Stop).OwningProcess |
              Select-Object -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue } } catch {}
    }
    Write-Host "RAGSEC demo stopped (ports $ApiPort / $UiPort)." -ForegroundColor Green
    exit 0
}

if (-not (Test-Path $py)) {
    Write-Host "FAIL: project venv Python not found at $py. Run 'uv sync' first, then retry." -ForegroundColor Red
    exit 2
}

# stop only a PRIOR demo we started; never force-kill an unknown process holding the port
Stop-DemoPids
Start-Sleep -Milliseconds 300
if ((Test-PortInUse $ApiPort) -or (Test-PortInUse $UiPort)) {
    Write-Host "FAIL: port $ApiPort or $UiPort is already in use by another process." -ForegroundColor Red
    Write-Host "  Close it, or use free ports:  .\scripts\demo_launch.ps1 -ApiPort 8010 -UiPort 8511"
    exit 2
}

# isolated per-run demo index + logs (OS temp; nothing leaks into the repo or other indexes)
$demo = Join-Path ([IO.Path]::GetTempPath()) ("ragsec-demo-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$logDir = Join-Path $demo "logs"
New-Item -ItemType Directory -Force $logDir | Out-Null

# demo-only environment, inherited by the child processes
$env:RAGSEC_LLM_BACKEND  = "mock"
$env:RAGSEC_AUTH_MODE    = "legacy"
$env:RAGSEC_API_KEY      = $Key
$env:RAGSEC_MAX_DISTANCE = "2.0"
$env:RAGSEC_DATA_DIR     = $demo
$env:RAGSEC_API_URL      = "http://127.0.0.1:$ApiPort"
$env:PYTHONDONTWRITEBYTECODE = "1"

Write-Host "Demo logs: $logDir"
Write-Host "Starting mock API on 127.0.0.1:$ApiPort ..." -ForegroundColor Cyan
$apiErr = Join-Path $logDir "api.err.log"
$api = Start-Process -FilePath $py -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
    -ArgumentList @("-m", "uvicorn", "ragsec.api:app", "--host", "127.0.0.1", "--port", "$ApiPort") `
    -RedirectStandardError $apiErr -RedirectStandardOutput (Join-Path $logDir "api.out.log")
if (-not (Wait-Ready "http://127.0.0.1:$ApiPort/health" $api $apiErr)) { exit 3 }

Write-Host "API ready. Seeding the synthetic W-01 investigation case ..." -ForegroundColor Cyan
& $py (Join-Path $repo "scripts\demo_investigation_seed.py")
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: seeding the demo index failed (see the SEED message above)." -ForegroundColor Red
    Stop-Process -Id $api.Id -Force -ErrorAction SilentlyContinue
    exit 4
}

Write-Host "Starting Streamlit UI on 127.0.0.1:$UiPort ..." -ForegroundColor Cyan
$uiErr = Join-Path $logDir "ui.err.log"
$ui = Start-Process -FilePath $py -WorkingDirectory $repo -WindowStyle Hidden -PassThru `
    -ArgumentList @("-m", "streamlit", "run", "ui/streamlit_app.py", "--server.address", "127.0.0.1",
                    "--server.port", "$UiPort", "--server.headless", "true", "--browser.gatherUsageStats", "false") `
    -RedirectStandardError $uiErr -RedirectStandardOutput (Join-Path $logDir "ui.out.log")
Set-Content -Path $pidFile -Value @($api.Id, $ui.Id)
if (-not (Wait-Ready "http://127.0.0.1:$UiPort/_stcore/health" $ui $uiErr)) {
    Stop-Process -Id $api.Id -Force -ErrorAction SilentlyContinue
    exit 5
}

Write-Host ""
Write-Host "RAGSEC handover demo is READY (mock, synthetic)." -ForegroundColor Green
Write-Host ("  Open in Chrome:   http://127.0.0.1:{0}" -f $UiPort)
Write-Host  "  Tab to click:     인수인계 자료"
Write-Host ("  Logs:             {0}" -f $logDir)
if ($Foreground) {
    Read-Host "Press Enter to stop both servers" | Out-Null
    Stop-DemoPids
    Write-Host "Stopped." -ForegroundColor Green
} else {
    Write-Host "  Stop services:    .\scripts\demo_launch.ps1 -Stop"
}
exit 0
