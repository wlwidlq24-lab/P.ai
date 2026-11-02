<#
  Server-binding preflight (Windows PowerShell).

  WHY: The application validating that it CONNECTS to 127.0.0.1 does NOT prove the Ollama server LISTENS
  only on loopback. The server may also listen on 0.0.0.0 or :: (via OLLAMA_HOST), exposing it to the LAN.
  Application URL validation cannot establish the server's actual binding — only inspecting the listeners can.

  This script inspects every listener on the configured port, fails on wildcard/non-loopback binds, names the
  owning process, and exits non-zero on failure OR when the result is indeterminate, so a strict experiment
  run can gate on it.

  LIMITATION: this is a POINT-IN-TIME check. Re-run it after any Ollama (or other owner) process restart or
  OLLAMA_HOST change; a pass now does not guarantee the binding later.

  Usage:
    .\scripts\preflight_binding.ps1                 # checks port 11434
    .\scripts\preflight_binding.ps1 -Port 11434
    if (-not (.\scripts\preflight_binding.ps1)) { throw "binding preflight failed" }
#>
param([int]$Port = 11434)

$ErrorActionPreference = "Stop"
function Fail($msg) { Write-Host "FAIL: $msg" -ForegroundColor Red; exit 2 }
function Indeterminate($msg) { Write-Host "INDETERMINATE: $msg" -ForegroundColor Yellow; exit 3 }

Write-Host "Binding preflight for TCP port $Port (point-in-time)" -ForegroundColor Cyan

if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
    Indeterminate "Get-NetTCPConnection is unavailable; cannot verify listeners on this host."
}

try {
    $listeners = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop
} catch {
    # No listener at all is not a binding exposure, but it means Ollama is not up: indeterminate for a run.
    Indeterminate "No listener found on port $Port (is Ollama running?). $_"
}

$bad = @()
foreach ($l in $listeners) {
    $addr = $l.LocalAddress
    $proc = $null
    try { $proc = Get-Process -Id $l.OwningProcess -ErrorAction Stop } catch {}
    $pname = if ($proc) { "$($proc.ProcessName) (PID $($l.OwningProcess))" } else { "PID $($l.OwningProcess)" }
    $isLoopback = ($addr -eq "127.0.0.1") -or ($addr -eq "::1")
    $isWildcard = ($addr -eq "0.0.0.0") -or ($addr -eq "::")
    $status = if ($isWildcard) { "WILDCARD" } elseif ($isLoopback) { "loopback" } else { "NON-LOOPBACK" }
    Write-Host ("  listener {0,-22} owner={1,-28} -> {2}" -f "$addr`:$Port", $pname, $status)
    if ($isWildcard -or -not $isLoopback) { $bad += "$addr ($pname)" }
}

if ($bad.Count -gt 0) {
    Fail ("Ollama/port $Port is reachable beyond loopback via: " + ($bad -join ", ") +
          ". Set OLLAMA_HOST=127.0.0.1 and restart Ollama, then re-run this preflight.")
}

Write-Host "PASS: port $Port listens only on loopback at this moment." -ForegroundColor Green
Write-Host "Reminder: re-run after any Ollama restart or OLLAMA_HOST change (point-in-time result)."
exit 0
