<#
  Live smoke test against a running Ollama with the 3 default models pulled.
  Generates the dataset (if needed), then runs a tiny LIVE experiment and prints the metrics location.
  Usage:  .\scripts\live_smoke.ps1
#>
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "0) Server-binding preflight (gates the run)" -ForegroundColor Cyan
& "$PSScriptRoot\preflight_binding.ps1" -Port 11434
if ($LASTEXITCODE -ne 0) { Write-Error "binding preflight failed/indeterminate (exit $LASTEXITCODE); aborting strict run."; exit $LASTEXITCODE }

Write-Host "`n1) Environment / model check (admin diagnostics client)" -ForegroundColor Cyan
uv run ragsec doctor

if (-not (Test-Path "data/synthetic/v1/dataset_manifest.json")) {
    Write-Host "`n2) Generating synthetic dataset" -ForegroundColor Cyan
    uv run ragsec gen-dataset
} else { Write-Host "`n2) Dataset already present (data/synthetic/v1)" }

Write-Host "`n3) Running LIVE smoke experiment (exaone3.5:2.4b, OFF vs HYBRID, few cases)" -ForegroundColor Cyan
$env:RAGSEC_LLM_BACKEND = "ollama"
uv run ragsec run experiments/smoke_live.json

Write-Host "`nDone. Inspect the newest run under var/logs/smoke-live/ (requests.jsonl, metrics.csv)." -ForegroundColor Green
