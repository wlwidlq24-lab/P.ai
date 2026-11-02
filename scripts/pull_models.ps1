<#
  Pulls the models used by the default 6 GB (RTX 4050) profile and verifies they are present.
  Usage (PowerShell):   .\scripts\pull_models.ps1          # default 2.4b target + guard + embed
                        .\scripts\pull_models.ps1 -All     # also pull 7.8b and qwen3:4b comparison model
#>
param([switch]$All)

$ErrorActionPreference = "Stop"
$base = if ($env:RAGSEC_OLLAMA_URL) { $env:RAGSEC_OLLAMA_URL } else { "http://127.0.0.1:11434" }

# Default-profile models for the RTX 4050 (6 GB).
$models = @("exaone3.5:2.4b", "bge-m3", "llama-guard3:1b")
if ($All) { $models += @("exaone3.5:7.8b", "qwen3:4b") }

Write-Host "Ollama endpoint: $base"
try { $v = Invoke-RestMethod "$base/api/version" -TimeoutSec 5; Write-Host "Ollama version: $($v.version)" }
catch { Write-Error "Ollama not reachable at $base. Start it with 'ollama serve' (or the tray app)."; exit 1 }

foreach ($m in $models) {
    Write-Host "`n=== ollama pull $m ===" -ForegroundColor Cyan
    ollama pull $m
    if ($LASTEXITCODE -ne 0) { Write-Error "pull failed for $m"; exit 1 }
}

Write-Host "`nInstalled models:" -ForegroundColor Green
$tags = Invoke-RestMethod "$base/api/tags"
$tags.models | ForEach-Object { "  {0,-28} {1}" -f $_.name, $_.details.quantization_level }
Write-Host "`nApprox. download sizes: exaone3.5:2.4b 1.6GB, bge-m3 1.2GB, llama-guard3:1b 1.6GB (+7.8b 4.8GB, qwen3:4b 2.5GB)."
