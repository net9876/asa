# Read-only live scan. Requires `az login` (Reader on the target scope is enough) and config\minibank.local.toml.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not (Test-Path config\minibank.local.toml)) { throw 'Copy config\minibank.example.toml to config\minibank.local.toml first.' }
az account show --query '{subscription:id,user:user.name}' -o table
.\.venv\Scripts\asa --out out scan --live --alerts
Write-Host 'Report: out\live-*.html (local only; contains tenant metadata, do not commit)'
