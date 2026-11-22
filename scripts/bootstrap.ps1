# Creates a local venv, installs ASA (dev extras) and runs the offline test suite. Changes nothing in any cloud.
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not (Test-Path .venv)) { python -m venv .venv }
.\.venv\Scripts\python -m pip install --quiet -e ".[dev]"
.\.venv\Scripts\python -m pytest -q
Write-Host "OK. Try: .\.venv\Scripts\asa --out out demo"
