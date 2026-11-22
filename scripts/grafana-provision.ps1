<#
 Creates/updates the ASA dashboard in Grafana Cloud. Run in YOUR PowerShell where $env:GRAFANA_SA_TOKEN
 (dashboard Editor service-account token) is loaded. The token never goes to ASA's job or repo.
#>
param([string]$Stack = 'https://net9876.grafana.net')
if (-not $env:GRAFANA_SA_TOKEN) { throw 'GRAFANA_SA_TOKEN is not set in this session' }
$dash = Get-Content (Join-Path $PSScriptRoot '..\dashboards\asa-overview.json') -Raw | ConvertFrom-Json
$body = @{ dashboard = $dash; overwrite = $true; message = 'ASA provisioning' } | ConvertTo-Json -Depth 30
$r = Invoke-RestMethod -Method Post -Uri "$Stack/api/dashboards/db" -ContentType 'application/json' `
  -Headers @{ Authorization = "Bearer $env:GRAFANA_SA_TOKEN" } -Body $body
"$Stack$($r.url)"
