<#
 Uploads ONE ASA secret to the ASA Key Vault. The value is typed hidden and never goes to shell
 history, Terraform state, code or chat. Needs az login + 'Key Vault Secrets Officer' on the vault.
 Example:  .\scripts\set-secret.ps1 -Name asa-grafana-push-token
 Upload the PUSH token only. Never the dashboard Editor token (the scan job must not hold it).
#>
param(
  [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9-]{1,40}$')][string]$Name,
  [string]$Vault = 'kv-asa-40094918',
  [int]$ExpiresInDays = 90
)
$sec = Read-Host "Value for $Name" -AsSecureString
$plain = [System.Net.NetworkCredential]::new('', $sec).Password
$exp = (Get-Date).ToUniversalTime().AddDays($ExpiresInDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
$tmp = Join-Path $env:TEMP ([guid]::NewGuid().ToString() + '.tmp')
try {
  [System.IO.File]::WriteAllText($tmp, $plain)
  az keyvault secret set --vault-name $Vault --name $Name --file $tmp --expires $exp --query id -o tsv
}
finally {
  if (Test-Path $tmp) { Remove-Item $tmp -Force }
  $plain = $null
}
