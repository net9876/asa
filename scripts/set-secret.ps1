<#
 Uploads ONE ASA secret to the ASA Key Vault. The value is typed hidden and never touches disk,
 history, Terraform state or chat. Needs az login + 'Key Vault Secrets Officer' on the vault.
 Example:  .\scripts\set-secret.ps1 -Name asa-grafana-push-token
 Use the PUSH token only here. Never upload the dashboard Editor token (the scan job must not hold it).
#>
param(
  [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9-]{1,40}$')][string]$Name,
  [string]$Vault = 'kv-asa-40094918',
  [int]$ExpiresInDays = 90
)
$sec = Read-Host "Value for $Name" -AsSecureString
$plain = [System.Net.NetworkCredential]::new('', $sec).Password
$exp = (Get-Date).ToUniversalTime().AddDays($ExpiresInDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
$plain | az keyvault secret set --vault-name $Vault --name $Name --file /dev/stdin --expires $exp --query id -o tsv 2>$null `
  || ($plain | Out-File -NoNewline -Encoding ascii "$env:TEMP\asa-secret.tmp"; az keyvault secret set --vault-name $Vault --name $Name --file "$env:TEMP\asa-secret.tmp" --expires $exp --query id -o tsv; Remove-Item "$env:TEMP\asa-secret.tmp" -Force)
$plain = $null
