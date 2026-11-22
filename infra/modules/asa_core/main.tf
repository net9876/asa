# ASA core: ONLY ASA's own resources. Nothing here creates or changes audited resources.
# Audited scopes receive READ-ONLY role assignments for ASA's identity, listed explicitly in
# var.reader_scopes / var.optional_role_assignments, and only when you run apply on purpose.
terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

variable "name" {
  type        = string
  default     = "asa"
  description = "Short prefix for ASA resources."
}
variable "location" { type = string }
variable "tags" {
  type    = map(string)
  default = { product = "asa", purpose = "read-only-security-auditor" }
}

variable "reader_scopes" {
  type        = list(string)
  default     = []
  description = "Scopes (resource group / subscription ids) that receive the built-in Reader role for ASA's identity. Empty = grants nothing."
}
variable "optional_role_assignments" {
  type        = map(object({ scope = string, role = string }))
  default     = {}
  description = "Extra READ roles, e.g. Security Reader. Write roles are rejected by validation."
  validation {
    condition = alltrue([for k, v in var.optional_role_assignments :
    !contains(["Owner", "Contributor", "User Access Administrator", "Role Based Access Control Administrator"], v.role)])
    error_message = "ASA must not be granted Owner, Contributor, User Access Administrator or RBAC Administrator."
  }
}
variable "foundry_account_id" {
  type        = string
  default     = null
  description = "Existing Foundry/Azure OpenAI account to REUSE for audit reasoning. null = no model access (mock agent). Setting it adds ONE role assignment (Cognitive Services OpenAI User) on that account; nothing else on it changes."
}
variable "snapshot_retention_days" {
  type    = number
  default = 180
}
variable "enable_observability" {
  type        = bool
  default     = false
  description = "ASA's OWN Log Analytics workspace (small pay-as-you-go cost, daily cap). Off by default."
}
variable "enable_scheduler" {
  type        = bool
  default     = false
  description = "Container Apps environment + cron job that runs the live scan (consumption plan; near-zero when idle). Off by default."
}
variable "scheduler_image" {
  type        = string
  default     = "docker.io/library/python:3.12-slim"
  description = "Public base image. ASA code is pulled at start from ASA's own storage (bootstrap/asa.zip) with the job identity: no registry needed."
}
variable "scheduler_bootstrap" {
  type        = string
  default     = ""
  description = "Inline python stub that downloads bootstrap/asa.zip + config and runs `asa scan --live --auth msi --upload`."
}
variable "scan_cron" {
  type    = string
  default = "0 6 * * *"
}

data "azurerm_client_config" "current" {}

locals { suffix = substr(sha256("${data.azurerm_client_config.current.subscription_id}-${var.name}"), 0, 8) }

resource "azurerm_resource_group" "asa" {
  name     = "rg-${var.name}-${local.suffix}"
  location = var.location
  tags     = var.tags
}

resource "azurerm_user_assigned_identity" "asa" {
  name                = "id-${var.name}-scanner"
  resource_group_name = azurerm_resource_group.asa.name
  location            = azurerm_resource_group.asa.location
  tags                = var.tags
}

# Findings store: private, Entra-only, versioned, retention-limited. No shared keys, no public access.
resource "azurerm_storage_account" "findings" {
  name                            = "st${var.name}${local.suffix}"
  resource_group_name             = azurerm_resource_group.asa.name
  location                        = azurerm_resource_group.asa.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false
  default_to_oauth_authentication = true
  tags                            = var.tags

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = 14
    }
  }
}

resource "azurerm_storage_container" "snapshots" {
  name                  = "snapshots"
  storage_account_id    = azurerm_storage_account.findings.id
  container_access_type = "private"
}

resource "azurerm_storage_management_policy" "retention" {
  storage_account_id = azurerm_storage_account.findings.id
  rule {
    name    = "expire-old-snapshots"
    enabled = true
    filters {
      blob_types   = ["blockBlob"]
      prefix_match = ["snapshots/"]
    }
    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = var.snapshot_retention_days
      }
    }
  }
}

# ASA may write ONLY to its own container.
resource "azurerm_role_assignment" "own_store" {
  scope                = "${azurerm_storage_account.findings.id}/blobServices/default/containers/${azurerm_storage_container.snapshots.name}"
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.asa.principal_id
}

# Read-only access to audited scopes (explicit list; empty by default).
resource "azurerm_role_assignment" "reader" {
  for_each                         = toset(var.reader_scopes)
  scope                            = each.value
  role_definition_name             = "Reader"
  principal_id                     = azurerm_user_assigned_identity.asa.principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "optional" {
  for_each                         = var.optional_role_assignments
  scope                            = each.value.scope
  role_definition_name             = each.value.role
  principal_id                     = azurerm_user_assigned_identity.asa.principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_role_assignment" "model" {
  count                            = var.foundry_account_id == null ? 0 : 1
  scope                            = var.foundry_account_id
  role_definition_name             = "Cognitive Services OpenAI User"
  principal_id                     = azurerm_user_assigned_identity.asa.principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_log_analytics_workspace" "asa" {
  count               = var.enable_observability ? 1 : 0
  name                = "log-${var.name}-${local.suffix}"
  resource_group_name = azurerm_resource_group.asa.name
  location            = azurerm_resource_group.asa.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  daily_quota_gb      = 0.1
  tags                = var.tags
}

resource "azurerm_container_app_environment" "asa" {
  count                      = var.enable_scheduler ? 1 : 0
  name                       = "cae-${var.name}-${local.suffix}"
  resource_group_name        = azurerm_resource_group.asa.name
  location                   = azurerm_resource_group.asa.location
  log_analytics_workspace_id = var.enable_observability ? azurerm_log_analytics_workspace.asa[0].id : null
  tags                       = var.tags
}

resource "azurerm_container_app_job" "scan" {
  count                        = var.enable_scheduler ? 1 : 0
  name                         = "job-${var.name}-scan"
  resource_group_name          = azurerm_resource_group.asa.name
  location                     = azurerm_resource_group.asa.location
  container_app_environment_id = azurerm_container_app_environment.asa[0].id
  replica_timeout_in_seconds   = 900
  replica_retry_limit          = 1
  tags                         = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.asa.id]
  }

  schedule_trigger_config {
    cron_expression = var.scan_cron
  }

  template {
    container {
      name    = "asa"
      image   = var.scheduler_image
      cpu     = 0.25
      memory  = "0.5Gi"
      command = ["python", "-c", var.scheduler_bootstrap]
      env {
        name  = "ASA_STORE_URL"
        value = "${azurerm_storage_account.findings.primary_blob_endpoint}${azurerm_storage_container.snapshots.name}"
      }
      env {
        name  = "AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.asa.client_id
      }
    }
  }
}

output "resource_group" { value = azurerm_resource_group.asa.name }
output "scanner_identity_principal_id" { value = azurerm_user_assigned_identity.asa.principal_id }
output "findings_storage_account" { value = azurerm_storage_account.findings.name }
output "reader_scopes_granted" { value = var.reader_scopes }
