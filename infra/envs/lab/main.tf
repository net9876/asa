# Example ASA deployment. DO NOT apply without owner approval. Plan first:
#   terraform init -backend-config=backend.example.hcl
#   terraform plan -var-file=asa.example.tfvars -out asa.tfplan   (review every role assignment)
# State is separate from any audited workload (own backend key, ideally own subscription).
terraform {
  required_version = ">= 1.10, < 2.0"
  backend "local" { path = "../../../data/tfstate/asa-lab.tfstate" }
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

variable "subscription_id" { type = string }
variable "location" { type = string }
variable "reader_scopes" { type = list(string) }
variable "foundry_account_id" {
  type    = string
  default = null
}
variable "enable_observability" {
  type    = bool
  default = false
}
variable "enable_scheduler" {
  type    = bool
  default = false
}
variable "scheduler_bootstrap" {
  type    = string
  default = ""
}
variable "enable_keyvault" {
  type    = bool
  default = false
}
variable "scan_cron" {
  type    = string
  default = "0 6 * * *"
}

provider "azurerm" {
  features {}
  subscription_id                 = var.subscription_id
  resource_provider_registrations = "none"
  storage_use_azuread             = true
}

module "asa" {
  source               = "../../modules/asa_core"
  location             = var.location
  reader_scopes        = var.reader_scopes
  foundry_account_id   = var.foundry_account_id
  enable_observability = var.enable_observability
  enable_scheduler     = var.enable_scheduler
  scheduler_bootstrap  = var.scheduler_bootstrap
  scan_cron            = var.scan_cron
  enable_keyvault      = var.enable_keyvault
}

output "asa" {
  value = {
    resource_group = module.asa.resource_group
    identity       = module.asa.scanner_identity_principal_id
    storage        = module.asa.findings_storage_account
    reader_scopes  = module.asa.reader_scopes_granted
  }
}
