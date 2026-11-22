subscription_id = "00000000-0000-0000-0000-000000000000" # ASA's own subscription (ideally separate from audited ones)
location        = "eastus2"
reader_scopes = [
  "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-minibank-lab",
]
# foundry_account_id = "/subscriptions/.../accounts/shared-lab-foundry" # optional: adds one role assignment on that account
enable_observability = false
enable_scheduler     = false
