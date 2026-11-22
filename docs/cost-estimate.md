# Cost estimate (ESTIMATE, not verified against the Azure pricing calculator)

Assumptions: one small subscription/resource-group scope, one scan per day, East US 2, pay-as-you-go. Re-check before approving.

| Item | Config | Estimated monthly | Notes |
|---|---|---|---|
| Findings storage | Standard LRS, versioned, ~50 MB | < $0.10 | retention rule deletes after 180 days |
| Scanner identity, RBAC | n/a | $0 | |
| Scheduler | Container Apps consumption job, 0.25 vCPU, ~2 min/day | ~$0 (inside free monthly grant) | optional, `enable_scheduler=false` by default; run locally instead |
| Dashboard | static HTML; local `asa serve`, or blob static site / SWA Free | $0 to < $1 | no hosting module in Terraform yet |
| Log Analytics (ASA's own) | daily cap 0.1 GB | $0 to ~$7 (cap) | optional, off by default |
| Model explanations | Foundry `gpt-4.1-mini`, ~20k tokens/day | cents to ~$1 | reuses existing Foundry account; mock agent costs $0 |
| Azure Resource Graph, ARM reads | | $0 | |
| Defender / Sentinel | not required | $0 | ASA never enables them |

**Expected: about $0 to $2 per month** with the defaults (storage only, local run, mock or small model use). Worst case with every option on: roughly $10/month.

## Approval prerequisites (nothing below has been done)

1. Choose ASA's subscription/RG (ideally separate from audited subscriptions) and a separate Terraform state account.
2. `terraform plan` with `reader_scopes` listed; owner reviews every role assignment in the plan output.
3. Owner approves `terraform apply` explicitly.
4. If the reasoning agent should use the shared Foundry: approve one `Cognitive Services OpenAI User` assignment on that account.
5. Planned collectors for Entra/Power Platform need tenant-admin consent and Power Platform admin role: approve separately, per collector.
