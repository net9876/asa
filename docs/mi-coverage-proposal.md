# Restoring Power Platform / Entra coverage for the scheduled job (proposal, nothing applied)

Status 2026-11-23: the job runs as managed identity `id-asa-scanner` and reaches 60% coverage vs ~79% under the
owner's interactive login. Everything below is read-only, needs the owner's explicit approval, and is ordered from
least to most privilege. Items marked (verify) rest on documentation I have not yet confirmed against this tenant.

## Update 2026-11-23: step 1 applied (owner-approved)
`ASA-Agent-Reader` now has read on Workflow, Connection Reference, Connector and Organization (all `prvRead*`);
its two inherited SharePoint create/write privileges were removed, so the role is read-only. The job now reads
cloud flows (name/state only, never the definition), connection reference counts and Dataverse audit settings.
Verified in job run `job-asa-scan-mo30zgl`. Remaining DENIED for the job: DLP, connector OAuth details, Entra apps.

## Already working for the job
- Azure Resource Manager (Reader on `rg-minibank-lab`), Log Analytics (Log Analytics Reader on one workspace).
- Dataverse `bots` (application user bound to the managed identity, custom read-only role `ASA-Agent-Reader`).

## What is still DENIED for the job, and the smallest fix for each

| Gap | Why denied | Smallest fix | Privilege added |
|---|---|---|---|
| `powerplatform.flows` | Flow admin API refuses the identity | Read flows from **Dataverse** (`workflows`, cloud flows) with the existing application user: add read on Process (`prvReadworkflow`) to `ASA-Agent-Reader`. Needs a collector change. | Read of flow definitions metadata inside one environment. No tenant consent. (verify the table exposes enough to match "Open review case") |
| `powerplatform.connectors` | BAP admin API refuses the identity | Read **connection references** from Dataverse (`connectionreferences`): add read on Connection Reference to the same role. | Read inside one environment. No tenant consent. (verify) |
| `powerplatform.dlp` | Tenant-level DLP policies are only on the admin API. Making a service principal allowed there means registering it as a Power Platform management app, which is **not read-only**. | **Do not grant.** Keep DLP as NOT_VERIFIED for the job and collect it only in owner-run scans (owner login), labelled as such in the report. | None |
| `entra.oauth` | Graph refuses the identity | Grant the managed identity the Graph **application permission `Application.Read.All`** (admin consent, one app-role assignment). Reads app registrations (expiry, scopes, secret/cert metadata; never values). | Tenant-wide read of app metadata. Needs your consent. |
| `telemetry.entra_logs` | needs `AuditLog.Read.All` | Optional, later. Tenant-wide read of audit/sign-in logs. | Broader; I recommend skipping for now. |
| `telemetry.powerplatform_audit` | not collected by this version | Read Dataverse audit settings (`organizations` audit flags) with the same application user; collector change only. | None beyond the role above |

## Suggested order
1. Dataverse role extension + collector changes for flows, connection references and audit settings (environment-local, no tenant consent).
2. `Application.Read.All` for the managed identity (one consent from you), for `entra.oauth`.
3. Leave DLP and Entra logs as NOT_VERIFIED in the job; report them as "owner-scan only" / "not collected".

## What stays true regardless
Missing evidence is NOT_VERIFIED, never PASS. ASA never writes to any of these systems. No secrets are involved:
all access is through the managed identity.
