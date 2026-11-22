# Read-only permissions and visibility matrix

All access is read. Role names are Azure built-ins. "Visibility" says what ASA can and cannot see with that permission.

| Area | API (method) | Minimum permission | Visibility / limit | Status in this repo |
|---|---|---|---|---|
| Inventory | `GET .../resourceGroups/{rg}/resources`; Resource Graph query (read-only POST) | `Reader` on RG/subscription | All resources and types in scope | live-tested (GET); ARG implemented, enabled via `use_resource_graph` |
| Storage posture | `GET Microsoft.Storage/storageAccounts` | Reader | public blob, shared key, network ACL, private endpoints. **Not** container ACLs or blobs | live-tested |
| SQL posture | `GET Microsoft.Sql/servers`, `firewallRules`, `azureADOnlyAuthentications` | Reader | public access, firewall rules, Entra-only. **Not** database users/permissions (T-SQL) | live-tested |
| APIM | `GET service`, `apis`, `apis/{id}/policies/policy` | Reader | policy XML: token validation, audience, claims, backend auth | live-tested |
| Functions | `GET Microsoft.Web/sites`, `config/authsettingsV2` | Reader | auth required, allowed identities. **Not** app setting values (POST `list` action) | live-tested (settings = documented gap) |
| Identities | `GET userAssignedIdentities`; `GET roleAssignments?$filter=principalId`, `roleDefinitions` | Reader | role assignments of managed identities. **Not** Entra directory roles | live-tested |
| Diagnostics | `GET {resource}/providers/Microsoft.Insights/diagnosticSettings` | Reader | whether logs are routed to a workspace. **Not** log content | live-tested |
| Defender plans | `GET Microsoft.Security/pricings` | Reader (or `Security Reader`) | plan tiers | live-tested |
| Foundry deployments | `GET accounts/{a}/deployments`, `raiPolicies/{name}` | Reader on the Foundry account | model, attached RAI policy; built-in policies return 404 so shielding stays NOT_VERIFIED | live-tested (gap recorded) |
| Foundry agents/tools | project data-plane endpoint | `Azure AI User` on project (read) | agent instructions, tools, connections | **not built** |
| Entra OAuth / consents | Microsoft Graph `applications`, `oauth2PermissionGrants`, `servicePrincipals` | Graph `Application.Read.All`, `DelegatedPermissionGrant.Read.All` (application permissions, admin consent) | real granted scopes | **not built; needs tenant admin consent, requires owner approval** |
| Power Platform / Copilot Studio / Dataverse | Power Platform admin API, Dataverse Web API (GET) | Power Platform admin read role, Dataverse read-only security role | agents, flows, connector auth, DLP | **not built; needs admin roles, requires owner approval** |
| Sentinel / Defender incidents (optional) | Log Analytics / Security APIs | `Reader` + `Log Analytics Reader` / `Security Reader` | optional correlation only | **not built**; ASA works without |

## ASA's own identity (Terraform `infra/modules/asa_core`)

| Grant | Scope | Why |
|---|---|---|
| `Reader` | each scope in `reader_scopes` (default: none) | discovery |
| optional read roles (`Security Reader`, ...) | `optional_role_assignments` (write roles rejected by validation) | extra signals |
| `Storage Blob Data Contributor` | ASA's own `snapshots` container only | history |
| `Cognitive Services OpenAI User` | the reused Foundry account, only if `foundry_account_id` set | explanations (inference only) |

Never granted: Owner, Contributor, User Access Administrator, RBAC Administrator, any write role on audited scopes, tenant-wide admin consent.
