# Tested vs mocked vs not built

Legend: **LIVE** = observed against the real MiniBank Azure scope on 2026-11-22 (read-only, GET only);
**UNIT** = automated test with synthetic data or a fake `az` runner; **MOCK** = deterministic stand-in; **NOT BUILT**.

The live scan ran under the owner's interactive `az login` identity, **not** under a dedicated ASA Reader identity, so it did
**not** verify that the minimal Reader grant is sufficient. That remains to be tested after the identity is created.

| Capability | LIVE | UNIT | MOCK | NOT BUILT |
|---|---|---|---|---|
| ARM inventory of `rg-minibank-lab` | yes | yes (fake runner) | | |
| Storage / SQL / APIM / Function / identity / role-assignment / diagnostics reads | yes | yes | | |
| APIM policy parsing (real policy has a UTF-8 BOM; false FAIL found and fixed live, regression-tested) | yes | yes | | |
| Resource Graph inventory | no (implemented, optional flag) | yes (POST allowlist) | | live run |
| Foundry deployment + RAI policy reads | yes (built-in policy returns 404 → NOT_VERIFIED) | | | custom policy case |
| Function app settings (secrets posture) | gap: needs POST action | yes | | |
| Sentinel presence | gap recorded | | | collector |
| Foundry agent/tool definitions (data plane) | | | | collector |
| Entra OAuth scopes / consent grants | | | | collector (needs admin consent) |
| Power Platform / Copilot Studio / Dataverse / DLP | | | declared overlay, labelled `declared` | collector (needs admin read roles) |
| 17 rules, PASS/FAIL/NOT_VERIFIED/N/A semantics | partly (rules ran on live data) | yes (secure/insecure/unobservable fixtures) | | |
| Evidence-never-PASS invariants (blanked data, crash, denied API) | | yes | | |
| Graph chains, weakest-edge labelling | live chain APIM→Function→identity→Storage | yes | operator→agent→connector declared | confirmed Power Platform hops |
| Prompt-injection handling (flag, sanitise, fence) | | yes | | adversarial corpus |
| Agent cannot call write tools | | yes | | |
| Foundry reasoning agent | | prompt building only | `MockAgent` | **no model call was made**; `FoundryAgent.explain` is unverified |
| Snapshot history, drift, alerts (new high/critical) | live snapshot saved + drift run | yes | file outbox only | webhook delivery untested |
| HTML/MD/JSON report, local dashboard | yes (generated from live data) | yes | | hosted dashboard, auth |
| Terraform `asa_core` | | `terraform validate` OK | | **no plan, no apply**; plan needs a target subscription and approval |

## Confirmed MiniBank dependency chain (live evidence)
`APIM api minibank-payments` **–invokes (confirmed: serviceUrl equals function host)→** `minibank-functions` **–runs-as (confirmed)→** `id-minibank-functions`
**–accesses (confirmed: role assignment)→** storage `mbdata…`. SQL access is *inferred* (Entra DB user is not visible through ARM).
Upstream hops (operator → Copilot Studio → connector → APIM) are `unknown`/`inferred`, taken from docs/MiniBank-Design.md.

## Roadmap
1. Create ASA Reader identity (needs approval) and re-run the live scan under it; fix permission gaps.
2. Collectors: Entra Graph (scopes/consents), Power Platform admin API + Dataverse (read), Foundry project data plane.
3. Run `FoundryAgent` against the reused account; evaluate explanation quality with a citation-validated test set.
4. Hosted dashboard + scheduler (Terraform options exist, off by default); immutable evidence storage.
5. Providers: AWS Bedrock/AgentCore, MCP servers, other agent platforms.
