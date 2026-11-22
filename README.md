# ASA: Autonomous Security Auditor

ASA discovers assets, identities, permissions and trust boundaries in a cloud/AI environment, tests them against
deterministic rules, and reports **what exists, which controls are missing, and which cannot be verified**.

**ASA is an auditor, not an enforcer.** It is read-only by construction: it never changes resources, RBAC, policies,
monitoring, guardrails or data, never blocks deployments, never remediates. Missing evidence is `NOT_VERIFIED`, never `PASS`.
First audited target: the MiniBank lab (a separate repo that ASA only reads). Collab decision `01M80YV1YQAYABHSEYSDBJZ7MT`.

## Quick start (offline, no cloud access needed)

```powershell
./scripts/bootstrap.ps1          # creates .venv, installs, runs tests
.\.venv\Scripts\asa --out out demo   # secure / insecure / unobservable fixtures + drift + alert outbox
start out\insecure.html          # the dashboard (static HTML, evidence drill-down per finding)
.\.venv\Scripts\python -m pytest -q
```

`demo` output is always labelled **SYNTHETIC FIXTURE**. Nothing in it was verified live.

## Real read-only scan of an Azure scope

```powershell
az login                                           # any identity with Reader on the target scope
copy config\minibank.example.toml config\minibank.local.toml   # edit subscription / resource group
.\.venv\Scripts\asa --out out scan --live          # GET-only ARM calls via the az CLI
.\.venv\Scripts\asa --out out serve                # local-only dashboard on 127.0.0.1:8765
```

The collector can issue **only HTTP GET** (plus the Resource Graph query endpoint, a read-only POST). Any other method or
host raises before reaching `az` (tested). Secret values are never read. Calls that are denied or need a POST action
become explicit **evidence gaps**.

## What is inside

| Path | Purpose |
|---|---|
| `src/asa/models.py` | Snapshot/Node/Edge/Finding/Gap. Invariant: PASS requires evidence; NOT_VERIFIED requires a reason |
| `src/asa/rules/library.py` | 17 rules (IAM, data, network, authz, logging, AI agents/tools/OAuth, DLP, detection, injection) |
| `src/asa/providers/azure_arm.py` | Read-only ARM/Resource Graph collector; `base.py` is the provider interface for future AWS/MCP/SaaS |
| `src/asa/graph.py` | Dependency chains; a chain is labelled by its weakest edge (confirmed/inferred/unknown) |
| `src/asa/agent.py`, `untrusted.py` | Read-only tool registry, untrusted-data fencing, citation validation, mock + Foundry adapter |
| `src/asa/store.py`, `alerts.py` | Timestamped snapshots, drift, opt-in notification-only alerts |
| `src/asa/report.py` | HTML dashboard, Markdown, JSON |
| `infra/` | Terraform for ASA's **own** resources only (validated, never applied) |
| `docs/` | Architecture, threat model, permissions matrix, cost, runbook, ADRs, tested-vs-mocked |

## Status

Phase 1 (offline MVP) and a first slice of Phase 2 (live ARM collector, graph, drift, alerts) are implemented.
See [docs/tested-vs-mocked.md](docs/tested-vs-mocked.md) for exactly what is verified live, what is simulated, and what is not built.
