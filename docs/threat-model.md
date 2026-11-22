# Threat model of ASA itself

ASA holds broad read access and processes attacker-influenceable text, so it is a target.

| # | Threat | Control (implemented unless marked) | Residual risk |
|---|---|---|---|
| T1 | Stolen ASA credentials give broad read of the environment | Dedicated user-assigned identity, `Reader` only on listed scopes, no standing write roles, Terraform validation rejects Owner/Contributor/UAA/RBAC-admin; no secrets in code/logs (az CLI broker, token never stored); *planned:* Conditional Access / workload identity restrictions | Reader still exposes configuration metadata. Treat ASA storage as sensitive |
| T2 | Prompt injection via resource names, tags, logs, tool results | `untrusted.py` scanner flags instruction-like text (rule ASA-AI-004 reports it); sanitised before the model; fenced `UNTRUSTED_DATA`; system prompt forbids following it; model cannot change verdicts | Pattern list is heuristic. Defence relies mainly on architecture: model has no write tools and verdicts are deterministic |
| T3 | Exfiltration through the model or alerts | Model sees metadata/findings only (never secret values, never business records); alert payload = rule/asset/severity; webhook https-only and opt-in; *planned:* egress restriction on ASA host | Resource names are included in alerts |
| T4 | Hallucinated findings | Rules own verdicts; `validate_explanation` rejects citations to non-existent findings; MOCK/FOUNDRY label on narrative | Model prose may still be misleading; the verdict table is the source of truth |
| T5 | Visibility gaps read as "secure" | Missing property/gap → NOT_VERIFIED; PASS without evidence raises; rule crash → NOT_VERIFIED; coverage % shown first | Rules only cover what is modelled; see unsupported list in tested-vs-mocked |
| T6 | Collector used to write to audited systems | Client allows GET only (+ ARG query POST); host allowlist; refusal tested; agent tool registry denies write verbs/unknown tools | `az` CLI session identity could be over-privileged; run ASA under the Reader identity (see runbook) |
| T7 | Evidence tampering / repudiation | Snapshots timestamped, versioned blobs (Terraform), retention policy; *planned:* immutability policy / hash chain | Local JSON history is not tamper-evident |
| T8 | Sensitive data retained too long | `snapshot_retention_days` lifecycle rule (default 180); local `data/` and `out/` are git-ignored | Local copies are the operator's responsibility |
| T9 | Supply chain of ASA | Stdlib-only runtime; dev tools pinned by range | No SBOM/signing yet |
| T10 | Over-claiming exploitability | Findings state configuration facts, confidence, and "no claim of exploitability"; chains labelled by weakest edge | Reader must not treat FAIL as proof of exploit |

Trust boundaries: (1) audited environment → collectors (untrusted data), (2) snapshot → model (fenced), (3) model → report (validated),
(4) ASA → outside (alerts only, opt-in). The LLM is outside the trust boundary for decisions.
