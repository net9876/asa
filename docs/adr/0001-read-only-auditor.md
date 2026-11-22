# ADR 0001: ASA is read-only and never enforces

Status: accepted (follows Collab decision 01M80YV1YQAYABHSEYSDBJZ7MT).

Decision: ASA discovers and assesses; it never remediates, blocks, enables Defender/Sentinel/guardrails or alters audited resources.
Enforced in code (GET-only client with host allowlist, agent tool allowlist) and in Terraform (write roles rejected).
Rejected: active guardian, self-remediation, CI/CD blocking, standing admin write access.
Consequence: findings need a human or another pipeline to act; ASA's value is evidence and honesty about visibility.
