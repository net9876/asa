# ADR 0003: Independent repo, separate identity and boundary

Status: accepted.

Decision: ASA lives in its own repository and deployment boundary (own resource group, ideally own subscription, own Terraform state,
own managed identity). MiniBank is the first target and is only read; its repo and deployed resources are never modified.
Python, standard library only at runtime (the live collector shells out to `az` for credentials, no SDK or secrets in ASA).
Provider interface (`Collector`) keeps Azure specifics out of rules so AWS/MCP/SaaS can be added.
Consequence: Windows `az` is resolved to its bundled Python (`-X utf8 -IBm azure.cli`) to avoid cmd.exe parsing of `&` in URLs.
