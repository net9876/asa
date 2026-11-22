# Operational runbook

## Run a scan locally
1. `az login` with an identity that has **Reader** on the target. Prefer a dedicated ASA identity over your personal admin account.
2. Fill `config/minibank.local.toml` (git-ignored).
3. `asa --out out scan --live` then `asa --out out serve` and open http://127.0.0.1:8765/.
4. Re-run later: `scan` compares with the previous snapshot in `data/history/` and prints drift. Add `--alerts` to write new high/critical alerts to `out/alerts.jsonl`.

## Reading a report
* **Coverage %** is how many applicable checks reached PASS/FAIL. Low coverage = low visibility, not good security.
* **NOT_VERIFIED** items list the reason (DENIED, UNSUPPORTED, NOT_COLLECTED, ERROR). Fix by granting a read permission or building the collector.
* **declared** nodes come from design docs, not observation; chains through them are `inferred`/`unknown`.

## Routine tasks
| Task | How |
|---|---|
| Add a rule | add a `NodeRule` (or `Rule`) in `rules/library.py`, append to `ALL_RULES`, add a fixture case, run tests |
| Add a provider | implement `Collector`, return nodes/edges/gaps with provenance, never raise on denied calls |
| Rotate/inspect ASA access | `terraform plan` shows role assignments; remove scopes from `reader_scopes` and apply (with approval) |
| Retention | storage lifecycle policy (`snapshot_retention_days`); delete local `data/` and `out/` when no longer needed |

## Incident handling for ASA itself
* **Suspected credential theft**: disable the scanner managed identity / remove role assignments; review activity log for the identity; ASA made no writes, so audited resources need no rollback.
* **Suspicious injection finding (ASA-AI-004)**: identify who wrote the flagged field (activity log); the text is already excluded from agent context.
* **Unexpected write attempt**: `WriteAttempt` exception or `ToolDenied` is a bug or attack; file an issue, do not relax the allowlist.

## Never
Run `terraform apply`, grant roles, enable Defender/Sentinel, or change audited resources from ASA. Those are owner actions outside ASA.
