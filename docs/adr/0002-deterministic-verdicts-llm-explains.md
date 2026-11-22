# ADR 0002: Deterministic rules decide, the model explains

Status: accepted.

Decision: PASS/FAIL/NOT_VERIFIED/N/A come only from rules over collected evidence. The Foundry model receives sanitised, fenced
read-only evidence, may correlate and narrate, must cite findings, and its output is rejected if it cites non-existent findings.
Unknown or missing data is NOT_VERIFIED. Rejected: LLM-as-judge verdicts (non-reproducible, injectable, hallucination risk).
Consequence: model quality affects readability only, not correctness; the pipeline works with `MockAgent` and no cloud access.
