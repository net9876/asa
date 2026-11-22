# ADR 0004: Evidence gaps and provenance are first-class

Status: accepted.

Decision: every node and edge records source, API, time and mode (live, fixture, declared). Denied or unsupported reads create `Gap`
records that rules turn into NOT_VERIFIED with the reason. Coverage % is reported before findings. Documentation-derived relationships are
`declared` with basis `inferred` or `unknown`, never `confirmed`. Reports show a banner stating the mode of the evidence.
Consequence: an environment with no read permission scores low coverage instead of looking secure.
