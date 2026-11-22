"""Rule engine: runs all rules, never lets an error or missing evidence become PASS."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from asa.models import Evidence, Finding, Severity, Snapshot, Status
from asa.rules.base import Rule
from asa.rules.library import ALL_RULES


@dataclass
class Assessment:
    snapshot: Snapshot
    findings: list[Finding] = field(default_factory=list)

    @property
    def coverage_pct(self) -> float:
        """Share of applicable checks that reached a verified verdict (PASS or FAIL)."""
        applicable = [f for f in self.findings if f.status is not Status.NOT_APPLICABLE]
        if not applicable:
            return 0.0
        verified = [f for f in applicable if f.status in (Status.PASS, Status.FAIL)]
        return round(100.0 * len(verified) / len(applicable), 1)

    def by_status(self) -> Counter[str]:
        return Counter(f.status.value for f in self.findings)

    def fails_by_severity(self) -> Counter[str]:
        return Counter(f.severity.value for f in self.findings if f.status is Status.FAIL)


def run(snapshot: Snapshot, rules: list[Rule] | None = None) -> Assessment:
    out: list[Finding] = []
    for rule in rules if rules is not None else ALL_RULES:
        try:
            out.extend(rule.evaluate(snapshot))
        except Exception as exc:  # a crashing rule is a visibility gap, never a PASS
            m = rule.meta
            out.append(
                Finding(
                    rule_id=m.id,
                    rule_version=m.version,
                    status=Status.NOT_VERIFIED,
                    severity=Severity.INFO,
                    asset_id=f"scope:{snapshot.scope}",
                    scope=snapshot.scope,
                    title=m.title,
                    evidence=[Evidence("asa-rule-engine", "n/a", snapshot.taken_at, snapshot.mode, {})],
                    context=f"Rule raised {type(exc).__name__}; result withheld, not treated as PASS.",
                    confidence="low",
                    impact=m.impact,
                    recommendation="Fix the rule or collector data and re-run.",
                    references=list(m.refs),
                    mode=snapshot.mode,
                )
            )
    out.sort(key=lambda f: (f.status is not Status.FAIL, -f.severity.rank, f.rule_id, f.asset_id))
    return Assessment(snapshot, out)
