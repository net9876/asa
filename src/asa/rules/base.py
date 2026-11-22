"""Rule framework. Rules are deterministic; the LLM never decides a verdict."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from asa.models import (
    Evidence,
    Finding,
    Node,
    Reference,
    RefKind,
    Severity,
    Snapshot,
    Status,
)


def req(name: str) -> Reference:
    return Reference(name, RefKind.REQUIREMENT)


def rec(name: str) -> Reference:
    return Reference(name, RefKind.RECOMMENDATION)


@dataclass(frozen=True)
class RuleMeta:
    id: str
    version: str
    title: str
    severity: Severity
    area: str  # evidence-gap area this rule depends on
    impact: str
    recommendation: str
    refs: tuple[Reference, ...]


@dataclass
class Verdict:
    status: Status
    context: str
    observed: dict[str, Any]
    severity: Severity | None = None  # override meta.severity for this asset
    confidence: str = "high"


def passed(context: str, **observed: Any) -> Verdict:
    return Verdict(Status.PASS, context, observed)


def failed(context: str, severity: Severity | None = None, **observed: Any) -> Verdict:
    return Verdict(Status.FAIL, context, observed, severity)


def unknown(context: str, **observed: Any) -> Verdict:
    return Verdict(Status.NOT_VERIFIED, context, observed, confidence="low")


Check = Callable[[Node, Snapshot], Verdict]


class Rule:
    meta: RuleMeta

    def evaluate(self, snap: Snapshot) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError


def make_finding(
    meta: RuleMeta,
    snap: Snapshot,
    asset_id: str,
    v: Verdict,
    node: Node | None,
    *,
    title_suffix: str = "",
) -> Finding:
    ev: list[Evidence] = []
    if node is not None and v.status is not Status.NOT_VERIFIED:
        ev.append(Evidence(node.prov.source, node.prov.api, node.prov.collected_at, node.prov.mode, v.observed))
    elif v.observed:
        ev.append(Evidence("asa-rule-engine", "n/a", snap.taken_at, snap.mode, v.observed))
    sev = v.severity or meta.severity
    if v.status in (Status.PASS, Status.NOT_APPLICABLE):
        sev = Severity.INFO
    return Finding(
        rule_id=meta.id,
        rule_version=meta.version,
        status=v.status,
        severity=sev,
        asset_id=asset_id,
        scope=snap.scope,
        title=meta.title + title_suffix,
        evidence=ev,
        context=v.context,
        confidence=v.confidence,
        impact=meta.impact,
        recommendation=meta.recommendation,
        references=list(meta.refs),
        mode=node.prov.mode if node else snap.mode,
    )


class NodeRule(Rule):
    """Applies a per-asset check to every node a selector returns."""

    def __init__(self, meta: RuleMeta, selector: Callable[[Snapshot], list[Node]], check: Check) -> None:
        self.meta = meta
        self._selector = selector
        self._check = check

    def evaluate(self, snap: Snapshot) -> list[Finding]:
        nodes = self._selector(snap)
        if not nodes:
            return [scope_level_result(self.meta, snap)]
        return [make_finding(self.meta, snap, n.id, self._check(n, snap), n) for n in nodes]


def scope_level_result(meta: RuleMeta, snap: Snapshot) -> Finding:
    """No applicable assets: a gap means NOT_VERIFIED, otherwise NOT_APPLICABLE."""
    gap = snap.gap_for(meta.area)
    if gap:
        v = unknown(f"Evidence gap [{gap.reason}] {gap.area}: {gap.detail}", gap_area=gap.area)
    else:
        v = Verdict(Status.NOT_APPLICABLE, "No assets of the applicable type in scope.", {})
    return make_finding(meta, snap, f"scope:{snap.scope}", v, None)


def selector(*types: str, kind: str | None = None) -> Callable[[Snapshot], list[Node]]:
    def sel(snap: Snapshot) -> list[Node]:
        out = snap.nodes_of(*types)
        if kind is not None:
            out = [n for n in out if n.props.get("kind") == kind]
        return out

    return sel
