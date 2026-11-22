"""Core data model. Invariants that protect the product contract live here:

* PASS requires evidence (lack of evidence can never produce PASS).
* NOT_VERIFIED must say why (gap reason).
* Every node/edge carries provenance (source, API, time, live|fixture mode).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_VERIFIED = "NOT_VERIFIED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["info", "low", "medium", "high", "critical"].index(self.value)


class Basis(StrEnum):
    CONFIRMED = "confirmed"  # observed through a read API
    INFERRED = "inferred"  # derived from configuration or documentation
    UNKNOWN = "unknown"  # relationship expected but not observable


class RefKind(StrEnum):
    REQUIREMENT = "requirement"  # a standard states this as a requirement
    RECOMMENDATION = "recommendation"  # guidance / good practice only


@dataclass(frozen=True)
class Provenance:
    source: str  # e.g. "arm", "fixture:insecure", "declared:minibank-iac"
    api: str  # e.g. "GET Microsoft.Storage/storageAccounts"
    collected_at: str  # ISO 8601 UTC
    mode: str  # "live" | "fixture" | "declared"


@dataclass
class Node:
    id: str
    type: str  # resource|identity|role|endpoint|agent|model|tool|connector|datastore|action
    name: str
    props: dict[str, Any]
    prov: Provenance


@dataclass
class Edge:
    src: str
    dst: str
    type: str  # invokes|accesses|runs-as|delegates-to|reads|writes|trusts
    basis: Basis
    props: dict[str, Any]
    prov: Provenance


@dataclass
class Gap:
    """An evidence gap: something ASA could not see. Never fabricated into a result."""

    area: str  # dotted key, e.g. "arm.role_assignments"
    reason: str  # DENIED | UNSUPPORTED | NOT_COLLECTED | ERROR
    detail: str
    scope: str = ""


@dataclass
class Snapshot:
    taken_at: str
    mode: str  # live | fixture | declared | mixed
    label: str
    scope: str
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    gaps: list[Gap] = field(default_factory=list)

    def nodes_of(self, *types: str) -> list[Node]:
        return [n for n in self.nodes if n.type in types]

    def node(self, node_id: str) -> Node | None:
        return next((n for n in self.nodes if n.id == node_id), None)

    def gap_for(self, area: str) -> Gap | None:
        """First gap whose area equals or is a prefix-parent of `area`."""
        for g in self.gaps:
            if area == g.area or area.startswith(g.area + "."):
                return g
        return None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Snapshot:
        def prov(p: dict[str, Any]) -> Provenance:
            return Provenance(**p)

        return Snapshot(
            taken_at=d["taken_at"],
            mode=d["mode"],
            label=d["label"],
            scope=d["scope"],
            nodes=[Node(n["id"], n["type"], n["name"], n["props"], prov(n["prov"])) for n in d["nodes"]],
            edges=[Edge(e["src"], e["dst"], e["type"], Basis(e["basis"]), e["props"], prov(e["prov"])) for e in d["edges"]],
            gaps=[Gap(**g) for g in d["gaps"]],
        )


@dataclass(frozen=True)
class Reference:
    name: str  # e.g. "CIS Azure Foundations 3.x: Ensure public access is disabled"
    kind: RefKind


@dataclass
class Evidence:
    source: str
    api: str
    collected_at: str
    mode: str
    observed: dict[str, Any]


@dataclass
class Finding:
    rule_id: str
    rule_version: str
    status: Status
    severity: Severity
    asset_id: str
    scope: str
    title: str
    evidence: list[Evidence]
    context: str
    confidence: str  # high | medium | low
    impact: str
    recommendation: str
    references: list[Reference] = field(default_factory=list)
    mode: str = "fixture"  # mode of the evidence base

    def __post_init__(self) -> None:
        if self.status is Status.PASS and not self.evidence:
            raise ValueError(f"{self.rule_id}: PASS without evidence is not allowed")
        if self.status is Status.NOT_VERIFIED and not self.context:
            raise ValueError(f"{self.rule_id}: NOT_VERIFIED must state why")

    @property
    def fingerprint(self) -> str:
        return f"{self.rule_id}|{self.asset_id}"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
