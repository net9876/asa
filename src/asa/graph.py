"""Dependency chains over the security graph. A chain is only as certain as its weakest edge."""

from __future__ import annotations

from dataclasses import dataclass

from asa.models import Basis, Edge, Snapshot

_ORDER = {Basis.CONFIRMED: 0, Basis.INFERRED: 1, Basis.UNKNOWN: 2}
TRAVERSE = {"invokes", "delegates-to", "accesses", "reads", "writes", "runs-as", "trusts"}


@dataclass
class Chain:
    nodes: list[str]
    edges: list[Edge]

    @property
    def basis(self) -> Basis:
        return max((e.basis for e in self.edges), key=lambda b: _ORDER[b]) if self.edges else Basis.CONFIRMED

    def describe(self, snap: Snapshot) -> str:
        parts = [snap.node(self.nodes[0]).name if snap.node(self.nodes[0]) else self.nodes[0]]  # type: ignore[union-attr]
        for e in self.edges:
            n = snap.node(e.dst)
            parts.append(f"-[{e.type}:{e.basis.value}]-> {n.name if n else e.dst}")
        return " ".join(parts)


def chains(snap: Snapshot, start_types: set[str], end_types: set[str], max_depth: int = 8) -> list[Chain]:
    """All simple paths from nodes of start_types to nodes of end_types."""
    adj: dict[str, list[Edge]] = {}
    for e in snap.edges:
        if e.type in TRAVERSE:
            adj.setdefault(e.src, []).append(e)
    found: list[Chain] = []

    def walk(cur: str, path: list[str], edges: list[Edge]) -> None:
        node = snap.node(cur)
        if edges and node and node.type in end_types:
            found.append(Chain(list(path), list(edges)))
        if len(path) > max_depth:
            return
        for e in adj.get(cur, []):
            if e.dst not in path:
                walk(e.dst, [*path, e.dst], [*edges, e])

    for n in snap.nodes:
        if n.type in start_types:
            walk(n.id, [n.id], [])
    return found
