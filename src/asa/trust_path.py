"""Machine-readable trust-path report: every hop labelled confirmed / inferred / unknown.

Nothing is invented: a hop is `confirmed` only when a collector saw it; `inferred` comes from design
or naming; `unknown` means no evidence. Business authorization is never claimed, only the hops'
technical basis plus what evidence would upgrade each non-confirmed hop.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from asa.graph import chains
from asa.models import Basis, Edge, Snapshot

_UPGRADE = {
    "delegates-to": "Read the connector/app OAuth settings and consent grants that bind this hop (Entra + Power Platform read).",
    "invokes": "Read the calling component's configured action/endpoint (Copilot Studio agent or flow definition: needs Dataverse read on Agent).",
    "runs-as": "Read the resource's assigned identity (ARM read).",
    "accesses": "Read the role assignment or network rule granting this access (ARM read).",
    "trusts": "Read the trust configuration (audience/issuer/CORS) on both sides.",
}


def _hop(s: Snapshot, e: Edge) -> dict[str, Any]:
    a, b = s.node(e.src), s.node(e.dst)
    return {
        "from": {"id": e.src, "name": a.name if a else e.src, "type": a.type if a else None},
        "to": {"id": e.dst, "name": b.name if b else e.dst, "type": b.type if b else None},
        "relation": e.type,
        "basis": e.basis.value,
        "evidence": {"source": e.prov.source, "api": e.prov.api, "collected_at": e.prov.collected_at, "mode": e.prov.mode},
        "observed_props": {k: v for k, v in e.props.items() if not isinstance(v, (dict, list))},
        "to_confirm": None if e.basis is Basis.CONFIRMED else _UPGRADE.get(e.type, "Collect direct evidence for this relation."),
    }


def build(s: Snapshot) -> dict[str, Any]:
    paths = []
    for c in chains(s, {"identity", "agent"}, {"datastore", "action"}):
        start = s.node(c.nodes[0])
        if not start or start.props.get("kind") not in ("human", None):
            continue
        paths.append(
            {
                "path_basis": c.basis.value,
                "summary": c.describe(s),
                "hops": [_hop(s, e) for e in c.edges],
                "business_authorization": "not_proven",
            }
        )
    seen: dict[tuple[str, str, str], Edge] = {(e.src, e.dst, e.type): e for e in s.edges}
    counts = Counter(e.basis.value for e in seen.values())
    open_hops = [_hop(s, e) for e in seen.values() if e.basis is not Basis.CONFIRMED]
    return {
        "scope": s.scope,
        "taken_at": s.taken_at,
        "mode": s.mode,
        "edge_counts": {k: counts.get(k, 0) for k in ("confirmed", "inferred", "unknown")},
        "paths": paths,
        "open_hops": open_hops,
        "note": "business_authorization is always not_proven: ASA proves technical hops, not approval workflows.",
    }


def to_markdown_section(t: dict[str, Any]) -> str:
    c = t["edge_counts"]
    out = [
        "## Trust path",
        "",
        f"Edges: confirmed {c['confirmed']} · inferred {c['inferred']} · unknown {c['unknown']}. Business authorization: not proven.",
        "",
    ]
    for p in t["paths"]:
        out.append(f"- **{p['path_basis']}**: {p['summary']}")
    if t["open_hops"]:
        out += ["", "To confirm:"]
        out += [f"- {h['from']['name']} -[{h['relation']}:{h['basis']}]-> {h['to']['name']}: {h['to_confirm']}" for h in t["open_hops"]]
    return "\n".join(out) + "\n"
