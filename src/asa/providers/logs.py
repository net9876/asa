"""Read-only Log Analytics freshness and correlation check.

Safety properties: GET only (the query API accepts GET), https only, host allowlist (SaaSClient). The KQL below
returns AGGREGATES ONLY: table names, last-ingest timestamps, row counts and distinct-id join counts. No log
message, URL, user, header or payload field is ever selected, so nothing sensitive can enter a snapshot.
"""

from __future__ import annotations

import urllib.parse
from datetime import UTC, datetime
from typing import Any

from asa.models import Gap, Provenance, Snapshot
from asa.providers.azure_arm import ArmError
from asa.providers.saas import SaaSClient

LA_HOST = "api.loganalytics.io"
LA_RESOURCE = "https://api.loganalytics.io"

FRESHNESS_KQL = (
    "union isfuzzy=true AppRequests, AppDependencies, AppTraces, AppExceptions, FunctionAppLogs, "
    "ApiManagementGatewayLogs, AzureDiagnostics "
    "| where TimeGenerated > ago(7d) "
    "| summarize last_ingest=max(TimeGenerated), rows_7d=count() by Type"
)
CORRELATION_KQL = (
    "let r = AppRequests | where TimeGenerated > ago(7d) | distinct OperationId; "
    "let d = AppDependencies | where TimeGenerated > ago(7d) | distinct OperationId; "
    "let t = AppTraces | where TimeGenerated > ago(7d) | distinct OperationId; "
    "print requests=toscalar(r | count), "
    "with_dependency=toscalar(r | join kind=inner d on OperationId | count), "
    "with_trace=toscalar(r | join kind=inner t on OperationId | count)"
)
STALE_AFTER_HOURS = 24.0


def make_client(token_for: Any) -> SaaSClient:
    return SaaSClient(token_for, extra_hosts=(LA_HOST,))


def _rows(resp: dict[str, Any]) -> list[dict[str, Any]]:
    tables = resp.get("tables") or []
    if not tables:
        return []
    cols = [c["name"] for c in tables[0].get("columns", [])]
    return [dict(zip(cols, r, strict=False)) for r in tables[0].get("rows", [])]


def _query(c: SaaSClient, customer_id: str, kql: str) -> list[dict[str, Any]]:
    url = f"https://{LA_HOST}/v1/workspaces/{customer_id}/query?query={urllib.parse.quote(kql, safe='')}"
    return _rows(c.get(url, LA_RESOURCE))


def _age_hours(ts: str, now: datetime) -> float | None:
    try:
        return round((now - datetime.fromisoformat(ts.replace("Z", "+00:00"))).total_seconds() / 3600, 1)
    except (ValueError, TypeError):
        return None


def collect(snap: Snapshot, client: SaaSClient, now: datetime | None = None) -> None:
    """Annotate each log-workspace node with `freshness` and `correlation`; resolve or refine the gap."""
    now = now or datetime.now(UTC)
    for n in snap.nodes:
        cid = n.props.get("customer_id")
        if n.props.get("kind") != "log-workspace" or not cid:
            continue
        prov = Provenance("log-analytics", "GET query (aggregates only)", now.strftime("%Y-%m-%dT%H:%M:%SZ"), "live")
        try:
            fresh = _query(client, cid, FRESHNESS_KQL)
        except ArmError as e:
            _set_gap(snap, "DENIED" if e.kind == "DENIED" else "ERROR", e.detail)
            return
        snap.gaps = [g for g in snap.gaps if g.area != "telemetry.log_freshness"]
        n.props["freshness"] = [
            {
                "table": r.get("Type"),
                "last_ingest": r.get("last_ingest"),
                "age_hours": _age_hours(str(r.get("last_ingest")), now),
                "rows_7d": r.get("rows_7d"),
            }
            for r in sorted(fresh, key=lambda x: str(x.get("Type")))
        ]
        try:
            rows = _query(client, cid, CORRELATION_KQL)
            n.props["correlation"] = {k: rows[0].get(k) for k in ("requests", "with_dependency", "with_trace")} if rows else None
        except ArmError as e:
            n.props["correlation"] = None
            snap.gaps.append(Gap("telemetry.log_correlation", "DENIED" if e.kind == "DENIED" else "ERROR", e.detail, snap.scope))
        n.prov = prov


def _set_gap(snap: Snapshot, reason: str, detail: str) -> None:
    snap.gaps = [g for g in snap.gaps if g.area != "telemetry.log_freshness"]
    snap.gaps.append(Gap("telemetry.log_freshness", reason, detail, snap.scope))
