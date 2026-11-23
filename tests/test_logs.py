from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from asa import telemetry
from asa.models import Gap, Node, Provenance, Snapshot
from asa.providers import logs
from asa.providers.azure_arm import ArmError, WriteAttempt
from asa.providers.saas import SaaSClient

P = Provenance("arm", "x", "2026-01-01T00:00:00Z", "live")
NOW = datetime(2026, 1, 2, 12, 0, tzinfo=UTC)
CID = "11111111-2222-3333-4444-555555555555"


def _snap() -> Snapshot:
    s = Snapshot(taken_at="2026-01-02T12:00:00Z", mode="live", label="t", scope="sub/rg")
    s.nodes.append(Node("/ws", "resource", "log-x", {"kind": "log-workspace", "customer_id": CID}, P))
    s.gaps.append(Gap("telemetry.log_freshness", "NOT_COLLECTED", "not yet", "sub/rg"))
    return s


def _table(cols: list[str], rows: list[list[Any]]) -> dict[str, Any]:
    return {"tables": [{"name": "PrimaryResult", "columns": [{"name": c} for c in cols], "rows": rows}]}


def _client(handler: Any, seen: list[str] | None = None) -> SaaSClient:
    def fetch(url: str, token: str) -> Any:
        if seen is not None:
            seen.append(url)
        return handler(url)

    return SaaSClient(lambda r: "tok", extra_hosts=(logs.LA_HOST,), fetch=fetch)


def test_freshness_and_correlation_are_aggregates_and_resolve_the_gap() -> None:
    def h(url: str) -> Any:
        if "print" in url or "print%20" in url:
            return _table(["requests", "with_dependency", "with_trace"], [[10, 9, 8]])
        return _table(
            ["Type", "last_ingest", "rows_7d"],
            [["AppRequests", "2026-01-02T11:00:00Z", 10], ["FunctionAppLogs", "2025-12-30T00:00:00Z", 4]],
        )

    s = _snap()
    logs.collect(s, _client(h), NOW)
    assert not any(g.area == "telemetry.log_freshness" for g in s.gaps)
    t = telemetry.build(s)
    fr = {r["asset"]: r for r in t["sources"] if r["source"] == "log-freshness"}
    assert fr["log-x/AppRequests"]["state"] == "fresh"
    assert fr["log-x/FunctionAppLogs"]["state"] == "stale"
    assert t["correlation"]["observed_in_app_insights"] == {"requests": 10, "with_dependency": 9, "with_trace": 8}
    assert t["correlation"]["verified"] is False  # end-to-end is never claimed from App Insights alone


def test_denied_query_stays_a_gap_not_a_pass() -> None:
    def h(url: str) -> Any:
        raise ArmError("DENIED", "HTTP 403")

    s = _snap()
    logs.collect(s, _client(h), NOW)
    g = next(x for x in s.gaps if x.area == "telemetry.log_freshness")
    assert g.reason == "DENIED"
    assert "freshness" not in s.nodes[0].props


def test_only_get_on_allowlisted_host_and_no_content_fields() -> None:
    seen: list[str] = []
    logs.collect(_snap(), _client(lambda u: _table(["Type", "last_ingest", "rows_7d"], []), seen), NOW)
    assert seen and all(u.startswith(f"https://{logs.LA_HOST}/v1/workspaces/{CID}/query?query=") for u in seen)
    for kql in (logs.FRESHNESS_KQL, logs.CORRELATION_KQL):
        low = kql.lower()
        for forbidden in ("message", "customdimensions", "url", "name,", "properties", "take ", "limit "):
            assert forbidden not in low


def test_other_hosts_are_refused() -> None:
    with pytest.raises(WriteAttempt):
        SaaSClient(lambda r: "t", fetch=lambda u, t: {}).get(f"https://{logs.LA_HOST}/v1/workspaces/x/query?query=1")
