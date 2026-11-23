"""Telemetry coverage report: what is configured to be logged, what is missing, what ASA cannot see.

Coverage = configuration and retention only. Whether logs actually arrive or can be correlated is
reported as unknown unless ASA was granted read access to the log store.
"""

from __future__ import annotations

from typing import Any

from asa.models import Snapshot
from asa.providers.logs import STALE_AFTER_HOURS


def _state(v: bool | None) -> str:
    return "unknown" if v is None else ("configured" if v else "missing")


def build(s: Snapshot) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for n in s.nodes:
        k = n.props.get("kind")
        if n.props.get("diagnostics_supported"):
            det = n.props.get("diag_detail") or []
            rows.append(
                {
                    "source": "azure-diagnostic-settings",
                    "asset": n.name,
                    "state": _state(n.props.get("diagnostics_enabled")),
                    "categories": sorted({c for d in det for c in d.get("log_categories", [])}),
                    "destinations": sorted({d["workspace_id"] for d in det if d.get("workspace_id")}),
                }
            )
        elif k == "appinsights":
            rows.append(
                {
                    "source": "application-insights",
                    "asset": n.name,
                    "state": _state(bool(n.props.get("workspace_id"))),
                    "retention_days": n.props.get("retention_days"),
                    "workspace_based": bool(n.props.get("workspace_id")),
                    "public_ingestion": n.props.get("public_ingestion"),
                }
            )
        elif k == "log-workspace":
            rows.append(
                {
                    "source": "log-analytics-workspace",
                    "asset": n.name,
                    "state": "configured",
                    "retention_days": n.props.get("retention_days"),
                    "daily_cap_gb": n.props.get("daily_cap_gb"),
                }
            )
            for f in n.props.get("freshness") or []:
                age = f.get("age_hours")
                rows.append(
                    {
                        "source": "log-freshness",
                        "asset": f"{n.name}/{f.get('table')}",
                        "state": "unknown" if age is None else ("fresh" if age <= STALE_AFTER_HOURS else "stale"),
                        "last_ingest": f.get("last_ingest"),
                        "age_hours": age,
                        "rows_7d": f.get("rows_7d"),
                    }
                )
        elif k == "power-platform-env" and n.props.get("dataverse_audit_enabled") is not None:
            rows.append(
                {
                    "source": "dataverse-audit",
                    "asset": n.name,
                    "state": _state(bool(n.props["dataverse_audit_enabled"])),
                    "retention_days": n.props.get("dataverse_audit_retention_days"),
                }
            )
        elif k == "alert-rules":
            total = sum(v for key, v in n.props.items() if key != "kind" and isinstance(v, int))
            rows.append(
                {
                    "source": "alert-rules",
                    "asset": n.name,
                    "state": "configured" if total else "missing",
                    "counts": {key: v for key, v in n.props.items() if key != "kind"},
                }
            )
        if k == "apim-service" and n.props.get("apim_loggers") is not None:
            rows.append(
                {
                    "source": "apim-logger",
                    "asset": n.name,
                    "state": "configured" if n.props["apim_loggers"] else "missing",
                    "logger_types": n.props["apim_loggers"],
                }
            )
    unknown = [
        {"source": g.area, "state": "unknown", "reason": g.reason, "why": g.detail}
        for g in s.gaps
        if g.area.startswith("telemetry.") or g.area == "arm.diagnostics"
    ]
    by_state: dict[str, int] = {}
    for r in rows:
        by_state[r["state"]] = by_state.get(r["state"], 0) + 1
    chain = [r for r in rows if r["source"] in ("azure-diagnostic-settings", "application-insights", "apim-logger")]
    # every observed diag/App Insights/APIM-logger source must be configured; one missing source breaks the chain
    chain_ready = bool(chain) and all(r["state"] == "configured" for r in chain)
    return {
        "scope": s.scope,
        "taken_at": s.taken_at,
        "mode": s.mode,
        "summary": by_state,
        "sources": rows,
        "not_verified": unknown,
        "correlation": {
            "configured_end_to_end": chain_ready,
            "verified": False,  # end-to-end (APIM -> Function -> SQL) is never claimed from partial evidence
            "observed_in_app_insights": next((n.props["correlation"] for n in s.nodes if n.props.get("correlation")), None),
            "note": (
                "observed_in_app_insights = request ids that also appear in dependency/trace records (aggregate counts). "
                "End-to-end correlation across APIM, Function and SQL is not verified: APIM gateway logs must also be present."
            ),
        },
    }


def to_markdown_section(t: dict[str, Any]) -> str:
    out = ["## Telemetry coverage", "", "Summary: " + ", ".join(f"{k} {v}" for k, v in sorted(t["summary"].items())), ""]
    for r in t["sources"]:
        extra = ", ".join(f"{k}={v}" for k, v in r.items() if k not in ("source", "asset", "state") and v not in (None, [], {}))
        out.append(f"- **{r['state']}** · {r['source']} · {r['asset']}" + (f" ({extra})" if extra else ""))
    if t["not_verified"]:
        out += ["", "Not verified:"] + [f"- {u['source']} [{u['reason']}] {u['why']}" for u in t["not_verified"]]
    c = t["correlation"]
    out += ["", f"Correlation: configured end-to-end={c['configured_end_to_end']}, verified={c['verified']}, observed in App Insights={c['observed_in_app_insights']}. {c['note']}"]
    return "\n".join(out) + "\n"
