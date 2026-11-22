"""Summary metrics for Grafana Cloud. Counts only: no evidence, asset ids or secrets leave ASA.

Format: InfluxDB line protocol (accepted by Grafana Cloud's Prometheus endpoint at
/api/v1/push/influx/write, basic auth: <metrics user id>:<push token>). Dry run by default.
The push token is read from env GRAFANA_PUSH_TOKEN or passed in by the caller (e.g. from Key Vault).
"""

from __future__ import annotations

import base64
import urllib.request
from collections import Counter
from collections.abc import Callable

from asa.engine import Assessment
from asa.models import Status

Post = Callable[[str, dict[str, str], bytes], int]


def _esc(v: str) -> str:
    return v.replace("\\", "").replace(",", "_").replace(" ", "_").replace("=", "_")


def to_lines(a: Assessment, ts_ns: int | None = None) -> list[str]:
    """One line per (rule, severity, status) count + scope-level gauges."""
    scope = _esc(a.snapshot.label)
    mode = _esc(a.snapshot.mode)
    ts = f" {ts_ns}" if ts_ns is not None else ""
    c: Counter[tuple[str, str, str]] = Counter((f.rule_id, f.severity.value, f.status.value) for f in a.findings)
    lines = [
        f"asa_findings,scope={scope},mode={mode},rule={_esc(r)},severity={_esc(s)},status={_esc(st)} count={n}i{ts}"
        for (r, s, st), n in sorted(c.items())
    ]
    by = a.by_status()
    for st in Status:
        lines.append(f"asa_status,scope={scope},mode={mode},status={st.value} count={by.get(st.value, 0)}i{ts}")
    lines.append(f"asa_audit,scope={scope},mode={mode} coverage_pct={a.coverage_pct}{ts}")
    return lines


def _urlopen_post(url: str, headers: dict[str, str], body: bytes) -> int:  # pragma: no cover - network
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 - https validated by push()
        return int(r.status)


def push(
    lines: list[str], url: str, user: str, token: str, post: Post = _urlopen_post
) -> int:
    if not url.startswith("https://"):
        raise ValueError("Grafana push URL must be https")
    auth = base64.b64encode(f"{user}:{token}".encode()).decode()
    return post(url, {"Authorization": f"Basic {auth}", "Content-Type": "text/plain"}, "\n".join(lines).encode())
