"""Static HTML dashboard, Markdown and JSON exports. No JS frameworks; all values HTML-escaped."""

from __future__ import annotations

import json
from html import escape as e

from asa.engine import Assessment
from asa.graph import chains
from asa.models import Status
from asa.store import Drift

CSS = """
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--bd:#ddd;--fail:#b00020;--nv:#8a5a00;--pass:#1b6e3c;--na:#666;--card:#f6f6f6}
@media (prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--mut:#aaa;--bd:#333;--fail:#ff6b81;--nv:#ffc15e;--pass:#5fd08a;--na:#999;--card:#222}}
body{font:14px/1.45 system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0 auto;max-width:1100px;padding:16px}
h1,h2{margin:.6em 0 .3em}.cards{display:flex;flex-wrap:wrap;gap:8px}.card{background:var(--card);border:1px solid var(--bd);
border-radius:6px;padding:8px 12px;min-width:120px}.card b{font-size:22px;display:block}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid var(--bd);padding:4px 6px;text-align:left;vertical-align:top}
.s-FAIL{color:var(--fail);font-weight:600}.s-NOT_VERIFIED{color:var(--nv);font-weight:600}.s-PASS{color:var(--pass)}.s-NOT_APPLICABLE{color:var(--na)}
.banner{padding:6px 10px;border:1px solid var(--bd);border-left:4px solid var(--nv);background:var(--card);margin:8px 0}
details{margin:2px 0}pre{white-space:pre-wrap;background:var(--card);padding:6px;border-radius:4px}.mut{color:var(--mut)}
"""


def _banner(a: Assessment) -> str:
    modes = sorted({f.mode for f in a.findings})
    text = {
        "fixture": "SYNTHETIC FIXTURE DATA: not a real environment. Nothing here was verified live.",
        "live": "LIVE read-only collection. Items marked NOT_VERIFIED were not observable with the granted permissions.",
        "declared": "Declared model (from IaC/docs), not observed.",
    }
    msg = " ".join(text.get(m, m) for m in modes) or "No findings."
    return f'<div class="banner"><b>Mode: {e(", ".join(modes))}</b>. {e(msg)}</div>'


def to_html(a: Assessment, drift: Drift | None = None, explanation: str | None = None) -> str:
    s = a.snapshot
    st, sev = a.by_status(), a.fails_by_severity()
    cards = [
        ("Coverage", f"{a.coverage_pct}%"),
        ("PASS", st["PASS"]),
        ("FAIL", st["FAIL"]),
        ("NOT_VERIFIED", st["NOT_VERIFIED"]),
        ("N/A", st["NOT_APPLICABLE"]),
    ] + [(f"FAIL {k}", sev.get(k, 0)) for k in ("critical", "high", "medium", "low")]
    h = [
        f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>ASA report: {e(s.label)}</title><style>{CSS}</style>",
        f"<h1>ASA audit: {e(s.label)}</h1><div class=mut>Scope {e(s.scope)} · taken {e(s.taken_at)} · read-only auditor, no changes made</div>",
        _banner(a),
        '<div class="cards">' + "".join(f"<div class=card>{e(str(k))}<b>{e(str(v))}</b></div>" for k, v in cards) + "</div>",
    ]

    if drift is not None:
        h.append("<h2>Change since previous snapshot</h2>")
        h.append(
            f"<p>New failures: <b>{len(drift.new_failures)}</b> (alertable high/critical: <b>{len(drift.alertable)}</b>) · "
            f"resolved: <b>{len(drift.resolved)}</b> · became unverifiable: <b>{len(drift.regressed_to_unverified)}</b> · "
            f"unchanged failures: {drift.unchanged_failures}</p>"
        )
        if drift.new_failures:
            h.append(
                "<ul>"
                + "".join(
                    f"<li class=s-FAIL>{e(f.severity.value)} {e(f.rule_id)} on {e(f.asset_id)}</li>" for f in drift.new_failures
                )
                + "</ul>"
            )

    h.append("<h2>Findings</h2><table><tr><th>Status<th>Sev<th>Rule<th>Asset<th>Summary</tr>")
    for f in a.findings:
        if f.status is Status.NOT_APPLICABLE:
            continue
        ev = (
            "".join(
                f"<pre>{e(json.dumps(x.observed, indent=1, default=str))}\n— {e(x.source)} · {e(x.api)} · {e(x.collected_at)} · {e(x.mode)}</pre>"
                for x in f.evidence
            )
            or "<i>no evidence collected</i>"
        )
        refs = "; ".join(f"{e(r.name)} ({r.kind.value})" for r in f.references)
        h.append(
            f"<tr><td class=s-{f.status.value}>{f.status.value}<td>{e(f.severity.value)}<td>{e(f.rule_id)} v{e(f.rule_version)}"
            f"<td>{e(f.asset_id)}<td><details><summary>{e(f.context)}</summary>"
            f"<p><b>Impact:</b> {e(f.impact)}<br><b>Recommendation:</b> {e(f.recommendation)}<br>"
            f"<b>Confidence:</b> {e(f.confidence)} · <b>References:</b> {refs}</p>{ev}</details></tr>"
        )
    h.append("</table>")

    h.append("<h2>Evidence gaps (not verified, never assumed secure)</h2>")
    h.append(
        "<table><tr><th>Area<th>Reason<th>Detail</tr>"
        + "".join(f"<tr><td>{e(g.area)}<td>{e(g.reason)}<td>{e(g.detail)}</tr>" for g in s.gaps)
        + "</table>"
        if s.gaps
        else "<p class=mut>None recorded.</p>"
    )

    h.append("<h2>AI agent and tool visibility</h2><table><tr><th>Type<th>Name<th>Observed settings</tr>")
    for n in s.nodes_of("agent", "model", "tool", "connector"):
        props = ", ".join(f"{k}={'unknown' if v is None else v}" for k, v in n.props.items())
        h.append(f"<tr><td>{e(n.type)}<td>{e(n.name)}<td>{e(props)}</tr>")
    h.append("</table>")

    h.append("<h2>Dependency chains (weakest edge sets the label)</h2><ul>")
    for c in chains(s, {"identity", "agent"}, {"datastore", "action"}):
        if s.node(c.nodes[0]) and s.node(c.nodes[0]).props.get("kind") in ("human", None):  # type: ignore[union-attr]
            h.append(f"<li><b>{c.basis.value}</b>: {e(c.describe(s))}</li>")
    h.append("</ul>")

    h.append(
        "<h2>Inventory</h2><table><tr><th>Type<th>Name<th>Id<th>Source</tr>"
        + "".join(
            f"<tr><td>{e(n.type)}<td>{e(n.name)}<td>{e(n.id)}<td>{e(n.prov.source)} ({e(n.prov.mode)})</tr>" for n in s.nodes
        )
        + "</table>"
    )
    if explanation:
        h.append(f"<h2>Narrative</h2><pre>{e(explanation)}</pre>")
    return "".join(h)


def to_markdown(a: Assessment, drift: Drift | None = None) -> str:
    s, st = a.snapshot, a.by_status()
    out = [
        f"# ASA audit: {s.label}",
        "",
        f"Scope `{s.scope}` · mode `{s.mode}` · {s.taken_at}",
        "",
        f"Coverage **{a.coverage_pct}%** · PASS {st['PASS']} · FAIL {st['FAIL']} · NOT_VERIFIED {st['NOT_VERIFIED']}",
        "",
    ]
    if drift:
        out += [
            f"Drift: {len(drift.new_failures)} new failures ({len(drift.alertable)} alertable), {len(drift.resolved)} resolved.",
            "",
        ]
    out += ["| Status | Severity | Rule | Asset | Summary |", "|---|---|---|---|---|"]
    for f in a.findings:
        if f.status is not Status.NOT_APPLICABLE:
            out.append(
                f"| {f.status.value} | {f.severity.value} | {f.rule_id} | `{f.asset_id}` | {f.context.replace('|', '/')} |"
            )
    if s.gaps:
        out += ["", "## Evidence gaps", *[f"- `{g.area}` [{g.reason}] {g.detail}" for g in s.gaps]]
    return "\n".join(out) + "\n"


def to_json(a: Assessment) -> str:
    return json.dumps(
        {"snapshot": a.snapshot.to_dict(), "findings": [f.to_dict() for f in a.findings], "coverage_pct": a.coverage_pct},
        indent=2,
        default=str,
    )
