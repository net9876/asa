"""asa CLI. `demo` is fully offline; `scan --live` performs read-only collection via the `az` CLI."""

from __future__ import annotations

import argparse
import http.server
import json
import socketserver
import sys
from pathlib import Path

from asa import trust_path
from asa.agent import MockAgent
from asa.alerts import FileNotifier, alert_new_high
from asa.engine import Assessment, run
from asa.report import to_html, to_json, to_markdown
from asa.store import Store, diff
from asa.synthetic import FIXTURES


def _agent_enabled(config: Path) -> bool:
    import tomllib

    return bool(tomllib.loads(config.read_text(encoding="utf-8")).get("agent", {}).get("enabled", False))


def _narrative(a: Assessment, config: Path, auth: str) -> str:
    """Optional model explanation. Never affects verdicts; any failure degrades to a visible note."""
    import tomllib

    cfg = tomllib.loads(config.read_text(encoding="utf-8")).get("agent")
    if not cfg:
        return "No [agent] section in config: no model explanation requested."
    try:
        if auth == "msi":
            from asa.providers.msi import msi_token

            token = msi_token("https://cognitiveservices.azure.com/")
        else:
            from asa.providers.azure_arm import _az_runner

            rc, out, err = _az_runner(["account", "get-access-token", "--resource", "https://cognitiveservices.azure.com", "--query", "accessToken", "-o", "tsv"])
            if rc != 0:
                raise RuntimeError(err.splitlines()[-1] if err else "az token failed")
            token = out.strip()
        from asa.agent import FoundryAgent

        return FoundryAgent(cfg["endpoint"], cfg["deployment"], token).explain(a)
    except Exception as e:  # network, auth, model output rejected: report, never guess
        return f"Model explanation unavailable ({type(e).__name__}: {str(e)[:200]}). Deterministic findings above are unaffected."


def _emit(a: Assessment, out: Path, drift=None, expl: str | None = None) -> None:  # type: ignore[no-untyped-def]
    out.mkdir(parents=True, exist_ok=True)
    base = out / a.snapshot.label
    if expl is None and a.snapshot.mode == "fixture":
        expl = MockAgent().explain(a)
    base.with_suffix(".html").write_text(to_html(a, drift, expl), encoding="utf-8")
    tp = trust_path.build(a.snapshot)
    base.with_suffix(".md").write_text(to_markdown(a, drift) + "\n" + trust_path.to_markdown_section(tp), encoding="utf-8")
    (out / f"{a.snapshot.label}.trust-path.json").write_text(json.dumps(tp, indent=2, default=str), encoding="utf-8")
    base.with_suffix(".json").write_text(to_json(a), encoding="utf-8")
    print(f"  wrote {base}.html/.md/.json  coverage={a.coverage_pct}%  {dict(a.by_status())}")


def cmd_demo(args: argparse.Namespace) -> int:
    out, data = Path(args.out), Path(args.data)
    store = Store(data / "demo-history")
    print("ASA demo: synthetic fixtures only (no cloud access, nothing live is verified)")
    previous = None
    for name in ("secure", "insecure", "unobservable"):
        a = run(FIXTURES[name]())
        d = diff(previous, a) if previous else None
        _emit(a, out, d)
        if d:
            alerts = alert_new_high(d, FileNotifier(out / "alerts.jsonl"))
            print(
                f"  drift vs {previous.snapshot.label}: +{len(d.new_failures)} new failures, {len(alerts)} alert(s) written (outbox only)"
            )
        store.save(a)
        previous = a
    print(f"Open {out / 'insecure.html'} in a browser.")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    out = Path(args.out)
    if args.live:
        from asa.providers.azure_arm import collect_from_config

        arm, token_for = None, None
        if args.auth == "msi":
            from asa.providers.azure_arm import ReadOnlyArm
            from asa.providers.msi import MsiArmRunner, msi_token

            arm, token_for = ReadOnlyArm(MsiArmRunner()), msi_token
        snap = collect_from_config(Path(args.config), arm, token_for)
    else:
        snap = FIXTURES[args.fixture]()
    a = run(snap)
    store = Store(Path(args.data) / "history")
    prev = store.latest(snap.label)
    d = diff(prev, a) if prev else None
    expl = _narrative(a, Path(args.config), args.auth) if args.live and (args.explain or _agent_enabled(Path(args.config))) else None
    _emit(a, out, d, expl)
    saved = store.save(a)
    if args.upload:
        from asa.providers.msi import upload_dir

        stamp = a.snapshot.taken_at.replace(":", "").replace("-", "")
        names = upload_dir(args.upload, f"results/{stamp}", [saved, *sorted(p for p in out.glob(f"{snap.label}.*") if p.is_file())])
        print(f"  uploaded to ASA findings store: {', '.join(names)}")
    if args.metrics or args.push_metrics:
        _metrics(a, out, Path(args.config), args.push_metrics)
    if d:
        print(f"  drift: {len(d.new_failures)} new, {len(d.resolved)} resolved, {len(d.alertable)} alertable")
        if args.alerts:
            alert_new_high(d, FileNotifier(out / "alerts.jsonl"))
    return 0


def _metrics(a: Assessment, out: Path, cfg: Path, push_it: bool) -> None:
    import os
    import time
    import tomllib

    from asa import metrics

    lines = metrics.to_lines(a, time.time_ns())
    (out / "metrics.lines").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  metrics: {len(lines)} summary lines (counts only) -> {out / 'metrics.lines'}  [dry run]")
    if not push_it:
        return
    g = tomllib.loads(cfg.read_text(encoding="utf-8")).get("grafana", {}) if cfg.exists() else {}
    token = os.environ.get("GRAFANA_PUSH_TOKEN", "")
    if not (g.get("push_url") and g.get("metrics_user") and token):
        print("  metrics NOT pushed: need [grafana] push_url + metrics_user in config and GRAFANA_PUSH_TOKEN in env")
        return
    print(f"  metrics pushed: HTTP {metrics.push(lines, g['push_url'], str(g['metrics_user']), token)}")


def cmd_serve(args: argparse.Namespace) -> int:
    root = Path(args.out).resolve()

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):  # type: ignore[no-untyped-def]
            super().__init__(*a, directory=str(root), **k)

    with socketserver.TCPServer(("127.0.0.1", args.port), H) as srv:  # localhost only
        print(f"Serving {root} on http://127.0.0.1:{args.port}/ (Ctrl+C to stop)")
        srv.serve_forever()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="asa", description="Autonomous Security Auditor (read-only)")
    p.add_argument("--out", default="out")
    p.add_argument("--data", default="data")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo").set_defaults(fn=cmd_demo)
    sc = sub.add_parser("scan")
    sc.add_argument("--fixture", choices=sorted(FIXTURES), default="insecure")
    sc.add_argument("--live", action="store_true", help="read-only Azure collection (needs az login + config)")
    sc.add_argument("--config", default="config/minibank.local.toml")
    sc.add_argument("--auth", choices=["az", "msi"], default="az", help="credential source for --live")
    sc.add_argument("--explain", action="store_true", help="add a Foundry model narrative ([agent] in config); read-only, citations validated")
    sc.add_argument("--metrics", action="store_true", help="write summary metrics (counts only) for Grafana; dry run")
    sc.add_argument("--push-metrics", action="store_true", help="also push them to Grafana Cloud ([grafana] config + GRAFANA_PUSH_TOKEN)")
    sc.add_argument("--upload", help="blob container URL of ASA's own findings store (managed identity)")
    sc.add_argument("--alerts", action="store_true", help="opt in: write alerts for new high/critical findings")
    sc.set_defaults(fn=cmd_scan)
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, default=8765)
    sv.set_defaults(fn=cmd_serve)
    args = p.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
