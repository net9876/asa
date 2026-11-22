"""asa CLI. `demo` is fully offline; `scan --live` performs read-only collection via the `az` CLI."""

from __future__ import annotations

import argparse
import http.server
import socketserver
import sys
from pathlib import Path

from asa.agent import MockAgent
from asa.alerts import FileNotifier, alert_new_high
from asa.engine import Assessment, run
from asa.report import to_html, to_json, to_markdown
from asa.store import Store, diff
from asa.synthetic import FIXTURES


def _emit(a: Assessment, out: Path, drift=None) -> None:  # type: ignore[no-untyped-def]
    out.mkdir(parents=True, exist_ok=True)
    base = out / a.snapshot.label
    expl = MockAgent().explain(a) if a.snapshot.mode == "fixture" else None
    base.with_suffix(".html").write_text(to_html(a, drift, expl), encoding="utf-8")
    base.with_suffix(".md").write_text(to_markdown(a, drift), encoding="utf-8")
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

        snap = collect_from_config(Path(args.config))
    else:
        snap = FIXTURES[args.fixture]()
    a = run(snap)
    store = Store(Path(args.data) / "history")
    prev = store.latest(snap.label)
    d = diff(prev, a) if prev else None
    _emit(a, out, d)
    store.save(a)
    if d:
        print(f"  drift: {len(d.new_failures)} new, {len(d.resolved)} resolved, {len(d.alertable)} alertable")
        if args.alerts:
            alert_new_high(d, FileNotifier(out / "alerts.jsonl"))
    return 0


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
    sc.add_argument("--alerts", action="store_true", help="opt in: write alerts for new high/critical findings")
    sc.set_defaults(fn=cmd_scan)
    sv = sub.add_parser("serve")
    sv.add_argument("--port", type=int, default=8765)
    sv.set_defaults(fn=cmd_serve)
    args = p.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
