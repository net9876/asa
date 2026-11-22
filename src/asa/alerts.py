"""Opt-in notifications for NEW high/critical findings. Notification only: ASA changes nothing.

Default is a local JSONL outbox. A webhook is used only if explicitly configured (https only).
Payloads carry rule, asset id and severity, never evidence values.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Protocol

from asa.models import Finding
from asa.store import Drift


class Notifier(Protocol):
    def send(self, payload: dict[str, object]) -> None: ...


class FileNotifier:
    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, payload: dict[str, object]) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload) + "\n")


class WebhookNotifier:
    def __init__(self, url: str) -> None:
        if not url.startswith("https://"):
            raise ValueError("webhook must be https")
        self.url = url

    def send(self, payload: dict[str, object]) -> None:  # pragma: no cover - needs network
        req = urllib.request.Request(
            self.url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(req, timeout=10).close()  # noqa: S310 - scheme validated above


def _payload(f: Finding) -> dict[str, object]:
    return {
        "rule": f.rule_id,
        "version": f.rule_version,
        "severity": f.severity.value,
        "asset": f.asset_id,
        "scope": f.scope,
        "mode": f.mode,
        "title": f.title,
    }


def alert_new_high(drift: Drift, notifier: Notifier | None) -> list[dict[str, object]]:
    """Send alerts for new high/critical failures. With notifier=None this is a dry run."""
    payloads = [_payload(f) for f in drift.alertable]
    if notifier is not None:
        for p in payloads:
            notifier.send(p)
    return payloads
