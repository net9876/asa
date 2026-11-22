"""Time-stamped snapshot history and drift. Local JSON files; ASA's own storage only."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from asa.engine import Assessment
from asa.models import Finding, Severity, Snapshot, Status


@dataclass
class Drift:
    new_failures: list[Finding]
    resolved: list[str]  # fingerprints that were FAIL and are now PASS/absent
    regressed_to_unverified: list[str]  # were verified, now NOT_VERIFIED
    unchanged_failures: int

    @property
    def alertable(self) -> list[Finding]:
        return [f for f in self.new_failures if f.severity.rank >= Severity.HIGH.rank]


def _key(f: Finding) -> str:
    return f.fingerprint


def diff(previous: Assessment | None, current: Assessment) -> Drift:
    prev = {_key(f): f for f in (previous.findings if previous else [])}
    cur = {_key(f): f for f in current.findings}
    new = [f for k, f in cur.items() if f.status is Status.FAIL and (k not in prev or prev[k].status is not Status.FAIL)]
    resolved = [k for k, f in prev.items() if f.status is Status.FAIL and (k not in cur or cur[k].status is Status.PASS)]
    regress = [
        k
        for k, f in cur.items()
        if f.status is Status.NOT_VERIFIED and k in prev and prev[k].status in (Status.PASS, Status.FAIL)
    ]
    same = sum(1 for k, f in cur.items() if f.status is Status.FAIL and k in prev and prev[k].status is Status.FAIL)
    return Drift(new, resolved, regress, same)


class Store:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, a: Assessment) -> Path:
        stamp = a.snapshot.taken_at.replace(":", "").replace("-", "")
        path = self.root / f"{stamp}_{a.snapshot.label}.json"
        payload = {"snapshot": a.snapshot.to_dict(), "findings": [f.to_dict() for f in a.findings]}
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        return path

    def latest(self, label: str | None = None) -> Assessment | None:
        files = sorted(self.root.glob(f"*_{label}.json" if label else "*.json"))
        return self._load(files[-1]) if files else None

    @staticmethod
    def _load(path: Path) -> Assessment:
        from asa.models import Evidence, Reference, RefKind

        d = json.loads(path.read_text(encoding="utf-8"))
        snap = Snapshot.from_dict(d["snapshot"])
        fs = []
        for f in d["findings"]:
            fs.append(
                Finding(
                    rule_id=f["rule_id"],
                    rule_version=f["rule_version"],
                    status=Status(f["status"]),
                    severity=Severity(f["severity"]),
                    asset_id=f["asset_id"],
                    scope=f["scope"],
                    title=f["title"],
                    evidence=[Evidence(**e) for e in f["evidence"]],
                    context=f["context"],
                    confidence=f["confidence"],
                    impact=f["impact"],
                    recommendation=f["recommendation"],
                    references=[Reference(r["name"], RefKind(r["kind"])) for r in f["references"]],
                    mode=f.get("mode", "fixture"),
                )
            )
        return Assessment(snap, fs)
