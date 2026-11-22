"""Provider interface. New clouds/agents/MCP/SaaS providers implement `Collector`.

A collector returns a Snapshot of nodes/edges plus explicit Gaps. It must be read-only and must
never raise for denied/unsupported APIs: it records a Gap instead.
"""

from __future__ import annotations

from typing import Protocol

from asa.models import Snapshot


class Collector(Protocol):
    name: str

    def collect(self) -> Snapshot: ...
