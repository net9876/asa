from __future__ import annotations

import pytest

from asa.engine import run
from asa.metrics import push, to_lines
from asa.synthetic import insecure


def test_lines_are_counts_only_and_leak_no_evidence() -> None:
    a = run(insecure())
    text = "\n".join(to_lines(a, 1))
    assert text.count("asa_status") == 4 and "coverage_pct=" in text
    for f in a.findings:
        assert f.asset_id not in text and f.title not in text


def test_push_requires_https_and_sends_basic_auth() -> None:
    seen: dict[str, object] = {}

    def fake(url: str, headers: dict[str, str], body: bytes) -> int:
        seen.update(url=url, h=headers, b=body)
        return 204

    assert push(["a x=1i"], "https://example.test/w", "123", "tok", fake) == 204
    assert str(seen["h"]["Authorization"]).startswith("Basic ")  # type: ignore[index]
    assert "tok" not in (seen["b"] or b"").decode()  # type: ignore[union-attr]
    with pytest.raises(ValueError):
        push([], "http://example.test", "1", "t", fake)
