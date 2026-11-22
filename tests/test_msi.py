from __future__ import annotations

import io
import json
import urllib.error
from typing import Any

import pytest

from asa.providers import msi
from asa.providers.azure_arm import ReadOnlyArm, WriteAttempt


class _Resp(io.BytesIO):
    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: Any) -> None:
        self.close()


def test_msi_runner_is_still_read_only(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[str] = []

    def fake(req: Any, timeout: int = 0) -> _Resp:
        sent.append(req.get_method())
        return _Resp(json.dumps({"ok": 1}).encode())

    monkeypatch.setattr(msi, "msi_token", lambda r: "t")
    monkeypatch.setattr(msi.urllib.request, "urlopen", fake)
    arm = ReadOnlyArm(msi.MsiArmRunner())
    assert arm.get("/subscriptions/x/resourceGroups/y", "2021-04-01") == {"ok": 1}
    with pytest.raises(WriteAttempt):
        arm._request("PUT", "https://management.azure.com/subscriptions/x")
    assert sent == ["GET"]


def test_msi_runner_maps_403_to_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake(req: Any, timeout: int = 0) -> _Resp:
        raise urllib.error.HTTPError(req.full_url, 403, "x", {}, io.BytesIO(b"AuthorizationFailed"))  # type: ignore[arg-type]

    monkeypatch.setattr(msi, "msi_token", lambda r: "t")
    monkeypatch.setattr(msi.urllib.request, "urlopen", fake)
    from asa.providers.azure_arm import ArmError

    with pytest.raises(ArmError) as e:
        ReadOnlyArm(msi.MsiArmRunner()).get("/subscriptions/x", "1")
    assert e.value.kind == "DENIED"


def test_msi_runner_encodes_spaces_in_filter(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake(req: Any, timeout: int = 0) -> _Resp:
        seen.append(req.full_url)
        return _Resp(b"{}")

    monkeypatch.setattr(msi, "msi_token", lambda r: "t")
    monkeypatch.setattr(msi.urllib.request, "urlopen", fake)
    ReadOnlyArm(msi.MsiArmRunner()).get("/subscriptions/x/ra", "1", "&$filter=principalId eq 'abc'")
    assert " " not in seen[0] and "%20eq%20" in seen[0]
