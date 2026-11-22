"""Managed-identity access for running ASA inside Azure (Container Apps job).

Used instead of the `az` CLI. Same read-only guarantees: ReadOnlyArm still decides which requests are
allowed; this module only transports them. The identity needs no secret; tokens are never logged.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

_cache: dict[str, tuple[str, float]] = {}


def msi_token(resource: str) -> str:
    hit = _cache.get(resource)
    if hit and hit[1] > time.time() + 120:
        return hit[0]
    client_id = os.environ.get("AZURE_CLIENT_ID", "")
    if os.environ.get("IDENTITY_ENDPOINT"):  # Container Apps / App Service
        url = f"{os.environ['IDENTITY_ENDPOINT']}?api-version=2019-08-01&resource={resource}&client_id={client_id}"
        req = urllib.request.Request(url, headers={"X-IDENTITY-HEADER": os.environ["IDENTITY_HEADER"]})
    else:  # VM-style IMDS
        url = f"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={resource}&client_id={client_id}"
        req = urllib.request.Request(url, headers={"Metadata": "true"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310
        d = json.load(r)
    exp = float(d.get("expires_on", time.time() + 3000))
    _cache[resource] = (d["access_token"], exp)
    return str(d["access_token"])


class MsiArmRunner:
    """Drop-in for the `az rest` runner used by ReadOnlyArm."""

    def __call__(self, args: list[str]) -> tuple[int, str, str]:
        opt = {args[i]: args[i + 1] for i in range(1, len(args) - 1, 2) if args[i].startswith("--")}
        method, url = opt["--method"].upper(), urllib.parse.quote(opt["--url"], safe=":/?&=$%,;'()@+")
        body = opt.get("--body")
        req = urllib.request.Request(
            url,
            data=body.encode() if body else None,
            method=method,
            headers={"Authorization": "Bearer " + msi_token("https://management.azure.com/"), "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
                return 0, r.read().decode("utf-8-sig", errors="replace"), ""
        except urllib.error.HTTPError as e:
            return 1, "", f"ERROR: HTTP {e.code} {e.read().decode('utf-8', 'replace')[:300]}"
        except Exception as e:  # network etc.
            return 1, "", f"ERROR: {type(e).__name__}"


def blob_url(base: str, name: str) -> str:
    return f"{base.rstrip('/')}/{name}"


def put_blob(base: str, name: str, data: bytes) -> None:
    """Write to ASA's own findings container only (base = https://<acct>.blob.core.windows.net/<container>)."""
    req = urllib.request.Request(
        blob_url(base, name),
        data=data,
        method="PUT",
        headers={
            "Authorization": "Bearer " + msi_token("https://storage.azure.com/"),
            "x-ms-version": "2023-11-03",
            "x-ms-blob-type": "BlockBlob",
        },
    )
    urllib.request.urlopen(req, timeout=60).close()  # noqa: S310


def upload_dir(base: str, prefix: str, files: list[Path]) -> list[str]:
    done = []
    for f in files:
        put_blob(base, f"{prefix}/{f.name}", f.read_bytes())
        done.append(f.name)
    return done
