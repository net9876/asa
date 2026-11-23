import io
import json
import os
import sys
import urllib.request as u
import zipfile

base = os.environ["ASA_STORE_URL"]
def tok():
    url = f"{os.environ['IDENTITY_ENDPOINT']}?api-version=2019-08-01&resource=https://storage.azure.com/&client_id={os.environ['AZURE_CLIENT_ID']}"
    return json.load(u.urlopen(u.Request(url, headers={"X-IDENTITY-HEADER": os.environ["IDENTITY_HEADER"]})))["access_token"]
def get(n):
    return u.urlopen(u.Request(f"{base}/{n}", headers={"Authorization": "Bearer " + tok(), "x-ms-version": "2023-11-03"})).read()
zipfile.ZipFile(io.BytesIO(get("bootstrap/asa.zip"))).extractall("/tmp/app")
open("/tmp/config.toml", "wb").write(get("bootstrap/config.toml"))
sys.path.insert(0, "/tmp/app/src")
from asa.cli import main  # noqa: E402

sys.exit(main(["--out", "/tmp/out", "--data", "/tmp/data", "scan", "--live", "--explain", "--push-metrics", "--auth", "msi", "--config", "/tmp/config.toml", "--upload", base]))
