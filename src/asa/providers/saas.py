"""Read-only collectors for Entra (Microsoft Graph) and Power Platform / Power Automate / Dataverse.

Safety properties (tested): GET only, https only, host allowlist, no request bodies. Only metadata is kept:
display names, scopes, counts, expiry dates. Secret values are never read (Graph does not return them) and any
`clientSecret`-like field is dropped. Denied / unsupported / failing calls become evidence Gaps.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from asa.models import Basis, Edge, Gap, Node, Provenance, Snapshot
from asa.providers.azure_arm import ArmError, WriteAttempt

GRAPH = "https://graph.microsoft.com"
BAP = "https://api.bap.microsoft.com"
PAPPS = "https://api.powerapps.com"
FLOW = "https://api.flow.microsoft.com"
BASE_HOSTS = {"graph.microsoft.com", "api.bap.microsoft.com", "api.powerapps.com", "api.flow.microsoft.com"}
RESOURCE_FOR = {GRAPH: GRAPH, BAP: BAP, PAPPS: "https://service.powerapps.com", FLOW: "https://service.flow.microsoft.com"}
SECRET_KEYS = {"clientsecret", "secrettext", "client_secret", "password", "accesstoken"}

TokenFor = Callable[[str], str]
Fetch = Callable[[str, str], Any]  # (url, token) -> parsed json


def _scrub(o: Any) -> Any:
    if isinstance(o, dict):
        return {k: _scrub(v) for k, v in o.items() if k.lower() not in SECRET_KEYS}
    if isinstance(o, list):
        return [_scrub(v) for v in o]
    return o


def _http_get(url: str, token: str) -> Any:  # pragma: no cover - needs network
    req = urllib.request.Request(url, method="GET", headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310
            text = r.read().decode("utf-8-sig", errors="replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:240]
        kind = "DENIED" if e.code in (401, 403) else "NOT_FOUND" if e.code == 404 else "ERROR"
        raise ArmError(kind, f"HTTP {e.code} {re.sub(r'[A-Za-z0-9+/=_-]{40,}', '[redacted]', body)}") from None
    except Exception as e:
        raise ArmError("ERROR", type(e).__name__) from None
    return json.loads(text) if text.strip() else {}


class SaaSClient:
    def __init__(self, token_for: TokenFor, extra_hosts: tuple[str, ...] = (), fetch: Fetch = _http_get) -> None:
        self._token_for, self._fetch = token_for, fetch
        self.hosts = BASE_HOSTS | {h.lower() for h in extra_hosts}
        self.calls: list[str] = []

    def get(self, url: str, resource: str | None = None) -> Any:
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or (u.hostname or "").lower() not in self.hosts:
            raise WriteAttempt(f"URL not allowed: {url}")
        res = resource or RESOURCE_FOR.get(f"{u.scheme}://{u.hostname}", f"{u.scheme}://{u.hostname}")
        safe = urllib.parse.quote(url, safe=":/?&=$%,;'()@+")
        self.calls.append(safe)
        try:
            tok = self._token_for(res)
        except ArmError:
            raise
        except Exception as e:
            raise ArmError("DENIED", f"token for {res} unavailable: {type(e).__name__}") from None
        return self._fetch(safe, tok)

    def pages(self, url: str, limit: int = 5) -> list[Any]:
        out: list[Any] = []
        for _ in range(limit):
            d = self.get(url)
            out += d.get("value", [])
            url = d.get("@odata.nextLink") or ""
            if not url:
                break
        return out


def _days_until(iso: str | None, now: datetime) -> int | None:
    if not iso:
        return None
    try:
        return (datetime.fromisoformat(iso.replace("Z", "+00:00")) - now).days
    except ValueError:
        return None


class SaaSCollector:
    """Adds observed Entra / Power Platform facts to a snapshot, upgrading declared nodes where observed."""

    def __init__(
        self,
        snap: Snapshot,
        client: SaaSClient,
        *,
        environment_id: str | None = None,
        dataverse_url: str | None = None,
        entra: bool = True,
        app_name_prefix: str | None = None,
    ) -> None:
        self.snap, self.c = snap, client
        self.env_id, self.dv, self.entra, self.prefix = environment_id, (dataverse_url or "").rstrip("/"), entra, app_name_prefix
        self.now = datetime.now(UTC)
        if self.dv:
            self.c.hosts.add(urllib.parse.urlsplit(self.dv).hostname or "")

    # -- helpers
    def _prov(self, src: str, api: str) -> Provenance:
        return Provenance(src, api, self.now.strftime("%Y-%m-%dT%H:%M:%SZ"), "live")

    def _resolve(self, area: str) -> None:
        self.snap.gaps = [g for g in self.snap.gaps if g.area != area]

    def _gap(self, area: str, reason: str, detail: str) -> None:
        self._resolve(area)
        self.snap.gaps.append(Gap(area, reason, detail, self.snap.scope))

    def _try(self, area: str, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except ArmError as e:
            self._gap(area, "DENIED" if e.kind == "DENIED" else "ERROR", e.detail)
            return None

    def _upd(self, nid: str, prov: Provenance, **props: Any) -> Node | None:
        n = self.snap.node(nid)
        if n:
            n.props.update(props)
            n.prov = prov
        return n

    def _add(self, nid: str, typ: str, name: str, prov: Provenance, **props: Any) -> Node:
        n = Node(nid, typ, name, props, prov)
        self.snap.nodes = [x for x in self.snap.nodes if x.id != nid] + [n]
        return n

    def _edge(self, a: str, b: str, t: str, basis: Basis, prov: Provenance, **props: Any) -> None:
        self.snap.edges = [e for e in self.snap.edges if not (e.src == a and e.dst == b and e.type == t)]
        self.snap.edges.append(Edge(a, b, t, basis, props, prov))

    # -- collection
    def collect(self) -> None:
        conn = self._power_platform()
        if self.entra:
            self._entra(conn)

    def _power_platform(self) -> dict[str, Any] | None:
        env_id = self.env_id
        if not env_id:
            self._gap("powerplatform.dlp", "NOT_COLLECTED", "No Power Platform environment id configured")
            return None
        envs = self._try(
            "powerplatform.dlp",
            lambda: self.c.get(f"{BAP}/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01"),
        )
        env = next((e for e in (envs or {}).get("value", []) if e.get("name") == env_id), None)
        if envs is not None and env is None:
            self._gap("powerplatform.dlp", "ERROR", "Configured environment id not found in the admin environment list")
        if env:
            ep = env.get("properties", {})
            pol = self._try("powerplatform.dlp", lambda: self.c.get(f"{BAP}/providers/PowerPlatform.Governance/v1/policies"))
            count: int | None = None
            if pol is not None and isinstance(pol.get("value"), list):
                count = 0
                for p in pol["value"]:
                    scope = (p.get("environmentType") or "AllEnvironments", [e.get("name") for e in p.get("environments", [])])
                    if scope[0] == "AllEnvironments" or (scope[0] == "OnlyEnvironments" and env_id in scope[1]) or (
                        scope[0] == "ExceptEnvironments" and env_id not in scope[1]
                    ):
                        count += 1
            if count is not None:
                self._resolve("powerplatform.dlp")
            self._upd(
                "declared:env",
                self._prov("powerplatform-admin", "GET environments + PowerPlatform.Governance policies"),
                dlp_policy_count=count,
                env_sku=ep.get("environmentSku"),
                env_name=ep.get("displayName"),
            )
        conn = self._connectors(env_id)
        self._flows(env_id)
        self._agents()
        return conn

    def _connectors(self, env_id: str) -> dict[str, Any] | None:
        flt = f"environment eq '{env_id}' and isCustomApi eq 'True'"
        url = f"{PAPPS}/providers/Microsoft.PowerApps/scopes/admin/environments/{env_id}/apis?api-version=2016-11-01&$filter={flt}"
        d = self._try("powerplatform.connectors", lambda: self.c.get(url))
        if d is None:
            return None
        found = None
        for x in d.get("value", []):
            p = x.get("properties", {})
            if "minibank" not in p.get("displayName", "").lower():
                continue
            oa = next((v.get("oAuthSettings") or v.get("oauthSetting") for v in (p.get("connectionParameters") or {}).values()
                      if isinstance(v, dict) and (v.get("oAuthSettings") or v.get("oauthSetting"))), None)
            oa = _scrub(oa) if oa else None
            cp = (oa or {}).get("customParameters", {})
            found = {
                "name": p["displayName"],
                "backend": (p.get("backendService") or {}).get("serviceUrl"),
                "client_id": (oa or {}).get("clientId"),
                "scopes": (oa or {}).get("scopes"),
                "audience": (cp.get("ResourceUri") or {}).get("value"),
                "obo": str((cp.get("EnableOnbehalfOfLogin") or {}).get("value", "")).lower() == "true" if oa else None,
                "idp": (oa or {}).get("identityProvider"),
            }
            kind = "oauth-delegated-user" if oa and found["obo"] is False and found["idp"] == "aad" else (
                "oauth-on-behalf-of" if oa and found["obo"] else ("oauth-other" if oa else None)
            )
            pv = self._prov("powerplatform-admin", "GET apis (custom connector definition)")
            self._upd(
                "declared:conn",
                pv,
                granted_scopes=found["scopes"],
                auth_kind=kind,
                client_id=found["client_id"],
                resource_audience=found["audience"],
                backend_url=found["backend"],
                observed_name=found["name"],
            )
            found["auth_kind"] = kind
            # connector -> APIM gateway: confirmed from the connector's own backend URL
            host = urllib.parse.urlsplit(found["backend"] or "").hostname or ""
            for n in self.snap.nodes:
                if n.props.get("kind") == "apim-service" and host.lower() == f"{n.name.lower()}.azure-api.net":
                    for e in list(self.snap.edges):
                        if e.src == "declared:conn" and e.type == "invokes":
                            api = self.snap.node(e.dst)
                            if api and api.id.startswith(n.id + "/"):
                                self._edge(
                                    "declared:conn", api.id, "invokes", Basis.CONFIRMED, pv,
                                    authn="entra-token-delegated" if kind == "oauth-delegated-user" else kind,
                                    observed="connector backend serviceUrl host == APIM gateway host",
                                )
            break
        if found is None:
            self._gap("powerplatform.connectors", "ERROR", "No custom connector named MiniBank in the environment")
        return found

    def _flows(self, env_id: str) -> None:
        url = f"{FLOW}/providers/Microsoft.ProcessSimple/scopes/admin/environments/{env_id}/v2/flows?api-version=2016-11-01"
        d = self._try("powerplatform.flows", lambda: self.c.get(url, "https://service.flow.microsoft.com"))
        if d is None:
            self._flows_dataverse()
            return
        self._resolve("powerplatform.flows")
        flows = d.get("value", [])
        pv = self._prov("power-automate-admin", "GET environments/flows (list)")
        for f in flows:
            p = f.get("properties", {})
            if p.get("state") != "Started" or p.get("isManaged"):
                continue
            self._add(
                f"pp:flow:{f['name']}", "tool", f"Flow · {p.get('displayName')}", pv,
                writes_data=None, requires_confirmation=None, state=p.get("state"),
                connections=sorted((p.get("connectionReferences") or {}).keys()) or None,
            )
        self._flow_match([f.get("properties", {}).get("displayName", "") for f in flows])

    def _flows_dataverse(self) -> None:
        """Least-privilege fallback: list cloud flows from Dataverse (name/state only; the flow definition is never read)."""
        if not self.dv:
            return
        q = "workflows?$select=name,workflowid,statecode,ismanaged&$filter=category eq 5 and type eq 1&$top=200"
        rows = self._try("powerplatform.flows", lambda: self.c.pages(f"{self.dv}/api/data/v9.2/{q}"))
        if rows is None:
            return
        self._resolve("powerplatform.flows")
        pv = self._prov("dataverse", "GET workflows (cloud flows; name/state only)")
        for r in rows:
            if r.get("statecode") != 1 or r.get("ismanaged"):
                continue
            self._add(
                f"pp:flow:{r['workflowid']}", "tool", f"Flow · {r.get('name')}", pv,
                writes_data=None, requires_confirmation=None, state="Started", connections=None,
            )
        self._flow_match([r.get("name", "") for r in rows])
        refs = self._try(
            "powerplatform.connection_references",
            lambda: self.c.pages(f"{self.dv}/api/data/v9.2/connectionreferences?$select=connectionreferencelogicalname,connectorid,statecode&$top=200"),
        )
        env = self.snap.node("declared:env")
        if refs is not None and env is not None:
            env.props["connection_reference_count"] = len(refs)
            env.props["connection_reference_connectors"] = sorted({str(r.get("connectorid", "")).rsplit("/", 1)[-1] for r in refs})
        org = self._try(
            "powerplatform.audit",
            lambda: self.c.get(f"{self.dv}/api/data/v9.2/organizations?$select=isauditenabled,auditretentionperiodv2", self.dv),
        )
        rows_o = (org or {}).get("value", [])
        if env is not None and rows_o:
            env.props["dataverse_audit_enabled"] = rows_o[0].get("isauditenabled")
            env.props["dataverse_audit_retention_days"] = rows_o[0].get("auditretentionperiodv2")
            self.snap.gaps = [g for g in self.snap.gaps if g.area != "telemetry.powerplatform_audit"]

    def _flow_match(self, names: list[str]) -> None:
        tool = self.snap.node("declared:tool-case")
        if tool is not None:
            tool.props["observed_in_env"] = any("review case" in n.lower() for n in names)
            tool.props["env_flow_count"] = len(names)
            if not tool.props["observed_in_env"]:
                tool.name += f" (declared in design; none of the {len(names)} flows in the environment matches)"

    def _agents(self) -> None:
        if not self.dv:
            self._gap("agent.tools", "NOT_COLLECTED", "No Dataverse URL configured")
            return
        d = self._try("agent.tools", lambda: self.c.get(f"{self.dv}/api/data/v9.2/bots?$select=name,statecode,authenticationmode", self.dv))
        if d is None:
            g = next(x for x in self.snap.gaps if x.area == "agent.tools")
            g.detail = (g.detail[:120] + " | needs Dataverse read privilege on Agent (prvReadbot), e.g. a read-only custom security role").strip()
            return
        self._resolve("agent.tools")
        bots = d.get("value", [])
        pv = self._prov("dataverse", "GET bots")
        ag = self._upd("declared:agent", pv, observed_bots=[b.get("name") for b in bots], auth_mode=bots[0].get("authenticationmode") if bots else None)
        if ag is not None and not bots:
            ag.name += " (declared in design; no agent found in Dataverse)"

    def _entra(self, conn: dict[str, Any] | None) -> None:
        apps = self._try("entra.oauth", lambda: self.c.pages(f"{GRAPH}/v1.0/applications?$top=100"))
        if apps is None:
            return
        self._resolve("entra.oauth")
        pv = self._prov("microsoft-graph", "GET applications (+ oauth2PermissionGrants)")
        wanted: dict[str, dict[str, Any]] = {}
        for a in apps:
            hit = (conn and conn.get("client_id") == a["appId"]) or (conn and conn.get("audience") in (a.get("identifierUris") or []))
            hit = hit or (self.prefix and self.prefix.lower() in a["displayName"].lower())
            if hit:
                wanted[a["appId"]] = a
        for app_id, a in wanted.items():
            pw = a.get("passwordCredentials", [])
            expiries = [_days_until(c.get("endDateTime"), self.now) for c in pw]
            self._add(
                f"entra:app:{app_id}", "identity", f"App registration · {a['displayName']}", pv,
                kind="app-registration",
                app_id=app_id,
                sign_in_audience=a.get("signInAudience"),
                secret_count=len(pw),
                cert_count=len(a.get("keyCredentials", [])),
                secret_days_to_expiry=expiries or None,
                secret_lifetime_days=[
                    (datetime.fromisoformat(c["endDateTime"].replace("Z", "+00:00")) - datetime.fromisoformat(c["startDateTime"].replace("Z", "+00:00"))).days
                    for c in pw if c.get("endDateTime") and c.get("startDateTime")
                ] or None,
                exposed_scopes=[s["value"] for s in (a.get("api") or {}).get("oauth2PermissionScopes", [])],
                identifier_uris=a.get("identifierUris"),
            )
        if conn:
            cid, aud = conn.get("client_id"), conn.get("audience")
            if cid in wanted:
                self._edge("declared:conn", f"entra:app:{cid}", "runs-as", Basis.CONFIRMED, pv, observed="connector oauth clientId == app registration appId")
            ra = next((x for x in wanted.values() if aud in (x.get("identifierUris") or [])), None)
            if ra:
                self._edge("declared:conn", f"entra:app:{ra['appId']}", "delegates-to", Basis.CONFIRMED, pv,
                           authn="entra-token-delegated", observed="connector ResourceUri == app identifierUri")
            self._grants(cid, pv)

    def _grants(self, client_app_id: str | None, pv: Provenance) -> None:
        if not client_app_id:
            return
        sp = self._try("entra.oauth", lambda: self.c.get(f"{GRAPH}/v1.0/servicePrincipals?$filter=appId eq '{client_app_id}'&$select=id"))
        sps = (sp or {}).get("value", [])
        if not sps:
            return
        gr = self._try("entra.oauth", lambda: self.c.get(f"{GRAPH}/v1.0/oauth2PermissionGrants?$filter=clientId eq '{sps[0]['id']}'"))
        if gr is None:
            return
        grants = [{"consent": g.get("consentType"), "scope": (g.get("scope") or "").strip()} for g in gr.get("value", [])]
        n = self.snap.node("declared:conn")
        if n is not None:
            n.props["consent_grants"] = grants
            scopes = set(n.props.get("granted_scopes") or [])
            for g in grants:
                scopes.update(s for s in g["scope"].split() if s)
            aud = (n.props.get("resource_audience") or "") + "/"
            n.props["granted_scopes"] = sorted({x[len(aud):] if aud != "/" and x.startswith(aud) else x for x in scopes})
            n.prov = pv


def az_token(resource: str) -> str:  # pragma: no cover - needs az
    from asa.providers.azure_arm import _az_runner

    rc, out, err = _az_runner(["account", "get-access-token", "--resource", resource, "--query", "accessToken", "-o", "tsv"])
    if rc != 0:
        raise ArmError("DENIED", "az could not issue a token for " + resource)
    return out.strip()
