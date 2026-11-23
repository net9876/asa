"""Read-only Azure collector (ARM + optional Resource Graph) using the `az` CLI as credential broker.

Safety properties (enforced in code and tested):
* Only HTTP GET is issued, with one exception: the Resource Graph *query* endpoint, which is a POST
  but read-only by definition. Any other POST/PUT/PATCH/DELETE is refused before reaching `az`.
* URLs must be on https://management.azure.com/.
* Only names and configuration flags are stored. Secret values (app settings, keys) are never read:
  the APIs that would return them are POST actions, which this client cannot call.
* Denied / unsupported calls become evidence Gaps, never results.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tomllib
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from asa.models import Basis, Edge, Gap, Node, Provenance, Snapshot

ARM = "https://management.azure.com"
ARG_PATH = "/providers/Microsoft.ResourceGraph/resources"

Runner = Callable[[list[str]], tuple[int, str, str]]


class WriteAttempt(Exception):
    """Raised if code tries to issue a non-read request."""


def _az_command() -> list[str]:  # pragma: no cover - needs az
    """Resolve the Azure CLI without going through cmd.exe (URLs contain '&', a cmd metacharacter)."""
    exe = shutil.which("az")
    if exe is None:
        raise ArmError("ERROR", "Azure CLI (az) not found on PATH")
    if exe.lower().endswith((".cmd", ".bat")) or os.path.basename(exe).lower() == "az":
        py = Path(exe).resolve().parent.parent / "python.exe"  # MSI layout: CLI2\wbin\az.cmd, CLI2\python.exe
        if py.exists():
            return [str(py), "-X", "utf8", "-IBm", "azure.cli"]  # utf8: APIM policy XML starts with a BOM
        raise ArmError("ERROR", "Cannot run az.cmd safely; install the MSI build of Azure CLI or run on Linux/macOS")
    return [exe]


def _az_runner(args: list[str]) -> tuple[int, str, str]:  # pragma: no cover - needs az
    p = subprocess.run(
        [*_az_command(), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, shell=False
    )  # noqa: S603
    return p.returncode, p.stdout, p.stderr


class ArmError(Exception):
    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind, self.detail = kind, detail


class ReadOnlyArm:
    def __init__(self, runner: Runner = _az_runner) -> None:
        self._run = runner
        self.calls: list[tuple[str, str]] = []

    def _request(self, method: str, url: str, body: dict[str, Any] | None = None) -> Any:
        if not url.startswith(ARM + "/"):
            raise WriteAttempt(f"URL not allowed: {url}")
        if method == "GET":
            args = ["rest", "--method", "get", "--url", url, "--output", "json"]
        elif method == "POST" and url.split("?")[0] == ARM + ARG_PATH:
            args = ["rest", "--method", "post", "--url", url, "--body", json.dumps(body), "--output", "json"]
        else:
            raise WriteAttempt(f"{method} {url} refused: ASA is read-only")
        self.calls.append((method, url))
        rc, out, err = self._run(args)
        if rc != 0:
            low = (err or "").lower()
            if "authorizationfailed" in low or "403" in low or "forbidden" in low or "authorization" in low:
                raise ArmError("DENIED", _first_line(err))
            if "notfound" in low or "404" in low or "could not be found" in low:
                raise ArmError("NOT_FOUND", _first_line(err))
            raise ArmError("ERROR", _first_line(err))
        text = out.lstrip("﻿").strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            if "/policies/" in url:  # APIM returns the policy as raw XML, not JSON
                return {"properties": {"value": text}}
            raise ArmError("ERROR", "response was not JSON") from None

    def get(self, path: str, api: str, extra: str = "") -> Any:
        sep = "&" if "?" in path else "?"
        return self._request("GET", f"{ARM}{path}{sep}api-version={api}{extra}")

    def resource_graph(self, query: str, subscription: str) -> Any:
        url = f"{ARM}{ARG_PATH}?api-version=2022-10-01"
        return self._request("POST", url, {"subscriptions": [subscription], "query": query})


def _first_line(s: str) -> str:
    lines = [ln for ln in (s or "").splitlines() if ln.strip()]
    line = next((ln for ln in lines if ln.startswith("ERROR")), lines[-1] if lines else "")
    return re.sub(r"(?i)(bearer|token)\s+[A-Za-z0-9._-]+", r"\1 [redacted]", line)[:300]


def _scope_level(scope: str) -> str:
    s = scope.lower()
    if re.fullmatch(r"/providers/microsoft.management/managementgroups/[^/]+", s):
        return "management_group"
    if re.fullmatch(r"/subscriptions/[^/]+", s):
        return "subscription"
    if re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+", s):
        return "resource_group"
    return "resource"


def parse_apim_policy(xml_text: str) -> dict[str, Any]:
    """Extract token-validation facts from APIM policy XML (no values beyond claim names/audiences)."""
    out: dict[str, Any] = {"validates_token": False, "audience": None, "required_scopes_or_groups": [], "backend_auth": None}
    try:
        root = ET.fromstring(xml_text.lstrip("﻿ï»¿").strip())  # BOM, also as mis-decoded bytes
    except ET.ParseError:
        out["validates_token"] = None  # unparseable policy is unknown, never "no validation"
        return out
    for el in root.iter():
        tag = el.tag.split("}")[-1]
        if tag in ("validate-azure-ad-token", "validate-jwt"):
            out["validates_token"] = True
            for a in el.iter("audience"):
                if a.text and a.text.strip() and not out["audience"]:
                    out["audience"] = a.text.strip()
            for c in el.iter("claim"):
                out["required_scopes_or_groups"].append(c.get("name", "?"))
        if tag == "authentication-managed-identity":
            out["backend_auth"] = "managed-identity"
    return out


class AzureArmCollector:
    name = "azure-arm"

    def __init__(
        self,
        subscription_id: str,
        resource_group: str,
        foundry_account_id: str | None = None,
        declared_overlay: bool = True,
        arm: ReadOnlyArm | None = None,
        foundry_deployments: list[str] | None = None,
        use_resource_graph: bool = False,
    ) -> None:
        self.only_deployments, self.use_graph = foundry_deployments, use_resource_graph
        self.sub, self.rg, self.foundry = subscription_id, resource_group, foundry_account_id
        self.overlay = declared_overlay
        self.arm = arm or ReadOnlyArm()
        self.now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.snap = Snapshot(
            taken_at=self.now,
            mode="live",
            label="live-" + resource_group,
            scope=f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}",
        )
        self._res: list[dict[str, Any]] = []

    # -- helpers
    def _prov(self, api: str, mode: str = "live") -> Provenance:
        return Provenance("arm", api, self.now, mode)

    def _node(self, nid: str, t: str, name: str, api: str, **props: Any) -> Node:
        n = Node(nid.lower(), t, name, props, self._prov(api))
        self.snap.nodes.append(n)
        return n

    def _edge(self, a: str, b: str, t: str, basis: Basis, api: str, mode: str = "live", **props: Any) -> None:
        self.snap.edges.append(Edge(a.lower(), b.lower(), t, basis, props, self._prov(api, mode)))

    def _try(self, area: str, fn: Callable[..., Any], scope: str = "") -> Any:
        try:
            return fn()
        except ArmError as e:
            if not any(g.area == area for g in self.snap.gaps):
                self.snap.gaps.append(Gap(area, "DENIED" if e.kind == "DENIED" else "ERROR", e.detail, scope or self.snap.scope))
            return None

    def _gap(self, area: str, reason: str, detail: str) -> None:
        self.snap.gaps.append(Gap(area, reason, detail, self.snap.scope))

    # -- collection
    def collect(self) -> Snapshot:
        base = f"/subscriptions/{self.sub}/resourceGroups/{self.rg}"
        res = self._try("arm.inventory", lambda: self.arm.get(f"{base}/resources", "2021-04-01"))
        self._res = (res or {}).get("value", [])
        by_type: dict[str, list[dict[str, Any]]] = {}
        for r in self._res:
            by_type.setdefault(r["type"].lower(), []).append(r)

        self._subscription_node()
        if self.use_graph:
            self._graph_inventory()
        self._storage(base)
        self._sql(base)
        apim_apis = self._apim(base)
        funcs = self._functions(base)
        idents = self._identities(base)
        self._role_assignments(idents)
        self._diagnostics(by_type)
        self._telemetry(by_type)
        self._foundry()
        self._link(apim_apis, funcs, idents)
        if self.overlay:
            self._declared_overlay(apim_apis)
        else:
            self._not_collected()
        return self.snap

    def _subscription_node(self) -> None:
        pr = self._try(
            "arm.security", lambda: self.arm.get(f"/subscriptions/{self.sub}/providers/Microsoft.Security/pricings", "2024-01-01")
        )
        defender: bool | None = None
        if pr is not None:
            defender = any(p.get("properties", {}).get("pricingTier") == "Standard" for p in pr.get("value", []))
        # Sentinel presence: only provable via workspace onboarding states; not collected here.
        self._gap("arm.security.sentinel", "NOT_COLLECTED", "Sentinel onboarding state not queried; reported as unknown")
        self._node(
            f"/subscriptions/{self.sub}",
            "resource",
            f"subscription {self.sub[:8]}…",
            "GET Microsoft.Security/pricings",
            kind="subscription",
            defender_plans_enabled=defender,
            sentinel_present=None,
        )

    def _graph_inventory(self) -> None:
        """Cross-check inventory through Azure Resource Graph (read-only query endpoint)."""
        q = f"resources | where resourceGroup =~ '{self.rg}' | project id, type, name"
        d = self._try("arg.inventory", lambda: self.arm.resource_graph(q, self.sub))
        if d is None:
            return
        rows = d.get("data", [])
        self._node(
            f"arg:{self.rg}",
            "resource",
            f"Resource Graph inventory ({len(rows)} resources)",
            "POST Microsoft.ResourceGraph/resources (read-only query)",
            kind="inventory",
            count=len(rows),
            types=sorted({r["type"] for r in rows}),
        )

    def _storage(self, base: str) -> None:
        d = self._try("arm.storage", lambda: self.arm.get(f"{base}/providers/Microsoft.Storage/storageAccounts", "2023-05-01"))
        for a in (d or {}).get("value", []):
            p = a.get("properties", {})
            acls = p.get("networkAcls") or {}
            self._node(
                a["id"],
                "datastore",
                a["name"],
                "GET Microsoft.Storage/storageAccounts",
                kind="storage-account",
                allow_blob_public_access=p.get("allowBlobPublicAccess"),
                shared_key_access=p.get("allowSharedKeyAccess"),
                network_default_action=acls.get("defaultAction"),
                private_endpoint_count=len(p.get("privateEndpointConnections") or []),
                diagnostics_supported=True,
                diagnostics_enabled=None,
            )

    def _sql(self, base: str) -> None:
        d = self._try("arm.sql", lambda: self.arm.get(f"{base}/providers/Microsoft.Sql/servers", "2023-08-01"))
        for s in (d or {}).get("value", []):
            p, sid = s.get("properties", {}), s["id"]
            fw = self._try("arm.sql", lambda sid=sid: self.arm.get(f"{sid}/firewallRules", "2023-08-01"))
            rules = (
                None
                if fw is None
                else [
                    {"name": r["name"], "start": r["properties"]["startIpAddress"], "end": r["properties"]["endIpAddress"]}
                    for r in fw.get("value", [])
                ]
            )
            ad = self._try("arm.sql", lambda sid=sid: self.arm.get(f"{sid}/azureADOnlyAuthentications/default", "2023-08-01"))
            aad_only = None if ad is None else bool(ad.get("properties", {}).get("azureADOnlyAuthentication"))
            self._node(
                sid,
                "datastore",
                s["name"],
                "GET Microsoft.Sql/servers (+firewallRules, azureADOnlyAuthentications)",
                kind="sql-server",
                public_network_access=p.get("publicNetworkAccess"),
                firewall_rules=rules,
                private_endpoint_count=len(p.get("privateEndpointConnections") or []),
                entra_only_auth=aad_only,
                vnet_rule_count=None,
                diagnostics_supported=False,
            )

    def _apim(self, base: str) -> list[tuple[str, str, str]]:
        """Returns [(api_node_id, service_url, apim_service_id)]."""
        out: list[tuple[str, str, str]] = []
        d = self._try("arm.apim", lambda: self.arm.get(f"{base}/providers/Microsoft.ApiManagement/service", "2022-08-01"))
        for svc in (d or {}).get("value", []):
            sid = svc["id"]
            apis = self._try("arm.apim", lambda sid=sid: self.arm.get(f"{sid}/apis", "2022-08-01"))
            self._node(
                sid,
                "resource",
                svc["name"],
                "GET Microsoft.ApiManagement/service",
                kind="apim-service",
                sku=svc.get("sku", {}).get("name"),
                diagnostics_supported=True,
                diagnostics_enabled=None,
            )
            for api in (apis or {}).get("value", []):
                ap = api.get("properties", {})
                pol = self._try("arm.apim", lambda api=api: self.arm.get(f"{api['id']}/policies/policy", "2022-08-01"))
                facts: dict[str, Any] = {
                    "policy_readable": False,
                    "validates_token": None,
                    "audience": None,
                    "required_scopes_or_groups": None,
                }
                backend_auth = None
                if pol is not None:
                    parsed = parse_apim_policy(pol.get("properties", {}).get("value", ""))
                    readable = parsed["validates_token"] is not None
                    facts = {
                        "policy_readable": readable,
                        **{k: parsed[k] for k in ("validates_token", "audience", "required_scopes_or_groups")},
                    }
                    backend_auth = parsed["backend_auth"]
                self._node(
                    api["id"],
                    "endpoint",
                    ap.get("displayName", api["name"]),
                    "GET apis + apis/policies/policy",
                    kind="apim-api",
                    subscription_required=ap.get("subscriptionRequired"),
                    backend_auth=backend_auth,
                    service_url=ap.get("serviceUrl"),
                    **facts,
                )
                out.append((api["id"], ap.get("serviceUrl") or "", sid))
        return out

    def _functions(self, base: str) -> list[dict[str, Any]]:
        d = self._try("arm.web", lambda: self.arm.get(f"{base}/providers/Microsoft.Web/sites", "2023-12-01"))
        funcs = [s for s in (d or {}).get("value", []) if "functionapp" in (s.get("kind") or "")]
        for s in funcs:
            auth = self._try("arm.web.authsettings", lambda s=s: self.arm.get(f"{s['id']}/config/authsettingsV2", "2023-12-01"))
            auth_required: bool | None = None
            allowed: list[str] | None = None
            if auth is not None:
                gp = auth.get("properties", {}).get("globalValidation", {})
                auth_required = bool(gp.get("requireAuthentication"))
                allowed = (
                    auth.get("properties", {})
                    .get("identityProviders", {})
                    .get("azureActiveDirectory", {})
                    .get("validation", {})
                    .get("defaultAuthorizationPolicy", {})
                    .get("allowedPrincipals", {})
                    .get("identities", [])
                )
            self._node(
                s["id"],
                "resource",
                s["name"],
                "GET Microsoft.Web/sites (+config/authsettingsV2)",
                kind="function-app",
                host=s.get("properties", {}).get("defaultHostName"),
                auth_required=auth_required,
                allowed_identities=allowed,
                https_only=s.get("properties", {}).get("httpsOnly"),
                inline_secret_settings=None,
                identity_ids=list((s.get("identity") or {}).get("userAssignedIdentities", {}).keys()),
                diagnostics_supported=True,
                diagnostics_enabled=None,
            )
        self._gap(
            "arm.web.appsettings",
            "UNSUPPORTED",
            "App settings are returned only by a POST 'list' action; ASA is GET-only, so secret-like settings are unverified.",
        )
        return funcs

    def _identities(self, base: str) -> list[Node]:
        d = self._try(
            "arm.identity",
            lambda: self.arm.get(f"{base}/providers/Microsoft.ManagedIdentity/userAssignedIdentities", "2023-01-31"),
        )
        nodes = []
        for i in (d or {}).get("value", []):
            nodes.append(
                self._node(
                    i["id"],
                    "identity",
                    i["name"],
                    "GET Microsoft.ManagedIdentity/userAssignedIdentities",
                    kind="managed-identity",
                    principal_id=i.get("properties", {}).get("principalId"),
                    role_assignments_known=False,
                    role_assignments=[],
                )
            )
        return nodes

    def _role_assignments(self, idents: list[Node]) -> None:
        defs = self._try(
            "arm.role_assignments",
            lambda: self.arm.get(f"/subscriptions/{self.sub}/providers/Microsoft.Authorization/roleDefinitions", "2022-04-01"),
        )
        names = {r["id"].lower(): r["properties"]["roleName"] for r in (defs or {}).get("value", [])}
        for n in idents:
            pid = n.props.get("principal_id")
            ra = self._try(
                "arm.role_assignments",
                lambda pid=pid: self.arm.get(
                    f"/subscriptions/{self.sub}/providers/Microsoft.Authorization/roleAssignments",
                    "2022-04-01",
                    f"&$filter=principalId eq '{pid}'",
                ),
            )
            if ra is None or defs is None:
                continue
            n.props["role_assignments"] = [
                {
                    "role": names.get(
                        a["properties"]["roleDefinitionId"].lower(), a["properties"]["roleDefinitionId"].split("/")[-1]
                    ),
                    "scope": a["properties"]["scope"],
                    "scope_level": _scope_level(a["properties"]["scope"]),
                }
                for a in ra.get("value", [])
            ]
            n.props["role_assignments_known"] = True
            n.prov = self._prov("GET Microsoft.Authorization/roleAssignments (principalId filter) + roleDefinitions")

    def _diagnostics(self, by_type: dict[str, list[dict[str, Any]]]) -> None:
        for n in self.snap.nodes:
            if not n.props.get("diagnostics_supported"):
                continue
            ds = self._try(
                "arm.diagnostics",
                lambda n=n: self.arm.get(f"{n.id}/providers/Microsoft.Insights/diagnosticSettings", "2021-05-01-preview"),
            )
            if ds is None:
                continue
            n.props["diagnostics_enabled"] = any(x.get("properties", {}).get("workspaceId") for x in ds.get("value", []))
            n.props["diagnostics_sink"] = "Log Analytics workspace"
            detail = []
            for x in ds.get("value", []):
                p = x.get("properties", {})
                detail.append(
                    {
                        "name": x.get("name"),
                        "workspace_id": (p.get("workspaceId") or "").lower() or None,
                        "other_destinations": [k for k in ("storageAccountId", "eventHubAuthorizationRuleId") if p.get(k)],
                        "log_categories": sorted(
                            (lg.get("category") or lg.get("categoryGroup") or "?") for lg in p.get("logs", []) if lg.get("enabled")
                        ),
                        "metrics_enabled": any(m.get("enabled") for m in p.get("metrics", [])),
                    }
                )
            n.props["diag_detail"] = detail

    def _telemetry(self, by_type: dict[str, list[dict[str, Any]]]) -> None:
        """Telemetry COVERAGE only (config + retention). Reading log contents/freshness is a separate scope."""
        ws_ids: set[str] = set()
        for n in self.snap.nodes:
            for d in n.props.get("diag_detail") or []:
                if d.get("workspace_id"):
                    ws_ids.add(d["workspace_id"])
        for c in by_type.get("microsoft.insights/components", []):
            comp = self._try("arm.telemetry.appinsights", lambda c=c: self.arm.get(c["id"], "2020-02-02"))
            if comp is None:
                continue
            p = comp.get("properties", {})
            wid = (p.get("WorkspaceResourceId") or "").lower() or None
            if wid:
                ws_ids.add(wid)
            self._node(
                c["id"],
                "resource",
                c["name"],
                "GET Microsoft.Insights/components",
                kind="appinsights",
                workspace_id=wid,
                retention_days=p.get("RetentionInDays"),
                ingestion_mode=p.get("IngestionMode"),
                public_ingestion=p.get("publicNetworkAccessForIngestion"),
                public_query=p.get("publicNetworkAccessForQuery"),
                sampling_pct=p.get("SamplingPercentage"),
            )
        for wid in sorted(ws_ids):
            ws = self._try("arm.telemetry.workspace", lambda wid=wid: self.arm.get(wid, "2023-09-01"))
            if ws is None:
                continue
            p = ws.get("properties", {})
            self._node(
                wid,
                "resource",
                ws.get("name", wid),
                "GET Microsoft.OperationalInsights/workspaces",
                kind="log-workspace",
                retention_days=p.get("retentionInDays"),
                customer_id=p.get("customerId"),
                sku=(p.get("sku") or {}).get("name"),
                daily_cap_gb=(p.get("workspaceCapping") or {}).get("dailyQuotaGb"),
                public_query=p.get("publicNetworkAccessForQuery"),
            )
        kinds = (
            "microsoft.insights/metricalerts",
            "microsoft.insights/scheduledqueryrules",
            "microsoft.insights/activitylogalerts",
            "microsoft.alertsmanagement/smartdetectoralertrules",
        )
        self._node(
            f"{self.snap.scope}/telemetry-alerts",
            "resource",
            "Alert rules in scope",
            "GET /resources (type counts)",
            kind="alert-rules",
            **{k.split("/")[1]: len(by_type.get(k, [])) for k in kinds},
        )
        for n in self.snap.nodes:
            if n.props.get("kind") == "apim-service":
                lg = self._try("arm.telemetry.apim", lambda n=n: self.arm.get(f"{n.id}/loggers", "2022-08-01"))
                if lg is not None:
                    n.props["apim_loggers"] = [x.get("properties", {}).get("loggerType") for x in lg.get("value", [])]
        self._gap(
            "telemetry.log_freshness",
            "NOT_COLLECTED",
            "Log freshness and correlation need read access to the workspace (Log Analytics Reader); not collected unless that check succeeds.",
        )
        self._gap(
            "telemetry.entra_logs",
            "NOT_COLLECTED",
            "Entra sign-in/audit log coverage needs AuditLog.Read.All (tenant consent, not requested).",
        )
        self._gap(
            "telemetry.powerplatform_audit",
            "NOT_COLLECTED",
            "Power Platform / Dataverse audit state needs Dataverse audit settings read; not collected in this version.",
        )

    def _foundry(self) -> None:
        if not self.foundry:
            self._gap("foundry.guardrails", "NOT_COLLECTED", "No foundry_account_id configured")
            return
        dep = self._try("foundry.guardrails", lambda: self.arm.get(f"{self.foundry}/deployments", "2024-10-01"))
        for d in (dep or {}).get("value", []):
            p = d.get("properties", {})
            if self.only_deployments is not None and d["name"] not in self.only_deployments:
                continue  # shared account: assess only deployments this target uses
            rai = p.get("raiPolicyName")
            shield: bool | None = None
            if rai:
                pol = self._try(
                    "foundry.guardrails", lambda rai=rai: self.arm.get(f"{self.foundry}/raiPolicies/{rai}", "2024-10-01")
                )
                if pol is not None:
                    filters = pol.get("properties", {}).get("contentFilters", [])
                    enabled = {f["name"] for f in filters if f.get("enabled")}
                    shield = {"Jailbreak", "Indirect Attack"} <= enabled
            self._node(
                d["id"],
                "model",
                d["name"],
                "GET cognitiveservices deployments (+raiPolicies)",
                model=(p.get("model") or {}).get("name"),
                model_kind="embedding" if "embedding" in ((p.get("model") or {}).get("name") or "") else "chat",
                content_filter=rai,  # absent = not observed (service may apply a default policy)
                prompt_shield=shield,
            )
        self._gap(
            "foundry.agents",
            "NOT_COLLECTED",
            "Foundry agent/tool definitions are data-plane (project endpoint); not collected in this version",
        )

    def _link(self, apis: list[tuple[str, str, str]], funcs: list[dict[str, Any]], idents: list[Node]) -> None:
        host_to_func = {
            f["properties"]["defaultHostName"].lower(): f for f in funcs if f.get("properties", {}).get("defaultHostName")
        }
        for api_id, url, _svc in apis:
            m = re.match(r"https://([^/]+)", url)
            f = host_to_func.get(m.group(1).lower()) if m else None
            if f:
                api_node = self.snap.node(api_id.lower())
                authn = api_node.props.get("backend_auth") if api_node else None
                self._edge(
                    api_id, f["id"], "invokes", Basis.CONFIRMED, "APIM api serviceUrl == function defaultHostName", authn=authn
                )
        for f in funcs:
            for uid in (f.get("identity") or {}).get("userAssignedIdentities", {}):
                self._edge(f["id"], uid, "runs-as", Basis.CONFIRMED, "Microsoft.Web/sites identity.userAssignedIdentities")
        for n in idents:
            for a in n.props.get("role_assignments", []):
                target = self._covering_resource(a["scope"])
                if target:
                    self._edge(
                        n.id,
                        target,
                        "accesses",
                        Basis.CONFIRMED,
                        "roleAssignments scope",
                        role=a["role"],
                        scope_level=a["scope_level"],
                    )
        # function -> data stores: via identity role assignments (observed) -> chain func -runs-as-> id -accesses-> store

    def _covering_resource(self, scope: str) -> str | None:
        s = scope.lower()
        for n in self.snap.nodes:
            if n.type == "datastore" and s.startswith(n.id):
                return n.id
        return None

    def _declared_overlay(self, apis: list[tuple[str, str, str]]) -> None:
        """Components documented in MiniBank design/IaC but outside ARM read scope. Labelled declared/unknown."""

        def decl(api: str) -> Provenance:
            return Provenance("declared:minibank-design-doc", api, self.now, "declared")

        def dn(nid: str, t: str, name: str, **props: Any) -> None:
            self.snap.nodes.append(Node(nid, t, name, props, decl("docs/MiniBank-Design.md")))

        dn("declared:user", "identity", "MiniBankOps operator (Entra user)", kind="human")
        dn("declared:agent", "agent", "Copilot Studio · Bank Operations Assistant", content_filter=None, prompt_shield=None)
        dn("declared:conn", "connector", "Power Platform custom connector · MiniBank API", writes_data=False, granted_scopes=None)
        dn("declared:tool-case", "tool", "Agent flow · Open review case", writes_data=True, requires_confirmation=None)
        dn("declared:action-case", "action", "Create review case (Dataverse)", sensitive_transition=True)
        dn(
            "declared:env",
            "resource",
            "Power Platform environment MiniBank-Lab",
            kind="power-platform-env",
            dlp_policy_count=None,
        )
        d = "docs/MiniBank-Design.md"
        self._edge("declared:user", "declared:agent", "invokes", Basis.UNKNOWN, d, "declared", authn=None)
        self._edge("declared:agent", "declared:conn", "invokes", Basis.INFERRED, d, "declared", authn=None)
        self._edge("declared:agent", "declared:tool-case", "invokes", Basis.INFERRED, d, "declared", authn=None)
        self._edge(
            "declared:tool-case",
            "declared:action-case",
            "invokes",
            Basis.UNKNOWN,
            d,
            "declared",
            authn=None,
            sensitive_transition=True,
        )
        for api_id, _u, _s in apis:
            api = self.snap.node(api_id.lower())
            authn = "entra-token" if api and api.props.get("validates_token") else None
            self._edge(
                "declared:conn",
                api_id,
                "invokes",
                Basis.INFERRED,
                "connector -> APIM per design; token enforcement seen on APIM side only",
                "declared",
                authn=authn,
            )
        for area, detail in (
            ("powerplatform.dlp", "Power Platform admin read access not granted/implemented"),
            ("powerplatform.flows", "Copilot Studio agent, flows and connector connections not readable by this collector"),
            ("entra.oauth", "App registrations and consent grants (Microsoft Graph) not collected in this version"),
            ("agent.tools", "Copilot Studio tool definitions and confirmation settings not collected"),
        ):
            self._gap(area, "NOT_COLLECTED", detail)

    def _not_collected(self) -> None:
        for area in ("powerplatform.dlp", "powerplatform.flows", "entra.oauth", "agent.tools"):
            self._gap(area, "NOT_COLLECTED", "Overlay disabled; no collector for this area")


def collect_from_config(path: Path, arm: ReadOnlyArm | None = None, token_for: Callable[[str], str] | None = None) -> Snapshot:
    cfg = tomllib.loads(path.read_text(encoding="utf-8"))
    t = cfg["target"]
    snap = AzureArmCollector(
        t["subscription_id"],
        t["resource_group"],
        t.get("foundry_account_id"),
        cfg.get("options", {}).get("declared_overlay", True),
        foundry_deployments=t.get("foundry_deployments"),
        use_resource_graph=cfg.get("options", {}).get("use_resource_graph", False),
        arm=arm,
    ).collect()
    pp, en = cfg.get("powerplatform"), cfg.get("entra")
    if (pp or en) and cfg.get("options", {}).get("declared_overlay", True):
        from asa.providers.saas import SaaSClient, SaaSCollector, az_token

        SaaSCollector(
            snap,
            SaaSClient(token_for or az_token),
            environment_id=(pp or {}).get("environment_id"),
            dataverse_url=(pp or {}).get("dataverse_url"),
            entra=bool((en or {}).get("enabled", False)),
            app_name_prefix=(en or {}).get("app_name_prefix"),
        ).collect()
    if cfg.get("options", {}).get("log_freshness", True):
        from asa.providers import logs
        from asa.providers.saas import az_token

        logs.collect(snap, logs.make_client(token_for or az_token))
    return snap
