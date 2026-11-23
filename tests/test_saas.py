from __future__ import annotations

from typing import Any

import pytest

from asa.engine import run
from asa.models import Basis, Edge, Node, Provenance, Snapshot, Status
from asa.providers.azure_arm import ArmError, WriteAttempt
from asa.providers.saas import SaaSClient, SaaSCollector
from asa.synthetic import insecure, secure, unobservable

ENV = "env-1"
AUD = "api://pay"
P = Provenance("declared", "doc", "2026-01-01T00:00:00Z", "declared")


def _snap() -> Snapshot:
    s = Snapshot(taken_at="2026-01-01T00:00:00Z", mode="live", label="t", scope="sub/rg")
    s.nodes += [
        Node("/apim", "resource", "svc", {"kind": "apim-service"}, P),
        Node("/apim/apis/pay", "endpoint", "pay", {"kind": "apim-api", "audience": AUD, "validates_token": True}, P),
        Node("declared:conn", "connector", "conn", {"writes_data": False, "granted_scopes": None}, P),
        Node("declared:env", "resource", "env", {"kind": "power-platform-env", "dlp_policy_count": None}, P),
        Node("declared:tool-case", "tool", "Open review case", {"writes_data": True}, P),
        Node("declared:agent", "agent", "agent", {"content_filter": None, "prompt_shield": None}, P),
    ]
    s.edges.append(Edge("declared:conn", "/apim/apis/pay", "invokes", Basis.INFERRED, {}, P))
    return s


def _fake(routes: dict[str, Any]):  # type: ignore[no-untyped-def]
    def fetch(url: str, token: str) -> Any:
        for key, val in routes.items():
            if key in url:
                if isinstance(val, ArmError):
                    raise val
                return val
        raise ArmError("NOT_FOUND", url)

    return fetch


CONNECTOR = {
    "value": [
        {
            "properties": {
                "displayName": "MiniBank Payments",
                "backendService": {"serviceUrl": "https://svc.azure-api.net/minibank"},
                "connectionParameters": {
                    "token": {
                        "oauthSetting": {
                            "clientId": "cid",
                            "clientSecret": "TOPSECRET",
                            "identityProvider": "aad",
                            "scopes": [AUD + "/Payments.Read"],
                            "customParameters": {"ResourceUri": {"value": AUD}, "EnableOnbehalfOfLogin": {"value": "false"}},
                        }
                    }
                },
            }
        }
    ]
}
ROUTES: dict[str, Any] = {
    "environments?api-version": {"value": [{"name": ENV, "properties": {"displayName": "Lab", "environmentSku": "Trial"}}]},
    "PowerPlatform.Governance": {"value": []},
    "/apis?api-version": CONNECTOR,
    "/v2/flows": {"value": [{"name": "f1", "properties": {"displayName": "Get payment", "state": "Started", "isManaged": False}}]},
    "/bots": ArmError("DENIED", "HTTP 403 missing prvReadbot"),
    "/applications": {
        "value": [
            {
                "appId": "cid",
                "displayName": "MiniBank Connector",
                "identifierUris": [],
                "passwordCredentials": [{"startDateTime": "2026-01-01T00:00:00Z", "endDateTime": "2026-12-31T00:00:00Z"}],
                "keyCredentials": [],
                "api": {"oauth2PermissionScopes": []},
            },
            {"appId": "api", "displayName": "MiniBank API", "identifierUris": [AUD], "passwordCredentials": [], "keyCredentials": [], "api": {"oauth2PermissionScopes": [{"value": "Payments.Read"}]}},
        ]
    },
    "/servicePrincipals": {"value": [{"id": "sp1"}]},
    "/oauth2PermissionGrants": {"value": [{"consentType": "Principal", "scope": "Payments.Read"}]},
}


def _collect(routes: dict[str, Any] = ROUTES) -> Snapshot:
    s = _snap()
    SaaSCollector(
        s,
        SaaSClient(lambda r: "tok", fetch=_fake(routes)),
        environment_id=ENV,
        dataverse_url="https://org.crm.dynamics.com",
        entra=True,
        app_name_prefix="MiniBank",
    ).collect()
    return s


def test_client_is_get_only_https_and_allowlisted() -> None:
    c = SaaSClient(lambda r: "t", fetch=_fake({}))
    for bad in ("http://graph.microsoft.com/v1.0/x", "https://evil.example.test/x", "https://graph.microsoft.com.evil.test/x"):
        with pytest.raises(WriteAttempt):
            c.get(bad)


def test_observed_facts_upgrade_declared_nodes_and_edges() -> None:
    s = _collect()
    conn, env = s.node("declared:conn"), s.node("declared:env")
    assert conn and env
    assert conn.props["auth_kind"] == "oauth-delegated-user" and conn.props["granted_scopes"] == ["Payments.Read"]
    assert env.props["dlp_policy_count"] == 0 and env.prov.mode == "live"
    e = next(e for e in s.edges if e.src == "declared:conn" and e.dst == "/apim/apis/pay")
    assert e.basis is Basis.CONFIRMED
    assert any(e.type == "delegates-to" and e.basis is Basis.CONFIRMED for e in s.edges)
    tool = s.node("declared:tool-case")
    assert tool and tool.props["observed_in_env"] is False and "declared in design" in tool.name


def test_secret_values_are_never_kept() -> None:
    import json

    assert "TOPSECRET" not in json.dumps(_collect().to_dict())


def test_denied_api_becomes_gap_not_pass() -> None:
    s = _collect()
    g = next(g for g in s.gaps if g.area == "agent.tools")
    assert g.reason == "DENIED" and "prvReadbot" in g.detail
    r = {**ROUTES, "PowerPlatform.Governance": ArmError("DENIED", "403")}
    s2 = _collect(r)
    f = next(x for x in run(s2).findings if x.rule_id == "ASA-DLP-001")
    assert f.status is Status.NOT_VERIFIED


def test_new_rules_on_observed_snapshot() -> None:
    by = {f.rule_id: f for f in run(_collect()).findings if f.asset_id in ("declared:conn", "entra:app:cid")}
    assert by["ASA-IAM-003"].status is Status.PASS
    assert by["ASA-AUTHZ-004"].status is Status.PASS
    assert by["ASA-SEC-002"].status in (Status.PASS, Status.FAIL)


def test_new_rules_on_fixtures() -> None:
    def st(a: Snapshot, rid: str) -> Status:
        return next(f.status for f in run(a).findings if f.rule_id == rid)

    assert st(secure(), "ASA-IAM-003") is Status.PASS and st(insecure(), "ASA-IAM-003") is Status.FAIL
    assert st(insecure(), "ASA-SEC-002") is Status.FAIL and st(unobservable(), "ASA-SEC-002") is Status.NOT_VERIFIED
    assert st(unobservable(), "ASA-AUTHZ-004") is Status.NOT_VERIFIED


def test_audience_in_two_forms_of_the_same_app_is_not_a_mismatch() -> None:
    s = _collect()
    api = s.node("/apim/apis/pay")
    assert api
    api.props["audience"] = "api"  # APIM validates the client-id form; connector requests the api:// form of the same app
    assert next(x for x in run(s).findings if x.rule_id == "ASA-AUTHZ-004").status is Status.PASS
    api.props["audience"] = "some-other-app"
    assert next(x for x in run(s).findings if x.rule_id == "ASA-AUTHZ-004").status is Status.FAIL


def test_flows_fall_back_to_dataverse_read_only_when_admin_api_denied() -> None:
    r = {
        **ROUTES,
        "/v2/flows": ArmError("DENIED", "403"),
        "/workflows?": {
            "value": [
                {"workflowid": "w1", "name": "Open review case", "statecode": 1, "ismanaged": False},
                {"workflowid": "w2", "name": "Draft flow", "statecode": 0, "ismanaged": False},
            ]
        },
        "/connectionreferences": {"value": [{"connectorid": "/providers/Microsoft.PowerApps/apis/shared_x", "statecode": 0}]},
        "/organizations": {"value": [{"isauditenabled": False, "auditretentionperiodv2": 90}]},
    }
    s = _collect(r)
    assert not any(g.area == "powerplatform.flows" for g in s.gaps)
    assert [n.name for n in s.nodes if n.id.startswith("pp:flow:")] == ["Flow · Open review case"]  # draft is not active
    tool = s.node("declared:tool-case")
    assert tool and tool.props["observed_in_env"] is True
    env = s.node("declared:env")
    assert env and env.props["connection_reference_count"] == 1 and env.props["dataverse_audit_enabled"] is False
    from asa import telemetry

    row = next(x for x in telemetry.build(s)["sources"] if x["source"] == "dataverse-audit")
    assert row["state"] == "missing"


def test_dataverse_fallback_never_selects_flow_definitions() -> None:
    seen: list[str] = []
    base = _fake({**ROUTES, "/v2/flows": ArmError("DENIED", "403"), "/workflows?": {"value": []}})

    def fetch(url: str, token: str) -> Any:
        seen.append(url)
        return base(url, token)

    SaaSCollector(_snap(), SaaSClient(lambda r: "t", fetch=fetch), environment_id=ENV, dataverse_url="https://org.crm.dynamics.com").collect()
    wf = [u for u in seen if "/workflows?" in u]
    assert wf and all("clientdata" not in u for u in wf)
