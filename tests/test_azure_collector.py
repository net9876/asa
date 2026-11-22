"""Collector tests use a fake `az` runner: they prove read-only behaviour and gap handling,
NOT live correctness (see docs/tested-vs-mocked.md for the live evidence)."""

from __future__ import annotations

import json

import pytest

from asa.engine import run
from asa.models import Basis, Status
from asa.providers.azure_arm import (
    AzureArmCollector,
    ReadOnlyArm,
    WriteAttempt,
    _scope_level,
    parse_apim_policy,
)

SUB, RG = "00000000-0000-0000-0000-000000000001", "rg-test"
BASE = f"/subscriptions/{SUB}/resourceGroups/{RG}"
FUNC = f"{BASE}/providers/Microsoft.Web/sites/fn1"
UAMI = f"{BASE}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id1"
STG = f"{BASE}/providers/Microsoft.Storage/storageAccounts/stg1"
APIM = f"{BASE}/providers/Microsoft.ApiManagement/service/apim1"
API = f"{APIM}/apis/pay"
POLICY = (
    '<policies><inbound><validate-azure-ad-token tenant-id="t"><audiences><audience>api://x</audience></audiences>'
    '<required-claims><claim name="scp"><value>Payments.Read</value></claim></required-claims></validate-azure-ad-token>'
    '<authentication-managed-identity resource="api://b"/></inbound></policies>'
)


def fake(responses: dict[str, object], denied: tuple[str, ...] = ()):  # type: ignore[no-untyped-def]
    seen: list[list[str]] = []

    def runner(args: list[str]) -> tuple[int, str, str]:
        seen.append(args)
        url = args[args.index("--url") + 1]
        assert args[args.index("--method") + 1] == "get"
        if any(d in url for d in denied):
            return 1, "", "ERROR: (AuthorizationFailed) does not have authorization"
        for key, val in responses.items():
            if key in url:
                return 0, json.dumps(val), ""
        return 1, "", "ERROR: (ResourceNotFound) 404"

    runner.seen = seen  # type: ignore[attr-defined]
    return runner


def world() -> dict[str, object]:
    return {
        "/resources": {"value": [{"type": "Microsoft.Storage/storageAccounts"}]},
        "Microsoft.Security/pricings": {"value": [{"properties": {"pricingTier": "Free"}}]},
        "Microsoft.Storage/storageAccounts?": {
            "value": [
                {
                    "id": STG,
                    "name": "stg1",
                    "properties": {
                        "allowBlobPublicAccess": False,
                        "allowSharedKeyAccess": False,
                        "networkAcls": {"defaultAction": "Allow"},
                    },
                }
            ]
        },
        "Microsoft.Sql/servers?": {"value": []},
        "Microsoft.ApiManagement/service?": {"value": [{"id": APIM, "name": "apim1", "sku": {"name": "Consumption"}}]},
        f"{APIM}/apis?": {
            "value": [
                {
                    "id": API,
                    "name": "pay",
                    "properties": {
                        "displayName": "pay",
                        "serviceUrl": "https://fn1.azurewebsites.net",
                        "subscriptionRequired": False,
                    },
                }
            ]
        },
        "/policies/policy": {"properties": {"value": POLICY}},
        "Microsoft.Web/sites?": {
            "value": [
                {
                    "id": FUNC,
                    "name": "fn1",
                    "kind": "functionapp,linux",
                    "properties": {"defaultHostName": "fn1.azurewebsites.net", "httpsOnly": True},
                    "identity": {"userAssignedIdentities": {UAMI: {}}},
                }
            ]
        },
        "authsettingsV2": {
            "properties": {
                "globalValidation": {"requireAuthentication": True},
                "identityProviders": {
                    "azureActiveDirectory": {
                        "validation": {"defaultAuthorizationPolicy": {"allowedPrincipals": {"identities": ["apim-principal"]}}}
                    }
                },
            }
        },
        "userAssignedIdentities?": {"value": [{"id": UAMI, "name": "id1", "properties": {"principalId": "pid-1"}}]},
        "roleDefinitions": {
            "value": [
                {"id": "/rd/blobreader", "properties": {"roleName": "Storage Blob Data Reader"}},
                {"id": "/rd/contrib", "properties": {"roleName": "Contributor"}},
            ]
        },
        "roleAssignments": {
            "value": [
                {"properties": {"roleDefinitionId": "/rd/blobreader", "scope": f"{STG}/blobServices/default/containers/p"}},
                {"properties": {"roleDefinitionId": "/rd/contrib", "scope": f"/subscriptions/{SUB}"}},
            ]
        },
        "diagnosticSettings": {"value": []},
    }


def collect(responses: dict[str, object], denied: tuple[str, ...] = (), overlay: bool = True):  # type: ignore[no-untyped-def]
    runner = fake(responses, denied)
    c = AzureArmCollector(SUB, RG, None, overlay, ReadOnlyArm(runner))
    return c, c.collect(), runner


def test_only_get_is_ever_issued_and_writes_are_refused() -> None:
    _, _, runner = collect(world())
    assert runner.seen and all(a[a.index("--method") + 1] == "get" for a in runner.seen)  # type: ignore[attr-defined]
    arm = ReadOnlyArm(runner)
    for method in ("PUT", "DELETE", "PATCH", "POST"):
        with pytest.raises(WriteAttempt):
            arm._request(method, f"https://management.azure.com{BASE}/resources")
    with pytest.raises(WriteAttempt):
        arm._request("GET", "https://evil.example/steal")


def test_resource_graph_post_allowed_only_for_query_endpoint() -> None:
    ok = {"data": []}
    arm = ReadOnlyArm(lambda a: (0, json.dumps(ok), ""))
    assert arm.resource_graph("Resources | take 1", SUB) == ok
    with pytest.raises(WriteAttempt):
        arm._request("POST", f"https://management.azure.com{BASE}/providers/Microsoft.Web/sites/x/config/appsettings/list")


def test_collects_inventory_edges_and_roles() -> None:
    _, snap, _ = collect(world())
    ident = snap.node(UAMI.lower())
    assert ident and ident.props["role_assignments_known"] is True
    roles = {(a["role"], a["scope_level"]) for a in ident.props["role_assignments"]}
    assert ("Contributor", "subscription") in roles
    assert any(e.type == "invokes" and e.dst == FUNC.lower() and e.basis is Basis.CONFIRMED for e in snap.edges)
    assert any(e.type == "runs-as" and e.src == FUNC.lower() for e in snap.edges)
    assert any(e.type == "accesses" and e.dst == STG.lower() for e in snap.edges)
    assert snap.mode == "live"


def test_live_findings_use_observed_values() -> None:
    _, snap, _ = collect(world())
    a = run(snap)
    by = {(f.rule_id, f.asset_id): f for f in a.findings}
    assert by[("ASA-IAM-001", UAMI.lower())].status is Status.FAIL
    assert by[("ASA-DATA-001", STG.lower())].status is Status.PASS
    assert by[("ASA-NET-001", STG.lower())].status is Status.FAIL
    assert by[("ASA-AUTHZ-001", API.lower())].status is Status.PASS
    assert by[("ASA-AUTHZ-002", FUNC.lower())].status is Status.PASS
    assert by[("ASA-SEC-001", FUNC.lower())].status is Status.NOT_VERIFIED  # app settings need a POST: gap
    assert all(f.mode in ("live", "declared") for f in a.findings if f.evidence)


def test_denied_calls_become_gaps_not_passes() -> None:
    _, snap, _ = collect(world(), denied=("roleAssignments", "authsettingsV2", "Microsoft.Security"))
    areas = {g.area: g.reason for g in snap.gaps}
    assert areas["arm.role_assignments"] == "DENIED" and areas["arm.web.authsettings"] == "DENIED"
    a = run(snap)
    by = {(f.rule_id, f.asset_id): f for f in a.findings}
    assert by[("ASA-IAM-001", UAMI.lower())].status is Status.NOT_VERIFIED
    assert by[("ASA-AUTHZ-002", FUNC.lower())].status is Status.NOT_VERIFIED
    assert by[("ASA-DET-001", f"/subscriptions/{SUB}".lower())].status is Status.NOT_VERIFIED


def test_declared_overlay_is_labelled_and_chain_is_not_overclaimed() -> None:
    from asa.graph import chains

    _, snap, _ = collect(world())
    cs = chains(snap, {"identity"}, {"datastore"})
    declared = [c for c in cs if c.nodes[0] == "declared:user"]
    assert declared and all(c.basis is Basis.UNKNOWN for c in declared)  # user->agent is unobserved
    assert all(n.prov.mode == "declared" for n in snap.nodes if n.id.startswith("declared:"))
    assert any(g.area == "powerplatform.flows" for g in snap.gaps)
    assert any(f.rule_id == "ASA-AUTHZ-003" and f.status is Status.NOT_VERIFIED for f in run(snap).findings)


def test_parse_policy_and_scope_levels() -> None:
    p = parse_apim_policy(POLICY)
    assert p["validates_token"] and p["audience"] == "api://x" and p["required_scopes_or_groups"] == ["scp"]
    assert p["backend_auth"] == "managed-identity"
    assert not parse_apim_policy("<policies><inbound/></policies>")["validates_token"]
    assert parse_apim_policy("not xml")["validates_token"] is None  # unparseable = unknown, not "no validation"
    assert parse_apim_policy("ï»¿" + POLICY)["validates_token"]  # BOM bytes mis-decoded as cp1252/latin-1
    assert parse_apim_policy("﻿" + POLICY)["validates_token"]  # APIM returns a BOM (real regression)
    assert _scope_level(f"/subscriptions/{SUB}") == "subscription"
    assert _scope_level(f"/subscriptions/{SUB}/resourceGroups/x") == "resource_group"
    assert _scope_level(f"{STG}") == "resource"
