"""Initial rule set (17 rules). Each verdict is derived only from collected evidence.

Convention: a property that is absent or None means "not observed" and yields
NOT_VERIFIED, never PASS. Standards references are tagged requirement vs recommendation.
"""

from __future__ import annotations

from typing import Any

from asa.models import Finding, Node, Severity, Snapshot, Status
from asa.rules.base import (
    NodeRule,
    Rule,
    RuleMeta,
    Verdict,
    failed,
    make_finding,
    passed,
    rec,
    req,
    scope_level_result,
    selector,
    unknown,
)
from asa.untrusted import scan_text

S = Severity
PRIVILEGED_ROLES = {
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Role Based Access Control Administrator",
}
BROAD_SCOPE_LEVELS = {"management_group", "subscription", "resource_group"}
SECURE_AUTHN = {"user-delegated", "managed-identity", "oauth-app", "entra-token"}
INSECURE_AUTHN = {"none", "anonymous", "shared-secret", "api-key"}
SECRET_NAME_HINTS = ("key", "secret", "password", "connectionstring", "token", "pwd")


def _meta(**kw: Any) -> RuleMeta:
    return RuleMeta(**kw)


# ---------------------------------------------------------------- identity / RBAC
def _check_rbac(n: Node, snap: Snapshot) -> Verdict:
    if not n.props.get("role_assignments_known"):
        gap = snap.gap_for("arm.role_assignments")
        why = f"{gap.reason}: {gap.detail}" if gap else "role assignments were not enumerated"
        return unknown(f"Cannot assess privileges of {n.name}: {why}")
    assigns = n.props.get("role_assignments", [])
    risky = [a for a in assigns if a["role"] in PRIVILEGED_ROLES and a["scope_level"] in BROAD_SCOPE_LEVELS]
    if risky:
        return failed(
            f"{n.name} holds privileged roles at broad scope: " + ", ".join(f"{a['role']}@{a['scope_level']}" for a in risky),
            S.HIGH,
            risky_assignments=risky,
            total_assignments=len(assigns),
        )
    return passed(
        f"{n.name}: {len(assigns)} assignment(s), none privileged at subscription/resource-group scope.",
        assignments=assigns,
    )


RBAC = NodeRule(
    _meta(
        id="ASA-IAM-001",
        version="1.0",
        title="Workload identity holds no privileged role at broad scope",
        severity=S.HIGH,
        area="arm.role_assignments",
        impact="A compromised workload identity could change or read everything in the scope.",
        recommendation="Replace Owner/Contributor with narrowly scoped data-plane roles on the specific resources.",
        refs=(req("NIST SP 800-53 AC-6 Least Privilege"), rec("Microsoft cloud security benchmark PA-7")),
    ),
    selector("identity", kind=None),
    lambda n, s: (
        _check_rbac(n, s)
        if n.props.get("kind") in ("managed-identity", "service-principal")
        else Verdict(Status.NOT_APPLICABLE, "Not a workload identity.", {})
    ),
)


# ---------------------------------------------------------------- storage
def _tri(n: Node, key: str) -> Any:
    return n.props.get(key)


def _storage_public(n: Node, _: Snapshot) -> Verdict:
    v = _tri(n, "allow_blob_public_access")
    if v is None:
        return unknown(f"{n.name}: blob public access setting not observed.")
    if v:
        return failed(f"{n.name} allows anonymous blob access.", S.HIGH, allow_blob_public_access=True)
    return passed(f"{n.name} disables anonymous blob access.", allow_blob_public_access=False)


def _storage_shared_key(n: Node, _: Snapshot) -> Verdict:
    v = _tri(n, "shared_key_access")
    if v is None:
        return unknown(f"{n.name}: shared key access setting not observed.")
    if v:
        return failed(f"{n.name} allows account-key (shared key) authorization.", S.MEDIUM, shared_key_access=True)
    return passed(f"{n.name} requires Entra ID authorization.", shared_key_access=False)


def _storage_network(n: Node, _: Snapshot) -> Verdict:
    act = _tri(n, "network_default_action")
    pe = _tri(n, "private_endpoint_count")
    if act is None:
        return unknown(f"{n.name}: network default action not observed.")
    if act == "Deny" or (pe or 0) > 0:
        return passed(f"{n.name} restricts network access.", network_default_action=act, private_endpoints=pe)
    return failed(
        f"{n.name} accepts traffic from all networks (default action Allow, no private endpoint).",
        S.MEDIUM,
        network_default_action=act,
        private_endpoints=pe,
    )


STORAGE_PUBLIC = NodeRule(
    _meta(
        id="ASA-DATA-001",
        version="1.0",
        title="Storage account blocks anonymous blob access",
        severity=S.HIGH,
        area="arm.storage",
        impact="Anonymous read of stored documents (for example policy documents or exports).",
        recommendation="Set allowBlobPublicAccess=false at account level.",
        refs=(req("CIS Microsoft Azure Foundations Benchmark: storage public access disabled"),),
    ),
    selector("datastore", kind="storage-account"),
    _storage_public,
)
STORAGE_KEY = NodeRule(
    _meta(
        id="ASA-DATA-002",
        version="1.0",
        title="Storage account disables shared key authorization",
        severity=S.MEDIUM,
        area="arm.storage",
        impact="Leaked account keys grant full data-plane access without identity or audit trail.",
        recommendation="Disable shared key access and use Entra ID roles.",
        refs=(rec("Microsoft cloud security benchmark IM-1"), rec("Azure Storage security recommendations")),
    ),
    selector("datastore", kind="storage-account"),
    _storage_shared_key,
)
STORAGE_NET = NodeRule(
    _meta(
        id="ASA-NET-001",
        version="1.0",
        title="Storage account network access is restricted",
        severity=S.MEDIUM,
        area="arm.storage",
        impact="Data endpoint reachable from the whole internet (still identity-gated if keys are disabled).",
        recommendation="Set default action Deny with VNet rules or private endpoints.",
        refs=(rec("Microsoft cloud security benchmark NS-2"), req("NIST SP 800-53 SC-7 Boundary Protection")),
    ),
    selector("datastore", kind="storage-account"),
    _storage_network,
)


# ---------------------------------------------------------------- SQL
def _sql_public(n: Node, _: Snapshot) -> Verdict:
    pna = _tri(n, "public_network_access")
    rules = _tri(n, "firewall_rules")
    pe = _tri(n, "private_endpoint_count")
    if pna is None:
        return unknown(f"{n.name}: public network access not observed.")
    if pna == "Disabled":
        return passed(f"{n.name} has public network access disabled.", public_network_access=pna)
    if rules is None:
        return unknown(f"{n.name}: public access enabled but firewall rules not observed.", public_network_access=pna)
    wide = [r for r in rules if (r["start"], r["end"]) in {("0.0.0.0", "0.0.0.0"), ("0.0.0.0", "255.255.255.255")}]
    if wide:
        return failed(
            f"{n.name} public endpoint allows all Azure services or all addresses.",
            S.HIGH,
            public_network_access=pna,
            wide_rules=wide,
        )
    return failed(
        f"{n.name} public endpoint is enabled ({len(rules)} scoped firewall rule(s), {pe or 0} private endpoint(s)).",
        S.MEDIUM,
        public_network_access=pna,
        firewall_rules=rules,
        private_endpoints=pe,
    )


def _sql_aad_only(n: Node, _: Snapshot) -> Verdict:
    v = _tri(n, "entra_only_auth")
    if v is None:
        return unknown(f"{n.name}: authentication mode not observed.")
    return (
        passed(f"{n.name} enforces Entra-only authentication.", entra_only_auth=True)
        if v
        else failed(f"{n.name} permits SQL logins.", S.MEDIUM, entra_only_auth=False)
    )


SQL_PUBLIC = NodeRule(
    _meta(
        id="ASA-NET-002",
        version="1.0",
        title="SQL server is not exposed on a public endpoint",
        severity=S.MEDIUM,
        area="arm.sql",
        impact="Database endpoint reachable from the internet; protection relies on firewall and identity alone.",
        recommendation="Disable public network access and use private endpoints, or keep scoped rules and document the exception.",
        refs=(req("NIST SP 800-53 SC-7 Boundary Protection"), rec("Microsoft cloud security benchmark NS-2")),
    ),
    selector("datastore", kind="sql-server"),
    _sql_public,
)
SQL_AAD = NodeRule(
    _meta(
        id="ASA-IAM-002",
        version="1.0",
        title="SQL server enforces Entra-only authentication",
        severity=S.MEDIUM,
        area="arm.sql",
        impact="Password-based SQL logins bypass central identity controls and conditional access.",
        recommendation="Enable Microsoft Entra-only authentication.",
        refs=(rec("Microsoft cloud security benchmark IM-1"),),
    ),
    selector("datastore", kind="sql-server"),
    _sql_aad_only,
)


# ---------------------------------------------------------------- API gateway / function
def _apim(n: Node, snap: Snapshot) -> Verdict:
    readable = _tri(n, "policy_readable")
    if not readable:
        return unknown(f"{n.name}: gateway policy could not be read, so token validation is unverified.")
    if not n.props.get("validates_token"):
        return failed(f"{n.name} has no token validation policy.", S.HIGH, validates_token=False)
    missing = [k for k in ("audience", "required_scopes_or_groups") if not n.props.get(k)]
    if missing:
        return failed(
            f"{n.name} validates tokens but does not pin {', '.join(missing)}.",
            S.MEDIUM,
            validates_token=True,
            missing=missing,
        )
    return passed(
        f"{n.name} validates Entra tokens with pinned audience and required claims.",
        audience=n.props["audience"],
        required_scopes_or_groups=n.props["required_scopes_or_groups"],
    )


def _function_auth(n: Node, _: Snapshot) -> Verdict:
    v = _tri(n, "auth_required")
    if v is None:
        return unknown(f"{n.name}: App Service authentication settings not readable with current permissions.")
    if not v:
        return failed(f"{n.name} accepts unauthenticated requests.", S.HIGH, auth_required=False)
    if not n.props.get("allowed_identities"):
        return failed(
            f"{n.name} requires authentication but any principal in the tenant with a valid token may call it.",
            S.MEDIUM,
            auth_required=True,
            allowed_identities=0,
        )
    return passed(
        f"{n.name} requires authentication restricted to {len(n.props['allowed_identities'])} identity(ies).",
        auth_required=True,
        allowed_identities=n.props["allowed_identities"],
    )


def _secrets(n: Node, _: Snapshot) -> Verdict:
    names = _tri(n, "inline_secret_settings")
    if names is None:
        return unknown(f"{n.name}: application settings not readable (names only are ever collected).")
    if names:
        return failed(f"{n.name} stores secret-like settings inline: {', '.join(names)}.", S.HIGH, settings=names)
    return passed(f"{n.name}: no inline secret-like settings found.", inline_secret_settings=[])


APIM = NodeRule(
    _meta(
        id="ASA-AUTHZ-001",
        version="1.0",
        title="API gateway validates caller tokens (audience and claims)",
        severity=S.HIGH,
        area="arm.apim",
        impact="Callers without proper authorization could reach backend business operations.",
        recommendation="Add validate-azure-ad-token with audience and required scope/group claims.",
        refs=(req("NIST SP 800-53 AC-3 Access Enforcement"), rec("OWASP API Security Top 10: broken authentication")),
    ),
    selector("endpoint", kind="apim-api"),
    _apim,
)
FUNC_AUTH = NodeRule(
    _meta(
        id="ASA-AUTHZ-002",
        version="1.0",
        title="Backend function enforces authentication limited to its gateway",
        severity=S.HIGH,
        area="arm.web.authsettings",
        impact="Direct calls to the backend could bypass gateway authorization.",
        recommendation="Require authentication and allow only the gateway identity.",
        refs=(req("NIST SP 800-53 AC-3 Access Enforcement"),),
    ),
    selector("resource", kind="function-app"),
    _function_auth,
)
SECRETS = NodeRule(
    _meta(
        id="ASA-SEC-001",
        version="1.0",
        title="No secrets stored inline in application settings",
        severity=S.HIGH,
        area="arm.web.appsettings",
        impact="Secrets visible to anyone with settings read access and captured in exports and logs.",
        recommendation="Use Key Vault references or managed identity; rotate any exposed secret.",
        refs=(rec("Microsoft cloud security benchmark DP-6/IM-8"), req("NIST SP 800-53 IA-5 Authenticator Management")),
    ),
    selector("resource", kind="function-app"),
    _secrets,
)


# ---------------------------------------------------------------- logging
def _diag(n: Node, _: Snapshot) -> Verdict:
    v = _tri(n, "diagnostics_enabled")
    if v is None:
        return unknown(f"{n.name}: diagnostic settings not observed.")
    if v:
        return passed(f"{n.name} sends diagnostics to {n.props.get('diagnostics_sink', 'a sink')}.", diagnostics_enabled=True)
    return failed(
        f"{n.name} has no diagnostic settings; control-plane/data-plane activity is not retained.",
        S.MEDIUM,
        diagnostics_enabled=False,
    )


DIAG = NodeRule(
    _meta(
        id="ASA-LOG-001",
        version="1.0",
        title="Security-relevant resource sends diagnostic logs to a workspace",
        severity=S.MEDIUM,
        area="arm.diagnostics",
        impact="Incidents on this resource cannot be investigated or alerted on.",
        recommendation="Create a diagnostic setting for audit/resource logs to a Log Analytics workspace.",
        refs=(req("NIST SP 800-53 AU-12 Audit Record Generation"), rec("Microsoft cloud security benchmark LT-3")),
    ),
    lambda s: [n for n in s.nodes if n.props.get("diagnostics_supported")],
    _diag,
)


# ---------------------------------------------------------------- AI agents, tools, OAuth
def _safety(n: Node, _: Snapshot) -> Verdict:
    """content_filter: policy name | False (observed: none attached) | None (not observed). prompt_shield: bool | None."""
    cf, ps = _tri(n, "content_filter"), _tri(n, "prompt_shield")
    if n.props.get("model_kind") == "embedding":
        return Verdict(Status.NOT_APPLICABLE, f"{n.name} is an embedding model (no generated content to filter).", {})
    if cf is False or ps is False:
        missing = ["a content filter"] if cf is False else []
        missing += ["prompt-injection shielding"] if ps is False else []
        return failed(f"{n.name} lacks {' and '.join(missing)}.", S.MEDIUM, content_filter=cf, prompt_shield=ps)
    if cf is None:
        return unknown(f"{n.name}: guardrail configuration not readable; safety controls unverified.")
    if ps is None:
        return unknown(
            f"{n.name}: content filter '{cf}' attached, but its prompt-shield settings were not readable.", content_filter=cf
        )
    return passed(f"{n.name} has a content filter and prompt-injection shielding.", content_filter=cf, prompt_shield=ps)


def _tool_write(n: Node, _: Snapshot) -> Verdict:
    w, c = _tri(n, "writes_data"), _tri(n, "requires_confirmation")
    if w is None:
        return unknown(f"{n.name}: tool capabilities not observed.")
    if not w:
        return passed(f"{n.name} is read-only.", writes_data=False)
    if c is None:
        return unknown(f"{n.name} can write; confirmation behaviour not observed.", writes_data=True)
    if not c:
        return failed(
            f"{n.name} can write data without human confirmation.", S.HIGH, writes_data=True, requires_confirmation=False
        )
    return passed(f"{n.name} writes only after human confirmation.", writes_data=True, requires_confirmation=True)


BROAD_SCOPES = ("*", ".All", "user_impersonation", "Directory.AccessAsUser.All", "full_access")


def _scopes(n: Node, _: Snapshot) -> Verdict:
    scopes = _tri(n, "granted_scopes")
    if scopes is None:
        return unknown(f"{n.name}: granted OAuth scopes not observed.")
    broad = [s for s in scopes if s == "*" or s.endswith(".All") or "impersonation" in s or s == "full_access"]
    if broad:
        return failed(f"{n.name} holds broad scopes: {', '.join(broad)}.", S.HIGH, broad_scopes=broad, all_scopes=scopes)
    return passed(f"{n.name} holds {len(scopes)} narrowly named scope(s).", scopes=scopes)


SAFETY = NodeRule(
    _meta(
        id="ASA-AI-001",
        version="1.0",
        title="Model deployment / agent has content filtering and prompt-injection shielding",
        severity=S.MEDIUM,
        area="foundry.guardrails",
        impact="Untrusted content (documents, tool results) can steer the agent.",
        recommendation="Attach a content filter policy and enable prompt shields / indirect-attack detection.",
        refs=(rec("OWASP Top 10 for LLM Applications: LLM01 Prompt Injection"), rec("NIST AI RMF: Manage")),
    ),
    selector("model", "agent"),
    _safety,
)
TOOL_WRITE = NodeRule(
    _meta(
        id="ASA-AI-002",
        version="1.0",
        title="Agent tools that change data require human confirmation",
        severity=S.HIGH,
        area="agent.tools",
        impact="A manipulated agent could create or alter business records unattended.",
        recommendation="Gate write tools behind explicit user confirmation; prefer read-only tools.",
        refs=(rec("OWASP Top 10 for LLM Applications: LLM06 Excessive Agency"),),
    ),
    selector("tool", "connector"),
    _tool_write,
)
SCOPES = NodeRule(
    _meta(
        id="ASA-AI-003",
        version="1.0",
        title="OAuth and tool scopes are narrow",
        severity=S.HIGH,
        area="entra.oauth",
        impact="Delegated or app-level tokens can reach far more than the business task needs.",
        recommendation="Request only task-specific scopes; remove wildcard and *.All permissions.",
        refs=(req("NIST SP 800-53 AC-6 Least Privilege"), rec("Microsoft identity platform least-privilege guidance")),
    ),
    lambda s: [n for n in s.nodes if "granted_scopes" in n.props or n.type in ("connector",)],
    _scopes,
)


# ---------------------------------------------------------------- DLP / optional Microsoft signals
def _dlp(n: Node, _: Snapshot) -> Verdict:
    c = _tri(n, "dlp_policy_count")
    if c is None:
        return unknown(f"{n.name}: DLP policies not readable (requires Power Platform admin read access).")
    if c == 0:
        return failed(f"{n.name} has no DLP policy applied.", S.MEDIUM, dlp_policy_count=0)
    return passed(f"{n.name} has {c} DLP policy(ies) applied.", dlp_policy_count=c)


DLP = NodeRule(
    _meta(
        id="ASA-DLP-001",
        version="1.0",
        title="Power Platform environment has a data loss prevention policy",
        severity=S.MEDIUM,
        area="powerplatform.dlp",
        impact="Connectors can move business data to unmanaged services.",
        recommendation="Apply an environment or tenant DLP policy classifying business vs non-business connectors.",
        refs=(rec("Power Platform DLP policies documentation"),),
    ),
    selector("resource", kind="power-platform-env"),
    _dlp,
)


def _signals(n: Node, _: Snapshot) -> Verdict:
    d, s = _tri(n, "defender_plans_enabled"), _tri(n, "sentinel_present")
    if d is None and s is None:
        return unknown("Defender/Sentinel state not observed. ASA works without them; this is informational.")
    if d or s:
        return passed("Optional Microsoft security signals present.", defender_plans_enabled=d, sentinel_present=s)
    if d is None or s is None:  # one signal absent, the other unobservable: cannot claim "neither"
        return unknown("One of Defender/Sentinel is absent and the other was not observed.", defender_plans_enabled=d, sentinel_present=s)
    return failed(
        "Neither Defender plans nor Sentinel are present. ASA does not need them, but no independent detection/response exists.",
        S.LOW,
        defender_plans_enabled=d,
        sentinel_present=s,
    )


SIGNALS = NodeRule(
    _meta(
        id="ASA-DET-001",
        version="1.0",
        title="Optional threat-detection services are present (informational)",
        severity=S.LOW,
        area="arm.security",
        impact="No independent threat detection or response signal to correlate with ASA findings.",
        recommendation="Consider enabling relevant Defender plans / Sentinel. Recommendation only: ASA never enables them.",
        refs=(rec("Microsoft cloud security benchmark LT-1"),),
    ),
    selector("resource", kind="subscription"),
    _signals,
)


# ---------------------------------------------------------------- cross-system / injection (graph-level)
class SensitiveTransitionAuthz(Rule):
    meta = _meta(
        id="ASA-AUTHZ-003",
        version="1.0",
        title="Calls into sensitive business transitions are authenticated and user-attributed",
        severity=S.HIGH,
        area="graph.authn",
        impact="Cross-system hops with shared secrets or no authentication let any holder act as the operator.",
        recommendation="Use delegated user tokens or managed identity on every hop; remove shared secrets and anonymous routes.",
        refs=(req("NIST SP 800-53 AC-3 Access Enforcement"), rec("OWASP Top 10 for LLM Applications: LLM06 Excessive Agency")),
    )

    def evaluate(self, snap: Snapshot) -> list[Finding]:
        out: list[Finding] = []
        for e in snap.edges:
            dst = snap.node(e.dst)
            if e.type not in ("invokes", "delegates-to") or not dst or not dst.props.get("sensitive_transition"):
                continue
            aid = f"{e.src}->{e.dst}"
            authn = e.props.get("authn")
            node = snap.node(e.src)
            if authn is None:
                v = unknown(f"Authentication on {aid} not observed ({e.basis.value} edge).")
            elif authn in INSECURE_AUTHN:
                v = failed(f"{aid} uses '{authn}' into a sensitive transition.", S.HIGH, authn=authn, basis=e.basis.value)
            elif authn in SECURE_AUTHN:
                v = passed(f"{aid} authenticates with '{authn}'.", authn=authn, basis=e.basis.value)
            else:
                v = unknown(f"{aid}: unrecognised authn '{authn}'.")
            out.append(make_finding(self.meta, snap, aid, v, node))
        return out or [scope_level_result(self.meta, snap)]


def _strings(v: Any) -> list[str]:
    """All string leaves (including dict keys and values) of a nested property."""
    if isinstance(v, str):
        return [v]
    if isinstance(v, dict):
        return [s for k, x in v.items() for s in [*_strings(k), *_strings(x)]]
    if isinstance(v, (list, tuple)):
        return [s for x in v for s in _strings(x)]
    return []


class UntrustedContent(Rule):
    meta = _meta(
        id="ASA-AI-004",
        version="1.0",
        title="Collected data contains no instruction-like content",
        severity=S.LOW,
        area="asa.untrusted",
        impact="Instruction-like text in resource names, tags or logs targets the auditor's own reasoning (prompt injection).",
        recommendation="Review the flagged field. ASA already quarantines it from agent context; investigate who wrote it.",
        refs=(rec("OWASP Top 10 for LLM Applications: LLM01 Prompt Injection"),),
    )

    def evaluate(self, snap: Snapshot) -> list[Finding]:
        out: list[Finding] = []
        scanned = 0
        for n in snap.nodes:
            hits: list[str] = []
            for k, val in [("name", n.name), *n.props.items()]:
                for t in _strings(val):
                    scanned += 1
                    if scan_text(t):
                        hits.append(k)
            if hits:
                v = failed(
                    f"Instruction-like content in field(s) {sorted(set(hits))} of {n.id}; quarantined from agent context.",
                    S.LOW,
                    fields=sorted(set(hits)),
                )
                out.append(make_finding(self.meta, snap, n.id, v, n))
        if not out:
            v = passed(f"Scanned {scanned} text field(s); no instruction-like content.", fields_scanned=scanned)
            out.append(make_finding(self.meta, snap, f"scope:{snap.scope}", v, None))
        return out


ALL_RULES: list[Rule] = [
    RBAC,
    SQL_AAD,
    STORAGE_PUBLIC,
    STORAGE_KEY,
    STORAGE_NET,
    SQL_PUBLIC,
    APIM,
    FUNC_AUTH,
    SECRETS,
    DIAG,
    SAFETY,
    TOOL_WRITE,
    SCOPES,
    DLP,
    SIGNALS,
    SensitiveTransitionAuthz(),
    UntrustedContent(),
]
