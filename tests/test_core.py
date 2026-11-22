from __future__ import annotations

import pytest

from asa.engine import run
from asa.graph import chains
from asa.models import Basis, Evidence, Finding, Severity, Snapshot, Status
from asa.report import to_html, to_json, to_markdown
from asa.rules.library import ALL_RULES
from asa.synthetic import insecure, secure, unobservable


def _by(a, status):  # type: ignore[no-untyped-def]
    return [f for f in a.findings if f.status is status]


# ---- invariants -----------------------------------------------------------------
def test_pass_without_evidence_is_impossible() -> None:
    with pytest.raises(ValueError):
        Finding("X", "1", Status.PASS, Severity.INFO, "a", "s", "t", [], "ctx", "high", "i", "r")


def test_not_verified_requires_reason() -> None:
    with pytest.raises(ValueError):
        Finding("X", "1", Status.NOT_VERIFIED, Severity.INFO, "a", "s", "t", [], "", "low", "i", "r")


def test_at_least_ten_rules() -> None:
    assert len({r.meta.id for r in ALL_RULES}) >= 10


# ---- secure / insecure / unobservable --------------------------------------------
def test_secure_has_no_failures_and_no_unknowns() -> None:
    a = run(secure())
    assert not _by(a, Status.FAIL) and not _by(a, Status.NOT_VERIFIED)
    assert a.coverage_pct == 100.0


def test_insecure_detects_many_distinct_rules() -> None:
    a = run(insecure())
    failing = {f.rule_id for f in _by(a, Status.FAIL)}
    assert len(failing) >= 14
    for expected in (
        "ASA-IAM-001",
        "ASA-DATA-001",
        "ASA-NET-002",
        "ASA-AUTHZ-001",
        "ASA-AUTHZ-003",
        "ASA-AI-002",
        "ASA-AI-003",
        "ASA-AI-004",
    ):
        assert expected in failing
    assert any(f.severity is Severity.HIGH for f in _by(a, Status.FAIL))


def test_unobservable_never_passes_what_it_cannot_see() -> None:
    a = run(unobservable())
    assert not _by(a, Status.FAIL)
    passes = {f.rule_id for f in _by(a, Status.PASS)}
    assert passes <= {"ASA-AI-004"}  # only the local text scan has evidence
    assert len(_by(a, Status.NOT_VERIFIED)) >= 15
    assert a.coverage_pct < 10


def test_denied_api_surfaces_gap_reason_in_finding() -> None:
    a = run(unobservable())
    f = next(x for x in a.findings if x.rule_id == "ASA-IAM-001" and x.asset_id == "id:func")
    assert f.status is Status.NOT_VERIFIED and "DENIED" in f.context


def test_every_unknown_property_yields_not_verified_never_pass() -> None:
    snap = secure()
    for n in snap.nodes:  # blank out every observed value
        for k in list(n.props):
            if k != "kind" and k not in ("diagnostics_supported", "sensitive_transition"):
                n.props[k] = None
    for e in snap.edges:
        if "authn" in e.props:
            e.props["authn"] = None
    a = run(snap)
    assert not _by(a, Status.FAIL)
    assert {f.rule_id for f in _by(a, Status.PASS)} <= {"ASA-AI-004"}


def test_rule_crash_is_not_a_pass() -> None:
    class Boom:
        meta = ALL_RULES[0].meta

        def evaluate(self, snap: Snapshot):  # type: ignore[no-untyped-def]
            raise RuntimeError("x")

    a = run(secure(), [Boom()])  # type: ignore[list-item]
    assert [f.status for f in a.findings] == [Status.NOT_VERIFIED]


def test_findings_carry_required_fields() -> None:
    for f in run(insecure()).findings:
        if f.status is Status.FAIL:
            assert f.evidence and f.recommendation and f.impact and f.rule_version and f.references and f.scope
            assert f.evidence[0].collected_at and f.evidence[0].mode == "fixture"


# ---- graph ------------------------------------------------------------------------
def test_chain_user_to_datastore_found() -> None:
    s = insecure()
    cs = chains(s, {"identity"}, {"datastore"})
    texts = [c.describe(s) for c in cs]
    assert any("operator@example.test" in t and "minibank-sql" in t for t in texts)


def test_chain_basis_is_weakest_edge() -> None:
    s = secure()
    s.edges[0].basis = Basis.UNKNOWN
    cs = chains(s, {"identity"}, {"datastore"})
    assert cs and all(c.basis is Basis.UNKNOWN for c in cs if c.edges[0] is s.edges[0])


# ---- reports ----------------------------------------------------------------------
def test_report_escapes_untrusted_content_and_labels_fixture() -> None:
    s = insecure()
    s.nodes[0].name = "<script>alert(1)</script>"
    html = to_html(run(s))
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "SYNTHETIC FIXTURE" in html
    assert "NOT_VERIFIED" in to_markdown(run(unobservable()))
    assert '"coverage_pct"' in to_json(run(secure()))


def test_evidence_roundtrip_json() -> None:
    a = run(insecure())
    s2 = Snapshot.from_dict(a.snapshot.to_dict())
    assert len(s2.nodes) == len(a.snapshot.nodes) and isinstance(Evidence, type)
