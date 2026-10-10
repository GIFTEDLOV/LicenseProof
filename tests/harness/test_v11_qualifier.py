"""v1.1 live-run preconditions; never execute signed transactions in CI."""
from __future__ import annotations

import sys
import json

import pytest

from conftest import semantic
from scripts import live_qualification_v11 as candidate
from scripts.studio_live_qualification import QualificationError


def test_exact_v11_semantic_preview_boundary():
    v11 = semantic()
    assert len(candidate.V11_SEMANTIC_FIELDS) == 17
    assert candidate.semantic_from_value(v11) == v11
    assert candidate.semantic_from_value(json.dumps(v11)) == v11
    v10 = dict(v11)
    del v10["applicability_clear"]
    assert candidate.semantic_from_value(v10) is None
    v10["applicability_clear"] = "false"
    assert candidate.semantic_from_value(v10) is None


def test_candidate_evidence_is_isolated_from_v10():
    assert candidate.QUALIFICATION_DIR.as_posix().endswith("evidence/qualification/v1.1")
    assert candidate.EXPECTED_SOURCE_SHA != "77fb66904787baab72210276f29d6c0cc29831e2d243cecad5c2eb249146c0c4"


def test_no_authorization_means_no_signer_loaded(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["live_qualification_v11", "--execute"])
    monkeypatch.delenv("LICENSEPROOF_V11_DEPLOY_APPROVAL", raising=False)
    monkeypatch.setattr(candidate, "LiveRun", lambda: (_ for _ in ()).throw(AssertionError("signer touched")))
    with pytest.raises(SystemExit, match="Missing explicit v1.1 approval"):
        candidate.main()


@pytest.mark.parametrize("value", ["", {"state": "DRAFT"}, {"state": "FROZEN"}])
def test_policy_readback_distinguishes_absence(monkeypatch, value):
    monkeypatch.setattr(candidate, "gen_call_read", lambda *args: value)
    assert candidate.read_policy(None, "contract", "policy") == (
        {"state": "NOT_FOUND"} if value == "" else value
    )


@pytest.mark.parametrize("value", ["not json", "null", "[]", None])
def test_malformed_policy_readback_is_not_absence(monkeypatch, value):
    monkeypatch.setattr(candidate, "gen_call_read", lambda *args: value)
    with pytest.raises(QualificationError):
        candidate.read_policy(None, "contract", "policy")


def test_policy_rpc_failure_propagates(monkeypatch):
    def failed_read(*args):
        raise RuntimeError("RPC unavailable")
    monkeypatch.setattr(candidate, "gen_call_read", failed_read)
    with pytest.raises(RuntimeError, match="RPC unavailable"):
        candidate.read_policy(None, "contract", "policy")
