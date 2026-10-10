"""Canonical proof is saved only after every mocked live read matches."""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from scripts import verify_live_readback_v11 as verifier


@pytest.fixture
def live(monkeypatch, tmp_path):
    root = Path(__file__).resolve().parents[2]
    summary = json.loads((root / "evidence/qualification/v1.1/summary.json").read_text())
    proof = json.loads((root / "evidence/qualification/v1.1/readback-proof.json").read_text())
    schema, _ = verifier.local_schema()
    state = {"proof": proof, "summary": summary, "schema": schema,
             "info": copy.deepcopy(summary["contractInfo"]), "events": summary["auditEvents"],
             "page": summary["auditEvents"], "chain": hex(verifier.CHAIN_ID),
             "code": (root / "contracts/LicenseProof.py").read_text().encode()}
    (tmp_path / "summary.json").write_text(json.dumps(summary))
    (tmp_path / "readback-proof.json").write_text("previous proof")
    monkeypatch.setattr(verifier, "QUALIFICATION_DIR", tmp_path)

    class Rpc:
        def __init__(self, url):
            pass

        def call(self, method, args):
            if method == "eth_chainId":
                return state["chain"], {}
            if method == "gen_getContractCode":
                return base64.b64encode(state["code"]).decode(), {}
            if method == "gen_getContractSchema":
                return state["schema"], {}
            raise AssertionError(f"unexpected RPC (writes forbidden): {method}")

    def read(rpc, address, method, args=None):
        assert address == verifier.CONTRACT
        if method == "contract_info":
            return state["info"]
        if method == "get_policy":
            return proof["policy"]
        if method == "get_policy_ids":
            return proof["policy_ids"]
        if method == "get_manifest_ids":
            return proof["manifest_ids"]
        if method == "get_audit_events":
            return state["events"]
        if method == "get_audit_events_page":
            return state["page"][args[0]:args[0] + args[1]]
        for case in proof["cases"].values():
            values = {"get_manifest": (case["manifest"]["manifest_id"], case["manifest"]),
                      "get_component": (case["component"]["component_id"], case["component"]),
                      "get_evidence": (case["evidence"]["evidence_id"], case["evidence"]),
                      "get_component_review": (case["component"]["component_id"], case["review"]),
                      "get_manifest_successor": (case["manifest"]["manifest_id"], case["successor"])}
            if method in values and args == [values[method][0]]:
                return values[method][1]
        raise AssertionError(f"unexpected read: {method} {args}")

    monkeypatch.setattr(verifier, "Rpc", Rpc)
    monkeypatch.setattr(verifier, "gen_call_read", read)
    monkeypatch.setattr(verifier, "account_state", lambda rpc: {})
    return state, tmp_path


def test_matching_live_readback_saves_proof(live):
    state, directory = live
    assert verifier.main() == 0
    proof = json.loads((directory / "readback-proof.json").read_text())
    assert proof["deployed_source_sha256"] == verifier.EXPECTED_SOURCE_SHA
    assert proof["cases"] == state["proof"]["cases"]


@pytest.mark.parametrize("target,path,value", [
    ("code", (), b"wrong source"),
    ("chain", (), "0x1"),
    ("schema", ("methods", "contract_info", "readonly"), False),
    ("info", ("contract_version",), "1.0.0"),
    ("info", ("semantic_schema_version",), "wrong"),
    ("info", ("runner",), "wrong"),
    ("proof", ("policy", "state"), "DRAFT"),
    ("proof", ("policy", "policy_hash"), "wrong"),
    ("proof", ("cases", "A", "manifest", "final_result"), "INCOMPATIBLE"),
    ("proof", ("cases", "B", "review", "final_result"), "COMPATIBLE"),
    ("proof", ("cases", "C", "component", "state"), "DRAFT"),
    ("proof", ("cases", "A", "evidence", "content_sha256"), "wrong"),
    ("proof", ("cases", "A", "successor"), "successor"),
    ("page", (), []),
    ("events", (), []),
])
def test_live_mismatch_fails_without_overwriting_proof(live, target, path, value):
    state, directory = live
    item = state
    for key in (target, *path)[:-1]:
        item = item[key]
    item[(target, *path)[-1]] = value
    with pytest.raises(RuntimeError, match="mismatch|successor"):
        verifier.main()
    assert (directory / "readback-proof.json").read_text() == "previous proof"


def test_audit_reads_all_pages(live):
    state, directory = live
    events = [f"event-{number}" for number in range(205)]
    state["events"] = state["page"] = events
    state["summary"]["auditEvents"] = events
    (directory / "summary.json").write_text(json.dumps(state["summary"]))
    assert verifier.main() == 0
    assert json.loads((directory / "readback-proof.json").read_text())["audit"]["page_count"] == 205
