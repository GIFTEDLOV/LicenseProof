"""Read-only canonical v1.1 deployment and qualification readback."""

from __future__ import annotations

import base64
import hashlib
import json
from scripts.live_qualification_v11 import QUALIFICATION_DIR, EXPECTED_SOURCE_SHA, RUNNER, NETWORK, CHAIN_ID
from scripts.studio_live_qualification import (
    RPC,
    Rpc,
    account_state,
    gen_call_read,
    parse_json_string,
    local_schema,
)
from scripts.studio_deploy_harness import fsync_json


CONTRACT = "0x18A850BB8cA6cb0F75a5A9ab95362c12f1E349e6"


def main() -> int:
    summary = json.loads((QUALIFICATION_DIR / "summary.json").read_text(encoding="utf-8"))
    if (summary["contract"] != CONTRACT or summary["network"] != NETWORK
            or summary["chainId"] != CHAIN_ID or summary["contractSha256"] != EXPECTED_SOURCE_SHA
            or summary["runner"] != RUNNER or summary["liveQualification"] != "VERIFIED"
            or set(summary["cases"]) != {"A", "B", "C"}):
        raise RuntimeError("qualification summary does not match the pinned deployment")
    rpc = Rpc(RPC)
    chain, _ = rpc.call("eth_chainId", [])
    if int(chain, 16) != CHAIN_ID:
        raise RuntimeError("live chain mismatch")
    info = parse_json_string(gen_call_read(rpc, CONTRACT, "contract_info"))
    if (info != summary["contractInfo"] or info["contract_version"] != "1.1.0"
            or info["semantic_schema_version"] != "licenseproof.semantic.v1.1" or info["runner"] != RUNNER):
        raise RuntimeError("live contract_info mismatch")
    policy_id = summary["policy"]["id"]
    cases = {
        key: {"manifest": value["manifest"], "component": value["component"]}
        for key, value in summary["cases"].items()
    }
    result: dict[str, object] = {
        "network": summary["network"],
        "chainId": summary["chainId"],
        "contract": CONTRACT,
        "contract_info": {
            "contract_version": info["contract_version"],
            "semantic_schema_version": info["semantic_schema_version"],
            "runner": info["runner"],
        },
        "policy": parse_json_string(gen_call_read(rpc, CONTRACT, "get_policy", [policy_id])),
        "policy_ids": gen_call_read(rpc, CONTRACT, "get_policy_ids"),
        "manifest_ids": gen_call_read(rpc, CONTRACT, "get_manifest_ids"),
        "cases": {},
    }
    policy = result["policy"]
    if (policy["policy_id"] != policy_id or policy["state"] != "FROZEN"
            or summary["policy"]["state"] != "FROZEN" or not summary["policy"]["hash"]
            or policy["policy_hash"] != summary["policy"]["hash"]
            or policy_id not in result["policy_ids"] or result["manifest_ids"] != summary["manifestIds"]):
        raise RuntimeError("live policy or manifest index mismatch")
    for key, identifiers in cases.items():
        manifest = parse_json_string(gen_call_read(rpc, CONTRACT, "get_manifest", [identifiers["manifest"]]))
        component = parse_json_string(gen_call_read(rpc, CONTRACT, "get_component", [identifiers["component"]]))
        evidence = parse_json_string(gen_call_read(rpc, CONTRACT, "get_evidence", [component["license_evidence_id"]]))
        review = parse_json_string(gen_call_read(rpc, CONTRACT, "get_component_review", [identifiers["component"]]))
        expected = summary["cases"][key]
        if (manifest != summary["finalManifests"][key] or manifest["state"] != "FINALIZED"
                or manifest["manifest_id"] != identifiers["manifest"] or manifest["policy_id"] != policy_id
                or manifest["final_result"] != expected["manifest_result"]
                or component["state"] != "FINALIZED" or component["component_id"] != identifiers["component"]
                or component["manifest_id"] != identifiers["manifest"]
                or review != expected["review"] or review["state"] != "FINALIZED"
                or review["final_result"] != expected["component_result"]
                or review["component_id"] != identifiers["component"]
                or review["manifest_id"] != identifiers["manifest"]
                or component["license_evidence_id"] != review["review_identity"]["evidence_id"]
                or component["package_hash"] != review["review_identity"]["package_hash"]
                or evidence["evidence_id"] != component["license_evidence_id"]
                or evidence["content_sha256"] != expected["evidence"]["sha256"]
                or evidence["content_byte_length"] != expected["evidence"]["bytes"]):
            raise RuntimeError(f"live case {key} mismatch")
        result["cases"][key] = {
            "manifest": manifest,
            "component": component,
            "evidence": {
                "evidence_id": evidence["evidence_id"],
                "content_sha256": evidence["content_sha256"],
                "content_byte_length": evidence["content_byte_length"],
            },
            "review": review,
            "successor": gen_call_read(rpc, CONTRACT, "get_manifest_successor", [identifiers["manifest"]]),
        }
        if result["cases"][key]["successor"] != "":
            raise RuntimeError(f"live case {key} has a successor")
    events = gen_call_read(rpc, CONTRACT, "get_audit_events")
    page = []
    for offset in range(0, len(events), 100):
        page.extend(gen_call_read(rpc, CONTRACT, "get_audit_events_page", [offset, 100]))
    if events != summary["auditEvents"] or page != events:
        raise RuntimeError("live audit mismatch")
    result["audit"] = {"full_count": len(events), "page_count": len(page), "page_matches_full": page == events}
    code, _ = rpc.call("gen_getContractCode", [CONTRACT])
    result["deployed_source_sha256"] = hashlib.sha256(base64.b64decode(code, validate=True)).hexdigest()
    schema, _ = rpc.call("gen_getContractSchema", [CONTRACT])
    expected_schema, _ = local_schema()
    if result["deployed_source_sha256"] != EXPECTED_SOURCE_SHA or schema != expected_schema:
        raise RuntimeError("live source or schema mismatch")
    result["deployed_schema_methods"] = len(schema["methods"])
    result["account_after"] = account_state(rpc)
    fsync_json(QUALIFICATION_DIR / "readback-proof.json", result)
    print(json.dumps({
        "contract": CONTRACT,
        "contract_version": info["contract_version"],
        "semantic_schema_version": info["semantic_schema_version"],
        "deployed_source_sha256": result["deployed_source_sha256"],
        "deployed_schema_methods": result["deployed_schema_methods"],
        "policy_state": result["policy"]["state"],
        "case_results": {key: value["manifest"]["final_result"] for key, value in result["cases"].items()},
        "audit": result["audit"],
        "account_after": result["account_after"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
