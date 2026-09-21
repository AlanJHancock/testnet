#!/usr/bin/env python3
"""
Smoke test for the protocol-attestation ledger (synq-server) and the
matching SXCP/SCETP node-side RPC methods (synergy-node).

Exercises the full real pipeline end to end:
  compile-aivm -> aivm/estimate-gas -> submit-mempool
  -> GET /protocol-attestation/:source_hash
  -> GET /protocol-attestation/status
  -> synergy_getScetpStatus / synergy_getProtocolActivitySummary (node RPC)

Added 19 Sep 2026 alongside the protocol_attestation module. Run after any
change touching synq-server's aivm_handler.rs / main.rs / protocol_attestation.rs
or rpc_server.rs's SXCP/SCETP methods, to catch regressions before they reach
a live Forge session.

Usage:
    python3 smoke_test_protocol_attestation.py
    python3 smoke_test_protocol_attestation.py --synq-url http://127.0.0.1:3030 --node-url http://127.0.0.1:5641

Exit code 0 = all checks passed, 1 = at least one check failed.
"""
import argparse
import json
import sys
import time
import urllib.request

PASS = "PASS"
FAIL = "FAIL"

results = []


def check(name, condition, detail=""):
    status = PASS if condition else FAIL
    results.append((name, status, detail))
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and status == FAIL else ""))
    return condition


def http_post(url, payload, timeout=20):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def http_get(url, timeout=20):
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def rpc_call(node_url, method, params=None):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}
    return http_post(node_url, payload)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--synq-url", default="http://127.0.0.1:3030")
    parser.add_argument("--node-url", default="http://127.0.0.1:5641")
    args = parser.parse_args()

    synq_url = args.synq_url.rstrip("/")
    node_url = args.node_url

    # Unique contract per run so this test never collides with a prior run's
    # source_hash (the ledger is keyed by content hash of source text).
    unique_tag = str(int(time.time()))
    source = f"""pragma synq ^0.9;

// Smoke-test-only contract, regenerated fresh on every run (unique tag in
// the comment below keeps the source hash unique across runs).
// tag:{unique_tag}
contract SmokeTestSxcpDemo{unique_tag} {{
  state {{
    counter: u256;
    ready: bool;
  }}

  function init() -> bool as caller {{
    counter = 0;
    ready = true;
    return true;
  }}

  function bumpAfterSxcpAttestation(delta: u256) -> u256 as caller {{
    counter = counter + delta;
    return counter;
  }}
}}
"""

    # --- 1. Reachability ----------------------------------------------------
    try:
        status_before = http_get(f"{synq_url}/protocol-attestation/status")
        check("synq-server reachable (/protocol-attestation/status)", True)
    except Exception as e:
        check("synq-server reachable (/protocol-attestation/status)", False, str(e))
        status_before = {"tracked_artifacts": 0}

    try:
        block_number = rpc_call(node_url, "synergy_getBlockNumber")
        check("synergy-node RPC reachable (synergy_getBlockNumber)", "result" in block_number)
    except Exception as e:
        check("synergy-node RPC reachable (synergy_getBlockNumber)", False, str(e))

    tracked_before = status_before.get("tracked_artifacts", 0)

    # --- 2. compile-aivm ------------------------------------------------------
    try:
        compile_resp = http_post(f"{synq_url}/compile-aivm", {"source": source})
    except Exception as e:
        check("compile-aivm succeeds", False, str(e))
        compile_resp = {}
    check("compile-aivm succeeds", compile_resp.get("success") is True, json.dumps(compile_resp)[:300])

    # --- 3. aivm/estimate-gas (dry run of init()) -----------------------------
    try:
        estimate_resp = http_post(f"{synq_url}/aivm/estimate-gas", {
            "source": source, "function": "init", "args": [],
            "caller": None, "state": {}, "assets": [], "next_asset_id": 1,
        })
    except Exception as e:
        check("aivm/estimate-gas dry-run of init() succeeds", False, str(e))
        estimate_resp = {}
    check("aivm/estimate-gas dry-run of init() succeeds",
          estimate_resp.get("success") is True and estimate_resp.get("status") == "success",
          json.dumps(estimate_resp)[:300])

    # --- 4. submit-mempool (real QuantumVM deploy path) -----------------------
    try:
        submit_resp = http_post(f"{synq_url}/submit-mempool", {"source": source})
    except Exception as e:
        check("submit-mempool succeeds", False, str(e))
        submit_resp = {}
    check("submit-mempool succeeds", submit_resp.get("success") is True, json.dumps(submit_resp)[:300])

    source_hash = submit_resp.get("source_hash")
    check("submit-mempool returns a source_hash", bool(source_hash))
    check("qvm_deterministic is true (independent recompile matched)",
          submit_resp.get("qvm_deterministic") is True, json.dumps(submit_resp)[:300])
    check("dry_run_tested_before_deploy is true (estimate-gas ran before submit)",
          submit_resp.get("dry_run_tested_before_deploy") is True, json.dumps(submit_resp)[:300])
    check("protocol_hint classified as 'sxcp' (source mentions SXCP)",
          submit_resp.get("protocol_hint") == "sxcp", json.dumps(submit_resp)[:300])

    # --- 5. GET /protocol-attestation/:source_hash -----------------------------
    report = {}
    if source_hash:
        try:
            report = http_get(f"{synq_url}/protocol-attestation/{source_hash}")
            check("attestation report found for source_hash", report.get("found") is True)
        except Exception as e:
            check("attestation report found for source_hash", False, str(e))
    else:
        check("attestation report found for source_hash", False, "no source_hash from submit-mempool")

    stage_names = [s.get("stage") for s in report.get("stages", [])]
    expected_stages = ["aivm_compiled", "aivm_dry_run_executed", "qvm_deploy_envelope_built", "mempool_admitted"]
    check("all 4 lifecycle stages recorded in order",
          stage_names == expected_stages, f"got: {stage_names}")
    check("cross_backend_gap correctly flagged true (AIVM dry-run + QuantumVM deploy both seen)",
          report.get("cross_backend_gap") is True)
    check("tested_before_deploy true in the report",
          report.get("tested_before_deploy") is True)
    check("deterministic_by_backend shows both aivm and quantumvm as true",
          report.get("deterministic_by_backend", {}).get("aivm") is True
          and report.get("deterministic_by_backend", {}).get("quantumvm") is True)

    # --- 6. GET /protocol-attestation/status ------------------------------------
    try:
        status_after = http_get(f"{synq_url}/protocol-attestation/status")
        check("tracked_artifacts count increased by this run",
              status_after.get("tracked_artifacts", 0) >= tracked_before + 1,
              f"before={tracked_before} after={status_after.get('tracked_artifacts')}")
    except Exception as e:
        check("tracked_artifacts count increased by this run", False, str(e))

    # --- 7. Node-side SXCP/SCETP RPC methods -------------------------------------
    try:
        scetp_resp = rpc_call(node_url, "synergy_getScetpStatus")
        result = scetp_resp.get("result", {})
        check("synergy_getScetpStatus returns expected shape",
              all(k in result for k in ("protocol", "total_finalized_transfers", "total_pending_transfers", "recent")),
              json.dumps(scetp_resp)[:300])
    except Exception as e:
        check("synergy_getScetpStatus returns expected shape", False, str(e))

    try:
        summary_resp = rpc_call(node_url, "synergy_getProtocolActivitySummary")
        result = summary_resp.get("result", {})
        check("synergy_getProtocolActivitySummary returns expected shape",
              all(k in result for k in ("activity_counts_by_type", "sxcp_native_tx_count", "scetp_native_tx_count", "sxcp_relayer_status")),
              json.dumps(summary_resp)[:300])
    except Exception as e:
        check("synergy_getProtocolActivitySummary returns expected shape", False, str(e))

    # --- Summary ------------------------------------------------------------
    failed = [r for r in results if r[1] == FAIL]
    print()
    print(f"{len(results) - len(failed)}/{len(results)} checks passed.")
    if failed:
        print("FAILED CHECKS:")
        for name, _, detail in failed:
            print(f"  - {name}" + (f" ({detail})" if detail else ""))
        sys.exit(1)
    else:
        print("All protocol-attestation smoke tests passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
