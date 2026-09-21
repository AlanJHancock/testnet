#!/usr/bin/env python3
"""
AIVM vs QuantumVM behavioral diff-test runner (v2 -- cleaner signal).

Replays every demo/examples/scenarios/*.scenario.json call sequence through
BOTH backends:
  - AIVM  (dry-run only, via POST /aivm/estimate-gas -- one call per step,
           chaining final_state/final_assets/next_asset_id between steps,
           exactly like a Forge debug session)
  - QVM   (the real deploy backend, via POST /quantumvm/dry-run -- one
           request per scenario, since that endpoint keeps one QuantumVM
           instance alive across the whole `calls` array itself)

v2 fixes three sources of noise identified in the v1 run:

1. DEFAULT CALLER. QuantumVM's IR compiler emits a real "caller != 0 or
   revert unauthenticated" check for every `as caller` function
   (compiler/src/ir/lower.rs emit_authority_prologue) -- AIVM's codegen
   does not enforce the equivalent check, so these fixture scenarios
   (written/tested against AIVM) mostly never bother setting "caller" at
   all. Left alone, every `as caller` call with no caller in the scenario
   file "succeeds" on AIVM (running as the implicit zero caller) and
   reverts "unauthenticated call" on QVM -- 30+ false diffs that are a
   test-harness gap, not a real bytecode/execution disagreement.

   Fixing this exposed a SECOND, more interesting divergence: AIVM and
   QVM decode a 41-byte caller string through two completely different
   conventions. AIVM's own numeric-identity comparisons (isAdmin(n),
   isRegistered(n), balanceOf(n)-style getters, map keys -- see
   aivm_handler.rs's caller_identity_slot_warning and
   aivm-scenario-testing-backlog.md item 7) read a 16-byte big-endian
   value out of bytes[5..21] of the 41-byte caller. QVM's
   qvm_call_context_for_caller instead just right-truncates to the raw
   LAST 20 bytes and treats that as a literal EVM-style address. A caller
   string built for one convention aliases to identity/address 0 under
   the other. DEFAULT_CALLER below writes the SAME identity value (1)
   into BOTH slots at once (byte 20 for AIVM's bytes[5..21] window, byte
   40 for QVM's trailing-20-bytes window) so plain "no caller specified"
   steps authenticate consistently on both backends -- but this dual
   encoding is a test-harness trick, not something a real caller address
   would ever naturally satisfy on both backends simultaneously. That
   AIVM/QVM caller-encoding mismatch is itself a real, confirmed
   architectural gap worth flagging on its own (see chat writeup).

2. VISIBILITY FILTER. AIVM's compiler (compiler/src/aivm_codegen.rs) marks
   a function Public only if it has `as caller` or an explicit `@public`
   attribute; everything else is Private, and avm.find_function() (used by
   /aivm/estimate-gas) only looks up Public functions -- so calling a
   plain getter with neither gets "function 'x' not found" from AIVM. This
   is AIVM correctly enforcing the language's own visibility rule, not a
   bug -- but /quantumvm/dry-run has no equivalent visibility gate, so it
   happily executes the same function. Diffing these two is apples-to-
   oranges. Fix: detect the "function '<name>' not found" signature from
   AIVM and report the step as SKIPPED (private-in-AIVM), not a DIFF.

3. $capture / $varName RESOLUTION. Several scenarios (AssetDemo) use
   {"capture": "name"} on one step to save its return value, then
   "$name" as a later step's arg to refer back to it (e.g. a dynamically
   allocated asset id). v1 didn't resolve these, so those calls got the
   literal string "$newAssetId" as an argument on both backends. Fix:
   track captured values per backend (each backend substitutes its OWN
   returned value, so a real per-backend divergence in the captured value
   itself would still surface downstream instead of being masked).

Usage:
    python3 diff_test_aivm_vs_quantumvm.py [--server http://127.0.0.1:3030] [--demo-root DIR]
"""
import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

# Dual-encoded "identity 1" caller: byte 20 = 0x01 satisfies AIVM's
# bytes[5..21] big-endian identity-slot convention; byte 40 = 0x01
# satisfies QVM's raw-last-20-bytes EVM-address convention. Both slots
# encode the SAME identity (1) so isAdmin(1)/isRegistered(1)-style
# checks against a plain numeric literal resolve consistently on both
# backends. See the module docstring for why these two conventions
# otherwise disagree.
DEFAULT_CALLER = "0x0000000000000000000000000000000000000000010000000000000000000000000000000000000001"

NOT_FOUND_RE = re.compile(r"function '([^']+)' not found")


def post_json(url, payload, timeout=20, max_retries=8):
    data = json.dumps(payload).encode("utf-8")
    body = None
    for attempt in range(max_retries):
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        err_list = body.get("errors") or []
        rate_limited = any("rate limit exceeded" in str(e) for e in err_list)
        if rate_limited and attempt < max_retries - 1:
            wait_s = 1.0
            m = re.search(r"retry in (\d+)s", " ".join(err_list))
            if m:
                wait_s = float(m.group(1))
            time.sleep(wait_s + 0.2)
            continue
        return body
    return body


def decode_aivm_address_identity(s):
    """AIVM represents ANY value that is actually a real Value::Address at
    runtime -- caller(), and (per aivm/src/host.rs's asset.owner/asset.create/
    asset.transfer, fixed 2026 for byte-for-byte asset_owner(id)==caller()
    comparisons) asset ownership -- as a 0x-prefixed 41-byte hex string via
    aivm_value_to_json, even when the SynQ-declared return type is a plain
    numeric one (e.g. AssetDemo.checkOwner(): -> u256, but returns
    asset_owner() which is really the creator's Value::Address). QuantumVM
    has no equivalent Address wrapper for this case -- its own asset model
    (vm/src/vm.rs's AssetRecord.owner) stores/returns a plain U256 throughout
    -- so it reports the SAME underlying identity as a plain decimal integer.
    Comparing the raw strings always "diffs" even when both sides agree on
    who the owner/caller actually is. Decode AIVM's side back to that same
    plain decimal integer, using the exact same canonical 16-byte
    big-endian identity slot at bytes[5..21] this harness's own
    DEFAULT_CALLER dual-encodes and every other identity-comparison in this
    file already relies on (Value::as_address()'s own convention). Returns
    None if  isn't shaped like one of these 41-byte addresses (e.g.
    V3Types' 32-byte session-id/bytes32 values are left untouched)."""
    if not isinstance(s, str) or not s.startswith("0x"):
        return None
    hex_part = s[2:]
    if len(hex_part) != 82:
        return None
    try:
        b = bytes.fromhex(hex_part)
    except ValueError:
        return None
    return str(int.from_bytes(b[5:21], "big"))


def normalize(value):
    if value is None:
        return None
    if isinstance(value, dict) and "value" in value and "type" in value:
        inner = value["value"]
        vtype = value["type"]
        if vtype == "Bool":
            if isinstance(inner, bool):
                return inner
            return str(inner).lower() == "true"
        # Tuple/struct returns: QVM wraps each element as its own typed
        # dict ({"type":"Tuple","value":[{"type":"UInt256","value":"3"},
        # ...]}) where AIVM just returns a plain list ([3, 4]). Recurse so
        # both sides end up as the same plain-list-of-normalized-scalars
        # shape instead of comparing a list to a string repr of a list of
        # dicts (which always "differs" even when every element matches).
        if vtype == "Tuple" and isinstance(inner, list):
            return [normalize(v) for v in inner]
        return str(inner)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return [normalize(v) for v in value]
    if isinstance(value, str):
        decoded = decode_aivm_address_identity(value)
        if decoded is not None:
            return decoded
        return value
    return value


def normalize_expect(expect):
    if isinstance(expect, bool):
        return expect
    if isinstance(expect, (int, float)):
        return str(expect)
    if isinstance(expect, list):
        return [normalize_expect(v) for v in expect]
    if isinstance(expect, str):
        decoded = decode_aivm_address_identity(expect)
        if decoded is not None:
            return decoded
    return expect


def to_arg_value(raw):
    """Turn a captured return_value (either backend's shape) back into a
    plain JSON arg value usable in a later call's args array."""
    if isinstance(raw, dict) and "value" in raw and "type" in raw:
        raw = raw["value"]
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        try:
            return int(raw)
        except ValueError:
            return raw
    return raw


def substitute_args(args, captured):
    out = []
    for a in args:
        if isinstance(a, str) and a.startswith("$"):
            name = a[1:]
            if name in captured:
                out.append(to_arg_value(captured[name]))
            else:
                out.append(a)  # leave as-is; will surface as a real error downstream
        else:
            out.append(a)
    return out


def aivm_not_found_fn(resp):
    """Return the function name if this AIVM response's failure is purely
    the Public-visibility gate rejecting a Private function, else None."""
    for e in (resp.get("errors") or []):
        m = NOT_FOUND_RE.search(e)
        if m:
            return m.group(1)
    return None


def run_aivm_companion_setup(server, companion):
    """Run a companion contract's setup calls (e.g. SimpleToken.init(...))
    as their own preliminary AIVM dry-run calls, chaining state the same
    way run_aivm_sequence does for the primary contract. Returns the
    companion's state dict after setup, ready to seed contract_states.
    """
    label = companion["label"]
    comp_source = companion["source"]
    state = {}
    for step in companion.get("setup", []):
        payload = {
            "source": comp_source,
            "function": step["call"],
            "args": step.get("args", []),
            "state": state,
            "caller": step.get("caller", DEFAULT_CALLER),
        }
        try:
            resp = post_json(f"{server}/aivm/estimate-gas", payload)
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            raise RuntimeError(f"companion '{label}' setup call '{step['call']}' failed: HTTP error: {e}")
        if not resp.get("success") or resp.get("status") == "reverted":
            raise RuntimeError(f"companion '{label}' setup call '{step['call']}' failed: {resp}")
        state = resp.get("final_state", state)
    return state


def run_aivm_sequence(server, source, steps, companion=None):
    results = []
    state = {}
    assets = []
    next_asset_id = 1
    captured = {}
    contract_states = {}
    if companion is not None:
        contract_states[companion["label"]] = run_aivm_companion_setup(server, companion)
    for step in steps:
        args = substitute_args(step.get("args", []), captured)
        payload = {
            "source": source,
            "function": step["call"],
            "args": args,
            "state": state,
            "assets": assets,
            "next_asset_id": next_asset_id,
            "caller": step.get("caller", DEFAULT_CALLER),
        }
        if companion is not None:
            payload["contracts"] = {companion["label"]: companion["source"]}
            payload["contract_states"] = contract_states
        try:
            resp = post_json(f"{server}/aivm/estimate-gas", payload)
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            resp = {"success": False, "errors": [f"HTTP error: {e}"]}
        not_found_fn = aivm_not_found_fn(resp) if not resp.get("success") else None
        results.append({
            "success": resp.get("success"),
            "return_value": resp.get("return_value"),
            "status": resp.get("status"),
            "revert_reason": resp.get("revert_reason"),
            "errors": resp.get("errors"),
            "private_skip": not_found_fn,
        })
        state = resp.get("final_state", state)
        assets = resp.get("final_assets", assets)
        next_asset_id = resp.get("next_asset_id", next_asset_id)
        if companion is not None:
            contract_states = resp.get("contract_final_states", contract_states)
        if step.get("capture") and resp.get("success"):
            captured[step["capture"]] = resp.get("return_value")
    return results


def run_qvm_sequence(server, source, steps, companion=None):
    """QVM dry-run keeps state within ONE request's calls array, but we
    need per-step $capture substitution which depends on THIS backend's
    own returned values -- so if any step uses a captured var or captures
    one itself, we run step-by-step (state seeded by re-sending the whole
    prefix each time would be wasteful/wrong since dry-run has no
    intermediate seeding API) -- instead detect the need and, when absent
    (the common case), keep the fast single-request path.

    `companion`, when given, is threaded through as /quantumvm/dry-run's
    native `contracts` + `contract_setup_calls` fields (see main.rs's
    QvmDryRunRequest) -- QVM's dry-run already runs the whole `calls`
    array against one persistent in-request VM/workspace, so (unlike
    AIVM's per-call state chaining) this only needs to be attached once
    per request, not threaded step-by-step.
    """
    needs_capture = any(step.get("capture") or any(isinstance(a, str) and a.startswith("$") for a in step.get("args", [])) for step in steps)

    def build_call(step, captured):
        call = {"function": step["call"], "args": substitute_args(step.get("args", []), captured)}
        call["caller"] = step.get("caller", DEFAULT_CALLER)
        return call

    def companion_extra_fields():
        if companion is None:
            return {}
        setup_calls = [
            {"function": s["call"], "args": s.get("args", []), "caller": s.get("caller", DEFAULT_CALLER)}
            for s in companion.get("setup", [])
        ]
        return {
            "contracts": {companion["label"]: companion["source"]},
            "contract_setup_calls": {companion["label"]: setup_calls},
        }

    if not needs_capture:
        calls = [build_call(step, {}) for step in steps]
        try:
            resp = post_json(f"{server}/quantumvm/dry-run", {"source": source, "calls": calls, **companion_extra_fields()})
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            return [{"success": False, "error": f"HTTP error: {e}", "return_value": None}] * len(steps)
        if resp.get("errors"):
            err = "; ".join(resp["errors"])
            return [{"success": False, "error": err, "return_value": None}] * len(steps)
        out = []
        for s in resp.get("steps", []):
            out.append({
                "success": s.get("success"),
                "return_value": s.get("return_value"),
                "error": s.get("error"),
                "revert_reason": s.get("revert_reason"),
            })
        return out

    # Capture-aware path: replay the growing prefix each time so the single
    # ephemeral VM instance still carries state naturally step-to-step, but
    # we can read back each step's own return value to resolve $vars before
    # building the NEXT call.
    results = []
    captured = {}
    calls_so_far = []
    for step in steps:
        call = build_call(step, captured)
        calls_so_far.append(call)
        try:
            resp = post_json(f"{server}/quantumvm/dry-run", {"source": source, "calls": calls_so_far, **companion_extra_fields()})
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            results.append({"success": False, "error": f"HTTP error: {e}", "return_value": None})
            continue
        if resp.get("errors"):
            results.append({"success": False, "error": "; ".join(resp["errors"]), "return_value": None})
            continue
        step_results = resp.get("steps", [])
        last = step_results[-1] if step_results else {"success": False, "return_value": None}
        results.append({
            "success": last.get("success"),
            "return_value": last.get("return_value"),
            "error": last.get("error"),
            "revert_reason": last.get("revert_reason"),
        })
        if step.get("capture") and last.get("success"):
            captured[step["capture"]] = last.get("return_value")
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://127.0.0.1:3030")
    ap.add_argument("--demo-root", default="/root/Downloads/synergy-testnet/SynQ/demo")
    ap.add_argument("--scenarios-dir", default=None)
    args = ap.parse_args()

    demo_root = Path(args.demo_root)
    scenarios_dir = Path(args.scenarios_dir) if args.scenarios_dir else demo_root / "examples" / "scenarios"

    scenario_files = sorted(scenarios_dir.glob("*.scenario.json"))
    if not scenario_files:
        print(f"No scenario files found in {scenarios_dir}")
        sys.exit(1)

    total_steps = 0
    total_matches = 0
    total_mismatches = 0
    total_skipped_private = 0
    mismatch_details = []
    load_skipped = []

    for sf in scenario_files:
        spec = json.loads(sf.read_text())
        contract_rel = spec.get("contract")
        contract_path = demo_root / contract_rel
        if not contract_path.exists():
            load_skipped.append(f"{sf.name}: contract source not found at {contract_path}")
            continue
        source = contract_path.read_text()

        # Optional companion contract (21 Sept 2026 -- real extern_call
        # support): a scenario file whose contract calls extern_call(...)
        # (currently just TokenVault.scenario.json -> SimpleToken) declares
        # {"companion": {"contract": "examples/SimpleToken.synq", "label":
        # "SimpleToken", "setup": [{"call": "init", "args": [...]}]}} at the
        # top level, applied fresh to every scenario in the file (each
        # scenario starts a brand-new vault + token, exactly like the
        # primary contract's own state starts fresh per scenario).
        companion_spec = spec.get("companion")
        companion = None
        if companion_spec is not None:
            companion_path = demo_root / companion_spec["contract"]
            if not companion_path.exists():
                load_skipped.append(f"{sf.name}: companion contract source not found at {companion_path}")
                continue
            companion = {
                "label": companion_spec.get("label", companion_path.stem),
                "source": companion_path.read_text(),
                "setup": companion_spec.get("setup", []),
            }

        print(f"\n=== {sf.name} ({contract_rel}) ===")
        for scenario in spec.get("scenarios", []):
            name = scenario.get("name", "(unnamed)")
            steps = scenario.get("steps", [])
            print(f"  -- scenario: {name}")

            aivm_results = run_aivm_sequence(args.server, source, steps, companion=companion)
            qvm_results = run_qvm_sequence(args.server, source, steps, companion=companion)

            for i, step in enumerate(steps):
                a = aivm_results[i] if i < len(aivm_results) else {"success": False, "return_value": None}
                q = qvm_results[i] if i < len(qvm_results) else {"success": False, "return_value": None}

                if a.get("private_skip"):
                    total_skipped_private += 1
                    print(f"     [SKIP-PRIVATE] {step['call']}(...)  AIVM treats '{a['private_skip']}' as Private (no as-caller/@public) -- not a cross-backend diff")
                    continue

                total_steps += 1
                # NOTE (20 Sep 2026 fix): AIVM's /aivm/estimate-gas always answers
                # HTTP-level success=true for a revert -- the dry-run call itself
                # didn't error -- and carries the real outcome in a separate
                # "status" field (status=="reverted"). QuantumVM's dry-run instead
                # flips success=false on revert. Scoring only on "success" made a
                # correctly-enforced AIVM revert look like a non-revert. Compute an
                # effective-reverted/effective-success flag per backend so both
                # conventions compare on equal terms. See aivm-vs-quantumvm
                # architectural writeup, "Correction" section, for the full story.
                a_reverted = (a.get("status") == "reverted") or (not a.get("success"))
                a_true_success = a.get("success") and not a_reverted
                q_reverted = not q.get("success")
                q_true_success = q.get("success")

                a_norm = normalize(a.get("return_value")) if a_true_success else f"<error: {a.get('revert_reason') or a.get('error') or '; '.join(a.get('errors') or []) or a.get('status')}>"
                q_norm = normalize(q.get("return_value")) if q_true_success else f"<error: {q.get('revert_reason') or q.get('error')}>"

                expect_return = step.get("expectReturn")
                expect_status = step.get("expectStatus")
                expected_norm = None
                if expect_return is not None:
                    expected_norm = normalize_expect(expect_return)
                elif expect_status == "reverted":
                    expected_norm = "<reverted>"

                a_ok_vs_expected = None
                q_ok_vs_expected = None
                if expected_norm is not None:
                    if expected_norm == "<reverted>":
                        a_ok_vs_expected = a_reverted
                        q_ok_vs_expected = q_reverted
                    else:
                        a_ok_vs_expected = (a_true_success and a_norm == expected_norm)
                        q_ok_vs_expected = (q_true_success and q_norm == expected_norm)

                cross_match = (a_reverted == q_reverted) and (
                    a_norm == q_norm if not a_reverted else True
                )

                status_tag = "MATCH" if cross_match else "DIFF"
                if cross_match:
                    total_matches += 1
                else:
                    total_mismatches += 1

                line = f"     [{status_tag}] {step['call']}({', '.join(map(str, step.get('args', [])))})  AIVM={a_norm!r}  QVM={q_norm!r}"
                if expected_norm is not None:
                    exp_tag = []
                    if a_ok_vs_expected is False:
                        exp_tag.append("AIVM!=expected")
                    if q_ok_vs_expected is False:
                        exp_tag.append("QVM!=expected")
                    if exp_tag:
                        line += f"  [expected={expected_norm!r}: {', '.join(exp_tag)}]"
                print(line)

                if not cross_match or a_ok_vs_expected is False or q_ok_vs_expected is False:
                    mismatch_details.append({
                        "scenario_file": sf.name,
                        "scenario": name,
                        "step_index": i,
                        "call": step["call"],
                        "args": step.get("args", []),
                        "aivm": a,
                        "qvm": q,
                        "expected": expected_norm,
                    })

    print("\n" + "=" * 70)
    print(f"TOTAL COMPARABLE STEPS: {total_steps}   MATCHES: {total_matches}   DIFFS: {total_mismatches}   SKIPPED (private-in-AIVM): {total_skipped_private}")
    if load_skipped:
        print("\nSkipped files (no contract source found):")
        for s in load_skipped:
            print(f"  - {s}")
    if mismatch_details:
        print(f"\n{len(mismatch_details)} step(s) flagged (cross-backend diff or expectation mismatch):")
        for m in mismatch_details:
            print(f"  - {m['scenario_file']} / {m['scenario']!r} / step {m['step_index']} "
                  f"({m['call']}({', '.join(map(str, m['args']))})):")
            print(f"      AIVM: {m['aivm']}")
            print(f"      QVM:  {m['qvm']}")
            print(f"      expected: {m['expected']}")
    else:
        print("\nNo cross-backend behavioral diffs and no expectation mismatches found.")

    sys.exit(1 if mismatch_details else 0)


if __name__ == "__main__":
    main()
