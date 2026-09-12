#!/usr/bin/env bash
# Regression check: standalone SynQ Playground (demo/tools/playground/index.html)
# must render EACH compile error as its own visible row, not collapse multiple
# errors into a single joined string with no line-wrap CSS.
#
# Background: the compiler backend has always returned all errors correctly in
# `data.errors` (array). The bug was purely front-end: errors were joined with
# '\n' into one .warn div with no white-space CSS, so 2+ errors visually
# collapsed into one scrolled-off line. Fixed 2026-09-12 (commit df60f115).
#
# Run this after ANY change to demo/tools/playground/index.html's compile()
# error-rendering path, and before/after any deploy that touches it.
#
# Usage: ./check_multi_error_render.sh [base_url] [index_html_path]
#   base_url         defaults to https://hanksweb.co.uk
#   index_html_path  defaults to the file next to this script

set -euo pipefail

BASE_URL="${1:-https://hanksweb.co.uk}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INDEX_HTML="${2:-$SCRIPT_DIR/index.html}"

FAIL=0

echo "== 1) Backend check: compiler must return 3 distinct errors for a known-broken contract =="

BROKEN_SOURCE=$(cat <<'SYNQ'
pragma synq ^0.9;

contract Counter {
  state {
    counter: u256;
    initialised: bool;
  }
  impl {
    @public
    function init() -> bool {
      counter = 0;
      initialised = true;
      return true;
    }

    @public
    function broken(x: u256) -> u256 {
      counter = aaa + bbb;
      counter = ccc;
      return counter;
    }
  }
}
SYNQ
)

JSON_PAYLOAD=$(python3 -c '
import json, sys
print(json.dumps({"source": sys.stdin.read()}))
' <<< "$BROKEN_SOURCE")

RESPONSE=$(curl -sS -X POST "$BASE_URL/synq/compile" \
  -H 'Content-Type: application/json' \
  -d "$JSON_PAYLOAD" || echo '{"success":true,"errors":[]}')

ERROR_COUNT=$(python3 -c "
import json, sys
try:
    data = json.loads(sys.argv[1])
except Exception:
    print(0); sys.exit(0)
errs = data.get('errors') or []
print(len(errs))
" "$RESPONSE")

echo "   backend returned $ERROR_COUNT error(s)"
if [ "$ERROR_COUNT" -lt 3 ]; then
  echo "   FAIL: expected 3 distinct errors (undefined vars aaa/bbb/ccc), got $ERROR_COUNT"
  echo "   raw response: $RESPONSE"
  FAIL=1
else
  echo "   OK"
fi

echo "== 2) Front-end check: index.html must render one row per error, not one joined blob =="

if [ ! -f "$INDEX_HTML" ]; then
  echo "   FAIL: $INDEX_HTML not found"
  FAIL=1
else
  # Regression guard: the old buggy pattern joined all errors into a single
  # div with '\n', relying on CSS that didn't exist. If this pattern comes
  # back, fail loudly.
  if grep -qE "\.join\('\\\\n'\)\)\s*\+\s*'</div>'" "$INDEX_HTML"; then
    echo "   FAIL: found the old single-div '\\n'-joined error pattern in $INDEX_HTML"
    FAIL=1
  else
    echo "   OK: old collapsed-error pattern not present"
  fi

  # Positive guard: the fixed per-error row pattern (or equivalent) must exist.
  if grep -qE "errList\.map" "$INDEX_HTML"; then
    echo "   OK: per-error row rendering (errList.map) present"
  else
    echo "   FAIL: expected per-error row rendering (errList.map(...)) not found in $INDEX_HTML"
    FAIL=1
  fi

  # CSS guard: .warn must not silently lose its wrap/line-break support again.
  if grep -qE "\.evidence \.warn\{color:#e8c766;white-space:pre-wrap" "$INDEX_HTML"; then
    echo "   OK: .evidence .warn keeps white-space:pre-wrap"
  else
    echo "   FAIL: .evidence .warn CSS no longer has white-space:pre-wrap"
    FAIL=1
  fi
fi

echo "=================================================="
if [ "$FAIL" -ne 0 ]; then
  echo "RESULT: FAIL - multi-error rendering regression detected"
  exit 1
else
  echo "RESULT: PASS - multi-error rendering intact"
  exit 0
fi
