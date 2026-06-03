#!/usr/bin/env bash
set -euo pipefail

PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="${1:-/Volumes/xcode/synergy-archive-mac-acceptance-$(date -u +%Y%m%dT%H%M%SZ)}"
BIN_ROOT="${TEST_ROOT}/usr/local/synergy/bin"
STORAGE_VOLUME="${TEST_ROOT}/Volumes/Synergy_Archive"
APP_ROOT="${STORAGE_VOLUME}/archive-validator"
PUBLISH_ROOT="${APP_ROOT}/snapshots"
WORKSPACE="${APP_ROOT}/workspace"
EVIDENCE="${APP_ROOT}/evidence/isolated-acceptance"
FORBIDDEN_APP_REL="/Library/Application Support/Synergy/archive""-validator"
FORBIDDEN_PUBLISH_REL="/srv/synergy""-snapshots"
mkdir -p "${EVIDENCE}"
BACKGROUND_PIDS=()

cleanup() {
  for pid in "${BACKGROUND_PIDS[@]}"; do
    kill "${pid}" >/dev/null 2>&1 || true
    wait "${pid}" 2>/dev/null || true
  done
}
trap cleanup EXIT

"${PACKAGE_ROOT}/setup-archive-validator-m4.sh" \
  --test-root "${TEST_ROOT}" \
  --public-host 127.0.0.1 \
  --snapshot-api-bind 127.0.0.1:48641 \
  --skip-launchd-load \
  --yes | tee "${EVIDENCE}/install.txt"
"${PACKAGE_ROOT}/verify-archive-validator-m4.sh" \
  --test-root "${TEST_ROOT}" \
  --skip-launchd-check | tee "${EVIDENCE}/verify.txt"

[[ -d "${APP_ROOT}" ]]
[[ -d "${APP_ROOT}/tmp" ]]
[[ -d "${APP_ROOT}/incoming/bootstrap" ]]
[[ -d "${PUBLISH_ROOT}/staging" ]]
[[ -d "${PUBLISH_ROOT}/failed" ]]
[[ -d "${PUBLISH_ROOT}/retired" ]]
[[ ! -e "${TEST_ROOT}${FORBIDDEN_APP_REL}" ]]
[[ ! -e "${TEST_ROOT}${FORBIDDEN_PUBLISH_REL}" ]]
if grep -R -F \
  -e "${FORBIDDEN_APP_REL}" \
  -e "${FORBIDDEN_PUBLISH_REL}" \
  "${TEST_ROOT}/Library/LaunchDaemons" "${APP_ROOT}" >/dev/null 2>&1
then
  echo "isolated acceptance found forbidden archive storage path" >&2
  exit 1
fi

python3 - "${WORKSPACE}/config/node.toml" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
for before, after in {
    "p2p_port = 5622": "p2p_port = 45622",
    "rpc_port = 5640": "rpc_port = 45640",
    "ws_port = 5660": "ws_port = 45660",
    'bind_address = "127.0.0.1:5640"': 'bind_address = "127.0.0.1:45640"',
    "http_port = 5640": "http_port = 45640",
    "ws_port = 5660": "ws_port = 45660",
    'listen_address = "0.0.0.0:5622"': 'listen_address = "127.0.0.1:45622"',
    'public_address = "127.0.0.1:5622"': 'public_address = "127.0.0.1:45622"',
    "discovery_port = 5680": "discovery_port = 45680",
    'discovery_listen_address = "0.0.0.0:5680"': 'discovery_listen_address = "127.0.0.1:45680"',
    'discovery_public_address = "127.0.0.1:5680"': 'discovery_public_address = "127.0.0.1:45680"',
    'metrics_bind = "127.0.0.1:6030"': 'metrics_bind = "127.0.0.1:46030"',
}.items():
    text = text.replace(before, after)
path.write_text(text, encoding="utf-8")
PY

SYNERGY_PROJECT_ROOT="${WORKSPACE}" \
SYNERGY_CONFIG_PATH="${WORKSPACE}/config/node.toml" \
  "${BIN_ROOT}/synergy-archive-validator-node" start \
    --config "${WORKSPACE}/config/node.toml" \
    > "${EVIDENCE}/archive-node.out" 2> "${EVIDENCE}/archive-node.err" &
NODE_PID=$!
BACKGROUND_PIDS+=("${NODE_PID}")
for _ in {1..30}; do
  if curl -fsS -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getChainId","params":[]}' \
    http://127.0.0.1:45640/ > "${EVIDENCE}/archive-node-qrpc.json"
  then
    break
  fi
  sleep 1
done
grep -q '"result"' "${EVIDENCE}/archive-node-qrpc.json"
kill "${NODE_PID}" >/dev/null 2>&1 || true
wait "${NODE_PID}" 2>/dev/null || true
BACKGROUND_PIDS=()

printf '{"acceptance":true}\n' > "${EVIDENCE}/payload.json"
"${BIN_ROOT}/aegis-pqvm" sign-json \
  --identity "${APP_ROOT}/keys/archive-authority-identity.json" \
  --domain SYNERGY_ARCHIVE_MAC_ACCEPTANCE_V1 \
  --input "${EVIDENCE}/payload.json" \
  --output "${EVIDENCE}/payload.json.sig" | tee "${EVIDENCE}/aegis-sign.json"
"${BIN_ROOT}/aegis-pqvm" verify-json \
  --domain SYNERGY_ARCHIVE_MAC_ACCEPTANCE_V1 \
  --input "${EVIDENCE}/payload.json" \
  --signature "${EVIDENCE}/payload.json.sig" | tee "${EVIDENCE}/aegis-verify.json"

FIXTURE_ROOT="${EVIDENCE}/fixture-validator-pruned"
SYNERGY_ARCHIVE_FIXTURE_MODE=1 "${BIN_ROOT}/aegis-pqvm" \
  test-only-create-snapshot-fixture \
  --output "${FIXTURE_ROOT}" \
  --snapshot-class validator-pruned | tee "${EVIDENCE}/fixture-create.json"
"${BIN_ROOT}/synergy-archive" publish-snapshot \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --workspace "${WORKSPACE}" \
  --source-node archive-fixture \
  --snapshot-class validator-pruned \
  --snapshot-root "${FIXTURE_ROOT}" \
  --manifest "${FIXTURE_ROOT}/snapshot-100-manifest.json" \
  --fixture-mode | tee "${EVIDENCE}/publish-snapshot.json"

SNAPSHOT_DIR="${PUBLISH_ROOT}/testnet-1264/validator-pruned/snapshot-000000100"
"${BIN_ROOT}/synergy-archive" verify-distribution \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --input "${SNAPSHOT_DIR}" \
  --workspace "${WORKSPACE}" \
  --source-node archive-fixture \
  --target-role validator \
  --extract-root "${EVIDENCE}/receiver-valid" | tee "${EVIDENCE}/receiver-verify.json"
if "${BIN_ROOT}/synergy-archive" verify-distribution \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --input "${SNAPSHOT_DIR}" \
  --workspace "${WORKSPACE}" \
  --source-node archive-fixture \
  --target-role rpc_gateway \
  --extract-root "${EVIDENCE}/receiver-wrong-class" \
  > "${EVIDENCE}/receiver-wrong-class.out" 2> "${EVIDENCE}/receiver-wrong-class.err"
then
  echo "wrong-class receiver was not rejected" >&2
  exit 1
fi
[[ ! -e "${EVIDENCE}/receiver-wrong-class" ]]

"${BIN_ROOT}/synergy-archive" pin \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --snapshot-id snapshot-000000100 \
  --snapshot-class validator-pruned \
  --reason isolated-mac-acceptance | tee "${EVIDENCE}/pin.json"
"${BIN_ROOT}/synergy-archive" unpin \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --snapshot-id snapshot-000000100 \
  --snapshot-class validator-pruned \
  --reason isolated-mac-acceptance | tee "${EVIDENCE}/unpin.json"
"${BIN_ROOT}/synergy-archive" prune \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" | tee "${EVIDENCE}/prune-dry-run.json"

"${BIN_ROOT}/synergy-archive" serve \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" \
  --bind 127.0.0.1:48641 > "${EVIDENCE}/snapshot-api.out" 2> "${EVIDENCE}/snapshot-api.err" &
API_PID=$!
BACKGROUND_PIDS+=("${API_PID}")
sleep 2
[[ "$(curl -fsS -H 'Range: bytes=0-4' \
  http://127.0.0.1:48641/testnet-1264/validator-pruned/snapshot-000000100/distribution-manifest.json \
  | wc -c | tr -d ' ')" == "5" ]]
curl -fsS http://127.0.0.1:48641/staging/not-public >/dev/null 2>&1 && {
  echo "snapshot API exposed staging path" >&2
  exit 1
}
kill "${API_PID}" >/dev/null 2>&1 || true
wait "${API_PID}" 2>/dev/null || true
BACKGROUND_PIDS=()

for plist in "${TEST_ROOT}/Library/LaunchDaemons/"*.plist; do
  plutil -lint "${plist}" >/dev/null
done
"${BIN_ROOT}/synergy-archive" status \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" | tee "${EVIDENCE}/final-status.json"
echo "isolated_mac_acceptance_ok=true"
echo "test_root=${TEST_ROOT}"
echo "evidence=${EVIDENCE}"
