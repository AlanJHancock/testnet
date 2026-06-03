#!/usr/bin/env bash
set -euo pipefail

TEST_ROOT=""
SKIP_LAUNCHD_CHECK="false"
SKIP_LISTENER_CHECK="false"
SERVICE_TIMEOUT_SECS="${ARCHIVE_VALIDATOR_SERVICE_TIMEOUT_SECS:-60}"
P2P_PORT="5622"
QRPC_PORT="5640"
WS_PORT="5660"
METRICS_PORT="6030"
SNAPSHOT_API_BIND="0.0.0.0:48640"
STORAGE_VOLUME_REL="/Volumes/Synergy_Archive"
STORAGE_ROOT_REL="${STORAGE_VOLUME_REL}/archive-validator"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --test-root) TEST_ROOT="$2"; shift 2 ;;
    --skip-launchd-check) SKIP_LAUNCHD_CHECK="true"; shift ;;
    --skip-listener-check) SKIP_LISTENER_CHECK="true"; shift ;;
    --service-timeout) SERVICE_TIMEOUT_SECS="$2"; shift 2 ;;
    --p2p-port) P2P_PORT="$2"; shift 2 ;;
    --qrpc-port) QRPC_PORT="$2"; shift 2 ;;
    --ws-port) WS_PORT="$2"; shift 2 ;;
    --metrics-port) METRICS_PORT="$2"; shift 2 ;;
    --snapshot-api-bind) SNAPSHOT_API_BIND="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

prefix_path() {
  if [[ -n "${TEST_ROOT}" ]]; then
    printf '%s%s' "${TEST_ROOT}" "$1"
  else
    printf '%s' "$1"
  fi
}

is_production_verify() {
  [[ -z "${TEST_ROOT}" ]]
}

snapshot_api_port() {
  printf '%s\n' "${SNAPSHOT_API_BIND##*:}"
}

install_evidence_dir() {
  install -d -m 0750 "${APP_ROOT}/evidence"
}

assert_stat() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(stat -f '%Su:%Sg %Lp' "${path}")"
  [[ "${actual}" == "${expected}" ]] || {
    echo "incorrect ownership/permissions for ${path}: actual=${actual} expected=${expected}" >&2
    exit 1
  }
}

assert_no_quarantine() {
  command -v xattr >/dev/null 2>&1 || return 0
  local path="$1"
  if xattr -p com.apple.quarantine "${path}" >/dev/null 2>&1; then
    echo "quarantine attribute still present on ${path}" >&2
    exit 1
  fi
}

assert_codesign_valid() {
  command -v codesign >/dev/null 2>&1 || {
    echo "codesign is required for Archive Validator launchd payload verification." >&2
    exit 1
  }
  local path="$1"
  codesign --verify --verbose=2 "${path}" >/dev/null 2>&1 || {
    echo "codesign verification failed for ${path}" >&2
    exit 1
  }
}

wait_for_tcp() {
  local host="$1"
  local port="$2"
  local name="$3"
  local timeout="$4"
  local attempt
  for ((attempt = 1; attempt <= timeout; attempt++)); do
    if python3 - "${host}" "${port}" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=1.0):
        pass
except OSError:
    raise SystemExit(1)
PY
    then
      echo "listener_ok=${name}:${host}:${port}"
      return 0
    fi
    sleep 1
  done
  echo "required listener unavailable: ${name} ${host}:${port}" >&2
  return 1
}

wait_for_qrpc_latest_block() {
  local port="$1"
  local timeout="$2"
  local output="${APP_ROOT}/evidence/archive-validator-verify-qrpc-latest-block.json"
  local attempt
  install_evidence_dir
  for ((attempt = 1; attempt <= timeout; attempt++)); do
    if python3 - "${port}" "${output}" <<'PY'
import json
import sys
import urllib.request

port, output = sys.argv[1:3]
payload = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "synergy_getLatestBlock",
    "params": [],
}).encode()
request = urllib.request.Request(
    f"http://127.0.0.1:{port}/",
    data=payload,
    headers={"Content-Type": "application/json"},
)
try:
    with urllib.request.urlopen(request, timeout=2.0) as response:
        value = json.loads(response.read().decode())
except Exception:
    raise SystemExit(1)
if "result" not in value:
    raise SystemExit(1)
with open(output, "w", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
    then
      echo "archive_qrpc_latest_block_ok=true"
      echo "archive_qrpc_latest_block_evidence=${output}"
      return 0
    fi
    sleep 1
  done
  echo "archive qRPC did not return synergy_getLatestBlock on 127.0.0.1:${port}" >&2
  return 1
}

assert_launchd_running() {
  local label="$1"
  local status_file="${APP_ROOT}/evidence/${label}.verify.launchctl.txt"
  install_evidence_dir
  launchctl print "system/${label}" > "${status_file}" 2>&1 || {
    echo "launchd service is not loaded: ${label}" >&2
    cat "${status_file}" >&2 2>/dev/null || true
    exit 1
  }
  if ! grep -Eq 'state = running|pid = [0-9]+' "${status_file}"; then
    echo "launchd service is not running: ${label}" >&2
    cat "${status_file}" >&2 2>/dev/null || true
    exit 1
  fi
  echo "launchd_running=${label}"
}

STORAGE_VOLUME="$(prefix_path "${STORAGE_VOLUME_REL}")"
if [[ -n "${TEST_ROOT}" ]]; then
  [[ -d "${STORAGE_VOLUME}" ]] || {
    echo "archive storage volume missing in test root: ${STORAGE_VOLUME}" >&2
    exit 1
  }
else
  [[ -d "${STORAGE_VOLUME}" ]] || {
    echo "required archive storage volume is not mounted: ${STORAGE_VOLUME}" >&2
    exit 1
  }
  /sbin/mount | grep -F " on ${STORAGE_VOLUME} " >/dev/null || {
    echo "required archive storage volume is not mounted as a filesystem: ${STORAGE_VOLUME}" >&2
    exit 1
  }
fi

BIN_ROOT="$(prefix_path /usr/local/synergy/bin)"
SHARE_ROOT="$(prefix_path /usr/local/synergy/share/archive-validator)"
APP_ROOT="$(prefix_path "${STORAGE_ROOT_REL}")"
PUBLISH_ROOT="${APP_ROOT}/snapshots"
LAUNCHD_ROOT="$(prefix_path /Library/LaunchDaemons)"
PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
export PATH
FORBIDDEN_APP_ROOT="$(prefix_path "/Library/Application Support/Synergy/archive""-validator")"
FORBIDDEN_PUBLISH_ROOT="$(prefix_path "/srv/synergy""-snapshots")"

[[ "$(uname -s)" == "Darwin" && "$(uname -m)" == "arm64" ]]
[[ -d "${APP_ROOT}" ]] || { echo "archive storage root missing: ${APP_ROOT}" >&2; exit 1; }
[[ -d "${PUBLISH_ROOT}" ]] || { echo "archive snapshot root missing: ${PUBLISH_ROOT}" >&2; exit 1; }
[[ ! -e "${FORBIDDEN_APP_ROOT}" ]] || {
  echo "forbidden archive storage path exists: ${FORBIDDEN_APP_ROOT}" >&2
  exit 1
}
[[ ! -e "${FORBIDDEN_PUBLISH_ROOT}" ]] || {
  echo "forbidden archive snapshot path exists: ${FORBIDDEN_PUBLISH_ROOT}" >&2
  exit 1
}
for binary in aegis-pqvm synergy-archive-validator-node synergy-archive; do
  [[ -x "${BIN_ROOT}/${binary}" ]]
  assert_no_quarantine "${BIN_ROOT}/${binary}"
  assert_codesign_valid "${BIN_ROOT}/${binary}"
  if is_production_verify; then
    assert_stat "${BIN_ROOT}/${binary}" "root:wheel 755"
  fi
done
(cd "${BIN_ROOT}" && shasum -a 256 -c "${SHARE_ROOT}/INSTALLED_BINARY_SHA256SUMS")
"${BIN_ROOT}/aegis-pqvm" smoke-test >/dev/null
"${BIN_ROOT}/synergy-archive-validator-node" version | grep -q 'Archive Validator Node'
"${BIN_ROOT}/synergy-archive" status \
  --root "${APP_ROOT}" \
  --publish-root "${PUBLISH_ROOT}" \
  --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
  --aegis "${BIN_ROOT}/aegis-pqvm" >/dev/null
for plist in "${LAUNCHD_ROOT}"/io.synergynetwork.archive-*.plist; do
  plutil -lint "${plist}" >/dev/null
  assert_no_quarantine "${plist}"
  if is_production_verify; then
    assert_stat "${plist}" "root:wheel 644"
  fi
done
if [[ "${SKIP_LAUNCHD_CHECK}" != "true" ]]; then
  for label in \
    io.synergynetwork.archive-validator \
    io.synergynetwork.archive-snapshot-api \
    io.synergynetwork.archive-snapshot-worker
  do
    assert_launchd_running "${label}"
  done
fi
if [[ "${SKIP_LISTENER_CHECK}" != "true" ]]; then
  wait_for_tcp 127.0.0.1 "${P2P_PORT}" archive_p2p "${SERVICE_TIMEOUT_SECS}"
  wait_for_tcp 127.0.0.1 "$(snapshot_api_port)" snapshot_api "${SERVICE_TIMEOUT_SECS}"
  wait_for_tcp 127.0.0.1 "${QRPC_PORT}" archive_qrpc "${SERVICE_TIMEOUT_SECS}"
  wait_for_tcp 127.0.0.1 "${WS_PORT}" archive_ws "${SERVICE_TIMEOUT_SECS}"
  wait_for_tcp 127.0.0.1 "${METRICS_PORT}" archive_metrics "${SERVICE_TIMEOUT_SECS}"
  wait_for_qrpc_latest_block "${QRPC_PORT}" "${SERVICE_TIMEOUT_SECS}"
fi
echo "archive_validator_verify_ok=true"
