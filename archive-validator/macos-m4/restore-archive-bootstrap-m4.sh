#!/usr/bin/env bash
set -euo pipefail

SNAPSHOT=""
EXPECTED_SHA256=""
TEST_ROOT=""
YES="false"
SERVICE_TIMEOUT_SECS="${ARCHIVE_VALIDATOR_RESTORE_TIMEOUT_SECS:-180}"
STORAGE_VOLUME_REL="/Volumes/Synergy_Archive"
LOCAL_ROOT_REL="/Users/Shared/Synergy/archive-validator"
SMB_ROOT_REL="${STORAGE_VOLUME_REL}/archive-validator"
INCOMING_BOOTSTRAP_REL="${SMB_ROOT_REL}/incoming/bootstrap"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot) SNAPSHOT="$2"; shift 2 ;;
    --sha256) EXPECTED_SHA256="$2"; shift 2 ;;
    --test-root) TEST_ROOT="$2"; shift 2 ;;
    --service-timeout) SERVICE_TIMEOUT_SECS="$2"; shift 2 ;;
    --yes) YES="true"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || { echo "Archive bootstrap restore requires macOS." >&2; exit 1; }
[[ -n "${SNAPSHOT}" && -f "${SNAPSHOT}" ]] || { echo "--snapshot must point to a bootstrap .tar.zst or .tar file." >&2; exit 1; }
[[ -n "${EXPECTED_SHA256}" ]] || { echo "--sha256 is required." >&2; exit 1; }
if [[ -n "${TEST_ROOT}" ]]; then
  mkdir -p "${TEST_ROOT}"
  TEST_ROOT="$(cd "${TEST_ROOT}" && pwd)"
fi

prefix_path() {
  if [[ -n "${TEST_ROOT}" ]]; then
    printf '%s%s' "${TEST_ROOT}" "$1"
  else
    printf '%s' "$1"
  fi
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
  [[ "$(id -u)" == "0" ]] || { echo "Run production restore with sudo." >&2; exit 1; }
fi

APP_ROOT="$(prefix_path "${LOCAL_ROOT_REL}")"
WORKSPACE="${APP_ROOT}/workspace"
DATA_DIR="${WORKSPACE}/data"
BACKUP_ROOT="${APP_ROOT}/backups"
LOG_ROOT="${APP_ROOT}/logs"
SMB_ROOT="$(prefix_path "${SMB_ROOT_REL}")"
INCOMING_BOOTSTRAP="$(prefix_path "${INCOMING_BOOTSTRAP_REL}")"
LAUNCHD_ROOT="$(prefix_path /Library/LaunchDaemons)"
MANAGE_LAUNCHD="true"
if [[ -n "${TEST_ROOT}" || "${SKIP_LAUNCHD_STOP:-false}" == "true" ]]; then
  MANAGE_LAUNCHD="false"
fi

install_dir() {
  local mode="$1"
  shift
  local path
  for path in "$@"; do
    if [[ -z "${TEST_ROOT}" ]]; then
      install -d -o root -g wheel -m "${mode}" "${path}"
    else
      install -d -m "${mode}" "${path}"
    fi
  done
}

wait_for_launchd_label() {
  local label="$1"
  local timeout="$2"
  local status_file="${APP_ROOT}/evidence/${label}.restore.launchctl.txt"
  install_dir 0750 "${APP_ROOT}/evidence"
  local attempt
  for ((attempt = 1; attempt <= timeout; attempt++)); do
    if launchctl print "system/${label}" > "${status_file}" 2>&1 &&
      grep -Eq 'state = running|pid = [0-9]+' "${status_file}"
    then
      echo "launchd_running=${label}"
      return 0
    fi
    sleep 1
  done
  echo "launchd service failed to stay running after restore: ${label}" >&2
  cat "${status_file}" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/archive-validator.err.log" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/snapshot-api.err.log" >&2 2>/dev/null || true
  tail -n 80 "${LOG_ROOT}/snapshot-worker.err.log" >&2 2>/dev/null || true
  return 1
}

restart_launchd_services() {
  local label
  for label in \
    io.synergynetwork.archive-snapshot-worker \
    io.synergynetwork.archive-snapshot-api \
    io.synergynetwork.archive-validator
  do
    launchctl bootout "system/${label}" >/dev/null 2>&1 || true
  done
  local plist
  for plist in \
    io.synergynetwork.archive-validator.plist \
    io.synergynetwork.archive-snapshot-api.plist \
    io.synergynetwork.archive-snapshot-worker.plist
  do
    launchctl bootstrap system "${LAUNCHD_ROOT}/${plist}"
    launchctl enable "system/${plist%.plist}"
    launchctl kickstart -k "system/${plist%.plist}"
  done
  wait_for_launchd_label io.synergynetwork.archive-validator "${SERVICE_TIMEOUT_SECS}"
  wait_for_launchd_label io.synergynetwork.archive-snapshot-api "${SERVICE_TIMEOUT_SECS}"
  wait_for_launchd_label io.synergynetwork.archive-snapshot-worker "${SERVICE_TIMEOUT_SECS}"
}

wait_for_qrpc_latest_block() {
  local output="${APP_ROOT}/evidence/archive-bootstrap-restore-qrpc-latest-block.json"
  install_dir 0750 "${APP_ROOT}/evidence"
  local attempt
  for ((attempt = 1; attempt <= SERVICE_TIMEOUT_SECS; attempt++)); do
    if python3 - "${output}" <<'PY'
import json
import sys
import urllib.request

output = sys.argv[1]
payload = json.dumps({
    "jsonrpc": "2.0",
    "id": 1,
    "method": "synergy_getLatestBlock",
    "params": [],
}).encode()
request = urllib.request.Request(
    "http://127.0.0.1:5640/",
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
  echo "archive qRPC did not return synergy_getLatestBlock after bootstrap restore" >&2
  tail -n 80 "${LOG_ROOT}/archive-validator.err.log" >&2 2>/dev/null || true
  return 1
}

if [[ -z "${TEST_ROOT}" ]]; then
  case "${APP_ROOT}" in
    /Volumes/*)
      echo "runtime root must be local storage, not an SMB/network volume: ${APP_ROOT}" >&2
      exit 1
      ;;
  esac
fi

install_dir 0750 "${APP_ROOT}" "${APP_ROOT}/tmp" "${SMB_ROOT}" "${INCOMING_BOOTSTRAP}"
app_root_real="$(cd "${APP_ROOT}" && pwd -P)"
bootstrap_root_real="$(cd "${INCOMING_BOOTSTRAP}" && pwd -P)"
snapshot_dir="$(cd "$(dirname "${SNAPSHOT}")" && pwd -P)"
snapshot_real="${snapshot_dir}/$(basename "${SNAPSHOT}")"
case "${snapshot_real}" in
  "${bootstrap_root_real}"/*) ;;
  *)
    echo "--snapshot must be staged under ${INCOMING_BOOTSTRAP}" >&2
    exit 1
    ;;
esac

actual_sha="$(shasum -a 256 "${SNAPSHOT}" | awk '{print $1}')"
[[ "${actual_sha}" == "${EXPECTED_SHA256}" ]] || {
  echo "bootstrap snapshot checksum mismatch: actual=${actual_sha} expected=${EXPECTED_SHA256}" >&2
  exit 1
}

if [[ "${YES}" != "true" ]]; then
  read -r -p "Stop Archive Validator, replace workspace data from ${SNAPSHOT}, and restart? [y/N] " answer
  [[ "${answer}" == "y" || "${answer}" == "Y" ]] || exit 1
fi

extract_root="$(mktemp -d "${APP_ROOT}/tmp/synergy-archive-bootstrap.XXXXXX")"
cleanup() {
  rm -rf "${extract_root}"
}
trap cleanup EXIT

case "${SNAPSHOT}" in
  *.tar.zst|*.tzst)
    command -v zstd >/dev/null 2>&1 || { echo "zstd is required to restore ${SNAPSHOT}." >&2; exit 1; }
    zstd -dc "${SNAPSHOT}" | tar -xf - -C "${extract_root}"
    ;;
  *.tar)
    tar -xf "${SNAPSHOT}" -C "${extract_root}"
    ;;
  *)
    echo "unsupported bootstrap archive extension: ${SNAPSHOT}" >&2
    exit 1
    ;;
esac

if [[ -d "${extract_root}/data" ]]; then
  RESTORE_SOURCE="${extract_root}/data"
elif [[ -d "${extract_root}/workspace/data" ]]; then
  RESTORE_SOURCE="${extract_root}/workspace/data"
else
  RESTORE_SOURCE="${extract_root}"
fi

for forbidden in keys key.pem private.pem node.env .env genesis.json config.toml node.toml; do
  if find "${RESTORE_SOURCE}" -iname "${forbidden}" -type f | grep -q .; then
    echo "bootstrap snapshot contains forbidden key/config material: ${forbidden}" >&2
    exit 1
  fi
done

if [[ "${MANAGE_LAUNCHD}" == "true" ]]; then
  for label in \
    io.synergynetwork.archive-snapshot-worker \
    io.synergynetwork.archive-snapshot-api \
    io.synergynetwork.archive-validator
  do
    launchctl bootout "system/${label}" >/dev/null 2>&1 || true
  done
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
install_dir 0750 "${BACKUP_ROOT}" "${WORKSPACE}"
if [[ -d "${DATA_DIR}" ]]; then
  mv "${DATA_DIR}" "${BACKUP_ROOT}/data-pre-bootstrap-${timestamp}"
fi
install_dir 0750 "${DATA_DIR}"
ditto "${RESTORE_SOURCE}/" "${DATA_DIR}/"
if [[ -z "${TEST_ROOT}" ]]; then
  chown -R root:wheel "${DATA_DIR}"
  chmod -R u+rwX,go-rwx "${DATA_DIR}"
fi

if [[ "${MANAGE_LAUNCHD}" == "true" ]]; then
  restart_launchd_services
  wait_for_qrpc_latest_block
fi

echo "archive_bootstrap_restore_ok=true"
echo "snapshot_sha256=${actual_sha}"
echo "runtime_root=${APP_ROOT}"
echo "incoming_bootstrap=${INCOMING_BOOTSTRAP}"
echo "data_dir=${DATA_DIR}"
echo "backup_root=${BACKUP_ROOT}"
echo "next_action=wait for archive qRPC to catch up, then preserve height/hash parity evidence before majority proof or snapshot publication"
