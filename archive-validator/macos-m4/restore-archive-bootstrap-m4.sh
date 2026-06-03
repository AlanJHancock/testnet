#!/usr/bin/env bash
set -euo pipefail

SNAPSHOT=""
EXPECTED_SHA256=""
TEST_ROOT=""
YES="false"
STORAGE_VOLUME_REL="/Volumes/Synergy_Archive"
STORAGE_ROOT_REL="${STORAGE_VOLUME_REL}/archive-validator"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --snapshot) SNAPSHOT="$2"; shift 2 ;;
    --sha256) EXPECTED_SHA256="$2"; shift 2 ;;
    --test-root) TEST_ROOT="$2"; shift 2 ;;
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
  mkdir -p "${STORAGE_VOLUME}"
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

APP_ROOT="$(prefix_path "${STORAGE_ROOT_REL}")"
WORKSPACE="${APP_ROOT}/workspace"
DATA_DIR="${WORKSPACE}/data"
BACKUP_ROOT="${APP_ROOT}/backups"
LAUNCHD_ROOT="$(prefix_path /Library/LaunchDaemons)"

install -d -m 0750 "${APP_ROOT}" "${APP_ROOT}/tmp" "${APP_ROOT}/incoming/bootstrap"
app_root_real="$(cd "${APP_ROOT}" && pwd -P)"
snapshot_dir="$(cd "$(dirname "${SNAPSHOT}")" && pwd -P)"
snapshot_real="${snapshot_dir}/$(basename "${SNAPSHOT}")"
case "${snapshot_real}" in
  "${app_root_real}"/*) ;;
  *)
    echo "--snapshot must be staged under ${APP_ROOT}, preferably ${APP_ROOT}/incoming/bootstrap" >&2
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

if [[ "${SKIP_LAUNCHD_STOP:-false}" != "true" ]]; then
  for label in \
    io.synergynetwork.archive-snapshot-worker \
    io.synergynetwork.archive-validator
  do
    launchctl bootout "system/${label}" >/dev/null 2>&1 || true
  done
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0750 "${BACKUP_ROOT}" "${WORKSPACE}"
if [[ -d "${DATA_DIR}" ]]; then
  mv "${DATA_DIR}" "${BACKUP_ROOT}/data-pre-bootstrap-${timestamp}"
fi
install -d -m 0750 "${DATA_DIR}"
ditto "${RESTORE_SOURCE}/" "${DATA_DIR}/"

if [[ "${SKIP_LAUNCHD_STOP:-false}" != "true" ]]; then
  for plist in \
    io.synergynetwork.archive-validator.plist \
    io.synergynetwork.archive-snapshot-worker.plist
  do
    launchctl bootstrap system "${LAUNCHD_ROOT}/${plist}" >/dev/null 2>&1 || true
    launchctl enable "system/${plist%.plist}" >/dev/null 2>&1 || true
  done
fi

echo "archive_bootstrap_restore_ok=true"
echo "snapshot_sha256=${actual_sha}"
echo "data_dir=${DATA_DIR}"
echo "backup_root=${BACKUP_ROOT}"
echo "next_action=wait for archive qRPC to catch up, then preserve height/hash parity evidence before majority proof or snapshot publication"
