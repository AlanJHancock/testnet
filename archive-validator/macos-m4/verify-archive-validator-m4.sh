#!/usr/bin/env bash
set -euo pipefail

TEST_ROOT=""
SKIP_LAUNCHD_CHECK="false"
STORAGE_VOLUME_REL="/Volumes/Synergy_Archive"
STORAGE_ROOT_REL="${STORAGE_VOLUME_REL}/archive-validator"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --test-root) TEST_ROOT="$2"; shift 2 ;;
    --skip-launchd-check) SKIP_LAUNCHD_CHECK="true"; shift ;;
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
done
if [[ "${SKIP_LAUNCHD_CHECK}" != "true" ]]; then
  for label in \
    io.synergynetwork.archive-validator \
    io.synergynetwork.archive-snapshot-api \
    io.synergynetwork.archive-snapshot-worker
  do
    launchctl print "system/${label}" >/dev/null
  done
fi
echo "archive_validator_verify_ok=true"
