#!/usr/bin/env bash
set -euo pipefail

PACKAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT=""
PUBLIC_HOST=""
SNAPSHOT_API_BIND="0.0.0.0:48640"
SKIP_LAUNCHD_LOAD="false"
YES="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --test-root) TEST_ROOT="$2"; shift 2 ;;
    --public-host) PUBLIC_HOST="$2"; shift 2 ;;
    --snapshot-api-bind) SNAPSHOT_API_BIND="$2"; shift 2 ;;
    --skip-launchd-load) SKIP_LAUNCHD_LOAD="true"; shift ;;
    --yes) YES="true"; shift ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ "$(uname -s)" == "Darwin" ]] || { echo "The M4 archive installer requires macOS." >&2; exit 1; }
[[ "$(uname -m)" == "arm64" ]] || { echo "The M4 archive installer requires Apple Silicon arm64." >&2; exit 1; }
if [[ -z "${TEST_ROOT}" ]]; then
  [[ "$(id -u)" == "0" ]] || { echo "Run the production install with sudo." >&2; exit 1; }
else
  mkdir -p "${TEST_ROOT}"
  TEST_ROOT="$(cd "${TEST_ROOT}" && pwd)"
fi
[[ -n "${PUBLIC_HOST}" ]] || { echo "--public-host is required." >&2; exit 1; }

prefix_path() {
  if [[ -n "${TEST_ROOT}" ]]; then
    printf '%s%s' "${TEST_ROOT}" "$1"
  else
    printf '%s' "$1"
  fi
}

BIN_ROOT="$(prefix_path /usr/local/synergy/bin)"
SHARE_ROOT="$(prefix_path /usr/local/synergy/share/archive-validator)"
APP_ROOT="$(prefix_path '/Library/Application Support/Synergy/archive-validator')"
WORKSPACE="${APP_ROOT}/workspace"
LOG_ROOT="$(prefix_path /Library/Logs/Synergy/archive-validator)"
PUBLISH_ROOT="$(prefix_path /srv/synergy-snapshots)"
LAUNCHD_ROOT="$(prefix_path /Library/LaunchDaemons)"
PROOF_MARKER="${APP_ROOT}/evidence/source-majority-branch-proven.json"

for dependency in python3 tar shasum plutil; do
  command -v "${dependency}" >/dev/null 2>&1 || {
    echo "Missing required macOS dependency: ${dependency}" >&2
    exit 1
  }
done
if ! command -v zstd >/dev/null 2>&1; then
  if [[ -n "${TEST_ROOT}" ]]; then
    echo "zstd is required for isolated acceptance testing." >&2
    exit 1
  fi
  command -v brew >/dev/null 2>&1 || {
    echo "Homebrew is required to install zstd. Install Homebrew, then rerun this script." >&2
    exit 1
  }
  brew install zstd
fi

if [[ "${YES}" != "true" ]]; then
  read -r -p "Install the Synergy Testnet 1264 Archive Validator on this Apple Silicon Mac? [y/N] " answer
  [[ "${answer}" == "y" || "${answer}" == "Y" ]] || exit 1
fi

(cd "${PACKAGE_ROOT}" && shasum -a 256 -c BINARY_SHA256SUMS)
for binary in aegis-pqvm synergy-archive-validator-node; do
  file "${PACKAGE_ROOT}/bin/${binary}" | grep -q 'arm64' || {
    echo "${binary} is not an Apple Silicon arm64 executable." >&2
    exit 1
  }
done

install -d -m 0755 "${BIN_ROOT}" "${SHARE_ROOT}" "${LAUNCHD_ROOT}"
install -d -m 0750 "${APP_ROOT}/"{config,keys,logs,evidence,tmp} "${WORKSPACE}/"{config,data} "${PUBLISH_ROOT}"
install -d -m 0755 "${LOG_ROOT}"
install -m 0755 "${PACKAGE_ROOT}/bin/aegis-pqvm" "${BIN_ROOT}/aegis-pqvm"
install -m 0755 "${PACKAGE_ROOT}/bin/synergy-archive-validator-node" "${BIN_ROOT}/synergy-archive-validator-node"
install -m 0755 "${PACKAGE_ROOT}/bin/synergy-archive" "${BIN_ROOT}/synergy-archive"
install -m 0644 "${PACKAGE_ROOT}/BINARY_SHA256SUMS" "${SHARE_ROOT}/BINARY_SHA256SUMS"
(cd "${BIN_ROOT}" && shasum -a 256 aegis-pqvm synergy-archive-validator-node synergy-archive > "${SHARE_ROOT}/INSTALLED_BINARY_SHA256SUMS")
install -m 0644 "${PACKAGE_ROOT}/SOURCE-PROVENANCE.json" "${SHARE_ROOT}/SOURCE-PROVENANCE.json"
install -m 0644 "${PACKAGE_ROOT}/config/genesis.json" "${WORKSPACE}/config/genesis.json"
install -m 0644 "${PACKAGE_ROOT}/config/snapshot-policy.toml" "${APP_ROOT}/config/snapshot-policy.toml"
sed "s/replace-with-public-host/${PUBLIC_HOST}/g" \
  "${PACKAGE_ROOT}/config/node.toml.template" > "${WORKSPACE}/config/node.toml"
chmod 0644 "${WORKSPACE}/config/node.toml"

GENESIS_HASH="$(python3 - "${WORKSPACE}/config/genesis.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))["integrity"]["genesis_hash"])
PY
)"
[[ "${GENESIS_HASH}" == "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789" ]] || {
  echo "Packaged genesis hash mismatch." >&2
  exit 1
}

PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  "${BIN_ROOT}/aegis-pqvm" smoke-test >/dev/null
PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  "${BIN_ROOT}/synergy-archive-validator-node" version >/dev/null
PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  "${BIN_ROOT}/synergy-archive" init \
    --root "${APP_ROOT}" \
    --publish-root "${PUBLISH_ROOT}" \
    --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
    --aegis "${BIN_ROOT}/aegis-pqvm" >/dev/null

render_plist() {
  local template="$1"
  local output="$2"
  sed \
    -e "s|__BIN_ROOT__|${BIN_ROOT}|g" \
    -e "s|__APP_ROOT__|${APP_ROOT}|g" \
    -e "s|__WORKSPACE__|${WORKSPACE}|g" \
    -e "s|__LOG_ROOT__|${LOG_ROOT}|g" \
    -e "s|__PUBLISH_ROOT__|${PUBLISH_ROOT}|g" \
    -e "s|__PROOF_MARKER__|${PROOF_MARKER}|g" \
    -e "s|__SNAPSHOT_API_BIND__|${SNAPSHOT_API_BIND}|g" \
    "${template}" > "${output}"
  chmod 0644 "${output}"
  plutil -lint "${output}" >/dev/null
}

for plist in "${PACKAGE_ROOT}/launchd/"*.plist.in; do
  name="$(basename "${plist%.in}")"
  render_plist "${plist}" "${LAUNCHD_ROOT}/${name}"
done

PATH="${BIN_ROOT}:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" \
  "${BIN_ROOT}/synergy-archive" status \
    --root "${APP_ROOT}" \
    --publish-root "${PUBLISH_ROOT}" \
    --runtime "${BIN_ROOT}/synergy-archive-validator-node" \
    --aegis "${BIN_ROOT}/aegis-pqvm" >/dev/null

if [[ "${SKIP_LAUNCHD_LOAD}" != "true" ]]; then
  for label in \
    io.synergynetwork.archive-snapshot-worker \
    io.synergynetwork.archive-snapshot-api \
    io.synergynetwork.archive-validator
  do
    launchctl bootout "system/${label}" >/dev/null 2>&1 || true
  done
  for plist in \
    io.synergynetwork.archive-validator.plist \
    io.synergynetwork.archive-snapshot-api.plist \
    io.synergynetwork.archive-snapshot-worker.plist
  do
    launchctl bootstrap system "${LAUNCHD_ROOT}/${plist}"
    launchctl enable "system/${plist%.plist}"
  done
fi

echo "archive_validator_install_ok=true"
echo "workspace=${WORKSPACE}"
echo "publish_root=${PUBLISH_ROOT}"
echo "majority_proof_marker=${PROOF_MARKER}"
echo "next_action=sync archive node, preserve parity evidence, then run synergy-archive record-majority-proof before worker publication"
