#!/usr/bin/env bash
set -euo pipefail

node="${SYNERGY_NODE:-unknown-node}"
row="${SYNERGY_SPREADSHEET_ROW:-unknown-row}"
workspace="${SYNERGY_WORKSPACE:-}"
runtime="${SYNERGY_RUNTIME:-/tmp/synergy-testnet-linux-amd64.v13.0.1}"
runtime_sha="${SYNERGY_RUNTIME_SHA:-f5a1cf5b96bd647ba8bf32a6372858c2e7a0e7bc66d8d129ab65c7461314d9d1}"
start_after="${SYNERGY_START_AFTER:-true}"
binary_name="${SYNERGY_BINARY_NAME:-synergy-testnet-linux-amd64}"

if [[ -z "$workspace" || ! -d "$workspace" ]]; then
  echo "unable to resolve workspace for $node" >&2
  exit 2
fi

binary="$workspace/bin/$binary_name"
test -f "$runtime"
actual_runtime_sha="$(sha256sum "$runtime" | awk '{print $1}')"
if [[ "$actual_runtime_sha" != "$runtime_sha" ]]; then
  echo "runtime checksum mismatch: $actual_runtime_sha" >&2
  exit 3
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
backup_root="$HOME/synergy-testnet-state-backups"
backup="$backup_root/${ts}-${node// /_}-runtime"
mkdir -p "$backup/bin" "$backup/process"

pgrep -af "synergy-testnet" > "$backup/process/before.txt" || true
if [[ -f "$binary" ]]; then
  cp -p "$binary" "$backup/bin/synergy-testnet-linux-amd64"
fi

if [[ -x "$workspace/nodectl.sh" ]]; then
  (cd "$workspace" && ./nodectl.sh stop) || true
fi
for pid in $(pgrep -f "$binary_name start --config" || true); do
  proc_cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
  proc_exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
  if [[ "$proc_cwd" == "$workspace" || "$proc_exe" == "$workspace"/bin/* ]]; then
    kill "$pid" 2>/dev/null || true
  fi
done
sleep 2
for pid in $(pgrep -f "$binary_name start --config" || true); do
  proc_cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
  proc_exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
  if [[ "$proc_cwd" == "$workspace" || "$proc_exe" == "$workspace"/bin/* ]]; then
    kill -9 "$pid" 2>/dev/null || true
  fi
done

cp -p "$runtime" "$binary"
chmod +x "$binary"
installed_sha="$(sha256sum "$binary" | awk '{print $1}')"
if [[ "$installed_sha" != "$runtime_sha" ]]; then
  echo "installed runtime checksum mismatch: $installed_sha" >&2
  exit 4
fi

if [[ "$start_after" == "true" ]]; then
  if [[ -x "$workspace/nodectl.sh" ]]; then
    (cd "$workspace" && ./nodectl.sh start)
  else
    mkdir -p "$workspace/logs"
    (cd "$workspace" && nohup "./bin/$binary_name" start --config config/node.toml >> logs/manual-v13-start.log 2>&1 &)
  fi
fi
sleep 2
pgrep -af "synergy-testnet" > "$backup/process/after.txt" || true

echo "spreadsheet_row_used=true row=$row node=$node workspace=$workspace binary=$binary_name backup=$backup installed_runtime_sha=$installed_sha start_after=$start_after"
