#!/usr/bin/env bash
set -euo pipefail

node="${SYNERGY_NODE:-unknown-node}"
row="${SYNERGY_SPREADSHEET_ROW:-unknown-row}"
workspace="${SYNERGY_WORKSPACE:-}"
runtime="${SYNERGY_RUNTIME:-/tmp/synergy-testnet-linux-amd64.v13.0.1}"
runtime_sha="${SYNERGY_RUNTIME_SHA:-f5a1cf5b96bd647ba8bf32a6372858c2e7a0e7bc66d8d129ab65c7461314d9d1}"
start_after="${SYNERGY_START_AFTER:-true}"
binary_name="${SYNERGY_BINARY_NAME:-synergy-testnet-linux-amd64}"
listener_wait_secs="${SYNERGY_LISTENER_WAIT_SECS:-240}"
listener_poll_secs="${SYNERGY_LISTENER_POLL_SECS:-2}"
rollback_on_health_fail="${SYNERGY_ROLLBACK_ON_HEALTH_FAIL:-false}"
systemd_service="${SYNERGY_SYSTEMD_SERVICE:-}"

node_env_value() {
  local key="$1"
  local env_file="$workspace/node.env"
  [[ -f "$env_file" ]] || return 0
  awk -F= -v key="$key" '$1 == key {print substr($0, index($0, "=") + 1); exit}' "$env_file"
}

listener_present() {
  local port="$1"
  [[ -n "$port" ]] || return 1
  ss -ltn 2>/dev/null | awk -v suffix=":$port" '$4 ~ suffix "$" {found=1} END {exit found ? 0 : 1}'
}

workspace_processes() {
  local proc pid exe cwd cmd
  for proc in /proc/[0-9]*; do
    [[ -d "$proc" ]] || continue
    pid="${proc##*/}"
    exe="$(readlink "$proc/exe" 2>/dev/null || true)"
    cwd="$(readlink "$proc/cwd" 2>/dev/null || true)"
    cmd="$(tr '\0' ' ' < "$proc/cmdline" 2>/dev/null || true)"
    [[ -n "$cmd" ]] || continue
    if [[ "$exe" == "$workspace"/bin/* || "$cwd" == "$workspace" || "$cmd" == *"$workspace"* ]]; then
      if [[ "$cmd" == *" start --config "* || "$exe" == "$binary" ]]; then
        printf '%s\t%s\t%s\t%s\n' "$pid" "$exe" "$cwd" "$cmd"
      fi
    fi
  done
}

query_latest_block() {
  local port="$1"
  [[ -n "$port" ]] || return 1
  curl -fsS --max-time 5 \
    -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","id":1,"method":"synergy_getLatestBlock","params":[]}' \
    "http://127.0.0.1:${port}" >/dev/null
}

if [[ -z "$workspace" || ! -d "$workspace" ]]; then
  echo "unable to resolve workspace for $node" >&2
  exit 2
fi

binary="$workspace/bin/$binary_name"
qrpc_port="${SYNERGY_QRPC_PORT:-${SYNERGY_RPC_PORT:-${RPC_PORT:-$(node_env_value RPC_PORT)}}}"
ws_port="${SYNERGY_WS_PORT:-${WS_PORT:-$(node_env_value WS_PORT)}}"
p2p_port="${SYNERGY_P2P_PORT:-${P2P_PORT:-$(node_env_value P2P_PORT)}}"
metrics_port="${SYNERGY_METRICS_PORT:-${METRICS_PORT:-$(node_env_value METRICS_PORT)}}"
test -f "$runtime"
actual_runtime_sha="$(sha256sum "$runtime" | awk '{print $1}')"
if [[ "$actual_runtime_sha" != "$runtime_sha" ]]; then
  echo "runtime checksum mismatch: $actual_runtime_sha" >&2
  exit 3
fi
chmod 755 "$runtime" 2>/dev/null || true

ts="$(date -u +%Y%m%dT%H%M%SZ)"
backup_root="$HOME/synergy-testnet-state-backups"
backup="$backup_root/${ts}-${node// /_}-runtime"
mkdir -p "$backup/bin" "$backup/process" "$backup/logs" "$backup/listeners"

workspace_processes > "$backup/process/before.tsv" || true
ss -ltnp > "$backup/listeners/before.txt" 2>/dev/null || true
if [[ -f "$binary" ]]; then
  cp -p "$binary" "$backup/bin/synergy-testnet-linux-amd64"
  sha256sum "$binary" > "$backup/bin/synergy-testnet-linux-amd64.sha256"
fi
for log_file in "$workspace/data/logs/node.out" "$workspace/data/logs/node.err"; do
  if [[ -f "$log_file" ]]; then
    cp -p "$log_file" "$backup/logs/$(basename "$log_file").before"
  fi
done

if [[ -n "$systemd_service" ]] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop "$systemd_service" || true
elif [[ -x "$workspace/nodectl.sh" ]]; then
  (cd "$workspace" && ./nodectl.sh stop) || true
fi
while IFS=$'\t' read -r pid _exe _cwd _cmd; do
  [[ -n "${pid:-}" ]] || continue
  kill "$pid" 2>/dev/null || true
done < <(workspace_processes)
sleep 2
while IFS=$'\t' read -r pid _exe _cwd _cmd; do
  [[ -n "${pid:-}" ]] || continue
  kill -9 "$pid" 2>/dev/null || true
done < <(workspace_processes)

cp "$runtime" "$binary"
chmod 755 "$binary"
installed_sha="$(sha256sum "$binary" | awk '{print $1}')"
if [[ "$installed_sha" != "$runtime_sha" ]]; then
  echo "installed runtime checksum mismatch: $installed_sha" >&2
  exit 4
fi

if [[ "$start_after" == "true" ]]; then
  if [[ -n "$systemd_service" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl start "$systemd_service"
  elif [[ -x "$workspace/nodectl.sh" ]]; then
    (cd "$workspace" && ./nodectl.sh start)
  else
    mkdir -p "$workspace/logs"
    (cd "$workspace" && nohup "./bin/$binary_name" start --config config/node.toml >> logs/manual-v13-start.log 2>&1 &)
  fi
fi

health_ok=false
if [[ "$start_after" == "true" ]]; then
  deadline=$(( $(date +%s) + listener_wait_secs ))
  while [[ $(date +%s) -le $deadline ]]; do
    process_count="$(workspace_processes | wc -l | tr -d ' ')"
    if [[ "$process_count" != "0" ]] \
      && listener_present "$p2p_port" \
      && listener_present "$qrpc_port" \
      && listener_present "$ws_port" \
      && query_latest_block "$qrpc_port"; then
      health_ok=true
      break
    fi
    sleep "$listener_poll_secs"
  done
fi

workspace_processes > "$backup/process/after.tsv" || true
ss -ltnp > "$backup/listeners/after.txt" 2>/dev/null || true
for log_file in "$workspace/data/logs/node.out" "$workspace/data/logs/node.err"; do
  if [[ -f "$log_file" ]]; then
    cp -p "$log_file" "$backup/logs/$(basename "$log_file").after"
  fi
done

if [[ "$start_after" == "true" && "$health_ok" != "true" ]]; then
  if [[ "$rollback_on_health_fail" == "true" && -f "$backup/bin/synergy-testnet-linux-amd64" ]]; then
    if [[ -n "$systemd_service" ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl stop "$systemd_service" || true
    elif [[ -x "$workspace/nodectl.sh" ]]; then
      (cd "$workspace" && ./nodectl.sh stop) || true
    fi
    cp "$backup/bin/synergy-testnet-linux-amd64" "$binary"
    chmod 755 "$binary"
    if [[ -n "$systemd_service" ]] && command -v systemctl >/dev/null 2>&1; then
      systemctl start "$systemd_service" || true
    elif [[ -x "$workspace/nodectl.sh" ]]; then
      (cd "$workspace" && ./nodectl.sh start) || true
    fi
    echo "runtime health check failed; restored backup runtime from $backup" >&2
  else
    echo "runtime health check failed: p2p_port=$p2p_port qrpc_port=$qrpc_port ws_port=$ws_port wait_secs=$listener_wait_secs backup=$backup" >&2
  fi
  exit 5
fi

echo "spreadsheet_row_used=true row=$row node=$node workspace=$workspace binary=$binary_name backup=$backup installed_runtime_sha=$installed_sha start_after=$start_after health_ok=$health_ok p2p_port=$p2p_port qrpc_port=$qrpc_port ws_port=$ws_port metrics_port=$metrics_port systemd_service=$systemd_service"
