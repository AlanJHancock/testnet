#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
manual-snapshot-receiver.sh \
  --input <distribution-dir> \
  --snapshot-class <class> \
  --target-role <role> \
  --extract-root <dir> \
  --runtime <synergy-testnet-linux-amd64> \
  --source-workspace <node-workspace>
USAGE
}

input_dir=""
snapshot_class=""
target_role=""
extract_root=""
runtime=""
source_workspace=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) input_dir="$2"; shift 2 ;;
    --snapshot-class) snapshot_class="$2"; shift 2 ;;
    --target-role) target_role="$2"; shift 2 ;;
    --extract-root) extract_root="$2"; shift 2 ;;
    --runtime) runtime="$2"; shift 2 ;;
    --source-workspace) source_workspace="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$input_dir" || -z "$snapshot_class" || -z "$target_role" || -z "$extract_root" || -z "$runtime" || -z "$source_workspace" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -d "$input_dir" || ! -x "$runtime" || ! -d "$source_workspace/config" ]]; then
  echo "input directory, runtime, or source workspace is not accessible" >&2
  exit 3
fi

command -v zstd >/dev/null
command -v sha256sum >/dev/null

manifest="$input_dir/distribution-manifest.json"
if [[ ! -f "$manifest" ]]; then
  echo "missing distribution manifest: $manifest" >&2
  exit 4
fi

python3 - "$manifest" "$snapshot_class" "$target_role" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
expected_class = sys.argv[2]
target_role = sys.argv[3]
actual_class = manifest.get("snapshot_class")
allowed = manifest.get("allowed_restore_roles") or []
if actual_class != expected_class:
    raise SystemExit(f"snapshot class mismatch: expected {expected_class}, got {actual_class}")
if target_role not in allowed:
    raise SystemExit(f"target role {target_role} is not allowed by snapshot class {actual_class}: {allowed}")
if manifest.get("chain_id") != 1264:
    raise SystemExit("snapshot chain_id mismatch")
if manifest.get("network_id") != "synergy-testnet-v2":
    raise SystemExit("snapshot network_id mismatch")
if manifest.get("genesis_hash") != "f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789":
    raise SystemExit("snapshot genesis_hash mismatch")
if (manifest.get("qc_vote_count") or 0) < 4:
    raise SystemExit("snapshot QC vote count is below 4")
if not manifest.get("safety", {}).get("h175518_contamination_rejected"):
    raise SystemExit("snapshot does not assert h175518 contamination rejection")
print(json.dumps({
    "distribution_manifest_accepted": True,
    "snapshot_class": actual_class,
    "target_role": target_role,
    "snapshot_height": manifest.get("snapshot_height"),
    "snapshot_block_hash": manifest.get("snapshot_block_hash"),
}, sort_keys=True))
PY

snapshot_name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["snapshot_name"])' "$manifest")"
archive_name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["archive_name"])' "$manifest")"

(
  cd "$input_dir"
  sha256sum -c "${snapshot_name}.${snapshot_class}.chunks.sha256"
  cat "${archive_name}.part-"* > "$archive_name"
  sha256sum -c "${snapshot_name}.${snapshot_class}.tar.zst.sha256"
  zstd -t "$archive_name"
)

mkdir -p "$extract_root"
tar -I zstd -xf "$input_dir/$archive_name" -C "$extract_root"

snapshot_root="$extract_root/$snapshot_name"
snapshot_manifest="$(find "$snapshot_root" -maxdepth 1 -name '*manifest.json' | head -n 1)"
if [[ -z "$snapshot_manifest" ]]; then
  echo "missing signed snapshot manifest after extraction" >&2
  exit 5
fi

"$runtime" verify-snapshot \
  --chain-id 1264 \
  --network-id synergy-testnet-v2 \
  --genesis-hash f79011f2aaddd40b120d47ba723104fafe3c998d4a17097fae018914b95f1789 \
  --source-workspace "$source_workspace" \
  --manifest "$snapshot_manifest" \
  --snapshot-root "$snapshot_root" \
  --snapshot-class "$snapshot_class" \
  --target-role "$target_role" \
  > "$input_dir/receiver-verify-snapshot.json"

python3 - "$input_dir/receiver-verify-snapshot.json" <<'PY'
import json
import sys
from pathlib import Path

result = json.loads(Path(sys.argv[1]).read_text())
if result.get("success") is not True:
    raise SystemExit("receiver verify-snapshot did not report success=true")
PY

echo "snapshot_receiver_verified=true snapshot_root=$snapshot_root manifest=$snapshot_manifest"
