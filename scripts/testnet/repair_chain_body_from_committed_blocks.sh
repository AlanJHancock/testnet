#!/usr/bin/env bash
set -euo pipefail

workspace="${SYNERGY_WORKSPACE:-$HOME/.synergy/testnet/nodes/validator-workspace}"
repair_log="${SYNERGY_COMMITTED_BLOCK_REPAIR_LOG:-$workspace/data/committed_blocks.jsonl}"

if [[ ! -d "$workspace" ]]; then
  echo "workspace not found: $workspace" >&2
  exit 2
fi
if [[ ! -f "$repair_log" ]]; then
  echo "committed block repair log not found: $repair_log" >&2
  exit 2
fi

cd "$workspace"

python3 - "$repair_log" <<'PY'
import json
import re
import shutil
import sys
import time
from pathlib import Path

repair_log = Path(sys.argv[1])
chain_path = Path("data/chain.json")
if not chain_path.exists():
    raise SystemExit(f"missing chain body: {chain_path}")

def tail_bytes(path: Path, size: int = 2 * 1024 * 1024) -> bytes:
    with path.open("rb") as handle:
        handle.seek(0, 2)
        length = handle.tell()
        handle.seek(max(0, length - size))
        return handle.read()

tail = tail_bytes(chain_path)
height_matches = re.findall(rb'"block_index"\s*:\s*(\d+)', tail)
if not height_matches:
    raise SystemExit("unable to read latest block_index from chain.json tail")
chain_tip_height = int(height_matches[-1])

entries = {}
with repair_log.open("r", encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, start=1):
        trimmed = line.strip()
        if not trimmed:
            continue
        entry = json.loads(trimmed)
        height = int(entry["height"])
        if height <= chain_tip_height:
            continue
        block = entry["block"]
        if int(block.get("block_index", -1)) != height:
            raise SystemExit(
                f"repair log line {line_number} height {height} does not match block_index"
            )
        if entry.get("hash") != block.get("hash"):
            raise SystemExit(f"repair log line {line_number} hash mismatch")
        entries.setdefault(height, block)

blocks = []
expected = chain_tip_height + 1
for height in sorted(entries):
    if height < expected:
        continue
    if height > expected:
        break
    blocks.append(entries[height])
    expected += 1

if not blocks:
    print(
        json.dumps(
            {
                "chain_body_repaired": False,
                "reason": "no contiguous committed blocks above tip",
                "chain_tip_height": chain_tip_height,
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0)

timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
backup_path = chain_path.with_name(f"chain.json.pre-body-repair-{timestamp}")
shutil.copy2(chain_path, backup_path)

with chain_path.open("r+b") as handle:
    handle.seek(0, 2)
    pos = handle.tell() - 1
    while pos >= 0:
        handle.seek(pos)
        byte = handle.read(1)
        if byte in b" \t\r\n":
            pos -= 1
            continue
        if byte != b"]":
            raise SystemExit("chain.json does not end with a JSON array close bracket")
        break
    if pos < 0:
        raise SystemExit("chain.json is empty")
    handle.truncate(pos)
    handle.write(b",")
    for index, block in enumerate(blocks):
        if index:
            handle.write(b",")
        handle.write(json.dumps(block, separators=(",", ":")).encode("utf-8"))
    handle.write(b"]\n")
    handle.flush()

new_tail = tail_bytes(chain_path)
new_heights = re.findall(rb'"block_index"\s*:\s*(\d+)', new_tail)
new_tip_height = int(new_heights[-1]) if new_heights else None
print(
    json.dumps(
        {
            "chain_body_repaired": True,
            "backup_path": str(backup_path),
            "old_tip_height": chain_tip_height,
            "new_tip_height": new_tip_height,
            "appended_blocks": len(blocks),
            "repair_log": str(repair_log),
        },
        sort_keys=True,
    )
)
PY
