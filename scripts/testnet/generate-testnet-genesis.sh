#!/usr/bin/env bash
set -euo pipefail

echo "This script is disabled. Testnet genesis must be produced by the canonical Synergy genesis ceremony and compiled with synergy-genesis." >&2
echo "Use the filled canonical genesis.json from the ceremony output. Do not generate a legacy local genesis template." >&2
exit 1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY_FILE="$ROOT_DIR/testnet/runtime/node-inventory.csv"
NODE_ADDRESSES_FILE="$ROOT_DIR/testnet/runtime/keys/node-addresses.csv"
OUTPUT_FILE="${1:-$ROOT_DIR/config/genesis.json}"

if [[ ! -f "$INVENTORY_FILE" ]]; then
  echo "Missing inventory file: $INVENTORY_FILE" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"

python3 - "$ROOT_DIR" "$INVENTORY_FILE" "$NODE_ADDRESSES_FILE" "$OUTPUT_FILE" <<'PY'
import csv
import json
import os
import sys
from pathlib import Path

root_dir, inventory_file, addresses_file, output_file = sys.argv[1:5]

chain_id = int(os.environ.get("TESTNET_CHAIN_ID", "1264"))
genesis_time = os.environ.get("TESTNET_GENESIS_TIME", "2026-01-01T00:00:00Z")
validator_stake = int(os.environ.get("TESTNET_VALIDATOR_STAKE", "50000000000000"))
validator_limit = int(os.environ.get("TESTNET_INITIAL_VALIDATOR_LIMIT", "4"))
minimum_stake_amount = int(os.environ.get("TESTNET_MIN_STAKE_AMOUNT", "5000000000000"))
burn_address = os.environ.get("TESTNET_BURN_ADDRESS", "synergy000000000000000000000000000000burn")

treasury_address = os.environ.get("TESTNET_TREASURY_ADDRESS", "synu1nd0fvzfhhj4s0te3ks06csfsnpg2hed8vsmh")
team_address = os.environ.get("TESTNET_TEAM_ADDRESS", "synw1pckkuqdeep4qz47ww9hnnm6uru2f9r6qtumv")
ecosystem_address = os.environ.get("TESTNET_ECOSYSTEM_ADDRESS", "synw1vkn2dq8mftcn7nkdhyv5t0jrv83thf0cakkj")
faucet_address = os.environ.get("TESTNET_FAUCET_ADDRESS", "synw1prdr55ggjhupx0d7jycftrl2hzs3k8zuw5ad")
public_sale_address = os.environ.get("TESTNET_PUBLIC_SALE_ADDRESS", "synw1f2kpjt9flxl6y4e3uez0zp3hjanamrlew5ja")
dao_address = os.environ.get("TESTNET_DAO_ADDRESS", "syndao1lf6q9zmfh4w4t30d04j05nmsku03te4685t5vn")

treasury_balance = int(os.environ.get("TESTNET_TREASURY_BALANCE", "400000000000000"))
team_balance = int(os.environ.get("TESTNET_TEAM_BALANCE", "150000000000000"))
ecosystem_balance = int(os.environ.get("TESTNET_ECOSYSTEM_BALANCE", "200000000000000"))
faucet_balance = int(os.environ.get("TESTNET_FAUCET_BALANCE", "100000000000000"))
public_sale_balance = int(os.environ.get("TESTNET_PUBLIC_SALE_BALANCE", "100000000000000"))

def parse_bool(raw: str) -> bool:
    value = (raw or "").strip().lower()
    return value in {"1", "true", "yes", "on"}

addresses = {}
if Path(addresses_file).is_file():
    with open(addresses_file, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            machine_id = row.get("machine_id", "").strip()
            address = row.get("address", "").strip()
            if machine_id and address:
                addresses[machine_id] = address
else:
    fallback_dir = Path(root_dir) / "config" / "genesis-validators"
    for index in range(1, validator_limit + 1):
        identity_path = fallback_dir / f"node-{index:02}.identity.json"
        if not identity_path.is_file():
            continue
        try:
            identity = json.loads(identity_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        address = str(identity.get("address") or "").strip()
        if address:
            addresses[f"machine-{index:02}"] = address

inventory_rows = []
with open(inventory_file, newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    for row in reader:
        inventory_rows.append(row)

bootnodes = [
    "snr://bootstrap@bootnode1.synergy-network.io:5620",
    "snr://bootstrap@bootnode2.synergy-network.io:5620",
    "snr://bootstrap@bootnode3.synergy-network.io:5620",
]

validator_rows = [
    row
    for row in inventory_rows
    if parse_bool(row.get("auto_register_validator", ""))
    and (row.get("role_group") or "").strip().lower() == "consensus"
    and (
        (row.get("node_type") or "").strip().lower() == "validator"
        or (row.get("role") or "").strip().lower() == "validator"
    )
][:validator_limit]
validators = []
validator_allocations = []
for index, row in enumerate(validator_rows, start=1):
    machine_id = row["machine_id"]
    address = addresses.get(machine_id)
    if not address:
        continue
    node_id = row.get("node_id", machine_id)
    validators.append(
        {
            "address": address,
            "public_key_file": f"config/genesis-validators/node-{index:02}.identity.json",
            "stake": str(validator_stake),
            "commission_rate": 0.05,
            "min_self_delegation": "1",
            "max_delegations": 1000,
            "details": {
                "name": f"Synergy Validator {index}",
                "identity": f"genesis-validator-{index}",
                "website": "https://synergy-network.io",
                "security_contact": "security@synergy-network.io",
                "class": int(row.get("address_class") or 1),
            },
        }
    )
    validator_allocations.append(
        {
            "type": "validator_wallet",
            "address": address,
            "balance": str(validator_stake),
            "stake": str(validator_stake),
            "description": f"Genesis allocation for Synergy Validator {index}",
        }
    )

genesis_allocations = [
    {
        "type": "treasury",
        "address": treasury_address,
        "balance": str(treasury_balance),
        "description": "Foundation/Treasury",
    },
    {
        "type": "team_wallet",
        "address": team_address,
        "balance": str(team_balance),
        "description": "Team",
    },
    {
        "type": "ecosystem_wallet",
        "address": ecosystem_address,
        "balance": str(ecosystem_balance),
        "description": "Ecosystem Development",
    },
    {
        "type": "faucet_wallet",
        "address": faucet_address,
        "balance": str(faucet_balance),
        "description": "Testnet Faucet Reserve",
    },
    {
        "type": "public_sale_wallet",
        "address": public_sale_address,
        "balance": str(public_sale_balance),
        "description": "Future Public Sale",
    },
]
genesis_allocations.extend(validator_allocations)

total_allocated = 0
for allocation in genesis_allocations:
    try:
        total_allocated += int(allocation.get("balance", "0"))
    except ValueError:
        pass

genesis = {
    "metadata": {
        "network_name": "Synergy Testnet",
        "network_id": "synergy-testnet",
        "genesis_time": genesis_time,
        "chain_id": str(chain_id),
        "version": "2.1.0-testnet",
        "description": "Non-authoritative checked-in Synergy Testnet genesis template. Replace with the signed ceremony output before launch.",
        "authority": "non-authoritative-template",
        "authoritative_launch_source": "genesis ceremony signed release output",
    },
    "consensus": {
        "algorithm": "PoSy",
        "version": "2.1",
        "parameters": {
            "block_time_ms": 2000,
            "epoch_length": 50,
            "min_validators": validator_limit,
            "max_validators": validator_limit,
            "quorum_threshold": 0.67,
            "min_stake_amount": str(minimum_stake_amount),
            "allow_zero_stake_validators": False,
            "dynamic_validator_registration": False,
            "slashing_conditions": {
                "double_sign_penalty": 1000000,
                "downtime_penalty": 100000,
                "max_missed_blocks": 10,
                "slashing_penalty": 100000,
            },
        },
    },
    "network": {
        "chain_id": chain_id,
        "rpc_endpoint": "https://testnet-core-rpc.synergy-network.io",
        "websocket_endpoint": "wss://testnet-core-ws.synergy-network.io",
        "api_endpoint": "https://testnet-api.synergy-network.io",
        "explorer_endpoint": "https://testnet-explorer.synergy-network.io",
        "rpc_port": 5640,
        "p2p_port": 5622,
        "websocket_port": 5660,
        "metrics_port": 6030,
        "bootnodes": bootnodes,
    },
    "supply": {
        "total_supply": str(total_allocated),
        "token_symbol": "SNRG",
        "token_name": "Synergy Token",
        "decimals": 9,
        "burn_address": burn_address,
    },
    "genesis_allocations": genesis_allocations,
    "validators": validators,
    "governance": {
        "dao_address": dao_address,
        "treasury_address": treasury_address,
        "proposal_deposit": "10000",
        "voting_period": 100,
        "execution_delay": 10,
        "quorum_percentage": 66.7,
        "pass_threshold": 51.0,
    },
    "cryptography": {
        "signature_algorithm": "FN-DSA-1024",
        "key_encapsulation": "ML-KEM-1024",
        "hash_algorithm": "SHA3-256",
        "address_encoding": "Bech32m",
        "security_level": "NIST Level 5",
    },
    "smart_contracts": {
        "aivm_enabled": True,
        "wasm_enabled": True,
        "max_gas_per_block": 100000000,
        "min_gas_price": 1,
    },
}

with open(output_file, "w", encoding="utf-8") as handle:
    json.dump(genesis, handle, indent=2)
    handle.write("\n")

print(f"Wrote genesis to {output_file}")
print(f"validators={len(validators)} bootnodes={len(bootnodes)}")
PY

echo "Genesis generation complete: $OUTPUT_FILE"
