#!/usr/bin/env python3
"""Portable Synergy Testnet transaction helper with embedded testnet keys.

This file intentionally embeds the shared Faucet, Token Sales, and Validator
Rewards TESTNET keys.
Do not adapt this pattern for mainnet or any wallet with real value.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import platform
import math
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

DEFAULT_RPC_URL = "https://testnet-core-rpc.synergy-network.io"
DEFAULT_ATLAS_API_URL = "https://testnet-atlas.synergy-network.io/api/v1"
TESTNET_CHAIN_ID = 1264
TESTNET_TRANSACTION_NETWORK_ID = "synergy-testnet-v2"
NWEI_PER_SNRG = Decimal("1000000000")
DEFAULT_VALIDATOR_STAKE_SNRG = "50000"
DEFAULT_GAS_PRICE = 1000
DEFAULT_GAS_LIMIT = 21000
EMBEDDED_WALLETS = {
    "faucet": {
        "address": "synw1zp7cxme7xm838663yrd43lxtxlw0ck90z4am",
        "public_key": "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",
        "private_key": "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"
    },
    "token-sales": {
        "address": "synw17nh265ug2fgc8guv2ad7tt8kv0wlhesxndl8",
        "public_key": "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",
        "private_key": "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"
    },
    "validator-rewards": {
            "address": "synw1at607x35rkmsmvgz069nx0j3q5km93krrvge",
            "public_key": "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",
            "private_key": "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"
    }
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rpc_call(rpc_url: str, method: str, params: list, timeout: int = 25) -> dict:
    payload = json.dumps({"jsonrpc":"2.0","method":method,"params":params,"id":1}, separators=(",", ":")).encode()
    request = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        result = json.loads(response.read().decode())
    if result.get("error"):
        raise RuntimeError(result["error"].get("message") if isinstance(result["error"], dict) else str(result["error"]))
    return result


def http_get_json(url: str, timeout: int = 25) -> dict:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def wallet_label_or_address(value: str) -> str:
    return EMBEDDED_WALLETS.get(value, {"address": value})["address"]


def load_wallet(label: str) -> dict:
    if label not in EMBEDDED_WALLETS:
        raise ValueError(f"unknown embedded wallet {label!r}; use one of: {', '.join(sorted(EMBEDDED_WALLETS))}")
    wallet = dict(EMBEDDED_WALLETS[label])
    wallet["label"] = label
    wallet["private_key_hex"] = base64.b64decode(wallet["private_key"]).hex()
    wallet["public_key_hex"] = base64.b64decode(wallet["public_key"]).hex()
    return wallet


def format_snrg(nwei: int) -> str:
    value = Decimal(nwei) / NWEI_PER_SNRG
    text = f"{value:.9f}"
    return text.rstrip("0").rstrip(".") if "." in text else text


def amount_to_nwei(amount_snrg: str | None, amount_nwei: int | None) -> int:
    if amount_nwei is not None:
        if amount_nwei <= 0:
            raise ValueError("amount nWei must be positive")
        return amount_nwei
    if amount_snrg is None:
        amount_snrg = "1"
    try:
        amount = Decimal(amount_snrg)
    except InvalidOperation as exc:
        raise ValueError("amount SNRG must be a valid decimal") from exc
    if amount <= 0:
        raise ValueError("amount SNRG must be positive")
    nwei = amount * NWEI_PER_SNRG
    if nwei != nwei.to_integral_value():
        raise ValueError("amount SNRG supports no more than 9 decimal places")
    return int(nwei)


def resolve_wallet_cli(cli_arg: str | None = None) -> str:
    candidates = []
    if cli_arg:
        candidates.append(Path(cli_arg))
    if os.environ.get("SYNERGY_WALLET_CLI"):
        candidates.append(Path(os.environ["SYNERGY_WALLET_CLI"]))

    here = Path(__file__).resolve().parent
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin" and machine in ("arm64", "aarch64"):
        candidates.append(here / "wallet-pqc-cli-darwin-arm64")
        candidates.append(here / "wallet-pqc-cli-macos-universal")
    elif system == "darwin":
        candidates.append(here / "wallet-pqc-cli-darwin-x64")
        candidates.append(here / "wallet-pqc-cli-macos-universal")
    elif system == "linux" and machine in ("arm64", "aarch64"):
        candidates.append(here / "wallet-pqc-cli-linux-arm64")
    elif system == "linux":
        candidates.append(here / "wallet-pqc-cli-linux-x64")
    elif system == "windows":
        candidates.append(here / "wallet-pqc-cli-windows-x64.exe")

    candidates.append(here / "wallet-pqc-cli")
    found = shutil.which("wallet-pqc-cli")
    if found:
        candidates.append(Path(found))

    for candidate in candidates:
        if candidate.is_file():
            if system != "windows":
                candidate.chmod(candidate.stat().st_mode | stat.S_IXUSR)
            return str(candidate)
    searched = "\\n  ".join(str(c) for c in candidates)
    raise FileNotFoundError(f"wallet-pqc-cli was not found. Searched:\\n  {searched}")


def build_unsigned_tx(sender: dict, receiver: str, amount_nwei: int, nonce: int, gas_price: int, gas_limit: int, algo: str, data: str | None = None) -> dict:
    return {
        "chain_id": TESTNET_CHAIN_ID,
        "network_id": TESTNET_TRANSACTION_NETWORK_ID,
        "sender": sender["address"],
        "receiver": receiver,
        "amount": amount_nwei,
        "nonce": nonce,
        "signature": [],
        "timestamp": int(time.time()),
        "gas_price": gas_price,
        "gas_limit": gas_limit,
        "data": data,
        "signature_algorithm": algo,
    }


def sign_tx(wallet_cli: str, sender: dict, tx: dict, algo: str) -> dict:
    proc = subprocess.run(
        [wallet_cli, "sign-tx", "--private-key", sender["private_key_hex"], "--tx", json.dumps(tx, separators=(",", ":")), "--algo", algo],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "wallet-pqc-cli sign-tx failed")
    signed = json.loads(proc.stdout)["transaction"]
    signed["chain_id"] = TESTNET_CHAIN_ID
    signed["network_id"] = TESTNET_TRANSACTION_NETWORK_ID
    signed["chainId"] = TESTNET_CHAIN_ID
    signed["networkId"] = TESTNET_TRANSACTION_NETWORK_ID
    signed["signer_public_key"] = sender["public_key_hex"]
    signed["signerPublicKey"] = sender["public_key_hex"]
    return signed


def submit_tx(rpc_url: str, signed_tx: dict) -> tuple[str, dict]:
    response = rpc_call(rpc_url, "synergy_sendTransaction", [signed_tx])
    result = response.get("result")
    if isinstance(result, dict) and result.get("success") is False:
        raise RuntimeError(str(result.get("error") or result))
    if isinstance(result, str):
        return result, response
    if isinstance(result, dict):
        return str(result.get("tx_hash") or result.get("hash") or ""), response
    return "", response


def wait_for_receipt(rpc_url: str, tx_hash: str, timeout_seconds: int = 60) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            receipt = rpc_call(rpc_url, "synergy_getTransactionReceipt", [tx_hash], timeout=10).get("result")
            if receipt:
                return True
        except Exception:
            pass
        try:
            tx = rpc_call(rpc_url, "synergy_getTransactionByHash", [tx_hash], timeout=10).get("result")
            if isinstance(tx, dict):
                status = str(tx.get("status") or "").lower()
                if status in {"confirmed", "finalized", "committed"}:
                    return True
                if tx.get("block_number") is not None or tx.get("blockNumber") is not None:
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False


def confirm_or_exit(args: argparse.Namespace, message: str) -> None:
    if getattr(args, "yes", False):
        return
    print(message)
    answer = input("Type yes to continue: ").strip()
    if answer != "yes":
        raise SystemExit("Cancelled. No transaction was submitted.")


class NonceTracker:
    def __init__(self, rpc_url: str, mode: str = "zero") -> None:
        self.rpc_url = rpc_url
        self.mode = mode
        self.next_by_sender: dict[str, int] = {}

    def next_nonce(self, sender_label: str, sender_address: str) -> int:
        if self.mode == "zero":
            return 0
        if sender_label not in self.next_by_sender:
            self.next_by_sender[sender_label] = int(
                rpc_call(self.rpc_url, "synergy_getAccountNonce", [sender_address])["result"] or 0
            )
        nonce = self.next_by_sender[sender_label]
        self.next_by_sender[sender_label] = nonce + 1
        return nonce


def command_list_wallets(_args: argparse.Namespace) -> int:
    for label, wallet in EMBEDDED_WALLETS.items():
        print(f"{label} {wallet['address']}")
    return 0


def command_chain_id(args: argparse.Namespace) -> int:
    reported = None
    node_info = None
    try:
        node_info = rpc_call(args.rpc_url, "synergy_nodeInfo", [])["result"]
        if isinstance(node_info, dict):
            reported = node_info.get("chainId") or node_info.get("chain_id") or node_info.get("networkId") or node_info.get("network_id")
    except Exception as exc:
        node_info = {"error": str(exc)}
    print_json({
        "expectedTestnetChainId": TESTNET_CHAIN_ID,
        "rpcUrl": args.rpc_url,
        "rpcReportedChainId": reported,
        "nodeInfo": node_info,
    })
    return 0


def command_height(args: argparse.Namespace) -> int:
    print(rpc_call(args.rpc_url, "synergy_blockNumber", [])["result"])
    return 0


def command_latest_block(args: argparse.Namespace) -> int:
    print_json(rpc_call(args.rpc_url, "synergy_getLatestBlock", [])["result"])
    return 0


def command_status(args: argparse.Namespace) -> int:
    print_json(rpc_call(args.rpc_url, "synergy_getNodeStatus", [])["result"])
    return 0


def command_node_info(args: argparse.Namespace) -> int:
    print_json(rpc_call(args.rpc_url, "synergy_nodeInfo", [])["result"])
    return 0


def command_network_stats(args: argparse.Namespace) -> int:
    print_json(rpc_call(args.rpc_url, "synergy_getNetworkStats", [])["result"])
    return 0


def command_validators(args: argparse.Namespace) -> int:
    for method in ("synergy_getValidatorActivity", "synergy_getValidators"):
        try:
            print_json(rpc_call(args.rpc_url, method, [])["result"])
            return 0
        except Exception:
            continue
    raise RuntimeError("validator query failed: synergy_getValidatorActivity and synergy_getValidators were unavailable")


def command_peers(args: argparse.Namespace) -> int:
    print_json(rpc_call(args.rpc_url, "synergy_getPeerInfo", [])["result"])
    return 0


def command_balance(args: argparse.Namespace) -> int:
    address = wallet_label_or_address(args.wallet_or_address)
    result = int(rpc_call(args.rpc_url, "synergy_getTokenBalance", [address, "SNRG"])["result"] or 0)
    print(f"{address} {format_snrg(result)} SNRG ({result} nWei)")
    return 0


def command_nonce(args: argparse.Namespace) -> int:
    address = wallet_label_or_address(args.wallet_or_address)
    print(rpc_call(args.rpc_url, "synergy_getAccountNonce", [address])["result"])
    return 0


def command_tx(args: argparse.Namespace) -> int:
    print_json(rpc_call(args.rpc_url, "synergy_getTransactionByHash", [args.tx_hash])["result"])
    return 0


def command_receipt(args: argparse.Namespace) -> int:
    print_json(rpc_call(args.rpc_url, "synergy_getTransactionReceipt", [args.tx_hash])["result"])
    return 0


def command_atlas_dag(args: argparse.Namespace) -> int:
    base = args.atlas_api_url.rstrip("/")
    if args.view == "status":
        url = f"{base}/dag/status"
    elif args.view == "frontier":
        url = f"{base}/dag/frontier"
    elif args.view == "vertices":
        url = f"{base}/dag/vertices?limit={args.limit}"
    else:
        url = f"{base}/dag/topology?limit={args.limit}"
    print_json(http_get_json(url))
    return 0


def send_once(args: argparse.Namespace, sender_label: str, receiver: str, amount_nwei: int, nonce_tracker: NonceTracker | None = None) -> str:
    sender = load_wallet(sender_label)
    wallet_cli = resolve_wallet_cli(args.wallet_cli)
    tracker = nonce_tracker or NonceTracker(args.rpc_url, args.nonce_mode)
    nonce = tracker.next_nonce(sender_label, sender["address"])
    data = getattr(args, "data", None)
    if getattr(args, "unique_data", False):
        unique = f"testnet-traffic:{utc_now()}:{time.time_ns()}:{sender_label}:{receiver}"
        data = f"{data}|{unique}" if data else unique
    tx = build_unsigned_tx(sender, receiver, amount_nwei, nonce, args.gas_price, args.gas_limit, args.algo, data=data)
    signed = sign_tx(wallet_cli, sender, tx, args.algo)
    tx_hash, _response = submit_tx(args.rpc_url, signed)
    print(f"[{utc_now()}] OK {sender_label} -> {receiver} nonce={nonce} tx={tx_hash}")
    if args.wait:
        print(f"[{utc_now()}] receipt tx={tx_hash} confirmed={str(wait_for_receipt(args.rpc_url, tx_hash, args.receipt_timeout_seconds)).lower()}")
    return tx_hash


def default_receiver_for_sender(sender_label: str, senders: list[str], sender_index: int, explicit_receiver: str | None = None) -> str:
    if explicit_receiver:
        return wallet_label_or_address(explicit_receiver)
    if len(senders) > 1:
        return EMBEDDED_WALLETS[senders[(sender_index + 1) % len(senders)]]["address"]
    if sender_label == "faucet":
        return EMBEDDED_WALLETS["token-sales"]["address"]
    return EMBEDDED_WALLETS["faucet"]["address"]


def run_transfer_loop(args: argparse.Namespace, plan: list[tuple[str, str]], amount_nwei: int, interval_seconds: float, nonce_tracker: NonceTracker) -> tuple[int, int]:
    sent = 0
    errors = 0
    start = time.monotonic()
    for index, (sender_label, receiver) in enumerate(plan):
        target = start + (index * interval_seconds)
        if target > time.monotonic():
            time.sleep(target - time.monotonic())
        try:
            send_once(args, sender_label, receiver, amount_nwei, nonce_tracker=nonce_tracker)
            sent += 1
        except Exception as exc:
            errors += 1
            print(f"[{utc_now()}] ERROR {sender_label} -> {receiver}: {exc}", file=sys.stderr)
            if not args.continue_on_error:
                raise
    return sent, errors


def command_send(args: argparse.Namespace) -> int:
    receiver = wallet_label_or_address(args.to)
    amount_nwei = amount_to_nwei(args.amount_snrg, args.amount_nwei)
    confirm_or_exit(args, f"Send {format_snrg(amount_nwei)} SNRG from {args.from_wallet} to {receiver} on Synergy Testnet.")
    send_once(args, args.from_wallet, receiver, amount_nwei)
    return 0


def command_seed_faucet(args: argparse.Namespace) -> int:
    receiver = EMBEDDED_WALLETS["faucet"]["address"]
    amount_nwei = amount_to_nwei(args.amount_snrg, args.amount_nwei)
    confirm_or_exit(args, f"Seed Faucet wallet with {format_snrg(amount_nwei)} SNRG from token-sales on Synergy Testnet.")
    send_once(args, "token-sales", receiver, amount_nwei)
    return 0


def command_fund_validator(args: argparse.Namespace) -> int:
    receiver = wallet_label_or_address(args.to)
    amount_nwei = amount_to_nwei(args.amount_snrg, args.amount_nwei)
    confirm_or_exit(
        args,
        f"Send {format_snrg(amount_nwei)} SNRG from validator-rewards to {receiver} on Synergy Testnet for validator staking."
    )
    args.unique_data = True
    send_once(args, "validator-rewards", receiver, amount_nwei)
    return 0


def command_pingpong(args: argparse.Namespace) -> int:
    amount_nwei = amount_to_nwei(args.amount_snrg, args.amount_nwei)
    if args.duration_seconds <= 0:
        raise ValueError("duration must be positive")
    if args.interval_seconds <= 0:
        raise ValueError("pingpong interval must be greater than zero")
    total = max(1, math.ceil(args.duration_seconds / args.interval_seconds))
    if args.max_transactions is not None:
        total = min(total, args.max_transactions)
    confirm_or_exit(args, f"Run {total} alternating transfers of {format_snrg(amount_nwei)} SNRG every {args.interval_seconds} seconds.")
    labels = ["faucet", "token-sales"]
    plan = []
    for index in range(total):
        sender_label = labels[index % 2]
        receiver_label = labels[(index + 1) % 2]
        plan.append((sender_label, EMBEDDED_WALLETS[receiver_label]["address"]))
    args.unique_data = True
    sent, errors = run_transfer_loop(args, plan, amount_nwei, args.interval_seconds, NonceTracker(args.rpc_url, args.nonce_mode))
    print(f"[{utc_now()}] complete sent={sent} errors={errors}")
    return 0


def command_burst(args: argparse.Namespace) -> int:
    amount_nwei = amount_to_nwei(args.amount_snrg, args.amount_nwei)
    senders = args.senders or ["faucet", "token-sales"]
    if args.tx_per_sender <= 0:
        raise ValueError("tx-per-sender must be positive")
    if args.interval_seconds < 0:
        raise ValueError("interval must not be negative")
    total = len(senders) * args.tx_per_sender
    confirm_or_exit(args, f"Run {total} signed burst transactions of {format_snrg(amount_nwei)} SNRG.")
    plan = []
    for seq in range(args.tx_per_sender):
        for idx, sender_label in enumerate(senders):
            receiver = default_receiver_for_sender(sender_label, senders, idx, args.receiver)
            plan.append((sender_label, receiver))
    args.unique_data = True
    sent, errors = run_transfer_loop(args, plan, amount_nwei, args.interval_seconds, NonceTracker(args.rpc_url, args.nonce_mode))
    print(f"[{utc_now()}] complete sent={sent} errors={errors}")
    return 0


def command_stress(args: argparse.Namespace) -> int:
    amount_nwei = amount_to_nwei(args.amount_snrg, args.amount_nwei)
    senders = args.senders or ["faucet", "token-sales"]
    interval = args.interval_seconds
    if args.duration_seconds <= 0:
        raise ValueError("duration must be positive")
    if interval < 0:
        raise ValueError("interval must not be negative")
    if interval == 0:
        if args.max_transactions is None:
            raise ValueError("interval 0 requires --max-transactions")
        total = args.max_transactions
    else:
        total = max(1, math.ceil(args.duration_seconds / interval))
    if args.max_transactions is not None and interval != 0:
        total = min(total, args.max_transactions)
    if total <= 0:
        raise ValueError("max-transactions must be positive")
    plan = []
    for index in range(total):
        sender_index = index % len(senders)
        sender_label = senders[sender_index]
        receiver = default_receiver_for_sender(sender_label, senders, sender_index, args.receiver)
        plan.append((sender_label, receiver))
    confirm_or_exit(
        args,
        f"Stress run on chain {TESTNET_CHAIN_ID}: {total} signed transactions over {args.duration_seconds} seconds, "
        f"interval={interval}, amount={format_snrg(amount_nwei)} SNRG."
    )
    args.unique_data = True
    sent, errors = run_transfer_loop(args, plan, amount_nwei, interval, NonceTracker(args.rpc_url, args.nonce_mode))
    print(f"[{utc_now()}] stress complete chain_id={TESTNET_CHAIN_ID} sent={sent} errors={errors}")
    return 0


def add_common_tx_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    parser.add_argument("--wallet-cli", default=None)
    parser.add_argument("--algo", choices=["fndsa", "mldsa", "slhdsa"], default="fndsa")
    parser.add_argument("--gas-price", type=int, default=DEFAULT_GAS_PRICE)
    parser.add_argument("--gas-limit", type=int, default=DEFAULT_GAS_LIMIT)
    parser.add_argument("--nonce-mode", choices=["zero", "rpc"], default=os.environ.get("SYNERGY_NONCE_MODE", "zero"))
    parser.add_argument("--data", default=None, help="Optional transaction data/memo string")
    parser.add_argument("--unique-data", action="store_true", help="Append a unique testnet memo so repeated sends have unique hashes")
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--receipt-timeout-seconds", type=int, default=60)
    parser.add_argument("--continue-on-error", action="store_true")
    parser.add_argument("--yes", action="store_true")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Portable Synergy Testnet helper with embedded testnet signing keys.")
    parser.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL), help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list-wallets", help="List embedded testnet wallet aliases and addresses")
    p.set_defaults(func=command_list_wallets)

    p = sub.add_parser("chain-id", help="Print expected Testnet chain ID and RPC-reported node info")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_chain_id)

    p = sub.add_parser("height", help="Print current block height")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_height)

    p = sub.add_parser("latest-block", help="Print latest block JSON")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_latest_block)

    p = sub.add_parser("status", help="Print node status JSON")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_status)

    p = sub.add_parser("node-info", help="Print node info JSON")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_node_info)

    p = sub.add_parser("network-stats", help="Print network statistics JSON")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_network_stats)

    p = sub.add_parser("validators", help="Print validator activity JSON")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_validators)

    p = sub.add_parser("peers", help="Print peer information JSON")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_peers)

    p = sub.add_parser("balance", help="Print SNRG balance for an embedded wallet alias or address")
    p.add_argument("wallet_or_address")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_balance)

    p = sub.add_parser("nonce", help="Print account nonce for an embedded wallet alias or address")
    p.add_argument("wallet_or_address")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_nonce)

    p = sub.add_parser("tx", help="Look up a transaction by hash")
    p.add_argument("tx_hash")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_tx)

    p = sub.add_parser("receipt", help="Look up a transaction receipt by hash")
    p.add_argument("tx_hash")
    p.add_argument("--rpc-url", default=os.environ.get("SYNERGY_RPC_URL", DEFAULT_RPC_URL))
    p.set_defaults(func=command_receipt)

    p = sub.add_parser("atlas-dag", help="Query Atlas DAG API status, frontier, vertices, or topology")
    p.add_argument("--atlas-api-url", default=os.environ.get("SYNERGY_ATLAS_API_URL", DEFAULT_ATLAS_API_URL))
    p.add_argument("--view", choices=["status", "frontier", "vertices", "topology"], default="status")
    p.add_argument("--limit", type=int, default=25)
    p.set_defaults(func=command_atlas_dag)

    p = sub.add_parser("send", help="Sign and submit one native SNRG transfer")
    p.add_argument("--from", dest="from_wallet", choices=sorted(EMBEDDED_WALLETS), required=True)
    p.add_argument("--to", required=True, help="Recipient address, faucet, or token-sales")
    p.add_argument("--amount-snrg", default="1")
    p.add_argument("--amount-nwei", type=int, default=None)
    add_common_tx_args(p)
    p.set_defaults(func=command_send)

    p = sub.add_parser("seed-faucet", help="Fund the embedded Faucet wallet from the embedded Token Sales wallet")
    p.add_argument("--amount-snrg", default="1000")
    p.add_argument("--amount-nwei", type=int, default=None)
    add_common_tx_args(p)
    p.set_defaults(func=command_seed_faucet)

    p = sub.add_parser("fund-validator", help="Send the default 50,000 SNRG stake grant from validator-rewards")
    p.add_argument("--to", required=True, help="New validator wallet/address to fund")
    p.add_argument("--amount-snrg", default=DEFAULT_VALIDATOR_STAKE_SNRG)
    p.add_argument("--amount-nwei", type=int, default=None)
    add_common_tx_args(p)
    p.set_defaults(func=command_fund_validator)

    p = sub.add_parser("pingpong", help="Alternate faucet <-> token-sales transfers")
    p.add_argument("--duration-seconds", type=float, default=3600.0)
    p.add_argument("--interval-seconds", type=float, default=5.0)
    p.add_argument("--amount-snrg", default="1")
    p.add_argument("--amount-nwei", type=int, default=None)
    p.add_argument("--max-transactions", type=int, default=None)
    add_common_tx_args(p)
    p.set_defaults(func=command_pingpong)

    p = sub.add_parser("burst", help="Send repeated signed transactions from embedded wallets")
    p.add_argument("--senders", nargs="+", choices=sorted(EMBEDDED_WALLETS), default=None)
    p.add_argument("--receiver", default=None, help="Receiver address/alias. Defaults to ring routing among senders.")
    p.add_argument("--tx-per-sender", type=int, default=3)
    p.add_argument("--interval-seconds", type=float, default=1.0)
    p.add_argument("--amount-snrg", default=None)
    p.add_argument("--amount-nwei", type=int, default=1)
    add_common_tx_args(p)
    p.set_defaults(func=command_burst)

    p = sub.add_parser("stress", help="Rapid-fire signed transfers for a configurable duration")
    p.add_argument("--senders", nargs="+", choices=sorted(EMBEDDED_WALLETS), default=None)
    p.add_argument("--receiver", default=None, help="Receiver address/alias. Defaults to ring routing among senders.")
    p.add_argument("--duration-seconds", type=float, default=60.0)
    p.add_argument("--interval-seconds", type=float, default=0.25)
    p.add_argument("--amount-snrg", default=None)
    p.add_argument("--amount-nwei", type=int, default=1)
    p.add_argument("--max-transactions", type=int, default=None)
    add_common_tx_args(p)
    p.set_defaults(func=command_stress)

    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print(f"\\n[{utc_now()}] interrupted", file=sys.stderr)
        raise SystemExit(130)
