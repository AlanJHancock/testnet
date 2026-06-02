# Synergy Testnet wallet-pqc-cli team bundle

This bundle is self-contained for Synergy Testnet signing. It includes `wallet-pqc-cli` binaries and `synergy-testnet-tx.py`, which embeds shared Synergy Testnet Faucet, Token Sales, and Validator Rewards keys so teammates do not need separate key files.

Do not use this embedded-key pattern for mainnet or any wallet with real value.

## Network

- Network: Synergy Testnet
- Chain ID: `1264`
- RPC: `https://testnet-core-rpc.synergy-network.io`
- Atlas API: `https://testnet-atlas.synergy-network.io/api/v1`

Any `testbeta` endpoint is wrong for this package.

## Included platforms

- macOS Universal: `wallet-pqc-cli-macos-universal`
- macOS Apple Silicon: `wallet-pqc-cli-darwin-arm64`
- macOS Intel: `wallet-pqc-cli-darwin-x64`
- Linux x64: `wallet-pqc-cli-linux-x64`

Windows users can run the bundle through WSL with the included Linux x64 binary until a native Windows build is produced.

## Setup

From macOS, Linux, or WSL:

```bash


```

The helper auto-detects the right local `wallet-pqc-cli` binary. Override it only if needed:

```bash
SYNERGY_WALLET_CLI="/path/to/wallet-pqc-cli" python3 ./synergy-testnet-tx.py chain-id
```

## Transaction nonce mode

The helper defaults to `--nonce-mode zero` because the current Testnet validator runtime verifies externally signed Faucet, Token Sales, and Validator Rewards wallet transactions against imported wallet metadata. The traffic and validator funding commands automatically append unique memo data, so repeated zero-nonce test transactions still produce unique transaction hashes and commit correctly.

Use `--nonce-mode rpc` only after the validator runtime nonce tracker is updated to advance imported external wallet metadata on committed transactions.

## Query commands

```bash
python3 ./synergy-testnet-tx.py chain-id
python3 ./synergy-testnet-tx.py height
python3 ./synergy-testnet-tx.py latest-block
python3 ./synergy-testnet-tx.py status
python3 ./synergy-testnet-tx.py node-info
python3 ./synergy-testnet-tx.py network-stats
python3 ./synergy-testnet-tx.py validators
python3 ./synergy-testnet-tx.py peers
python3 ./synergy-testnet-tx.py atlas-dag --view status
python3 ./synergy-testnet-tx.py atlas-dag --view vertices --limit 25
python3 ./synergy-testnet-tx.py atlas-dag --view topology --limit 25
```

Wallet checks:

```bash
python3 ./synergy-testnet-tx.py preflight
python3 ./synergy-testnet-tx.py balance faucet
python3 ./synergy-testnet-tx.py balance token-sales
python3 ./synergy-testnet-tx.py balance validator-rewards
python3 ./synergy-testnet-tx.py nonce faucet
python3 ./synergy-testnet-tx.py nonce token-sales
python3 ./synergy-testnet-tx.py nonce validator-rewards
```

`preflight` prints public-key encoding, public-key fingerprint, address-derivation match, public RPC balance, and nonce without printing any private key. Before submitting a controlled probe, build and sign the exact transport envelope without broadcasting it:

```bash
python3 ./synergy-testnet-tx.py build-preview \
  --from token-sales \
  --to faucet \
  --amount-nwei 1
```

Transaction lookup:

```bash
python3 ./synergy-testnet-tx.py tx syntxn-replace-with-real-hash
python3 ./synergy-testnet-tx.py receipt syntxn-replace-with-real-hash
```

## Fund the Faucet wallet

The reset chain may start with the embedded Faucet wallet at `0` SNRG while Token Sales is funded from genesis. Seed Faucet before running Faucet-origin traffic:

```bash
python3 ./synergy-testnet-tx.py seed-faucet \
  --amount-snrg 1000 \
  --wait \
  --yes
```

## Send one signed transaction

From Faucet:

```bash
python3 ./synergy-testnet-tx.py send \
  --from faucet \
  --to synw1replacewithdestinationwallet \
  --amount-snrg 1 \
  --wait \
  --yes
```

From Token Sales:

```bash
python3 ./synergy-testnet-tx.py send \
  --from token-sales \
  --to synw1replacewithdestinationwallet \
  --amount-snrg 1 \
  --wait \
  --yes
```

Tiny smoke transaction:

```bash
python3 ./synergy-testnet-tx.py send \
  --from token-sales \
  --to faucet \
  --amount-nwei 1 \
  --wait \
  --yes
```

## Fund a new validator stake wallet

Use this command to send the required 50,000 SNRG stake amount from the embedded Validator Rewards wallet to a new validator address:

```bash
python3 ./synergy-testnet-tx.py fund-validator \
  --to synw1wkeaxhs5sm2hw8r6cmelacvky4a4jd7jns6y \
  --wait \
  --yes
```

The default amount is `50,000` SNRG. Override only when intentionally sending a different testnet stake grant:

```bash
python3 ./synergy-testnet-tx.py fund-validator \
  --to synw1jmtpyjw62nxgattrcjc2tx2hezwj6rka5war \
  --amount-snrg 50000 \
  --wait \
  --yes
```

## One-hour Faucet and Token Sales ping-pong

This sends 1 SNRG every 5 seconds for one hour, alternating directions.

```bash
python3 ./synergy-testnet-tx.py pingpong \
  --duration-seconds 3600 \
  --interval-seconds 5 \
  --amount-snrg 1 \
  --wait \
  --yes
```

Two-transaction smoke test:

```bash
python3 ./synergy-testnet-tx.py pingpong \
  --duration-seconds 10 \
  --interval-seconds 5 \
  --amount-nwei 1 \
  --max-transactions 2 \
  --wait \
  --yes
```

## Rapid-fire DAG stress traffic

Use `stress` for configurable duration-based transaction generation. The default amount is `1` nWei.

Short local smoke:

```bash
python3 ./synergy-testnet-tx.py stress \
  --senders token-sales \
  --receiver faucet \
  --duration-seconds 10 \
  --interval-seconds 0.5 \
  --amount-nwei 1 \
  --max-transactions 20 \
  --continue-on-error \
  --yes
```

Single-machine mixed-source run:

```bash
python3 ./synergy-testnet-tx.py stress \
  --senders faucet token-sales \
  --duration-seconds 300 \
  --interval-seconds 0.25 \
  --amount-nwei 1 \
  --continue-on-error \
  --yes
```

One-hour mixed-source run:

```bash
python3 ./synergy-testnet-tx.py stress \
  --senders faucet token-sales \
  --duration-seconds 3600 \
  --interval-seconds 0.25 \
  --amount-nwei 1 \
  --continue-on-error \
  --yes
```

Maximum-rate bounded run:

```bash
python3 ./synergy-testnet-tx.py stress \
  --senders token-sales \
  --receiver faucet \
  --interval-seconds 0 \
  --max-transactions 100 \
  --amount-nwei 1 \
  --continue-on-error \
  --yes
```

## Multi-machine traffic

The bundle is safe to run from multiple machines with the default `--nonce-mode zero`; each generated traffic transaction includes unique memo data to avoid duplicate hashes. Use one sender per machine when you want cleaner source attribution in Atlas and logs.

Machine A:

```bash
python3 ./synergy-testnet-tx.py stress \
  --senders token-sales \
  --receiver faucet \
  --duration-seconds 600 \
  --interval-seconds 0.25 \
  --amount-nwei 1 \
  --continue-on-error \
  --yes
```

Machine B:

```bash
python3 ./synergy-testnet-tx.py stress \
  --senders faucet \
  --receiver token-sales \
  --duration-seconds 600 \
  --interval-seconds 0.25 \
  --amount-nwei 1 \
  --continue-on-error \
  --yes
```

## Endpoint overrides

The default RPC and Atlas API are already TESTNET:

```bash
SYNERGY_RPC_URL="https://testnet-core-rpc.synergy-network.io" python3 ./synergy-testnet-tx.py height
SYNERGY_ATLAS_API_URL="https://testnet-atlas.synergy-network.io/api/v1" python3 ./synergy-testnet-tx.py atlas-dag --view status
```
