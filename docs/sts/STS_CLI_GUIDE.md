# STS CLI Guide

`synergy-sts` is the dedicated command-line tool for building Synergy Token System payloads on testnet.

Current scope in this branch:

- Native SNRG identity inspection.
- Fungible token payloads for `synb1`, `synb2`, and `synb3`.
- Payload decode and gas/fee estimation.
- Metadata-file hashing with SHA3-256.
- Output artifacts for later signing and transaction submission.

The CLI does not mutate chain state by itself. It builds deterministic STS payload bytes that must be wrapped in a signed Synergy transaction and submitted through the normal transaction path.

## Install From GitHub Releases

The supported user install path is the dedicated CLI release repository:

[synergy-network-hq/synergy-sts-cli-releases](https://github.com/synergy-network-hq/synergy-sts-cli-releases)

macOS and Linux users can install the latest released CLI with:

```bash
curl -fsSL https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/latest/download/install-synergy-sts.sh | bash
```

The installer detects the local platform and downloads the matching binary:

- `synergy-sts-linux-amd64`
- `synergy-sts-linux-arm64`
- `synergy-sts-macos-amd64`
- `synergy-sts-macos-arm64`

By default the binary is installed to:

```text
$HOME/.local/bin/synergy-sts
```

Install a specific release tag:

```bash
curl -fsSL https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/latest/download/install-synergy-sts.sh \
  | bash -s -- --version synergy-sts-v15.0.6
```

Install to a different directory:

```bash
curl -fsSL https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/latest/download/install-synergy-sts.sh \
  | bash -s -- --install-dir /usr/local/bin
```

Add the install directory to your shell profile when needed:

```bash
curl -fsSL https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/latest/download/install-synergy-sts.sh \
  | bash -s -- --add-to-path
```

Verify installation:

```bash
synergy-sts version
synergy-sts native-info
```

The installer verifies release `.sha256` checksums by default. Advanced users can install a pinned binary URL with an expected hash:

```bash
./install-synergy-sts.sh \
  --url https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/download/synergy-sts-v15.0.6/synergy-sts-linux-amd64 \
  --sha256 <expected_sha256>
```

## Install From Source

From the testnet runtime repository:

```bash
cd /Volumes/xcode/Synergy-Network-Projects/network-components/01-Testnet/synergy-testnet
cargo build -p synergy-testnet --bin synergy-sts --release
```

Install the binary somewhere on your `PATH`:

```bash
mkdir -p "$HOME/.local/bin"
cp target/release/synergy-sts "$HOME/.local/bin/synergy-sts"
chmod 755 "$HOME/.local/bin/synergy-sts"
```

Verify installation:

```bash
synergy-sts version
synergy-sts native-info
```

For local development without installing:

```bash
cargo run -p synergy-testnet --bin synergy-sts -- native-info
```

## Native SNRG Address Rule

Native SNRG is the gas and fee asset. It is not an STS object and has no canonical token address.

`synergy-sts native-info` returns:

```json
{
  "symbol": "SNRG",
  "token_address": null,
  "compatibility_placeholder_address": "00000000000000000000000000000000000000000"
}
```

The 41-zero value is only for string-only compatibility surfaces. It is not a token contract, not an STS object ID, and not a signable address.

Every non-native STS token has a deterministic Bech32m token address. For fungible tokens, `expected_token_address` equals `expected_token_id` and starts with the class prefix:

- `synb1` for B1 basic fungible tokens.
- `synb2` for B2 managed fungible tokens.
- `synb3` for B3 policy fungible tokens.

## Payload Lifecycle

STS write commands produce a review artifact:

- `payload_hex`: hex-encoded STS payload bytes with the `synergy-sts-v1:` prefix.
- `payload`: the decoded payload JSON.
- `estimated_gas`: STS operation gas estimate.
- `estimated_fee_nwei`: `estimated_gas * gas_price_nwei`.
- `expected_token_id`: creation-only deterministic token ID.
- `expected_token_address`: creation-only non-native token address.

Recommended workflow:

1. Build a payload with `synergy-sts`.
2. Save the artifact with `--out`.
3. Review or decode it with `synergy-sts decode`.
4. Estimate gas with `synergy-sts estimate`.
5. Wrap `payload_hex` in the canonical signed transaction format.
6. Submit the signed transaction to testnet.
7. Query RPC/Atlas after finality.

## Output Modes

All payload-producing commands support:

```bash
--output json
--output compact-json
--output payload-hex
--output payload-json
--out ./artifact.json
```

Examples:

```bash
synergy-sts token create ... --output json --out ./tgld-create.json
synergy-sts token transfer ... --output payload-hex --out ./transfer.payload.hex
```

If `--out` is provided, the CLI writes the selected output to the file and also prints it to stdout.

## Decode And Estimate

Decode an artifact JSON file:

```bash
synergy-sts decode --file ./tgld-create.json
```

Decode raw payload hex:

```bash
synergy-sts decode --payload-hex "$(cat ./transfer.payload.hex)"
```

Estimate gas and fee with the default 40 nWei gas price:

```bash
synergy-sts estimate --file ./tgld-create.json
```

Estimate with an explicit gas price:

```bash
synergy-sts estimate --file ./tgld-create.json --gas-price-nwei 50
```

## Metadata Files

The CLI can hash a metadata file:

```bash
synergy-sts token create \
  --network testnet \
  --class b1 \
  --name "Testnet Gold" \
  --symbol TGLD \
  --decimals 9 \
  --initial-supply 1000000000000000 \
  --metadata-uri ipfs://bafy.../metadata.json \
  --metadata-file ./metadata.json \
  --from synw1... \
  --creator-nonce 1
```

Rules:

- Hash algorithm is SHA3-256.
- The emitted hash is lowercase hex without `0x`.
- If both `--metadata-file` and `--metadata-hash` are supplied, they must match.
- A metadata URI requires a metadata hash.
- Amounts are integer base units. The CLI does not accept floating-point token amounts.

## Create B1 Token

B1 is the basic fungible class. It does not allow freeze, pause, clawback, allowlist, denylist, or transfer approval flags.

```bash
synergy-sts token create \
  --network testnet \
  --class b1 \
  --name "Testnet Gold" \
  --symbol TGLD \
  --decimals 9 \
  --initial-supply 1000000000000000 \
  --max-supply 1000000000000000 \
  --metadata-uri ipfs://tgld \
  --metadata-hash aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --from synw1testcreator000000000000000000000000 \
  --creator-nonce 1 \
  --created-at 1700000000 \
  --out ./tgld-create.json
```

The output includes:

```json
{
  "expected_token_id": "synb1...",
  "expected_token_address": "synb1...",
  "native_snrg_token_address": null,
  "payload_hex": "73796e657267792d7374732d76313a..."
}
```

## Create B2 Managed Token

B2 allows managed issuer powers, but dangerous powers must be declared at creation.

```bash
synergy-sts token create \
  --network testnet \
  --class b2 \
  --name "Managed USD" \
  --symbol MUSD \
  --decimals 6 \
  --initial-supply 1000000000000 \
  --max-supply 1000000000000 \
  --metadata-uri ipfs://musd \
  --metadata-hash bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --from synw1issuer0000000000000000000000000000 \
  --creator-nonce 2 \
  --can-freeze \
  --can-pause \
  --can-clawback \
  --metadata-mutable \
  --out ./musd-create.json
```

B2 control commands require a `synb2...` token ID:

```bash
synergy-sts token freeze --network testnet --token synb2... --owner synw1... --from synw1...
synergy-sts token thaw --network testnet --token synb2... --owner synw1... --from synw1...
synergy-sts token pause --network testnet --token synb2... --from synw1...
synergy-sts token unpause --network testnet --token synb2... --from synw1...
synergy-sts token clawback --network testnet --token synb2... --source synw1... --to synw1... --amount 1000 --from synw1...
```

## Create B3 Policy Token

B3 supports approved native policy templates. Current implemented templates:

- `transfer_fee_v1`
- `snapshot_v1`
- `vesting_v1`
- `max_wallet_v1`

Unsupported policy templates fail closed.

```bash
synergy-sts token create \
  --network testnet \
  --class b3 \
  --name "Governance Token" \
  --symbol GOV \
  --decimals 9 \
  --initial-supply 100000000000000000 \
  --metadata-uri ipfs://gov \
  --metadata-hash cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc \
  --from synw1issuer0000000000000000000000000000 \
  --creator-nonce 3 \
  --policy snapshot_v1 \
  --policy transfer_fee_v1:fee_bps=25,recipient=synw1fee000000000000000000000000000 \
  --policy max_wallet_v1:max_balance=50000000000000000 \
  --out ./gov-create.json
```

Create a B3 snapshot payload:

```bash
synergy-sts token snapshot --network testnet --token synb3... --from synw1... --out ./gov-snapshot.json
```

## Mint, Transfer, Burn

Mint:

```bash
synergy-sts token mint \
  --network testnet \
  --token synb1... \
  --to synw1recipient000000000000000000000000 \
  --amount 5000000000 \
  --from synw1mintauthority0000000000000000000 \
  --out ./mint.json
```

Transfer:

```bash
synergy-sts token transfer \
  --network testnet \
  --token synb1... \
  --from synw1sender00000000000000000000000000 \
  --to synw1recipient000000000000000000000000 \
  --amount 1250000000 \
  --out ./transfer.json
```

Burn:

```bash
synergy-sts token burn \
  --network testnet \
  --token synb1... \
  --from synw1holder00000000000000000000000000 \
  --amount 1000000000 \
  --out ./burn.json
```

## Payload Shape

STS payloads are JSON encoded under a binary prefix before being hex encoded.

Decoded create payload shape:

```json
{
  "version": 1,
  "chain_id": 1264,
  "network": "testnet",
  "tx": {
    "op": "create_fungible",
    "data": {
      "class": "b1",
      "creator": "synw1...",
      "creator_nonce": 1,
      "name": "Testnet Gold",
      "symbol": "TGLD",
      "decimals": 9,
      "initial_supply": 1000000000000000,
      "max_supply": 1000000000000000,
      "metadata_uri": "ipfs://...",
      "metadata_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  }
}
```

The consensus payload bytes are:

```text
synergy-sts-v1:<json payload bytes>
```

Then those bytes are encoded as lowercase hex for CLI output.

## Safety Checks

The CLI fails closed when:

- Network is not `testnet`.
- Token class is not one of the supported stable wire strings.
- A B2 control command receives a non-`synb2` token ID.
- A B3 snapshot command receives a non-`synb3` token ID.
- Payload hex uses `0x`, uppercase hex, or malformed bytes.
- Metadata hash is uppercase, has `0x`, or does not match `--metadata-file`.
- Amounts are not integer base units.

## Current Limitations

- `synergy-sts` currently builds and inspects payload artifacts. It does not submit them directly.
- Signing and RPC submission must use the canonical Synergy transaction tooling once the STS wrapper flow is finalized.
- NFT, multi-asset, and credential CLI commands are planned but not yet implemented in this binary.
