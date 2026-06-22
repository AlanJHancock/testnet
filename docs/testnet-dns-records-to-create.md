# Testnet DNS Baseline and Remaining Actions

This file is the frozen DNS baseline for `synergy-testnet`.

It reflects:

- the canonical Testnet hostnames referenced by the live repo
- the current DNS inventory for `synergy-network.io` and `synergy-network.io`
- the frozen bootstrap topology of exactly 3 bootnodes and 3 seed services

## Summary

No additional launch-critical DNS records remain to be created.

The required Testnet records should now be treated as the frozen keep set. Remaining launch work is service deployment and endpoint verification, not creation of new names.

The required 3-host bootstrap set is:

- `bootnode1.synergy-network.io`
- `bootnode2.synergy-network.io`
- `bootnode3.synergy-network.io`
- `seed1.synergy-network.io`
- `seed2.synergy-network.io`
- `seed3.synergy-network.io`
- `_dnsaddr.bootstrap.synergy-network.io` TXT records for bootnodes 1-3
- `_synergy-seed._tcp.synergy-network.io` SRV records for seeds 1-3

The required Testnet surface on `synergy-network.io` is also part of the frozen keep set.

## Canonical Testnet Keep Set

These are the records the canonical Testnet launch surfaces expect to exist and remain stable.

| Host | Type | Target | Status |
| --- | --- | --- | --- |
| `testnet-core-rpc.synergy-network.io` | `A` | `74.208.227.23` | Keep as the canonical public Testnet RPC endpoint |
| `testnet-core-ws.synergy-network.io` | `A` | `74.208.227.23` | Keep as the canonical public Testnet WebSocket endpoint |
| `testnet-api.synergy-network.io` | `A` | `65.21.202.144` | Keep as the canonical Testnet API endpoint |
| `testnet-wallet-api.synergy-network.io` | `A` | `65.21.202.144` | Keep as the wallet helper API endpoint |
| `testnet-faucet.synergy-network.io` | `A` | `65.21.202.144` | Keep as the faucet endpoint |
| `testnet-sxcp-api.synergy-network.io` | `A` | `65.21.202.144` | Keep as the SXCP API endpoint |
| `testnet-sxcp-ws.synergy-network.io` | `A` | `65.21.202.144` | Keep as the SXCP WebSocket endpoint |
| `testnet-synq-verify.synergy-network.io` | `A` | `65.21.202.144` | Keep as the SynQ verification endpoint |
| `testnet-aegis-verify.synergy-network.io` | `A` | `65.21.202.144` | Keep as the Aegis verification endpoint |
| `testnet-evm-rpc.synergy-network.io` | `A` | `65.21.202.144` | Keep as the compatibility EVM HTTP endpoint |
| `testnet-evm-ws.synergy-network.io` | `A` | `65.21.202.144` | Keep as the compatibility EVM WebSocket endpoint |
| `testnet.synergy-network.io` | `A` | `65.21.202.144` | Keep as the binary and update manifest host |
| `testnet-explorer.synergy-network.io` | `A` | `74.208.227.23` | Keep as the explorer UI hostname |
| `testnet-indexer.synergy-network.io` | `A` | `74.208.227.23` | Keep as the indexer host |
| `testnet-atlas-api.synergy-network.io` | `A` | `74.208.227.23` | Keep as the Atlas backend API hostname |
| `testnet-atlas.synergy-network.io` | `A` | `74.208.227.23` | Keep as the Atlas host alias |

## Compatibility Aliases

No compatibility aliases are part of the frozen Testnet keep set.

## Bootstrap Discovery Keep Set

These records remain the approved bootstrap discovery surface:

- `bootnode1.synergy-network.io` -> `170.64.187.206`
- `bootnode2.synergy-network.io` -> `146.190.210.121`
- `bootnode3.synergy-network.io` -> `157.245.226.240`
- `seed1.synergy-network.io` -> `170.64.187.206`
- `seed2.synergy-network.io` -> `146.190.210.121`
- `seed3.synergy-network.io` -> `157.245.226.240`
- `_dnsaddr.bootstrap.synergy-network.io` TXT records pointing at `tcp/5620`
- `_synergy-seed._tcp.synergy-network.io` SRV records pointing at `5621`

## Remaining DNS Work

DNS work is now limited to:

- verifying every keep-set record resolves exactly as frozen
- correcting `seed1.synergy-network.io` and `seed2.synergy-network.io` if they still resolve to legacy RPC/validator hosts instead of the seed-service hosts above
- keeping retired and removed names out of certificates, docs, configs, and launch procedures
- verifying the services behind these names are actually deployed and healthy

## Assumptions

- `65.21.202.144` remains the host for the shared Testnet API, wallet, faucet, verification, SXCP, and compatibility EVM surfaces.
- `74.208.227.23` remains the host for the core RPC, core WS, explorer, indexer, and Atlas surfaces.
- `testnet.synergy-network.io` should resolve to the machine serving `/var/www/synergy-portal/binaries`. If that is not `65.21.202.144` in your environment, change that one record to the correct binary host.
