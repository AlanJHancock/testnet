# Synergy Testnet Chain 1264 Topology

Date: 2026-05-19

This document describes the intended Synergy Testnet chain 1264 topology.

Canonical identity:

- chain_id: `1264`
- chain_id_hex: `0x4f0`
- network_id: `synergy-testnet-v2`
- genesis validators: 5
- active validator quorum: dynamic 67% of the active validator set
- cluster_count: 1
- cluster_id: 0

## Roles

Validators:

- Validator 1 through Validator 5 are the only genesis validators.
- Validators listen for validator service traffic on the VPN/private plane.
- Validators may vote, propose, and count toward quorum only while ACTIVE.
- Validator public service exposure must be closed or restricted according to the deployment firewall policy.

Relayers:

- Relayers bridge public-facing nodes to validator VPN/private-plane surfaces.
- Relayers expose public-facing ports and private/VPN-facing ports.
- Relayers do not vote, propose, aggregate QCs as validators, or count toward quorum.
- Relayers must verify canonical chain data and reject stale or wrong-chain artifacts.

Public-facing service nodes:

- RPC gateway, Explorer/Atlas/indexer, bootnodes, and seed services are public-facing support roles.
- Public-facing nodes must communicate with validators through relayers unless a future architecture explicitly changes this.
- Public-facing support nodes do not vote, propose, or count toward quorum.

Observer/archive/follower roles:

- Observer and archive/follower roles are read-only verification and observability infrastructure.
- They must not vote, propose, or count toward quorum.
- Archive snapshots, when used, are acceleration artifacts only and must be independently verified against finalized block QCs.

## Required Runtime Checks

Run `scripts/testnet/verify-relayer-topology.sh` during preflight and after rollout. The script is intentionally read-only and should be extended rather than bypassed when new topology checks are needed.

Minimum checks:

- validator peer tables contain expected private-plane validator and relayer peers
- relayer peer tables contain validator private-plane peers and public support peers
- RPC and Explorer/Atlas peer tables do not show direct validator public peers
- public service nodes route validator-facing traffic through relayers
- relayers do not advertise validator role
- observer/archive/follower roles do not advertise validator role
- validator public P2P/qRPC/WS/discovery exposure is closed or restricted as required

## Non-Negotiable Safety Rules

- Do not lower the dynamic 67% validator quorum locally to work around liveness problems.
- Do not remove a validator from the active set locally unless a finalized epoch transition changes the canonical set.
- Do not allow public support-node catch-up traffic to share an unbounded queue with votes, proposals, QCs, view-change messages, or handshakes.
- Do not accept peer blocks, votes, QCs, or transactions with wrong `chain_id`, wrong `network_id`, missing signatures, invalid signatures, or stale validator-set context.
- Do not treat an archive, observer, relayer, bootnode, seed, RPC, or indexer process as a validator unless it is separately onboarded and ACTIVE through finalized chain state.
