# Dynamic Validator Clusters

Dynamic validator cluster handling must derive quorum and liveness from the
planned validator count in the evidence being evaluated. Current six-validator
Testnet fixtures are compatibility inputs, not permanent protocol topology.

## Offline Cluster Assignment Preview

```bash
synergy-node validator cluster-assignment preview \
  --input cluster-assignment.json \
  --output cluster-assignment-report.json \
  --chain-id 1264 \
  --network-id synergy-testnet-v2
```

The preview model evaluates:

- Testnet v2 chain and network identity.
- Candidate validator id.
- Existing and planned validator counts.
- Planned cluster id.
- Dynamic quorum threshold from the planned validator count.
- Active liveness margin.
- Anti-affinity and fault-domain diversity checks.
- Whether the assignment would reduce quorum or displace an active validator.
- Archive-contained dependency isolation.

The command is dry-run only. It fails closed on wrong chain/network, missing
cluster assignment, non-expanding validator count, anti-affinity failure,
fault-domain diversity failure, quorum reduction, active-validator displacement,
or archive-contained dependency.

## Safety Rules

- Cluster expansion must not hard-code six validators or `4-of-6`.
- New validators join through observer sync, vote-only, proposer probation, and
  activation proof gates.
- Archive-contained state cannot be used as cluster assignment evidence.
- Assignment preview does not create identities, keys, WireGuard peers,
  validator services, or live cluster changes.
