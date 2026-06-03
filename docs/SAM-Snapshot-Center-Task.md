# SAM Snapshot Center Task

Status: launch-blocking implementation contract. The portable SAM source workspace was not present in this checkout during the Gate 4 recovery pass, so these requirements remain open until they are implemented and verified in the SAM repository.

SAM must expose a Snapshot Center that can:

- List available snapshots from the temporary publisher and later Archive Validator catalog.
- Show snapshot class, height/hash, producer, size, runtime version/SHA, chain/network/genesis, QC vote count, QC signers, and manifest signature status.
- Download 512 MiB chunks with resume.
- Verify chunk SHA256s and whole archive SHA256.
- Extract to staging.
- Run runtime `verify-snapshot`.
- Run supported self-heal or support-role recovery workflow.
- Show progress, current phase, and evidence path.
- Reject wrong snapshot class for the selected node role.
- Reject h175518-contaminated or unresolved-conflict snapshots.
- Support Val5 recovery, relayer/RPC recovery, and non-genesis validator onboarding.
- Integrate the Archive Validator snapshot catalog once the Archive Validator is operational.
- Use workbook-exact host paths from `/Users/devpup/Desktop/node-machine-credentials.xlsx`.

SAM must also expose a Transaction Center that can:

- Run sender public-key presence, encoding, and address-derivation preflight.
- Show public RPC freshness, balance, and nonce.
- Build a dry-run transaction preview before submission.
- Submit and wait for a public receipt.
- Show Atlas visibility.
- Inspect pending transactions and classify invalid or stale entries.

SAM must expose checkpointed consensus-fork status from `synergy_getConsensusForkStatus`:

- Show whether a fork migration object is configured.
- Show `fork_height`, `fork_parent_height`, `fork_parent_hash`, and `state_root`.
- Show `old_consensus_algorithm`, `new_consensus_algorithm`, and `parser_mode`.
- Show each validator address, consensus key type, and consensus public key byte size.
- Warn if any post-fork validator key resolves to ML-DSA, has missing or unknown metadata, or uses an ambiguous label such as `pqc` or `aegis`.
- Warn if a post-fork snapshot manifest is missing `consensus_fork` metadata.
- Frame the migration as a protocol upgrade preserving `chain_id=1264` and `network_id=synergy-testnet-v2`, not a block-0 reset.

Minimum launch acceptance for SAM integration:

- Snapshot metadata is read from `distribution-manifest.json`.
- Consensus fork metadata is read from `synergy_getConsensusForkStatus`.
- Wrong-class restore is rejected before download or extraction.
- Failed chunk/hash/runtime verification is fail-closed.
- Evidence is written for each Snapshot Center action.
