# Val5 FN-DSA Rejoin Proof

- phase: `shadow-start`
- execute: `true`
- workspace: `/home/justin/.synergy/testnet/nodes/validator-workspace`
- runtime: `/home/justin/.synergy/testnet/nodes/validator-workspace/bin/synergy-testnet-linux-amd64`
- expected runtime sha256: `7939c0bda667c8abd42fa9b3d1a32e86b1b2ed7db132a558c9969bf397be63f4`
- all gates passed: `true`
- failure count: `0`
- private key material: `redacted`

## Gate Table

| Gate | Status | Detail |
| --- | --- | --- |
| `trusted_runtime_sha_input` | `PASS` | trusted runtime sha supplied |
| `workspace_exists` | `PASS` | /home/justin/.synergy/testnet/nodes/validator-workspace |
| `workspace_structure` | `PASS` | config and data directories exist |
| `runtime_sha` | `PASS` | 7939c0bda667c8abd42fa9b3d1a32e86b1b2ed7db132a558c9969bf397be63f4 |
| `runtime_executable` | `PASS` | /home/justin/.synergy/testnet/nodes/validator-workspace/bin/synergy-testnet-linux-amd64 |
| `val5_process_stopped` | `PASS` | process_count=0 |
| `listener_absent_p2p` | `PASS` | port=5622 |
| `listener_absent_qrpc` | `PASS` | port=5640 |
| `listener_absent_ws` | `PASS` | port=5660 |
| `listener_absent_discovery` | `PASS` | port=5680 |
| `listener_absent_metrics` | `PASS` | port=6030 |
| `quarantine_marker` | `PASS` | /home/justin/.synergy/testnet/nodes/validator-workspace/data/validator_quarantine.json |
| `fork_metadata_file` | `PASS` | /home/justin/.synergy/testnet/nodes/validator-workspace/config/consensus-fork-migration.json |
| `fork_height` | `PASS` | 204216 |
| `fork_parent_height` | `PASS` | 204215 |
| `fork_parent_hash` | `PASS` | e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816 |
| `fork_chain_continuity_state_root` | `PASS` | state_root present |
| `fork_old_consensus_algorithm` | `PASS` | ML-DSA-65 |
| `fork_new_consensus_algorithm` | `PASS` | FN-DSA |
| `fork_parser_mode` | `PASS` | fail_closed |
| `fork_registry_shape` | `PASS` | entries=5 |
| `fork_registry_all_fndsa` | `PASS` | [] |
| `fork_registry_val5_entry` | `PASS` | synv11kguave5fpdpm9hru4acfvw0hcp4fcc7zv9f |
| `fork_registry_val5_public_key_base64` | `PASS` | base64 |
| `fork_registry_val5_public_key_bytes` | `PASS` | 1793 |
| `fndsa_private_key_file` | `PASS` | /home/justin/.synergy/testnet/nodes/validator-workspace/keys/fndsa-consensus-fork-204216/private.key |
| `fndsa_private_key_bytes` | `PASS` | 2305 |
| `fndsa_private_key_permissions` | `PASS` | 0o600 |
| `fndsa_public_key_file` | `PASS` | /home/justin/.synergy/testnet/nodes/validator-workspace/keys/fndsa-consensus-fork-204216/public.key |
| `fndsa_public_key_bytes` | `PASS` | 1793 |
| `fndsa_public_key_matches_fork_registry` | `PASS` | public_sha=7c77ab0249a19a00ed9b9f90bbcc10ab1676deb9b1d6da526129c3363436e376 registry_sha=7c77ab0249a19a00ed9b9f90bbcc10ab1676deb9b1d6da526129c3363436e376 |
| `runtime_phase_start-shadow-observe` | `PASS` | output=/home/justin/synergy-testnet-evidence/20260603T223136Z-Val5-fndsa-rejoin-shadow-start/runtime-phase-output.json |

## Evidence

- JSON proof: `/home/justin/synergy-testnet-evidence/20260603T223136Z-Val5-fndsa-rejoin-shadow-start/val5-rejoin-proof.json`
- transcript: `/home/justin/synergy-testnet-evidence/20260603T223136Z-Val5-fndsa-rejoin-shadow-start/command-transcript.txt`
- activation command: `/home/justin/synergy-testnet-evidence/20260603T223136Z-Val5-fndsa-rejoin-shadow-start/activation-command.txt`
