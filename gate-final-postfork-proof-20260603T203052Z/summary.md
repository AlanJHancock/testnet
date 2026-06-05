# Gate Final Post-Fork Proof Summary

Captured: 2026-06-03T21:02:34.325112+00:00

## Current Chain Status

| Field | Value |
|---|---|
| Public latest at refresh | `206100` / `cc7b9799d69bf1d871c8a05bed1bc102285e445e904964cec06e91d15b6c01b5` |
| Atlas latest at refresh | `206045` |
| Fixed common height | `205905` |
| Fixed common hash | `e64f31282497eb2093130ab2c7e2a6433c40d6b8efc36f35a140471fcc32ed4f` |
| Fixed proof all match | `True` |
| Relayer1 lag at proof capture | `20` blocks |
| Relayer2 lag at proof capture | `20` blocks |
| Public pending count | `0` |
| Local pending counts after follow-up | `{'Relayer1': 0, 'Relayer2': 0, 'Val1': 0, 'Val2': 0, 'Val3': 0, 'Val4': 0, 'row9-Explorer': 0, 'row9-Gateway': 0}` |
| Fork height | `204216` |
| Parent height/hash | `204215` / `e209bd7554a06dfb052d5ff7ffd5664efc05e6cd1c5cadc9d139fa5bb9072816` |
| New consensus algorithm | `FN-DSA` |
| Parser mode | `fail_closed` |
| Fork validator count | `5` |

## Gate 4 Valid Transaction

| Field | Value |
|---|---|
| Transaction | `syntxn-6075c3a9f449ca66d65e07e61e428af9b368d839c8c552ea3a7d4bd019ac55ae` |
| Public RPC | `https://testnet-core-rpc.synergy-network.io` |
| Algorithm | `fndsa` |
| Chain/network | `1264` / `synergy-testnet-v2` |
| Signer public key bytes | `1793` |
| Signature bytes | `1266` |
| Nonce before/used/after | `4` / `4` / `5` |
| Sender balance before/after | `999509747998` / `999445819997` |
| Receiver balance before/after | `2225998999572940002` / `2225998999572940003` |
| Receipt | `0x1` at `205822` / `2c3bb8fdd088aaede2e29efd0b7270ba115de79d776304dec21f0165cbdfaae1` |
| Atlas visibility | `True` |
| Public pending empty after | `True` |
| Follow-up all-role pending empty | `True` |

Raw files: `transactions/valid-unsigned-transaction.json`, `transactions/valid-signed-transaction.json`, `transactions/valid-submit-response.json`, `transactions/valid-receipt.json`, `transactions/valid-atlas-visibility.json`, `transactions/valid-node-propagation/`, `transactions/pending-current/`.

## Gate 4 Invalid Matrix

| Field | Value |
|---|---|
| Probe count | `19` |
| All pass | `True` |
| Final sender nonce | `5` |
| Final public pending | `[]` |

Raw files: `invalid/invalid-transaction-proof.json`, `invalid/invalid-transaction-proof.md`, `invalid/requests/`, `invalid/responses/`, `invalid/after/`.

## Remaining Launch Blockers

- Relayer1 and Relayer2 were found inactive during proof capture and were restarted. They now serve qRPC and all fixed-height hashes match, but the relayer service pattern shows repeated OOM/signal/deactivation history and needs stability/lag monitoring before final soak.
- Trusted release artifacts are not complete: current live runtime is still the local hotfix SHA until CI/release artifacts are cut or proven byte-for-byte equivalent.
- Archive Validator fork package is not rebuilt/accepted for the new local-runtime plus SMB-publish architecture.
- Val5 is staged/quarantined, but automated dry-run/rejoin tooling and activation proof are not complete.
- New validator onboarding proof is not complete.
- SAM/control-panel updates are not complete.
- Final soak is not eligible until the above gates are finished or explicitly signed off.
