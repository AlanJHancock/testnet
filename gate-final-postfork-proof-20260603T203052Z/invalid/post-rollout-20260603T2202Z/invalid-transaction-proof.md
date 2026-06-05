# Gate 4 Post-Rollout Invalid Transaction Fail-Closed Proof

| Probe | Pass | Actual error | Included | Nonce before/after | Pending after |
|---|---:|---|---:|---|---:|
| `missing_signer_public_key` | `True` | `Transaction signer public key is missing` | `False` | `6 / 6` | `0` |
| `invalid_fndsa_signature` | `True` | `Aegis PQC transaction signature verification failed` | `False` | `6 / 6` | `0` |
| `signature_key_mismatch` | `True` | `Transaction signer public key does not derive sender address` | `False` | `6 / 6` | `0` |
| `missing_signature_algorithm` | `True` | `Missing signatureAlgorithm; use fndsa explicitly` | `False` | `6 / 6` | `0` |
| `unknown_signature_algorithm_pqc` | `True` | `Ambiguous signature algorithm 'pqc'; use fndsa, mldsa, or slhdsa explicitly` | `False` | `6 / 6` | `0` |
| `unknown_signature_algorithm_aegis` | `True` | `Ambiguous signature algorithm 'aegis'; use fndsa, mldsa, or slhdsa explicitly` | `False` | `6 / 6` | `0` |
| `unknown_signature_algorithm_default` | `True` | `Unsupported signature algorithm 'default'` | `False` | `6 / 6` | `0` |
| `unknown_signature_algorithm_auto` | `True` | `Unsupported signature algorithm 'auto'` | `False` | `6 / 6` | `0` |
| `unknown_signature_algorithm_unknown` | `True` | `Unsupported signature algorithm 'unknown'` | `False` | `6 / 6` | `0` |
| `wrong_algorithm_label_ml_dsa_65` | `True` | `Aegis PQC transaction signature verification failed` | `False` | `6 / 6` | `0` |
| `malformed_signer_public_key` | `True` | `signerPublicKey must be a valid hex string or byte array` | `False` | `6 / 6` | `0` |
| `stale_nonce` | `True` | `Transaction failed runtime validation: stale nonce; expected 6, got 5` | `False` | `6 / 6` | `0` |
| `duplicate_nonce_same_last_committed` | `True` | `Transaction failed runtime validation: stale nonce; expected 6, got 4` | `False` | `6 / 6` | `0` |
| `future_nonce_gap` | `True` | `Transaction failed runtime validation: future nonce gap; expected 6, got 106` | `False` | `6 / 6` | `0` |
| `wrong_chain_id_1265` | `True` | `Transaction chainId 1265 does not match local chain 1264` | `False` | `6 / 6` | `0` |
| `wrong_network_id` | `True` | `Transaction network_id synergy-testnet-v3 does not match synergy-testnet-v2` | `False` | `6 / 6` | `0` |
| `legacy_schema_missing_required_fields` | `True` | `Missing transaction nonce` | `False` | `6 / 6` | `0` |
| `tampered_amount_after_signing` | `True` | `Aegis PQC transaction signature verification failed` | `False` | `6 / 6` | `0` |
| `tampered_recipient_after_signing` | `True` | `Aegis PQC transaction signature verification failed` | `False` | `6 / 6` | `0` |

All pass: `True`
