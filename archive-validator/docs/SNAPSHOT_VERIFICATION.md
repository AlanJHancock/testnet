# Snapshot Verification

Validators must reject snapshots with missing or invalid Aegis PQC signatures, wrong chain ID, wrong network ID, wrong genesis hash, wrong state root, invalid QC, corrupted content root, corrupted chunk hash, unauthorized signer, or unsupported state format.

Receivers must also reject wrong-class snapshots before download or extraction. The supported classes are `validator-pruned`, `support-relayer`, `support-rpc`, `indexer-replay`, `indexer-full`, `archive-full`, and `archive-bootstrap`. Distribution archives use zstd, 512 MiB chunks, per-chunk SHA-256, and whole-archive SHA-256.
