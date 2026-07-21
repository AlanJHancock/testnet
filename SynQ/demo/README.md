# SynQ In-Browser IDE

Live at: **https://hanksweb.co.uk/demo/**

## What it is

The IDE is a fully self-contained SynQ development environment that runs
the compiler entirely in the browser via WebAssembly. No source code
leaves the browser during compilation — the WASM binary is a direct port
of the same Rust compiler codebase that runs on the server.

## Workflow

The workflow mirrors a production deployment flow:

1. **Write or load a contract** — the editor supports the full SynQ
   grammar including mappings, roles, extern calls, and capability
   declarations
2. **Compile** — the WASM compiler runs locally, produces bytecode
   instantly, and reports errors inline with line references
3. **Attest** — the compiled bytecode is submitted to the server for PQC
   signing via a Dilithium key, producing a `CompileResult` with a
   verifiable attestation
4. **Sign** — an EIP-712 typed data request is sent to the connected
   wallet (MetaMask, chainId 1337) binding the caller's address to the
   session
5. **Deploy** — the signed, attested bytecode is deployed to a new VM
   session on the server, ready to receive function calls

## Features

- **State panel** — updates live after each function call, showing all
  contract state variables with their current values
- **Workspace panel** — tracks multi-contract deployments and wires up
  ExternCall routing between them automatically
- **Demo contracts** — one-click load for SimpleToken, TokenVault, and
  ComprehensiveToken; the latter is the reference contract used by the
  benchmark
- **PQC attestation display** — shows the Dilithium key fingerprint,
  trust model, and bytecode hash for every compile

## Rate limiting

The in-browser compiler is fast enough for interactive use — keystroke-
level feedback is practical — but the attest and deploy steps require
server-side PQC signing regardless of where compilation happened. These
are subject to the server's rate limit of 30 requests/minute. The
compilation step itself is unaffected as it runs entirely locally.

## Execution speeds and bytecode parity

For a precise characterisation of execution speeds across all three
compilation paths, and to verify that the browser compiler, server
loopback, and full HTTP compile all produce identical bytecode, see the
**[Compiler Parity Benchmark](bench.html)**.

The benchmark exists specifically to:

- Quantify the rate-limit headroom by separating pure compilation time
  from the network and PQC signing overhead
- Prove that the WASM binary is not an approximation of the server
  compiler — it is the same compiler, producing the same bytes

A ✓ MATCH result from a live benchmark run is the definitive confirmation
that the vendored WASM compiler sources are in sync with the server. If
the benchmark reports a mismatch, the vendored files in
`synq-compiler-wasm/src/compiler/` need to be resynced from
`compiler/src/` — see [BENCHMARK.md](../BENCHMARK.md) for the procedure.

## Files

| File | Description |
|------|-------------|
| `index.html` | The IDE — editor, compile/deploy flow, state and workspace panels |
| `bench.html` | Compiler parity benchmark |
| `ComprehensiveToken.synq` | Reference contract (roles, mappings, mint/transfer/burn) |
| `wasm/synq-wasm-loader.js` | WASM bootstrap shim — exposes `window.SynQWasm` |
| `wasm/synq_compiler_wasm_bg.*.wasm` | Compiled WASM binary (build artefact, not tracked) |
| `wasm/synq_compiler_wasm.*.js` | wasm-bindgen JS glue (build artefact, not tracked) |

Build artefacts are excluded via `.gitignore`. See
[BENCHMARK.md](../BENCHMARK.md) for the redeploy procedure.

