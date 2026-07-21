# SynQ Compiler Parity Benchmark

Live at: **https://hanksweb.co.uk/demo/bench.html**

## What the benchmark does

The bench page compiles the `ComprehensiveToken` contract through three
independent paths in a single run and compares their raw bytecode output
byte-for-byte:

| Path | Description |
|------|-------------|
| **WASM** | Compiled entirely in the browser using the Rust compiler codebase compiled to WebAssembly — zero network round-trips |
| **Loopback** | The server's native Rust compiler, timed internally via `/synq/bench-compile`, eliminating HTTP and TLS overhead |
| **HTTP** | A full remote compile over TLS including EIP-712 PQC attestation signing — real-world latency |

## What the buttons do

- **Run** — executes a configurable number of live rounds (default 8), each calling all three paths, and reports median/min/avg/max timings plus a bytecode verdict
- **Simulate Mismatch** — renders a static mock of what a *failing* run looks like, using the pre-fix bytecode sizes as a reference (WASM 3374B vs server 3361B)
- **Show OK** — renders a static mock of what a *passing* run looks like; useful for checking the verdict panel layout without waiting for a live run

The two mock buttons are UI reference states only — they do not compile anything.

## Why bytecode parity matters

A ✓ MATCH result from a live run confirms that the WASM compiler and the
server compiler are deterministically identical: same grammar, same AST,
same codegen, same dispatch table ordering.

This matters for two concrete reasons:

**1. No silent drift.**
A developer compiling in the browser gets exactly what the server will
execute. The WASM codebase is a faithful local mirror of the server
compiler, not an approximation. Changes to the server compiler must be
manually synced to `synq-compiler-wasm/src/compiler/` — a mismatch here
is what the benchmark is designed to catch early.

**2. Attestation soundness.**
The PQC signing scheme hashes the compiled bytecode. Parity is a
prerequisite for that hash to mean anything. If the two compilers
diverged, a browser-compiled contract and a server-attested contract
would be different things, silently.

The benchmark is a **correctness and performance diagnostic**. The
authority layer — attestation, PQC signing, session management, nonce
issuance — remains server-side regardless of the WASM compiler being
in sync.

## Typical results (ComprehensiveToken, 8 rounds)

| Path | Median | vs loopback |
|------|--------|-------------|
| WASM | ~4 ms | ~5× slower (JIT penalty) |
| Loopback | ~0.7 ms | 1× (baseline) |
| HTTP | ~40 ms | ~57× slower (TLS + PQC attestation) |

The WASM JIT penalty (~5×) is a one-time cost per page load; subsequent
compiles in the same session are faster as the JIT warms up. The HTTP
overhead (~57×) is dominated by TLS handshake and the Dilithium signing
step, not by the compilation itself.

## Problems fixed during development of this benchmark

### 1. Non-deterministic bytecode (HashMap iteration order)
The compiler's dispatch table was built from a `HashMap`, whose iteration
order is randomised per process in Rust. This meant two compiles of the
same source could produce different bytecode, making the parity check
meaningless. Fixed by sorting function addresses and capability lists
before assembling the dispatch table.

### 2. WASM parser/grammar out of sync with server
The vendored `parser.rs` and `synq.pest` inside `synq-compiler-wasm/`
were 598 lines behind the server compiler. Missing rules included
`while_statement`, `break_statement`, `continue_statement`, and the full
`interface_definition` handler. This caused the WASM compiler to parse
the same source differently, generating 14 extra bytes in the output.
Fixed by fully syncing the vendored copies from `compiler/src/`.

### 3. Bytecode size display off-by-one
The bench page calculated bytecode size as `bytecode.length / 2`, but
the bytecode field is a `0x`-prefixed hex string, making the string two
characters longer than the actual hex data. This caused WASM and HTTP
sizes to display as 3362 instead of the correct 3361, triggering a false
mismatch against the loopback path which used the server's integer field
directly. Fixed by stripping the `0x` prefix before halving.

### 4. nginx serving stale WASM from cache
The active nginx config (`zelf-domain-tool`) was serving `/demo/wasm/`
with `Cache-Control: no-cache`, which allows conditional revalidation
and does not prevent disk-cache hits. Previous edits had also been
applied to the wrong config file (`hanksweb-synq.conf`, which is not
symlinked into `sites-enabled`). Fixed by patching the correct file with
`no-store, no-cache, must-revalidate` and deploying WASM assets under
content-hashed filenames (e.g. `synq_compiler_wasm_bg.b2979828f934.wasm`)
so the browser module registry cannot serve a stale version.

## Deployment

The WASM binary is not committed to this repository (it is a build
artefact). To redeploy after changes to the compiler codebase:

```bash
# 1. Sync vendored files from the canonical compiler
cp compiler/src/parser.rs  synq-compiler-wasm/src/compiler/parser.rs
cp compiler/src/codegen.rs synq-compiler-wasm/src/compiler/codegen.rs
cp compiler/src/synq.pest  synq-compiler-wasm/src/compiler/synq.pest
cp compiler/src/ast.rs     synq-compiler-wasm/src/compiler/ast.rs
# Fix import paths in the vendored copies (crate:: → super:: / vm_inner)
sed -i 's/use crate::ast::/use super::ast::/' synq-compiler-wasm/src/compiler/parser.rs
sed -i 's/use crate::ast::/use super::ast::/' synq-compiler-wasm/src/compiler/codegen.rs

# 2. Build
cd synq-compiler-wasm
cargo build --release --target wasm32-unknown-unknown

# 3. Generate JS bindings
wasm-bindgen target/wasm32-unknown-unknown/release/synq_compiler_wasm.wasm \
  --out-dir /tmp/wasm_out --target web

# 4. Deploy (update filenames + references in bench.html / synq-wasm-loader.js)
#    Use a content hash as the filename suffix to bust the browser module cache.
cp /tmp/wasm_out/synq_compiler_wasm_bg.wasm /var/www/synq-demo/wasm/synq_compiler_wasm_bg.<hash>.wasm
cp /tmp/wasm_out/synq_compiler_wasm.js      /var/www/synq-demo/wasm/synq_compiler_wasm.<hash>.js
```

