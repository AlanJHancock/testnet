# SynQ browser compiler

The production browser loads `synq_compiler_bg.wasm` from this public directory.
The generated JavaScript bridge and type declarations live under
`app/lib/ide/generated` so Vite can bundle them in both development and
production.

Regenerate with:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --locked
bash tools/synq-compiler-wasm/build.sh
```

The wrapper performs the same parser, semantic analysis, bytecode generation,
ABI generation, manifest generation, and compatibility generation as the SynQ
CLI. It does not simulate AIVM execution or fabricate test/deployment results.
