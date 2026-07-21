/**
 * SynQ WASM Compiler Loader
 * Drop this <script type="module"> tag into demo/index.html.
 *
 * Exports window.SynQWasm with:
 *   .ready     — Promise that resolves when WASM is initialised
 *   .compile(source: string) → { success, bytecode, state_vars, warnings, errors }
 *   .version() → string
 *
 * Usage in the IDE's compile handler:
 *
 *   const { success, bytecode, errors, warnings, state_vars } =
 *         await window.SynQWasm.compile(sourceCode);
 *
 *   // If you also want the ML-DSA-65 sidecar:
 *   if (success && wantAttestation) {
 *     const res = await fetch('/synq/sign', {
 *       method: 'POST',
 *       headers: {'Content-Type': 'application/json'},
 *       body: JSON.stringify({ bytecode })
 *     });
 *     const { signature_sidecar } = await res.json();
 *   }
 */

import init, { compile_synq, synq_version }
    from '/demo/wasm/synq_compiler_wasm.b2979828f934.js';

const _ready = init('/demo/wasm/synq_compiler_wasm_bg.b2979828f934.wasm');

window.SynQWasm = {
    ready: _ready,

    async compile(source) {
        await _ready;
        const json = compile_synq(source);
        return JSON.parse(json);
    },

    async version() {
        await _ready;
        return synq_version();
    },
};

// Log init confirmation
_ready.then(() => {
    console.log('[SynQ WASM] compiler ready —', synq_version());
}).catch(err => {
    console.error('[SynQ WASM] init failed:', err);
});
