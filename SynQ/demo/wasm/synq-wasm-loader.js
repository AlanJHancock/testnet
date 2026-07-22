/**
 * SynQ WASM Compiler Loader
 */

import init, { compile_synq, synq_version }
    from '/demo/wasm/synq_compiler_wasm.95568bfd541ee592.js';

const _ready = init('/demo/wasm/synq_compiler_wasm_bg.31f9742157044464.wasm');

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

_ready.then(() => {
    console.log('[SynQ WASM] compiler ready —', synq_version());
}).catch(err => {
    console.error('[SynQ WASM] init failed:', err);
});
