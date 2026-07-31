/**
 * SynQ WASM Compiler Loader
 */

import init, { compile_synq, synq_version }
    from '/demo/wasm/synq_compiler_wasm.34625e58b527c84f.js';

const _ready = init({ module_or_path: '/demo/wasm/synq_compiler_wasm_bg.34625e58b527c84f.wasm' });

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

_ready.then(() => console.log('[SynQ WASM] compiler ready'));
