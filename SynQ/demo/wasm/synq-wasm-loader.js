/**
 * SynQ WASM Compiler Loader (--target web)
 * Cache-busted via version parameter to ensure fresh WASM after rebuilds.
 */
const _WASM_VERSION = '42f8787c';
import init, { compile_synq, synq_version }
    from '/demo/wasm/synq_compiler_wasm.js?v=' + _WASM_VERSION;

const _wasmReady = init({ module_or_path: '/demo/wasm/synq_compiler_wasm_bg.wasm?v=' + _WASM_VERSION });

window.SynQWasm = {
    ready: _wasmReady,

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

_ready.then(() => console.log('[SynQ WASM] compiler ready (v=' + _WASM_VERSION + ')'));
