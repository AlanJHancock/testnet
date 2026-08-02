/**
 * SynQ WASM Compiler Loader (bundler target — self-initializing)
 */
import { compile_synq, synq_version } from '/demo/wasm/synq_compiler_wasm.js';

const _ready = Promise.resolve(true);

window.SynQWasm = {
    ready: _ready,

    async compile(source) {
        const json = compile_synq(source);
        return JSON.parse(json);
    },

    async version() {
        return synq_version();
    },
};

_ready.then(() => console.log('[SynQ WASM] compiler ready'));
