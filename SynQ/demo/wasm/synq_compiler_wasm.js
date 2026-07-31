/* @ts-self-types="./synq_compiler_wasm.d.ts" */
import * as wasm from "./synq_compiler_wasm_bg.wasm";
import { __wbg_set_wasm } from "./synq_compiler_wasm_bg.js";

__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    compile_synq, synq_version
} from "./synq_compiler_wasm_bg.js";
