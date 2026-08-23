// Server-side WASM executor via wasmtime
// Loads synq_compiler_wasm.wasm and calls the C-ABI export compile_synq_c,
// bypassing wasm-bindgen entirely. Includes fuel/gas metering.

use wasmtime::*;
use std::net::SocketAddr;
use serde_json::{json, Value};

/// Default fuel cap per compilation request. ~10M fuel units is generous
/// enough for any realistic SynQ contract but prevents runaway loops or
/// pathological inputs from pegging the server.
const DEFAULT_FUEL_LIMIT: u64 = 100_000_000;

pub struct WasmRuntime {
    engine: Engine,
    module: Module,
    fuel_limit: u64,
}

impl WasmRuntime {
    pub fn new(wasm_path: &str) -> Result<Self, String> {
        Self::with_fuel_limit(wasm_path, DEFAULT_FUEL_LIMIT)
    }

    pub fn with_fuel_limit(wasm_path: &str, fuel_limit: u64) -> Result<Self, String> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)
            .map_err(|e| format!("Engine init: {}", e))?;
        let module = Module::from_file(&engine, wasm_path)
            .map_err(|e| format!("Failed to load WASM module: {}", e))?;
        Ok(Self { engine, module, fuel_limit })
    }

    pub fn compile(&self, source: &str) -> Result<Value, String> {
        let mut store = Store::new(&self.engine, ());

        // Add fuel and configure trap-on-exhaustion
        store.add_fuel(self.fuel_limit)
            .map_err(|e| format!("add_fuel: {}", e))?;
        store.out_of_fuel_trap();

        // wbindgen imports (no-ops needed for instantiation)
        // Support both old module names (__wbindgen_placeholder__, __wbindgen_externref_xform__)
        // and new wasm-bindgen module name (./synq_compiler_wasm_bg.js)
        let mut linker = Linker::new(&self.engine);

        // ── Old-style module names (backward compat) ──────────────────────
        linker.func_wrap("__wbindgen_placeholder__", "__wbindgen_describe", |_: i32| {})
            .map_err(|e| format!("linker: {}", e))?;
        linker.func_wrap("__wbindgen_externref_xform__", "__wbindgen_externref_table_set_null", |_: i32| {})
            .map_err(|e| format!("linker: {}", e))?;
        linker.func_wrap("__wbindgen_externref_xform__", "__wbindgen_externref_table_grow", |d: i32| -> i32 { d })
            .map_err(|e| format!("linker: {}", e))?;

        // ── New-style module name from wasm-pack/wasm-bindgen 0.2.100+ ─────
        // Only import: __wbindgen_init_externref_table — signature () -> ()
        // All other wbindgen functions are exported by the WASM binary itself.
        let wbmod = "./synq_compiler_wasm_bg.js";
        linker.func_wrap(wbmod, "__wbindgen_init_externref_table", || {})
            .map_err(|e| format!("linker init_externref: {}", e))?;

        let instance = linker.instantiate(&mut store, &self.module)
            .map_err(|e| format!("Instantiate: {}", e))?;

        let memory = instance.get_memory(&mut store, "memory").ok_or("no memory export")?;

        // C-ABI exports
        let alloc_fn = instance.get_typed_func::<i32, i32>(&mut store, "synq_wasm_alloc")
            .map_err(|e| format!("no synq_wasm_alloc: {}", e))?;
        let compile_fn = instance.get_typed_func::<(i32, i32, i32, i32), i32>(&mut store, "compile_synq_c")
            .map_err(|e| format!("no compile_synq_c: {}", e))?;

        let source_bytes = source.as_bytes();
        let src_len = source_bytes.len() as i32;

        let src_ptr = alloc_fn.call(&mut store, src_len)
            .map_err(|e| format!("alloc source: {}", e))?;
        if src_ptr == 0 {
            return Err("WASM alloc returned null for source".to_string());
        }
        memory.write(&mut store, src_ptr as usize, source_bytes)
            .map_err(|e| format!("write source: {}", e))?;

        let out_len = (src_len * 4 + 65536) as i32;
        let out_ptr = alloc_fn.call(&mut store, out_len)
            .map_err(|e| format!("alloc output: {}", e))?;
        if out_ptr == 0 {
            return Err("WASM alloc returned null for output".to_string());
        }

        // Execute compilation — will trap if fuel runs out
        let written = compile_fn.call(&mut store, (src_ptr, src_len, out_ptr, out_len))
            .map_err(|e| {
                let msg = format!("{}", e);
                if msg.contains("fuel") || msg.contains("out of gas") {
                    format!("OUT_OF_FUEL: compilation exceeded {} fuel units", self.fuel_limit)
                } else {
                    format!("compile_synq_c: {}", e)
                }
            })?;

        if written < 0 {
            return Err("compile_synq_c returned error code".to_string());
        }

        // Read fuel consumed
        let fuel_consumed = store.fuel_consumed().unwrap_or(0);

        // Read result from WASM memory
        let mut result_buf = vec![0u8; written as usize];
        memory.read(&store, out_ptr as usize, &mut result_buf)
            .map_err(|e| format!("read result: {}", e))?;

        let result_str = String::from_utf8(result_buf)
            .map_err(|e| format!("utf8: {}", e))?;

        let mut result = serde_json::from_str::<Value>(&result_str)
            .map_err(|e| format!("JSON: {} (got: {})", e, &result_str[..result_str.len().min(200)]))?;

        // Inject fuel metadata into the response
        if let Some(obj) = result.as_object_mut() {
            obj.insert("fuel_consumed".to_string(), json!(fuel_consumed));
            obj.insert("fuel_limit".to_string(), json!(self.fuel_limit));
        }

        Ok(result)
    }

}

// POST /compile-wasm — compile via server-side wasmtime execution with fuel metering
pub async fn compile_wasm_handler(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
    axum::extract::State(state): axum::extract::State<crate::AppState>,
    axum::Json(req): axum::Json<crate::CompileRequest>,
) -> (axum::http::StatusCode, axum::response::Json<Value>) {
    use crate::{check_rate_limit, MAX_SOURCE_BYTES};

    if let Err(wait) = check_rate_limit(&state.rate_limiter, addr.ip()) {
        return (axum::http::StatusCode::TOO_MANY_REQUESTS, axum::response::Json(json!({
            "success": false,
            "errors": [format!("rate limit exceeded retry in {}s", wait)],
        })));
    }

    if req.source.len() > MAX_SOURCE_BYTES {
        return (axum::http::StatusCode::PAYLOAD_TOO_LARGE, axum::response::Json(json!({
            "success": false,
            "errors": ["Source too large"],
        })));
    }

    match state.wasm_runtime.as_ref() {
        Some(rt) => match rt.compile(&req.source) {
            Ok(result) => (axum::http::StatusCode::OK, axum::response::Json(result)),
            Err(e) => (axum::http::StatusCode::OK, axum::response::Json(json!({
                "success": false,
                "errors": [format!("WASM runtime error: {}", e)],
            }))),
        },
        None => (axum::http::StatusCode::SERVICE_UNAVAILABLE, axum::response::Json(json!({
            "success": false,
            "errors": ["WASM runtime not configured"],
        }))),
    }
}
