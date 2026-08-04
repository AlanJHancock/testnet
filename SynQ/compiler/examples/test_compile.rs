use synq_compiler::{parser::parse, compile_ir};
use std::fs;

fn main() {
    for name in &["TokenVault", "SimpleToken", "ComprehensiveToken", "TypeTestContract"] {
        let path = format!("/var/www/synq-demo/contracts/{}.synq", name);
        let src = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => { eprintln!("{}: READ ERROR: {}", name, e); continue; }
        };
        match parse(&src) {
            Ok(_ast) => {
                match compile_ir(&src) {
                    Ok(result) => {
                        println!("{}: COMPILE OK ({} bytes bytecode, {} warnings)",
                            name, result.bytecode.len(), result.warnings.len());
                    }
                    Err(e) => {
                        println!("{}: COMPILE FAILED: {}", name, e);
                    }
                }
            }
            Err(e) => eprintln!("{}: PARSE ERROR: {}", name, e),
        }
    }
}
