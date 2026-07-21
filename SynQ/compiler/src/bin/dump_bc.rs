use std::fs;
fn main() {
    let src = fs::read_to_string(std::env::args().nth(1).unwrap()).expect("read source");
    match synq_compiler::compile(&src) {
        Ok(r) => {
            let hex: String = r.bytecode.iter().map(|b| format!("{:02x}",b)).collect();
            eprintln!("bytecode {} bytes", r.bytecode.len());
            println!("{}", hex);
        }
        Err(e) => { eprintln!("compile error: {}", e); std::process::exit(1); }
    }
}
