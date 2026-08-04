use synq_compiler::{parser::parse, transpile_solidity::transpile_to_solidity};
use std::fs;

fn main() {
    for name in &["TokenVault", "SimpleToken", "ComprehensiveToken", "TypeTestContract"] {
        let path = format!("/var/www/synq-demo/contracts/{}.synq", name);
        let src = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => { eprintln!("{}: READ ERROR: {}", name, e); continue; }
        };
        match parse(&src) {
            Ok(ast) => {
                let sol = transpile_to_solidity(&ast);
                let issues: Vec<&str> = sol.lines()
                    .filter(|l| l.contains("return ;") || l.contains("returns ()") || l.contains("void"))
                    .collect();
                if issues.is_empty() {
                    println!("{}: OK ({} bytes)", name, sol.len());
                } else {
                    println!("{}: ISSUES:", name);
                    for issue in issues {
                        println!("  {}", issue.trim());
                    }
                }
                if *name == "TokenVault" {
                    println!("--- TokenVault Solidity ---");
                    println!("{}", sol);
                    println!("--- end ---");
                }
            }
            Err(e) => eprintln!("{}: PARSE ERROR: {}", name, e),
        }
    }
}
