use std::path::PathBuf;
use std::fs;
use std::env;
use synq_pqc_shims::dilithium;
use sha3::{Keccak256, Digest};

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut output_path = "compiler.key";
    
    // Simple command-line argument parsing
    if args.len() > 1 {
        if args[1] == "--help" || args[1] == "-h" {
            println!("synq-keygen: Generate persistent ML-DSA-65 compiler-attestation keys");
            println!("Usage: synq-keygen [OUTPUT_PATH]");
            println!("Default output path: compiler.key");
            return;
        }
        output_path = &args[1];
    }
    
    let path = PathBuf::from(output_path);
    
    // Generate real ML-DSA-65 keypair
    let (pk, sk) = dilithium::keygen();
    
    // Hex encode keys
    let pk_hex = hex::encode(&pk);
    let sk_hex = hex::encode(&sk);
    
    // Compute key_id fingerprint: Keccak256(pk_bytes) first 8 bytes (16 hex chars)
    let mut hasher = Keccak256::new();
    hasher.update(&pk);
    let hash = hasher.finalize();
    let key_id = hex::encode(&hash[..8]);
    
    // Write private key hex to file (with a single newline at the end)
    if let Err(e) = fs::write(&path, format!("{}\n", sk_hex)) {
        eprintln!("Error writing private key file: {}", e);
        std::process::exit(1);
    }
    
    println!("Private key successfully written to: {}", path.display());
    println!("Public Key Hex: {}", pk_hex);
    println!("Key ID (fingerprint): {}", key_id);
}

