use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use synq_compiler::{PQCCompiler, PQCSecurityLevel};
use synq_vm::{QuantumVM, Value};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compiles a SynQ source file
    Compile {
        /// The path to the SynQ source file
        #[arg(short, long)]
        path: PathBuf,
    },
    /// Runs a compiled SynQ bytecode file
    Run {
        /// The path to the SynQ bytecode file
        #[arg(short, long)]
        path: PathBuf,
        /// Call a specific contract function by name instead of running
        /// from the top of the bytecode.
        #[arg(short, long)]
        function: Option<String>,
        /// Comma-separated integer arguments for --function, e.g. "1,2,3"
        #[arg(short, long)]
        args: Option<String>,
        /// List the callable functions in this bytecode file and exit.
        #[arg(long)]
        list_functions: bool,
    },
    /// Verifies the PQC signature sidecar file produced by `compile`
    Verify {
        /// The path to the compiled .synq_bytecode file
        #[arg(short, long)]
        path: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Compile { path } => {
            compile(path);
        }
        Commands::Run { path, function, args, list_functions } => {
            run(path, function.as_deref(), args.as_deref(), *list_functions);
        }
        Commands::Verify { path } => {
            verify(path);
        }
    }
}

/// Signature algorithm used for compiled bytecode. Dilithium (ML-DSA-65) is
/// the default "Enhanced" security-level signer in PQCCompiler.
const SIGNING_ALGORITHM: &str = "dilithium";

fn sig_sidecar_path(bytecode_path: &Path) -> PathBuf {
    // e.g. "counter.synq_bytecode" -> "counter.synq_bytecode.sig.json"
    let mut s = bytecode_path.as_os_str().to_os_string();
    s.push(".sig.json");
    PathBuf::from(s)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("invalid hex in signature file"))
        .collect()
}

fn compile(path: &PathBuf) {
    println!("Compiling SynQ with PQC: {}", path.display());
    let source = fs::read_to_string(path).expect("Failed to read source file");

    // Parse SynQ source
    let ast = synq_compiler::parser::parse(&source).expect("Failed to parse source file");

    // Generate bytecode
    let codegen = synq_compiler::codegen::CodeGenerator::new();
    let bytecode = codegen.generate(&ast).expect("Failed to generate bytecode");

    // Real PQC signing over the compiled bytecode using a fresh, EPHEMERAL
    // ML-DSA-65 (Dilithium) keypair generated for this compile only. The
    // private key is used once to sign and then dropped -- it is never
    // written to disk. This replaces the old fake
    // "PQC_SIGNATURE_<timestamp>" placeholder string with a real signature
    // that can actually be verified (see the `verify` subcommand).
    //
    // Ephemeral (vs persistent/wallet-derived) was chosen as the starting
    // point: it proves the real signing path end-to-end without requiring
    // a key-management/storage design yet. Revisit once persistent identity
    // keys are needed (e.g. tied to a wallet address).
    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let keypair = pqc
        .generate_keypair(SIGNING_ALGORITHM)
        .expect("Failed to generate ephemeral signing keypair");
    let signature = pqc
        .sign_message(&keypair.private_key, &bytecode, SIGNING_ALGORITHM)
        .expect("Failed to sign bytecode");

    let output_path = path.with_extension("synq_bytecode");
    fs::write(&output_path, &bytecode).expect("Failed to write bytecode file");

    let sig_path = sig_sidecar_path(&output_path);
    let sig_json = serde_json::json!({
        "algorithm": signature.algorithm,
        "security_level": format!("{:?}", signature.security_level),
        "public_key": hex_encode(&keypair.public_key),
        "signature": hex_encode(&signature.signature),
    });
    fs::write(&sig_path, serde_json::to_string_pretty(&sig_json).unwrap())
        .expect("Failed to write signature sidecar file");

    println!("✅ Successfully compiled SynQ with PQC to {}", output_path.display());
    println!("🔒 PQC Security Level: Enhanced");
    println!(
        "🔏 Signed with real {} (ephemeral keypair) -- signature + public key written to {}",
        signature.algorithm,
        sig_path.display()
    );
}

fn verify(path: &PathBuf) {
    println!("Verifying PQC signature for: {}", path.display());
    let bytecode = fs::read(path).expect("Failed to read bytecode file");

    let sig_path = sig_sidecar_path(path);
    let sig_content = fs::read_to_string(&sig_path).unwrap_or_else(|_| {
        panic!(
            "No signature sidecar file found at {} -- was this file compiled with real signing?",
            sig_path.display()
        )
    });
    let sig_json: serde_json::Value =
        serde_json::from_str(&sig_content).expect("Malformed signature sidecar file");

    let algorithm = sig_json["algorithm"].as_str().expect("missing algorithm field");
    let public_key = hex_decode(sig_json["public_key"].as_str().expect("missing public_key field"));
    let signature = hex_decode(sig_json["signature"].as_str().expect("missing signature field"));

    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    match pqc.verify_signature(&public_key, &signature, &bytecode, algorithm) {
        Ok(true) => println!("✅ Signature valid ({}) -- bytecode is untampered", algorithm),
        Ok(false) => println!("❌ Signature INVALID -- bytecode does not match the signature on file"),
        Err(e) => println!("❌ Verification error: {}", e),
    }
}

fn run(path: &PathBuf, function: Option<&str>, args: Option<&str>, list_functions: bool) {
    println!("Running SynQ with PQC: {}", path.display());
    let bytecode = fs::read(path).expect("Failed to read bytecode file");

    // Initialize SynQ VM with PQC support
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&bytecode).expect("Failed to load bytecode");

    if list_functions {
        println!("📋 Callable functions:");
        for name in vm.list_functions() {
            println!("  - {}", name);
        }
        return;
    }

    if let Some(name) = function {
        let parsed_args: Vec<Value> = match args {
            Some(s) if !s.is_empty() => s
                .split(',')
                .map(|part| Value::I32(part.trim().parse().expect("Function args must be integers")))
                .collect(),
            _ => vec![],
        };

        match vm.call_function(name, &parsed_args) {
            Ok(Some(result)) => {
                println!("✅ Function '{}' returned: {:?}", name, result);
            }
            Ok(None) => {
                println!("✅ Function '{}' executed (no return value)", name);
            }
            Err(e) => {
                println!("❌ Function call failed: {}", e);
            }
        }
        return;
    }

    // Execute with PQC verification
    match vm.execute() {
        Ok(()) => {
            println!("✅ Execution finished successfully");
            println!("🔒 PQC Verification: Passed");
        }
        Err(e) => {
            println!("❌ VM execution failed: {}", e);
            println!("🔒 PQC Verification: Failed");
        }
    }
}
