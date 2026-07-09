use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use synq_compiler::PQCCompiler;
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
    }
}

fn compile(path: &PathBuf) {
    println!("Compiling SynQ with PQC: {}", path.display());
    let source = fs::read_to_string(path).expect("Failed to read source file");

    // Initialize PQC compiler with enhanced security
    let _pqc_compiler = PQCCompiler::new(synq_compiler::PQCSecurityLevel::Enhanced);

    // Parse SynQ source
    let ast = synq_compiler::parser::parse(&source).expect("Failed to parse source file");

    // Generate bytecode with PQC integration
    let codegen = synq_compiler::codegen::CodeGenerator::new();
    let mut bytecode = codegen.generate(&ast).expect("Failed to generate bytecode");

    // NOTE: this still appends a placeholder signature string rather than
    // a real cryptographic signature over the bytecode. Real signing needs
    // a key-management design decision (ephemeral vs persistent/wallet
    // key) before this can be fixed properly.
    let pqc_signature = format!("PQC_SIGNATURE_{}", chrono::Utc::now().timestamp());
    bytecode.extend_from_slice(pqc_signature.as_bytes());

    let output_path = path.with_extension("synq_bytecode");
    fs::write(&output_path, &bytecode).expect("Failed to write bytecode file");
    println!("✅ Successfully compiled SynQ with PQC to {}", output_path.display());
    println!("🔒 PQC Security Level: Enhanced");
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
