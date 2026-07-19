use synq_compiler::{PQCCompiler, PQCSecurityLevel};
fn main() {
    let pqc = PQCCompiler::new(PQCSecurityLevel::Enhanced);
    let kp  = pqc.generate_keypair("ML-DSA-65").expect("keygen failed");
    println!("PRIVATE:{}", hex::encode(&kp.private_key));
    println!("PUBLIC:{}", hex::encode(&kp.public_key));
}
