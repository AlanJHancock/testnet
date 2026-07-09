use assert_cmd::prelude::*;
use std::process::Command;
use tempfile::NamedTempFile;
use std::io::Write;
use predicates::prelude::*;

#[test]
fn test_compile_and_run() {
    let contract = r#"
        contract MyContract {
            function my_function() {}
        }
    "#;

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", contract).unwrap();

    let mut cmd = Command::cargo_bin("synq-cli").unwrap();
    cmd.arg("compile")
        .arg("--path")
        .arg(file.path());

    cmd.assert().success();

    let bytecode_path = file.path().with_extension("synq_bytecode");
    assert!(bytecode_path.exists());

    let mut run_cmd = Command::cargo_bin("synq-cli").unwrap();
    run_cmd.arg("run")
        .arg("--path")
        .arg(&bytecode_path);

    run_cmd.assert().success().stdout(predicate::str::contains("Execution finished successfully"));
}
