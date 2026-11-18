//! Determinism guard: the same source must always compile to the same bytes.
//!
//! Regression for the benchdev "Bytecode differs between compilation paths"
//! MISMATCH. promote_to_ssa walked a HashMap/HashSet in per-process random
//! order, so loop-carried variables swapped phi value ids and the local slot
//! addresses changed from run to run. Rust seeds every HashMap separately, so
//! repeating the compile inside one process is enough to expose it.

use synq_compiler::compile_ir;

const LOOPS: &str = r#"pragma synq ^0.9;
contract LoopDeterminism {
  state {
    total: u256;
    count: u256;
    initialised: bool;
  }

  impl {
    @public
    function sumRange(n: u256) -> u256 {
      let i: u256 = 1;
      let acc: u256 = 0;
      let evens: u256 = 0;
      while (i <= n) {
        acc = acc + i;
        if (i % 2 == 0) { evens = evens + 1; }
        i = i + 1;
      }
      return acc + evens;
    }

    @public
    function nested(a: u256, b: u256) -> u256 {
      let x: u256 = 0;
      let y: u256 = 0;
      let z: u256 = 0;
      while (x < a) {
        let k: u256 = 0;
        while (k < b) {
          y = y + k;
          z = z + x;
          k = k + 1;
        }
        x = x + 1;
      }
      return y + z;
    }

    @public
    function factorial(n: u256) -> u256 {
      let result: u256 = 1;
      let c: u256 = 2;
      while (c <= n) {
        result = result * c;
        c = c + 1;
      }
      return result;
    }
  }
}
"#;

fn bytecode_of(source: &str) -> Vec<u8> {
    let result = compile_ir(source).expect("source must compile");
    result.bytecode
}

#[test]
fn repeated_compiles_of_one_source_are_byte_identical() {
    let first = bytecode_of(LOOPS);
    assert!(!first.is_empty());
    for run in 1..=40 {
        let next = bytecode_of(LOOPS);
        assert_eq!(first.len(), next.len(), "run {run}: length changed");
        let diffs: Vec<usize> = first.iter().zip(&next).enumerate()
            .filter(|(_, (a, b))| a != b).map(|(i, _)| i).collect();
        assert!(diffs.is_empty(), "run {run}: {} bytes differ, first at offset {:?}", diffs.len(), diffs.first());
    }
}

#[test]
fn ir_dump_is_identical_across_compiles() {
    let first = compile_ir(LOOPS).expect("compiles").ir_dump;
    for run in 1..=40 {
        let next = compile_ir(LOOPS).expect("compiles").ir_dump;
        assert_eq!(first, next, "run {run}: IR dump changed between compiles of the same source");
    }
}
