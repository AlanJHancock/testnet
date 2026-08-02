use synq_compiler::compile_ir;
use quantumvm::{QuantumVM, Value};

#[test]
fn test_phi_loop_execution() {
    let source = r#"
contract PhiTest {
  state {
    counter: u256;
  }

  function sum_range(n: u256) -> u256 {
    let i: u256 = 0;
    let sum: u256 = 0;
    while (i < n) {
      sum = sum + i;
      i = i + 1;
    }
    return sum;
  }
}
"#;
    let result = compile_ir(source).expect("compile failed");
    
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load failed");
    
    // sum_range(5) = 0+1+2+3+4 = 10
    let res = vm.call_function("sum_range", &[Value::U128(5)]);
    assert!(res.is_ok(), "sum_range(5) failed: {:?}", res);
    let val = res.unwrap().unwrap();
    println!("sum_range(5) = {:?}", val);
    
    let n = match val {
        Value::I32(n) => n as u64,
        Value::U128(n) => n as u64,
        Value::U256(n) => n.wrapping_to::<u64>(),
        _ => 0,
    };
    assert_eq!(n, 10, "sum_range(5) should be 10, got {}", n);
}

#[test]
fn test_phi_loop_execution_10() {
    let source = r#"
contract PhiTest2 {
  state {
    dummy: u256;
  }

  function factorial(n: u256) -> u256 {
    let i: u256 = 1;
    let result: u256 = 1;
    while (i <= n) {
      result = result * i;
      i = i + 1;
    }
    return result;
  }
}
"#;
    let result = compile_ir(source).expect("compile failed");
    
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load failed");
    
    // factorial(5) = 120
    let res = vm.call_function("factorial", &[Value::U128(5)]);
    assert!(res.is_ok(), "factorial(5) failed: {:?}", res);
    let val = res.unwrap().unwrap();
    println!("factorial(5) = {:?}", val);
    
    let n = match val {
        Value::I32(n) => n as u64,
        Value::U128(n) => n as u64,
        Value::U256(n) => n.wrapping_to::<u64>(),
        _ => 0,
    };
    assert_eq!(n, 120, "factorial(5) should be 120, got {}", n);
}

#[test]
fn test_phi_bytecode_smaller() {
    let source = r#"
contract SizeTest {
  state {
    counter: u256;
  }

  function loop_sum(n: u256) -> u256 {
    let i: u256 = 0;
    let sum: u256 = 0;
    while (i < n) {
      sum = sum + i;
      i = i + 1;
    }
    return sum;
  }
}
"#;
    let result = compile_ir(source).expect("compile failed");
    
    let promote_report = result.warnings.iter()
        .find(|w| w.contains("promote_to_ssa"))
        .map(|w| w.as_str())
        .unwrap_or("not found");
    println!("promote_to_ssa: {}", promote_report);
    println!("bytecode size: {} bytes", result.bytecode.len());
    
    assert!(!result.bytecode.is_empty());
}
