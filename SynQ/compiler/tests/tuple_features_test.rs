use synq_compiler::compile_ir;
use quantumvm::{QuantumVM, Value};
use ruint::aliases::U256;

fn compile_and_load(source: &str) -> QuantumVM {
    let result = compile_ir(source).expect("compile failed");
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load failed");
    vm
}

fn as_u128(v: &Value) -> u128 {
    match v {
        Value::I32(n) => *n as u128,
        Value::U128(n) => *n as u128,
        Value::U256(n) => n.to::<u128>(),
        _ => panic!("expected integer, got {:?}", v),
    }
}

fn as_bool(v: &Value) -> bool {
    match v {
        Value::Bool(b) => *b,
        Value::I32(0) => false,
        Value::I32(_) => true,
        Value::U256(n) => !(*n == U256::ZERO),
        _ => panic!("expected bool, got {:?}", v),
    }
}

#[test]
fn test_tuple_index_access() {
    let source = r#"
pragma synq ^0.9;
struct Point { x: u256; y: u256; }
contract Test {
    state { corner: Point; initialised: bool; }
    @public
    function init() -> bool { corner = Point { x: 42, y: 99 }; initialised = true; return true; }
    @public
    function getCornerX() -> u256 { return corner.0; }
    @public
    function getCornerY() -> u256 { return corner.1; }
}
"#;
    let mut vm = compile_and_load(source);
    vm.call_function("init", &[]).unwrap();
    let result = vm.call_function("getCornerX", &[]).unwrap();
    assert_eq!(as_u128(&result.unwrap()), 42, "corner.0 should be 42");
    println!("OK: corner.0 = 42");
    let result = vm.call_function("getCornerY", &[]).unwrap();
    assert_eq!(as_u128(&result.unwrap()), 99, "corner.1 should be 99");
    println!("OK: corner.1 = 99");
}

#[test]
fn test_tuple_destructure() {
    let source = r#"
pragma synq ^0.9;
struct Point { x: u256; y: u256; }
contract Test {
    state { corner: Point; initialised: bool; }
    @public
    function init() -> bool { corner = Point { x: 42, y: 99 }; initialised = true; return true; }
    @public
    function testDestructure() -> u256 {
        let (a, b) = corner;
        return a + b;
    }
}
"#;
    let mut vm = compile_and_load(source);
    vm.call_function("init", &[]).unwrap();
    let result = vm.call_function("testDestructure", &[]).unwrap();
    assert_eq!(as_u128(&result.unwrap()), 141, "42 + 99 = 141");
    println!("OK: destructure a+b = 141");
}

#[test]
fn test_tuple_literal_index() {
    let source = r#"
pragma synq ^0.9;
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function testTupleLiteral() -> u256 {
        let t = (42, 99);
        return t.0 + t.1;
    }
}
"#;
    let mut vm = compile_and_load(source);
    vm.call_function("init", &[]).unwrap();
    let result = vm.call_function("testTupleLiteral", &[]).unwrap();
    assert_eq!(as_u128(&result.unwrap()), 141, "42 + 99 = 141");
    println!("OK: tuple literal t.0 + t.1 = 141");
}
