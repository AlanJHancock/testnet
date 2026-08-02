use synq_compiler::compile_ir;
use quantumvm::{QuantumVM, Value};
use ruint::aliases::U256;

fn compile_and_load(source: &str) -> QuantumVM {
    let result = compile_ir(source).expect("compile failed");
    let mut vm = QuantumVM::new();
    vm.load_bytecode(&result.bytecode).expect("load failed");
    vm
}

/// Extract a u128 from either I32 or U256 Value
fn as_u128(v: &Value) -> u128 {
    match v {
        Value::I32(n) => *n as u128,
        Value::U128(n) => *n as u128,
        Value::U256(n) => n.to::<u128>(),
        _ => panic!("expected integer, got {:?}", v),
    }
}

#[test]
fn test_struct_pass_and_return() {
    let source = r#"
pragma synq ^0.9;
struct Point { x: u256; y: u256; }
contract Test {
    state { initialised: bool; }
    @public
    function init() -> bool { initialised = true; return true; }
    @public
    function translate(p: Point, dx: u256, dy: u256) -> Point {
        let result = Point { x: p.x + dx, y: p.y + dy };
        return result;
    }
    @public
    function makePoint(x: u256, y: u256) -> Point {
        return Point { x: x, y: y };
    }
}
"#;
    let mut vm = compile_and_load(source);
    let p = Value::Tuple(vec![Value::I32(10), Value::I32(20)]);
    let result = vm.call_function("translate", &[p, Value::I32(5), Value::I32(3)]).unwrap();
    match &result {
        Some(Value::Tuple(fields)) => {
            assert_eq!(fields.len(), 2);
            assert_eq!(as_u128(&fields[0]), 15, "x should be 15");
            assert_eq!(as_u128(&fields[1]), 23, "y should be 23");
        }
        other => panic!("expected Tuple, got {:?}", other),
    }
    println!("OK: struct param + struct return");
}

#[test]
fn test_field_access_on_call_result() {
    let source = r#"
pragma synq ^0.9;
struct Point { x: u256; y: u256; }
contract Test {
    state { corner: Point; initialised: bool; }
    @public
    function init() -> bool { corner = Point { x: 42, y: 99 }; initialised = true; return true; }
    @public
    function getCorner() -> Point { return corner; }
    @public
    function getCornerX() -> u256 { return getCorner().x; }
    @public
    function getCornerY() -> u256 { return getCorner().y; }
}
"#;
    let mut vm = compile_and_load(source);
    vm.call_function("init", &[]).unwrap();
    let result = vm.call_function("getCornerX", &[]).unwrap();
    assert_eq!(as_u128(&result.unwrap()), 42, "getCornerX should be 42");
    println!("OK: getCornerX() = 42 - field access on call result");
    let result = vm.call_function("getCornerY", &[]).unwrap();
    assert_eq!(as_u128(&result.unwrap()), 99, "getCornerY should be 99");
    println!("OK: getCornerY() = 99");
}

#[test]
fn test_nested_struct_field_access() {
    let source = r#"
pragma synq ^0.9;
struct Point { x: u256; y: u256; }
struct Rect { origin: Point; size: Point; }
contract Test {
    state { box_val: Rect; initialised: bool; }
    @public
    function init() -> bool {
        box_val = Rect { origin: Point { x: 1, y: 2 }, size: Point { x: 100, y: 200 } };
        initialised = true; return true;
    }
    @public
    function getBoxOriginX() -> u256 { return box_val.origin.x; }
    @public
    function getBoxSizeY() -> u256 { return box_val.size.y; }
}
"#;
    let mut vm = compile_and_load(source);
    vm.call_function("init", &[]).unwrap();
    let result = vm.call_function("getBoxOriginX", &[]).unwrap();
    assert_eq!(as_u128(&result.unwrap()), 1, "getBoxOriginX should be 1");
    println!("OK: getBoxOriginX() = 1 - nested struct field access");
    let result = vm.call_function("getBoxSizeY", &[]).unwrap();
    assert_eq!(as_u128(&result.unwrap()), 200, "getBoxSizeY should be 200");
    println!("OK: getBoxSizeY() = 200");
}

#[test]
fn test_struct_from_function_call() {
    let source = r#"
pragma synq ^0.9;
struct Point { x: u256; y: u256; }
contract Test {
    state { corner: Point; initialised: bool; }
    @public
    function init() -> bool { corner = Point { x: 0, y: 0 }; initialised = true; return true; }
    @public
    function makePoint(x: u256, y: u256) -> Point { return Point { x: x, y: y }; }
    @public
    function setCornerFromMake(x: u256, y: u256) -> bool { corner = makePoint(x, y); return true; }
    @public
    function getCornerX() -> u256 { return corner.x; }
}
"#;
    let mut vm = compile_and_load(source);
    vm.call_function("init", &[]).unwrap();
    vm.call_function("setCornerFromMake", &[Value::I32(10), Value::I32(20)]).unwrap();
    let result = vm.call_function("getCornerX", &[]).unwrap();
    assert_eq!(as_u128(&result.unwrap()), 10, "getCornerX should be 10");
    println!("OK: setCornerFromMake then getCornerX() = 10");
}

#[test]
fn test_chained_struct_operations() {
    let source = r#"
pragma synq ^0.9;
struct Point { x: u256; y: u256; }
contract Test {
    state { corner: Point; initialised: bool; }
    @public
    function init() -> bool { corner = Point { x: 0, y: 0 }; initialised = true; return true; }
    @public
    function translate(p: Point, dx: u256, dy: u256) -> Point {
        let result = Point { x: p.x + dx, y: p.y + dy };
        return result;
    }
    @public
    function moveCorner(dx: u256, dy: u256) -> bool { corner = translate(corner, dx, dy); return true; }
    @public
    function getCornerX() -> u256 { return corner.x; }
    @public
    function getCornerY() -> u256 { return corner.y; }
}
"#;
    let mut vm = compile_and_load(source);
    vm.call_function("init", &[]).unwrap();
    vm.call_function("moveCorner", &[Value::I32(100), Value::I32(200)]).unwrap();
    let rx = vm.call_function("getCornerX", &[]).unwrap();
    assert_eq!(as_u128(&rx.unwrap()), 100, "getCornerX should be 100");
    let ry = vm.call_function("getCornerY", &[]).unwrap();
    assert_eq!(as_u128(&ry.unwrap()), 200, "getCornerY should be 200");
    println!("OK: moveCorner(100, 200) then getCorner=(100,200) - chained struct ops");
}
