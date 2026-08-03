use synq_compiler::parser;
use synq_compiler::transpile_solidity::transpile_to_solidity;

fn transpile(source: &str) -> String {
    let ast = parser::parse(source).expect("parse failed");
    transpile_to_solidity(&ast)
}

// ── Basic structure tests ────────────────────────────────────────────────────

#[test]
fn test_transpile_empty_contract() {
    let sol = transpile("contract Blank { }");
    assert!(sol.contains("contract Blank"));
    assert!(sol.contains("pragma solidity"));
}

#[test]
fn test_transpile_state_vars() {
    let sol = transpile(r#"
        contract Vault {
            state {
                balance: u256;
                active: bool;
                owner: Bytes<20>;
            }
        }
    "#);
    assert!(sol.contains("uint256 internal balance"));
    assert!(sol.contains("bool internal active"));
    assert!(sol.contains("bytes20 internal owner"));
}

#[test]
fn test_transpile_struct_defs() {
    let sol = transpile(r#"
        struct Point {
            x: u256;
            y: u256;
        }
        contract Geometry {
            state {
                origin: Point;
            }
        }
    "#);
    assert!(sol.contains("struct Point"));
    assert!(sol.contains("uint256 x"));
    assert!(sol.contains("uint256 y"));
}

#[test]
fn test_transpile_enum() {
    let sol = transpile(r#"
        contract States {
            state {
                status: u256;
            }
        }
    "#);
    // The contract should compile
    assert!(sol.contains("contract States"));
}

// ── Function tests ───────────────────────────────────────────────────────────

#[test]
fn test_transpile_function_signatures() {
    let sol = transpile(r#"
        contract Funcs {
            state {
                value: u256;
            }
            function get() -> u256 {
                return value;
            }
            function set(v: u256) -> bool as caller {
                value = v;
                return true;
            }
        }
    "#);
    assert!(sol.contains("function get() internal returns (uint256)"));
    assert!(sol.contains("function set(uint256 v) internal returns (bool)"));
}

#[test]
fn test_transpile_bool_return_cast() {
    let sol = transpile(r#"
        contract BoolCast {
            state {
                flag: bool;
            }
            function getAsInt() -> u256 {
                return flag;
            }
        }
    "#);
    // bool -> uint256 cast
    assert!(sol.contains("? uint256(1) : uint256(0)"));
}

#[test]
fn test_transpile_address_cast() {
    let sol = transpile(r#"
        contract AddrCast {
            state {
                owner: Bytes<20>;
            }
            function init() -> bool as caller {
                owner = caller;
                return true;
            }
        }
    "#);
    // caller -> bytes20 cast, should be clean (no double cast)
    assert!(sol.contains("bytes20(uint160(msg.sender))"));
    // Should NOT have the redundant double-cast pattern
    assert!(!sol.contains("bytes20(uint160(uint256(uint160("));
}

#[test]
fn test_transpile_string_concat() {
    let sol = transpile(r#"
        contract StrConcat {
            state {
                greeting: str;
            }
            function build(s: str) -> str {
                return greeting + s;
            }
        }
    "#);
    assert!(sol.contains("string.concat("));
}

// ── Control flow tests ───────────────────────────────────────────────────────

#[test]
fn test_transpile_if_else() {
    let sol = transpile(r#"
        contract Branch {
            state {
                value: u256;
            }
            function clamp(min: u256, max: u256) -> u256 {
                if (value < min) {
                    return min;
                } else {
                    if (value > max) {
                        return max;
                    }
                }
                return value;
            }
        }
    "#);
    assert!(sol.contains("if ("));
    assert!(sol.contains("} else {"));
}

#[test]
fn test_transpile_while_loop() {
    let sol = transpile(r#"
        contract Loopy {
            function sum(n: u256) -> u256 {
                let i = 0;
                let total = 0;
                while (i < n) {
                    total = total + i;
                    i = i + 1;
                }
                return total;
            }
        }
    "#);
    assert!(sol.contains("while ("));
}

// ── Built-in stub tests ──────────────────────────────────────────────────────

#[test]
fn test_transpile_pqc_stubs() {
    let sol = transpile(r#"
        contract PQC {
            function verify(sig: Bytes<64>, msg: Bytes, pk: Bytes<1952>) -> bool {
                return ml_dsa_verify(sig, msg, pk);
            }
        }
    "#);
    assert!(sol.contains("SXCP"));
    assert!(sol.contains("ml_dsa_verify"));
}

#[test]
fn test_transpile_bech32_stubs() {
    let sol = transpile(r#"
        contract Bech {
            function toStr(addr: u256) -> str {
                return to_syna(addr);
            }
        }
    "#);
    assert!(sol.contains("string"));
    assert!(sol.contains("to_syna"));
}

#[test]
fn test_transpile_authority_stubs() {
    let sol = transpile(r#"
        contract Auth {
            function check() -> u256 {
                let env = authority_identity(authority_envelope());
                return env;
            }
        }
    "#);
    assert!(sol.contains("authority_identity"));
    assert!(sol.contains("SXCP"));
}

// ── Reserved word tests ──────────────────────────────────────────────────────

#[test]
fn test_transpile_reserved_words() {
    let sol = transpile(r#"
        contract Reserved {
            state {
                msg: u256;
            }
            function set(v: u256) -> bool as caller {
                msg = v;
                return true;
            }
        }
    "#);
    // `msg` should be renamed to avoid Solidity reserved word
    assert!(sol.contains("msg_"));
}

// ── Annotation tests ─────────────────────────────────────────────────────────

#[test]
fn test_transpile_effects_annotation() {
    let sol = transpile(r#"
        contract Effects {
            state {
                value: u256;
                initialised: bool;
            }
            @effects(value)
            function set(v: u256) -> bool as caller {
                require(initialised, "not ready");
                value = v;
                return true;
            }
        }
    "#);
    assert!(sol.contains("modifies: value"));
    assert!(sol.contains("require("));
}

#[test]
fn test_transpile_init_pattern() {
    let sol = transpile(r#"
        contract Init {
            state {
                initialised: bool;
            }
            function init() -> bool as caller {
                if (initialised) { return false; }
                initialised = true;
                return true;
            }
        }
    "#);
    assert!(sol.contains("function init()"));
    assert!(sol.contains("if (initialised)"));
}

// ── Struct value tests ───────────────────────────────────────────────────────

#[test]
fn test_transpile_struct_literal() {
    let sol = transpile(r#"
        struct Point {
            x: u256;
            y: u256;
        }
        contract StructLit {
            state {
                origin: Point;
            }
            function init() -> bool as caller {
                origin = Point { x: 0, y: 0 };
                return true;
            }
        }
    "#);
    assert!(sol.contains("Point({x: 0, y: 0})"));
}

#[test]
fn test_transpile_field_access() {
    let sol = transpile(r#"
        struct Point {
            x: u256;
            y: u256;
        }
        contract FieldAcc {
            state {
                p: Point;
            }
            function getX() -> u256 {
                return p.x;
            }
        }
    "#);
    assert!(sol.contains(".x"));
}

// ── UMAIdentity type test ────────────────────────────────────────────────────

#[test]
fn test_transpile_uma_identity_type() {
    let sol = transpile(r#"
        contract UMA {
            state {
                umaId: UMAIdentity;
                initialised: bool;
            }
            function init() -> bool as caller {
                if (initialised) { return false; }
                let env = authority_identity(authority_envelope());
                umaId = env;
                initialised = true;
                return true;
            }
            function getId() -> u256 {
                return umaId;
            }
        }
    "#);
    // UMAIdentity -> address in Solidity
    assert!(sol.contains("address"));
    // Assignment cast: uint256 -> address
    assert!(sol.contains("address(uint160(env))"));
    // Return cast: address -> uint256
    assert!(sol.contains("uint256(uint160(umaId))"));
}

// ── Comprehensive contract test ──────────────────────────────────────────────

#[test]
fn test_transpile_comprehensive_contract() {
    let sol = transpile(r#"
        struct Point {
            x: u256;
            y: u256;
        }
        contract Comp {
            state {
                count: u256;
                active: bool;
                owner: Bytes<20>;
                origin: Point;
                initialised: bool;
            }
            function init() -> bool as caller {
                if (initialised) { return false; }
                count = 0;
                active = true;
                owner = caller;
                origin = Point { x: 1, y: 2 };
                initialised = true;
                return true;
            }
            function increment() -> u256 as caller {
                require(initialised, "not init");
                count = count + 1;
                return count;
            }
            function isActive() -> bool {
                return active;
            }
        }
    "#);
    // State vars
    assert!(sol.contains("uint256 internal count"));
    assert!(sol.contains("bool internal active"));
    assert!(sol.contains("bytes20 internal owner"));

    // Functions
    assert!(sol.contains("function init()"));
    assert!(sol.contains("function increment()"));
    assert!(sol.contains("function isActive()"));

    // Casts
    assert!(sol.contains("bytes20(uint160(msg.sender))"));
    assert!(!sol.contains("bytes20(uint160(uint256(uint160("));

    // Struct literal
    assert!(sol.contains("Point({x: 1, y: 2})"));
}
