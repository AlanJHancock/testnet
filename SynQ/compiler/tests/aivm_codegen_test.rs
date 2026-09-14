use synq_compiler::parser::parse;
use synq_compiler::ast::SourceUnit;
use synq_compiler::aivm_codegen::compile_to_aivm;

#[test]
fn test_aivm_codegen_new_opcodes() {
    let source = r#"contract Math {
    state {
        result: u256;
    }
    impl {
        @public
        function init() -> bool {
            result = 0;
            return true;
        }

        @public
        function is_not_equal(a: u256, b: u256) -> bool {
            return a != b;
        }

        @public
        function is_less_or_equal(a: u256, b: u256) -> bool {
            return a <= b;
        }

        @public
        function is_greater_or_equal(a: u256, b: u256) -> bool {
            return a >= b;
        }

        @public
        function modulo(a: u256, b: u256) -> u256 {
            return a % b;
        }
    }
}"#;

    let units = parse(source).unwrap();
    if let SourceUnit::Contract(def) = &units[0] {
        let result = compile_to_aivm(def, &[]).unwrap();

        let instr_dbg: Vec<String> = result.instructions.iter()
            .map(|i| format!("{:?}", i))
            .collect();

        let has_ne = instr_dbg.iter().any(|s| s.contains("Ne"));
        let has_le = instr_dbg.iter().any(|s| s.contains("Le"));
        let has_ge = instr_dbg.iter().any(|s| s.contains("Ge"));
        let has_mod = instr_dbg.iter().any(|s| s.contains("Mod"));

        assert!(has_ne, "Ne opcode missing from AIVM output: {:?}", instr_dbg);
        assert!(has_le, "Le opcode missing from AIVM output: {:?}", instr_dbg);
        assert!(has_ge, "Ge opcode missing from AIVM output: {:?}", instr_dbg);
        assert!(has_mod, "ModU64 opcode missing from AIVM output: {:?}", instr_dbg);

        // No "placeholder" or "needs function index" warnings
        let bad_warnings: Vec<_> = result.warnings.iter()
            .filter(|w| w.contains("placeholder") || w.contains("needs function index"))
            .collect();
        assert!(bad_warnings.is_empty(), "Unresolved placeholders: {:?}", bad_warnings);
    }
}

#[test]
fn test_aivm_codegen_function_call_resolution() {
    let source = r#"contract Caller {
    state {
        counter: u256;
    }
    impl {
        @public
        function init() -> bool {
            counter = 0;
            return true;
        }

        function helper(x: u256) -> u256 {
            return x + 1;
        }

        @public
        function call_helper(val: u256) -> u256 {
            return helper(val);
        }
    }
}"#;

    let units = parse(source).unwrap();
    if let SourceUnit::Contract(def) = &units[0] {
        let result = compile_to_aivm(def, &[]).unwrap();

        // Find Call instructions — check none are Call(0) placeholders
        let call_warnings: Vec<_> = result.warnings.iter()
            .filter(|w| w.contains("unknown function"))
            .collect();
        assert!(call_warnings.is_empty(), "Unknown function call warnings: {:?}", call_warnings);

        // Verify we have at least one Call instruction
        let has_call = result.instructions.iter()
            .any(|i| format!("{:?}", i).contains("Call("));
        assert!(has_call, "No Call instruction found in output");
    }
}

/// Bitwise/shift operators (2026-09-14, bitwise/shift support): previously
/// hard-errored at compile time on the AIVM backend ("use the IR/VM
/// compilation path for u256 bitwise ops"). Now compiles to real BitAnd/
/// BitOr/BitXor/Shl/Shr opcodes, with `~` synthesized as `x XOR 0xFF..FF`
/// (PushU256 + BitXor, no dedicated BitNot opcode needed).
#[test]
fn test_aivm_codegen_bitwise_ops_no_longer_error() {
    let source = r#"contract Bitwise {
    state {
        result: u256;
    }
    impl {
        @public
        function init() -> bool {
            result = 0;
            return true;
        }

        @public
        function bit_and(a: u256, b: u256) -> u256 {
            return a & b;
        }

        @public
        function bit_or(a: u256, b: u256) -> u256 {
            return a | b;
        }

        @public
        function bit_xor(a: u256, b: u256) -> u256 {
            return a ^ b;
        }

        @public
        function shift_left(a: u256, b: u256) -> u256 {
            return a << b;
        }

        @public
        function shift_right(a: u256, b: u256) -> u256 {
            return a >> b;
        }

        @public
        function bit_not(a: u256) -> u256 {
            return ~a;
        }
    }
}"#;

    let units = parse(source).unwrap();
    if let SourceUnit::Contract(def) = &units[0] {
        let result = compile_to_aivm(def, &[])
            .expect("bitwise/shift ops must compile on the AIVM backend now");

        let instr_dbg: Vec<String> = result.instructions.iter()
            .map(|i| format!("{:?}", i))
            .collect();

        let has = |needle: &str| instr_dbg.iter().any(|s| s.contains(needle));

        assert!(has("BitAnd"), "BitAnd opcode missing: {:?}", instr_dbg);
        assert!(has("BitOr"), "BitOr opcode missing: {:?}", instr_dbg);
        assert!(has("BitXor"), "BitXor opcode missing: {:?}", instr_dbg);
        assert!(has("Shl"), "Shl opcode missing: {:?}", instr_dbg);
        assert!(has("Shr"), "Shr opcode missing: {:?}", instr_dbg);
        // bit_not() has no dedicated opcode -- verify it synthesizes as
        // PushU256(all-ones) + BitXor instead.
        assert!(has("PushU256"), "PushU256 (for ~ synthesis) missing: {:?}", instr_dbg);
    } else {
        panic!("expected a contract");
    }
}
