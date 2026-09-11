// Regression tests for check_undefined_refs' error-accumulation guarantee.
//
// check_undefined_refs is documented to collect EVERY undefined-variable /
// undefined-function error in a contract before compile_ir() fails, so
// ForgeIDE/Playground can list them all from a single compile instead of
// only ever showing the first (line-order) one.
//
// Bug fixed here: assignment-style statements (`x = expr;`, `obj.field = v;`,
// `map[k] = v;`, `set.add(v);`) carry a target name that lives outside the
// `exprs` list the accumulating check walks, so a typo'd assignment TARGET
// silently skipped this pass entirely and only surfaced later as a single,
// position-less, fail-fast "assignment to undefined variable" error out of
// the IR builder -- discarding any other errors found in the same compile.
// That produced the observed "sometimes multiple errors, sometimes only one"
// inconsistency: it depended entirely on which side of an `=` the typo was on.

use synq_compiler::compile_ir;

#[test]
fn undefined_identifiers_in_expressions_all_accumulate() {
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
        initialised: bool;
    }
    impl {
        @public
        function init() -> bool {
            counter = 0;
            initialised = qqqundefined;
            counter = counter + zzzundefined;
            return true;
        }
    }
}
"#;
    let err = compile_ir(source).expect_err("expected compile failure");
    assert!(err.contains("qqqundefined"), "missing first error: {err}");
    assert!(err.contains("zzzundefined"), "missing second error: {err}");
}

#[test]
fn undefined_assignment_target_is_reported() {
    // `nonExistentVar` is never declared as a state var, param, or let-binding.
    // Before the fix this slipped past check_undefined_refs entirely (its
    // RHS, `5`, has no undefined identifiers) and only failed later inside
    // the IR builder with a bare, position-less "assignment to undefined
    // variable" error.
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
    }
    impl {
        @public
        function init() -> bool {
            nonExistentVar = 5;
            return true;
        }
    }
}
"#;
    let err = compile_ir(source).expect_err("expected compile failure");
    assert!(err.contains("nonExistentVar"), "assignment target error missing: {err}");
    // Must come with a real line:col, matching the "--> LINE:COL" convention
    // used by every other accumulated semantic error, not a bare message.
    assert!(err.contains("-->"), "expected a real source position: {err}");
}

#[test]
fn undefined_assignment_target_and_undefined_expression_both_reported_together() {
    // The exact mixed case that used to break the "list every error"
    // guarantee: one undefined identifier used in an EXPRESSION (which the
    // old code already collected) plus one undefined ASSIGNMENT TARGET
    // (which the old code silently ignored, letting a later fail-fast IR
    // builder error mask everything else). Both must now come back from a
    // single compile_ir() call.
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
    }
    impl {
        @public
        function init() -> bool {
            counter = counter + qqqundefined;
            anotherMissingVar = 1;
            return true;
        }
    }
}
"#;
    let err = compile_ir(source).expect_err("expected compile failure");
    assert!(err.contains("qqqundefined"), "expression-side error missing: {err}");
    assert!(err.contains("anotherMissingVar"), "assignment-target error missing: {err}");
}

#[test]
fn valid_assignment_targets_still_compile_clean() {
    // Sanity guard: state vars, params, and let-bindings used as assignment
    // targets must NOT be flagged as undefined by the new target-name check.
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
        initialised: bool;
    }
    impl {
        @public
        function bump(amt: u256) -> u256 {
            let total: u256 = amt;
            counter = counter + total;
            initialised = true;
            total = total + 1;
            return counter;
        }
    }
}
"#;
    compile_ir(source).expect("valid contract should compile cleanly");
}
