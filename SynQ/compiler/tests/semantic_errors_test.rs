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

// Bug fixed here: check_undefined_refs only ever walked
// `f.body.statements` directly. An If/While statement's `condition`
// expression was checked, but everything inside its `then_block` /
// `else_block` / loop `body` was completely invisible to this pass --
// those nested statements were never even visited, let alone checked for
// undefined identifiers. In practice this meant undefined-reference
// errors nested inside if/else or while blocks (more common the longer
// and more branchy a contract gets) went unreported by this accumulating
// pass entirely, and only ever surfaced later -- one at a time, with no
// position -- via the IR builder's separate fail-fast check, if the
// compile even got that far. flatten_block_statements() now recurses into
// every nesting level so these are collected exactly like top-level ones.

#[test]
fn undefined_identifier_inside_if_block_is_reported() {
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
    }
    impl {
        @public
        function bump(flag: bool) -> u256 {
            if (flag) {
                counter = counter + insideIfUndefined;
            }
            return counter;
        }
    }
}
"#;
    let err = compile_ir(source).expect_err("expected compile failure");
    assert!(err.contains("insideIfUndefined"), "nested if-block error missing: {err}");
    assert!(err.contains("-->"), "expected a real source position: {err}");
}

#[test]
fn undefined_identifier_inside_else_block_is_reported() {
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
    }
    impl {
        @public
        function bump(flag: bool) -> u256 {
            if (flag) {
                counter = counter + 1;
            } else {
                counter = counter + insideElseUndefined;
            }
            return counter;
        }
    }
}
"#;
    let err = compile_ir(source).expect_err("expected compile failure");
    assert!(err.contains("insideElseUndefined"), "nested else-block error missing: {err}");
}

#[test]
fn undefined_identifier_inside_while_block_is_reported() {
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
    }
    impl {
        @public
        function loopIt(n: u256) -> u256 {
            while (counter < n) {
                counter = counter + insideWhileUndefined;
            }
            return counter;
        }
    }
}
"#;
    let err = compile_ir(source).expect_err("expected compile failure");
    assert!(err.contains("insideWhileUndefined"), "nested while-block error missing: {err}");
}

#[test]
fn undefined_identifiers_top_level_and_nested_all_accumulate_together() {
    // The exact "long contract, some errors go missing" scenario: one
    // undefined identifier at the top level of the function plus another
    // nested two levels deep (while inside if). Both must come back from
    // a single compile_ir() call, not just the top-level one.
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
    }
    impl {
        @public
        function run(flag: bool, n: u256) -> u256 {
            counter = counter + topLevelUndefined;
            if (flag) {
                while (counter < n) {
                    counter = counter + deeplyNestedUndefined;
                }
            }
            return counter;
        }
    }
}
"#;
    let err = compile_ir(source).expect_err("expected compile failure");
    assert!(err.contains("topLevelUndefined"), "top-level error missing: {err}");
    assert!(err.contains("deeplyNestedUndefined"), "deeply nested error missing: {err}");
}

#[test]
fn undefined_assignment_target_inside_if_block_is_reported() {
    // Same assignment-target blind spot as the top-level fix above, but
    // for a target nested inside an if-block.
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
    }
    impl {
        @public
        function bump(flag: bool) -> u256 {
            if (flag) {
                nestedBadTarget = 5;
            }
            return counter;
        }
    }
}
"#;
    let err = compile_ir(source).expect_err("expected compile failure");
    assert!(err.contains("nestedBadTarget"), "nested assignment-target error missing: {err}");
}

#[test]
fn let_bound_inside_if_block_is_recognized_as_defined() {
    // Sanity guard: a `let` declared inside an if-block must not be
    // falsely flagged as undefined now that nested statements are checked.
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
    }
    impl {
        @public
        function bump(flag: bool) -> u256 {
            if (flag) {
                let extra: u256 = 1;
                counter = counter + extra;
            }
            return counter;
        }
    }
}
"#;
    compile_ir(source).expect("valid contract with nested let should compile cleanly");
}

#[test]
fn valid_nested_if_while_contract_still_compiles_clean() {
    // Sanity guard: a contract with legitimate if/else/while nesting and
    // no undefined references anywhere must still compile clean -- the
    // new recursive walk must not introduce false positives.
    let source = r#"pragma synq ^0.9;
contract Counter {
    state {
        counter: u256;
    }
    impl {
        @public
        function run(flag: bool, n: u256) -> u256 {
            if (flag) {
                while (counter < n) {
                    counter = counter + 1;
                }
            } else {
                counter = counter + 2;
            }
            return counter;
        }
    }
}
"#;
    compile_ir(source).expect("valid nested contract should compile cleanly");
}
