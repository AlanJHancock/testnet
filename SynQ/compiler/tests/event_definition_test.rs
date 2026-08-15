use synq_compiler::ast::SourceUnit;
use synq_compiler::parser;

const FLAT_EVENT_CONTRACT: &str = r#"
contract Main {
  state {
    owner: address;
    initialised: bool;
  }

  event OwnerChanged(owner: address);
  event Transfer(from: address, to: address, indexed amount: u256);

  impl {
    @public
    function init(initialOwner: address) -> bool {
      owner = initialOwner;
      initialised = true;
      return true;
    }
  }
}
"#;

const WRAPPED_EVENT_CONTRACT: &str = r#"
contract Main {
  state {
    owner: address;
  }

  events {
    event OwnerChanged(owner: address);
  }

  impl {
    @public
    function init(initialOwner: address) -> bool {
      owner = initialOwner;
      return true;
    }
  }
}
"#;

fn parse_single_contract(source: &str) -> synq_compiler::ast::ContractDefinition {
    let units = parser::parse(source).expect("parse failed");
    assert_eq!(units.len(), 1);
    match units.into_iter().next().unwrap() {
        SourceUnit::Contract(c) => c,
        other => panic!("expected a contract, got {:?}", other),
    }
}

#[test]
fn test_flat_event_declaration_parses() {
    // Regression test: `event Name(...);` declared directly in the contract
    // body (the syntax used by every SynQ Starter / HRZN / project template)
    // used to be rejected outright by the grammar ("expected contract_section")
    // because event_definition was missing from the flat-legacy list.
    let c = parse_single_contract(FLAT_EVENT_CONTRACT);
    assert_eq!(c.event_defs.len(), 2, "expected both flat events to be captured");

    let owner_changed = &c.event_defs[0];
    assert_eq!(owner_changed.name, "OwnerChanged");
    assert_eq!(owner_changed.params.len(), 1);
    assert_eq!(owner_changed.params[0].name, "owner");
    assert!(!owner_changed.params[0].is_indexed);

    let transfer = &c.event_defs[1];
    assert_eq!(transfer.name, "Transfer");
    assert_eq!(transfer.params.len(), 3);
    assert_eq!(transfer.params[2].name, "amount");
    assert!(transfer.params[2].is_indexed, "`indexed amount` should set is_indexed = true");
    assert!(!transfer.params[0].is_indexed);
}

#[test]
fn test_wrapped_events_section_parses() {
    // Even the grammar-valid `events { event X(...); }` form used to silently
    // parse-but-drop every event (parser.rs had no match arm for
    // Rule::events_section, and hardcoded event_defs: vec![] on return).
    let c = parse_single_contract(WRAPPED_EVENT_CONTRACT);
    assert_eq!(c.event_defs.len(), 1);
    assert_eq!(c.event_defs[0].name, "OwnerChanged");
}

#[test]
fn test_event_defs_feed_solidity_transpile() {
    // event_defs must actually reach the Solidity transpiler's ABI output,
    // not just parse successfully.
    let units = parser::parse(FLAT_EVENT_CONTRACT).expect("parse failed");
    let sol = synq_compiler::transpile_solidity::transpile_to_solidity(&units);
    assert!(sol.contains("event OwnerChanged"), "solidity output missing OwnerChanged event:\n{}", sol);
    assert!(sol.contains("event Transfer"), "solidity output missing Transfer event:\n{}", sol);
}
