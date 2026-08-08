use synq_compiler::parser::parse;
use synq_compiler::ast::*;

#[test]
fn test_spec_style_pub_fn() {
    let src = "contract Counter {\n  state {\n    count: u64;\n  }\n  security {\n    admin: \"admin_key\";\n  }\n  impl {\n    pub fn init() -> bool {\n      self.count = 0;\n      return true;\n    }\n    pub fn increment() -> bool {\n      self.count = self.count + 1;\n      return true;\n    }\n    view fn get() -> u64 {\n      return self.count;\n    }\n    priv fn helper() -> bool {\n      return true;\n    }\n  }\n}\n";
    let ast = parse(src).unwrap();
    let contract = ast.iter().find_map(|u| {
        if let SourceUnit::Contract(c) = u { Some(c) } else { None }
    }).unwrap();
    
    // Should have 4 functions
    let fns: Vec<&FunctionDefinition> = contract.parts.iter()
        .filter_map(|p| if let ContractPart::Function(f) = p { Some(f) } else { None })
        .collect();
    assert_eq!(fns.len(), 4);
    
    // init and increment should be public (pub fn)
    assert!(fns[0].is_public, "init should be public");
    assert!(fns[1].is_public, "increment should be public");
    
    // get should be public (view fn)
    assert!(fns[2].is_public, "get should be public (view fn)");
    
    // helper should be private (priv fn)
    assert!(!fns[3].is_public, "helper should be private");
}

#[test]
fn test_spec_style_trap() {
    let src = "contract Vault {\n  state {\n    balance: u64;\n  }\n  impl {\n    @public\n    function withdraw(amount: u64) -> bool {\n      if (self.balance < amount) {\n        trap 1;\n      }\n      self.balance = self.balance - amount;\n      return true;\n    }\n  }\n}\n";
    let ast = parse(src).unwrap();
    assert_eq!(ast.len(), 1);
}

#[test]
fn test_spec_style_mixed_syntax() {
    // Mix old-style and new-style in same contract
    let src = "contract Mixed {\n  state {\n    val: u64;\n  }\n  impl {\n    @public\n    function old_style() -> bool {\n      val = 1;\n      return true;\n    }\n    pub fn new_style() -> bool {\n      self.val = 2;\n      return true;\n    }\n  }\n}\n";
    let ast = parse(src).unwrap();
    let contract = ast.iter().find_map(|u| {
        if let SourceUnit::Contract(c) = u { Some(c) } else { None }
    }).unwrap();
    let fns: Vec<&FunctionDefinition> = contract.parts.iter()
        .filter_map(|p| if let ContractPart::Function(f) = p { Some(f) } else { None })
        .collect();
    assert_eq!(fns.len(), 2);
    assert!(fns[0].is_public, "old_style @public should be public");
    assert!(fns[1].is_public, "new_style pub fn should be public");
}
