//! Gap-analysis test v2: fixed syntax to match the actual pest grammar.
//! Runs every contract pattern through compile_ir() to find true IR backend gaps.
//!
//! Run with: cargo test --release -p synq-compiler ir_backend_gap_analysis -- --nocapture

use synq_compiler::compile_ir;

struct TestCase { name: &'static str, source: &'static str }

// ── Passing tests (unchanged) ───────────────────────────────────────────────

const SIMPLE_WITH_PARAMS: &str = r#"pragma synq ^0.9;
contract SimpleContract {
    state {
        value: u256;
        initialised: bool;
    }
    @public
    function init() -> bool {
        if (!initialised) { value = 42; initialised = true; }
        return true;
    }
    @public
    function get_value() -> u256 { return value; }
}
"#;

const TWO_STATE_VARS: &str = r#"pragma synq ^0.9;
contract MultiState {
    state { a: u256; b: u256; c: bool; }
    @public
    function set_all(x: u256, y: u256) -> bool {
        a = x; b = y; c = true;
        return true;
    }
}
"#;

const IF_ELSE: &str = r#"pragma synq ^0.9;
contract CondContract {
    state { flag: bool; result: u256; }
    @public
    function set_if(x: u256) -> bool {
        if (x > 10) { result = x; flag = true; }
        else { result = 0; flag = false; }
        return true;
    }
}
"#;

const WHILE_LOOP: &str = r#"pragma synq ^0.9;
contract LoopContract {
    state { sum: u256; }
    @public
    function loop_sum(n: u256) -> bool {
        let i: u256 = 0;
        sum = 0;
        while (i < n) { sum = sum + i; i = i + 1; }
        return true;
    }
}
"#;

const BINARY_SEARCH: &str = r#"pragma synq ^0.9;
contract SqrtFinder {
    state { result: u256; }
    @public
    function sqrt(target: u256) -> bool {
        let lo: u256 = 0;
        let hi: u256 = target;
        result = 0;
        while (lo <= hi) {
            let mid: u256 = lo + (hi - lo) / 2;
            if (mid <= target / mid) { result = mid; lo = mid + 1; }
            else { hi = mid - 1; }
        }
        return true;
    }
}
"#;

const REQUIRE_STATEMENT: &str = r#"pragma synq ^0.9;
contract RequireTest {
    state { balance: u256; }
    @public
    function withdraw(amount: u256) -> bool {
        require(balance >= amount, "insufficient balance");
        balance = balance - amount;
        return true;
    }
}
"#;

const NESTED_CALLS: &str = r#"pragma synq ^0.9;
contract Caller {
    state { value: u256; }
    @public
    function double(x: u256) -> u256 { return x + x; }
    @public
    function quad(x: u256) -> u256 { return double(double(x)); }
}
"#;

const AUTHORITY_FUNCTION: &str = r#"pragma synq ^0.9;
contract AuthContract {
    state { owner: u256; }
    @public
    function init() -> bool { owner = 0; return true; }
    @authority(Owner)
    function set_owner(new_owner: u256) -> bool {
        owner = new_owner;
        return true;
    }
}
"#;

const GOVERNANCE_FUNCTION: &str = r#"pragma synq ^0.9;
contract GovContract {
    state { proposal_count: u256; }
    @governance(ProposalManager)
    function create_proposal() -> bool {
        proposal_count = proposal_count + 1;
        return true;
    }
}
"#;

const TUPLE_RETURN: &str = r#"pragma synq ^0.9;
contract TupleContract {
    state { a: u256; b: u256; }
    @public
    function swap(x: u256, y: u256) -> (u256, u256) {
        return (y, x);
    }
    @public
    function set_both(x: u256, y: u256) -> bool {
        let result: (u256, u256) = swap(x, y);
        a = result.0;
        b = result.1;
        return true;
    }
}
"#;

const STRUCT_BASIC: &str = r#"pragma synq ^0.9;
struct Point { x: u256; y: u256; }
contract StructTest {
    state { origin: Point; }
    @public
    function set_origin(x: u256, y: u256) -> bool {
        origin = Point { x: x, y: y };
        return true;
    }
    @public
    function get_x() -> u256 { return origin.x; }
}
"#;

const STRUCT_FIELD_ASSIGN: &str = r#"pragma synq ^0.9;
struct Point { x: u256; y: u256; }
contract FieldAssignTest {
    state { pt: Point; }
    @public
    function set_x(val: u256) -> bool {
        pt.x = val;
        return true;
    }
    @public
    function get_x() -> u256 { return pt.x; }
}
"#;

const TUPLE_PACK_UNPACK: &str = r#"pragma synq ^0.9;
contract TuplePackTest {
    state { stored: (u256, u256, u256); }
    @public
    function store_triple(a: u256, b: u256, c: u256) -> bool {
        stored = (a, b, c);
        return true;
    }
    @public
    function get_first() -> u256 { return stored.0; }
}
"#;

const TUPLE_SWAP_DESTRUCTURE: &str = r#"pragma synq ^0.9;
contract SwapTest {
    state { a: u256; b: u256; }
    @public
    function do_swap() -> bool {
        let tmp: u256 = a;
        a = b;
        b = tmp;
        return true;
    }
}
"#;

const ENUM_FULL: &str = r#"pragma synq ^0.9;
enum Status { Active, Inactive, Pending, Cancelled }
contract EnumContract {
    state { status: u256; }
    @public
    function set_active() -> bool { status = Status::Active; return true; }
    @public
    function set_pending() -> bool { status = Status::Pending; return true; }
    @public
    function get_status() -> u256 { return status; }
}
"#;

const REVERT_NAMED: &str = r#"pragma synq ^0.9;
enum VaultError { InsufficientBalance, Unauthorized, InvalidAmount }
contract Vault {
    state { balance: u256; }
    @public
    function withdraw(amount: u256) -> bool {
        if (amount > balance) { revert VaultError::InsufficientBalance; }
        balance = balance - amount;
        return true;
    }
}
"#;

const EFFECTS_ATTR: &str = r#"pragma synq ^0.9;
contract EffectsContract {
    state { value: u256; }
    @effects(read, write)
    @public
    function read_write() -> u256 {
        value = value + 1;
        return value;
    }
    @effects(read)
    @public
    function read_only() -> u256 { return value; }
}
"#;

// ── Fixed syntax tests ──────────────────────────────────────────────────────

const MAP_OPERATIONS: &str = r#"pragma synq ^0.9;
contract MapTest {
    state { data: map<u256, u256>; }
    @public
    function set(key: u256, val: u256) -> bool {
        data[key] = val;
        return true;
    }
    @public
    function get(key: u256) -> u256 {
        return data[key];
    }
}
"#;

const SET_OPERATIONS: &str = r#"pragma synq ^0.9;
contract SetTest {
    state { members: set<u256>; }
    @public
    function add(val: u256) -> bool {
        members.add(val);
        return true;
    }
    @public
    function check(val: u256) -> bool {
        return members.contains(val);
    }
}
"#;

const EXTERN_CALL: &str = r#"pragma synq ^0.9;
contract Token {
    state { supply: u256; }
    @public
    function init() -> bool { supply = 1000; return true; }
    @public
    function mint(to: u256, amount: u256) -> bool {
        supply = supply + amount;
        return true;
    }
}
contract Vault {
    state { token: u256; }
    @public
    function init(token_addr: u256) -> bool { token = token_addr; return true; }
    @public
    function deposit(amount: u256) -> bool {
        extern_call("Token", "mint", token, amount);
        return true;
    }
}
"#;

const ASSET_OPS: &str = r#"pragma synq ^0.9;
contract AssetContract {
    state { count: u256; }
    @public
    function create_asset() -> bool {
        let a: u256 = asset_create("TestAsset", 100);
        asset_burn(a);
        count = count + 1;
        return true;
    }
}
"#;

const REQUIRES_MODIFIES: &str = r#"pragma synq ^0.9;
contract StateContract {
    state { value: u256; flag: bool; }
    @public
    function get_value() -> u256
        requires value >= 0
    {
        return value;
    }
    @public
    function set_value(v: u256) -> bool
        modifies value
    {
        value = v;
        return true;
    }
}
"#;

fn all_test_cases() -> Vec<TestCase> {
    vec![
        TestCase { name: "simple_with_params",      source: SIMPLE_WITH_PARAMS },
        TestCase { name: "two_state_vars",           source: TWO_STATE_VARS },
        TestCase { name: "if_else",                 source: IF_ELSE },
        TestCase { name: "while_loop",              source: WHILE_LOOP },
        TestCase { name: "binary_search",           source: BINARY_SEARCH },
        TestCase { name: "require_statement",       source: REQUIRE_STATEMENT },
        TestCase { name: "nested_calls",            source: NESTED_CALLS },
        TestCase { name: "authority_function",       source: AUTHORITY_FUNCTION },
        TestCase { name: "governance_function",      source: GOVERNANCE_FUNCTION },
        TestCase { name: "tuple_return",            source: TUPLE_RETURN },
        TestCase { name: "struct_basic",            source: STRUCT_BASIC },
        TestCase { name: "struct_field_assign",      source: STRUCT_FIELD_ASSIGN },
        TestCase { name: "tuple_pack_unpack",        source: TUPLE_PACK_UNPACK },
        TestCase { name: "tuple_swap_destructure",    source: TUPLE_SWAP_DESTRUCTURE },
        TestCase { name: "enum_full",               source: ENUM_FULL },
        TestCase { name: "revert_named",            source: REVERT_NAMED },
        TestCase { name: "effects_attr",            source: EFFECTS_ATTR },
        // Fixed syntax:
        TestCase { name: "map_operations",           source: MAP_OPERATIONS },
        TestCase { name: "set_operations",            source: SET_OPERATIONS },
        TestCase { name: "extern_call",             source: EXTERN_CALL },
        TestCase { name: "asset_ops",                source: ASSET_OPS },
        TestCase { name: "requires_modifies",        source: REQUIRES_MODIFIES },
    ]
}

#[test]
fn ir_backend_gap_analysis() {
    let cases = all_test_cases();
    let mut passed = 0;
    let mut failed = 0;
    let mut errors: Vec<(String, String)> = Vec::new();

    for tc in &cases {
        match compile_ir(tc.source) {
            Ok(result) => {
                if result.bytecode.is_empty() {
                    failed += 1;
                    errors.push((tc.name.to_string(), "empty bytecode".to_string()));
                    println!("❌ {} — empty bytecode", tc.name);
                } else {
                    let magic = u32::from_le_bytes(result.bytecode[0..4].try_into().unwrap());
                    if magic == 0x51564D00 {
                        passed += 1;
                        println!("✅ {} — {} bytes", tc.name, result.bytecode.len());
                    } else {
                        failed += 1;
                        errors.push((tc.name.to_string(), format!("bad magic: 0x{:08X}", magic)));
                        println!("❌ {} — bad magic 0x{:08X}", tc.name, magic);
                    }
                }
            }
            Err(e) => {
                failed += 1;
                let short = if e.len() > 200 { format!("{}...", &e[..200]) } else { e };
                errors.push((tc.name.to_string(), short.clone()));
                println!("❌ {} — {}", tc.name, &short);
            }
        }
    }

    println!("\n══════════════════════════════════════════════════════");
    println!("IR Backend Gap Analysis: {} passed, {} failed, {} total",
        passed, failed, passed + failed);
    println!("══════════════════════════════════════════════════════");

    if !errors.is_empty() {
        println!("\nFailures:");
        for (name, err) in &errors {
            println!("  ❌ {}: {}", name, err);
        }
    }
}
