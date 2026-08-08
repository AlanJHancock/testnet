// ── SynQ → Solidity Transpiler ─────────────────────────────────────────────────
//
// Transpiles SynQ AST to Solidity source for EVM deployment via SXCP.
// Both QVM bytecode and Solidity derive from the same AST → same SQB signature
// attests their semantic equivalence.
//
// Limitations: PQC ops (Aegis, authority envelopes), governance scopes, and
// asset builtins are emitted as comments/stubs — the common subset (state,
// functions, arithmetic, branching, loops, maps, structs, enums, events)
// maps directly to Solidity.

use std::fmt::Write;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use crate::ast::*;


// ── Type inference context ───────────────────────────────────────────────────
// Tracks variable types per-function for Solidity type inference.
// SynQ infers types at compile time; the transpiler needs them to emit
// correct Solidity (bool vs uint256, int32 vs uint256, string vs bytes).

thread_local! {
    static TYPE_CTX: RefCell<HashMap<String, Type>> = RefCell::new(HashMap::new());
    static BUILTIN_FLAGS: RefCell<BuiltinFlags> = RefCell::new(BuiltinFlags::default());
}

#[derive(Default)]
struct BuiltinFlags {
    needs_to_tsynq: bool,
    needs_from_tsynq: bool,
    needs_contract_addr: bool,
    needs_asset: bool,
}

fn set_type(name: &str, ty: Type) {
    TYPE_CTX.with(|ctx| ctx.borrow_mut().insert(name.to_string(), ty));
}

fn get_type(name: &str) -> Option<Type> {
    TYPE_CTX.with(|ctx| ctx.borrow().get(name).cloned())
}

/// Infer the SynQ type of an expression, given the current type context.
fn infer_expr_type(expr: &Expression) -> Type {
    match expr {
        Expression::BinaryOp(l, op, _) => match op {
            BinaryOperator::Eq | BinaryOperator::Ne | BinaryOperator::Lt
            | BinaryOperator::Le | BinaryOperator::Gt | BinaryOperator::Ge
            | BinaryOperator::And | BinaryOperator::Or => Type::Bool,
            BinaryOperator::Add => {
                let lt = infer_expr_type(l);
                if matches!(lt, Type::Str) { Type::Str } else { lt }
            }
            _ => infer_expr_type(l),
        },
        Expression::UnaryOp(op, val) => match op {
            UnaryOperator::Not => Type::Bool,
            UnaryOperator::Neg => infer_expr_type(val),
        },
        Expression::Literal(lit) => match lit {
            Literal::String(_) => Type::Str,
            Literal::Bool(_) => Type::Bool,
            Literal::Number(_) | Literal::BigNumber(_) => Type::UInt256,
            Literal::Hex(_) => Type::Bytes,
        },
        Expression::Identifier(name) => get_type(name).unwrap_or(Type::UInt256),
        Expression::Call(name, _) => match name.as_str() {
            "str_concat" => Type::Str,
            "str_eq" => Type::Bool,
            "str_len" => Type::UInt256,
            _ => {
                // Check if it's a known function returning a struct
                // For now, return UInt256 (most functions return uint256/bool)
                Type::UInt256
            }
        },
        Expression::Caller => Type::UInt256,
        Expression::FieldAccess { object, .. } => infer_expr_type(object),
        Expression::StructLiteral { type_name, .. } => Type::Named(type_name.clone()),
        _ => Type::UInt256,
    }
}

/// Transpile a parsed SynQ contract AST to Solidity source.
/// Collect (enum_name, variant_name, arg_count) tuples from all revert EnumName::VariantName(args) statements.
fn collect_revert_enum_errors(contract: &ContractDefinition) -> Vec<(String, String, usize)> {
    let mut errors = Vec::new();
    let mut seen = HashSet::new();
    for part in &contract.parts {
        if let ContractPart::Function(f) = part {
            scan_block_for_revert_enums(&f.body, &mut errors, &mut seen);
        }
    }
    errors
}

fn scan_block_for_revert_enums(
    block: &Block,
    errors: &mut Vec<(String, String, usize)>,
    seen: &mut HashSet<(String, String, usize)>,
) {
    for stmt in &block.statements {
        match stmt {
            Statement::RevertEnum { enum_name, error, args } => {
                let key = (enum_name.clone(), error.clone(), args.len());
                if !seen.contains(&key) {
                    seen.insert(key.clone());
                    errors.push(key);
                }
            }
            Statement::If { then_block, else_block, .. } => {
                scan_block_for_revert_enums(then_block, errors, seen);
                if let Some(eb) = else_block { scan_block_for_revert_enums(eb, errors, seen); }
            }
            Statement::While { body, .. } => scan_block_for_revert_enums(body, errors, seen),
            _ => {}
        }
    }
}

/// Detect which state variables are used as sets (have .add/.remove/.contains calls).
fn detect_set_vars(contract: &ContractDefinition) -> HashSet<String> {
    let mut vars = HashSet::new();
    for part in &contract.parts {
        if let ContractPart::Function(f) = part {
            scan_block_for_sets(&f.body, &mut vars);
        }
    }
    vars
}

fn scan_block_for_sets(block: &Block, vars: &mut HashSet<String>) {
    for stmt in &block.statements {
        match stmt {
            Statement::SetOp { set, .. } => { vars.insert(set.clone()); }
            Statement::Expression(expr) => { scan_expr_for_sets(expr, vars); }
            Statement::If { then_block, else_block, .. } => {
                scan_block_for_sets(then_block, vars);
                if let Some(eb) = else_block { scan_block_for_sets(eb, vars); }
            }
            Statement::While { body, .. } => scan_block_for_sets(body, vars),
            Statement::Return(e) => { if let Some(e) = e { scan_expr_for_sets(e, vars); } }
            _ => {}
        }
    }
}

fn scan_expr_for_sets(expr: &Expression, vars: &mut HashSet<String>) {
    match expr {
        Expression::SetMethod { set, .. } => { vars.insert(set.clone()); }
        Expression::BinaryOp(l, _, r) => { scan_expr_for_sets(l, vars); scan_expr_for_sets(r, vars); }
        Expression::Call(_, args) => { for a in args { scan_expr_for_sets(a, vars); } }
        Expression::MapIndex(_, keys) => { for k in keys { scan_expr_for_sets(k, vars); } }
        _ => {}
    }
}

pub fn transpile_to_solidity(units: &[SourceUnit]) -> String {
    // Find the contract definition
    let contract = units.iter().find_map(|u| {
        if let SourceUnit::Contract(c) = u { Some(c) } else { None }
    });
    let contract = match contract {
        Some(c) => c,
        None => return String::new(),
    };
    let mut out = String::new();

    // Reset builtin flags
    BUILTIN_FLAGS.with(|f| *f.borrow_mut() = BuiltinFlags::default());

    // Header
    writeln!(out, "// ═════════════════════════════════════════════════════════════════").unwrap();
    writeln!(out, "//  Auto-transpiled from SynQ → Solidity for EVM deployment (SXCP)").unwrap();
    writeln!(out, "//  Contract: {}", contract.name).unwrap();
    writeln!(out, "//").unwrap();
    writeln!(out, "//  This Solidity was generated from the same SynQ AST that produced").unwrap();
    writeln!(out, "//  the QVM bytecode in this SQB artifact. The ML-DSA-87 signature").unwrap();
    writeln!(out, "//  on the SQB attests that both targets derive from the same source.").unwrap();
    writeln!(out, "//").unwrap();
    writeln!(out, "//  NOTE: PQC operations, authority scopes, and asset builtins are").unwrap();
    writeln!(out, "//  emitted as comments — they require SXCP bridge precompiles on EVM.").unwrap();
    writeln!(out, "// ═════════════════════════════════════════════════════════════════").unwrap();
    writeln!(out, "// SPDX-License-Identifier: MIT").unwrap();
    writeln!(out, "pragma solidity ^0.8.20;").unwrap();
    writeln!(out).unwrap();

    // Struct definitions (top-level)
    for unit in units {
        if let SourceUnit::Struct(sd) = unit {
            writeln!(out, "struct {} {{", sd.name).unwrap();
            for field in &sd.fields {
                let mut ty_str = ty_to_sol(&field.ty);
                // Struct types need "memory" for local vars, but not in struct definitions
                // Just use the type name directly
                if ty_str.contains(" memory") { ty_str = ty_str.replace(" memory", ""); }
                writeln!(out, "    {} {};", ty_str, field.name).unwrap();
            }
            writeln!(out, "}}").unwrap();
            writeln!(out).unwrap();
        }
    }

    // Enums
    for ed in &contract.enums {
        writeln!(out, "enum {} {{", ed.name).unwrap();
        for (i, variant) in ed.variants.iter().enumerate() {
            let comma = if i + 1 < ed.variants.len() { "," } else { "" };
            if variant.fields.is_empty() {
                writeln!(out, "    {}{}", variant.name, comma).unwrap();
            } else {
                // Algebraic enums don't exist in Solidity — emit as comment + plain enum
                writeln!(out, "    {}{} // SynQ algebraic variant — fields: {:?}", variant.name, comma,
                    variant.fields.iter().map(|f| format!("{}: {:?}", f.name, f.ty)).collect::<Vec<_>>()
                ).unwrap();
            }
        }
        writeln!(out, "}}").unwrap();
        writeln!(out).unwrap();
    }

    // Custom error declarations for enum-based reverts
    // Scan all functions for revert EnumName::VariantName(args) and generate matching Solidity errors
    let revert_errors = collect_revert_enum_errors(contract);
    for (enum_name, variant_name, arg_count) in &revert_errors {
        let args: Vec<String> = (0..*arg_count).map(|_| "uint256".to_string()).collect();
        if *arg_count == 0 {
            writeln!(out, "error {}_{}();", enum_name, variant_name).unwrap();
        } else {
            writeln!(out, "error {}_{}({});", enum_name, variant_name, args.join(", ")).unwrap();
        }
    }
    if !revert_errors.is_empty() { writeln!(out).unwrap(); }

    // Events
    for ev in &contract.event_defs {
        let params: Vec<String> = ev.params.iter()
            .map(|p| {
                let ty_str = ty_to_sol(&p.ty);
                // Events use "memory" for reference types
                let needs_memory = matches!(p.ty, Type::Named(_) | Type::Str | Type::Bytes);
                let mem = if needs_memory { " memory" } else { "" };
                format!("{}{}{} {}", ty_str, mem, if p.is_indexed { " indexed" } else { "" }, p.name)
            })
            .collect();
        writeln!(out, "event {}({});", ev.name, params.join(", ")).unwrap();
    }
    if !contract.event_defs.is_empty() { writeln!(out).unwrap(); }

    // Named errors
    for err in &contract.error_defs {
        let params: Vec<String> = err.params.iter()
            .map(|p| {
                let ty_str = ty_to_sol(&p.ty);
                let needs_memory = matches!(p.ty, Type::Named(_) | Type::Str | Type::Bytes);
                if needs_memory {
                    format!("{} memory {}", ty_str, p.name)
                } else {
                    format!("{} {}", ty_str, p.name)
                }
            }).collect();
        writeln!(out, "error {}({});", err.name, params.join(", ")).unwrap();
    }
    if !contract.error_defs.is_empty() { writeln!(out).unwrap(); }

    // Contract body
    writeln!(out, "contract {} {{", contract.name).unwrap();
    writeln!(out).unwrap();

    // State variables
    let set_vars = detect_set_vars(contract);
    let mut has_state = false;
    for part in &contract.parts {
        if let ContractPart::StateVariable(sv) = part {
            let vis = if sv.is_public { "public" } else { "internal" };
            let ty_str = if set_vars.contains(&sv.name) {
                if let Type::Array(inner) = &sv.ty {
                    format!("mapping({} => bool)", ty_to_sol(inner))
                } else {
                    ty_to_sol(&sv.ty)
                }
            } else {
                ty_to_sol(&sv.ty)
            };
            writeln!(out, "    {} {} {};", ty_str, vis, sol_identifier(&sv.name)).unwrap();
            has_state = true;
        }
    }
    if has_state { writeln!(out).unwrap(); }

    // Constructor
    for part in &contract.parts {
        if let ContractPart::Constructor(c) = part {
            let params: Vec<String> = c.params.iter()
                .map(|p| {
                    let ty_str = ty_to_sol(&p.ty);
                    let needs_memory = matches!(p.ty, Type::Named(_) | Type::Str | Type::Bytes);
                    if needs_memory {
                        format!("{} memory {}", ty_str, p.name)
                    } else {
                        format!("{} {}", ty_str, p.name)
                    }
                }).collect();
            writeln!(out, "    constructor({}) {{", params.join(", ")).unwrap();
            transpile_block(&mut out, &c.body, 2);
            writeln!(out, "    }}").unwrap();
            writeln!(out).unwrap();
        }
    }

    // Functions
    let mut first_func = true;
    for part in &contract.parts {
        if let ContractPart::Function(f) = part {
            if !first_func { writeln!(out).unwrap(); }
            first_func = false;
            transpile_function(&mut out, f, contract);
        }
    }

    // Emit helper functions for used builtins
    BUILTIN_FLAGS.with(|flags| {
        let f = flags.borrow();
        if f.needs_asset {
            writeln!(out, "").unwrap();
            writeln!(out, "    // ── Asset registry (EVM simulation of SynQ asset builtins) ──").unwrap();
            writeln!(out, "    uint256 internal _nextAssetId;").unwrap();
            writeln!(out, "    mapping(uint256 => uint256) internal _assetBalance;").unwrap();
            writeln!(out, "    mapping(uint256 => uint256) internal _assetOwner;").unwrap();
            writeln!(out, "    mapping(uint256 => bool) internal _assetBurned;").unwrap();
            writeln!(out, "").unwrap();
            writeln!(out, "    function _asset_create(string memory /*symbol*/, uint256 value) internal returns (uint256) {{").unwrap();
            writeln!(out, "        uint256 id = ++_nextAssetId;").unwrap();
            writeln!(out, "        _assetBalance[id] = value;").unwrap();
            writeln!(out, "        _assetOwner[id] = uint256(uint160(msg.sender));").unwrap();
            writeln!(out, "        return id;").unwrap();
            writeln!(out, "    }}").unwrap();
            writeln!(out, "").unwrap();
            writeln!(out, "    function _asset_transfer(uint256 asset_id, uint256 to) internal returns (uint256) {{").unwrap();
            writeln!(out, "        require(!_assetBurned[asset_id], \"asset burned\");").unwrap();
            writeln!(out, "        require(_assetOwner[asset_id] == uint256(uint160(msg.sender)), \"not owner\");").unwrap();
            writeln!(out, "        uint256 new_id = ++_nextAssetId;").unwrap();
            writeln!(out, "        _assetBalance[new_id] = _assetBalance[asset_id];").unwrap();
            writeln!(out, "        _assetOwner[new_id] = to;").unwrap();
            writeln!(out, "        _assetBurned[asset_id] = true;").unwrap();
            writeln!(out, "        return new_id;").unwrap();
            writeln!(out, "    }}").unwrap();
            writeln!(out, "").unwrap();
            writeln!(out, "    function _asset_burn(uint256 asset_id) internal returns (uint256) {{").unwrap();
            writeln!(out, "        require(!_assetBurned[asset_id], \"already burned\");").unwrap();
            writeln!(out, "        require(_assetOwner[asset_id] == uint256(uint160(msg.sender)), \"not owner\");").unwrap();
            writeln!(out, "        uint256 value = _assetBalance[asset_id];").unwrap();
            writeln!(out, "        _assetBurned[asset_id] = true;").unwrap();
            writeln!(out, "        _assetBalance[asset_id] = 0;").unwrap();
            writeln!(out, "        return value;").unwrap();
            writeln!(out, "    }}").unwrap();
            writeln!(out, "").unwrap();
            writeln!(out, "    function _asset_balance(uint256 asset_id) internal view returns (uint256) {{").unwrap();
            writeln!(out, "        if (_assetBurned[asset_id]) return 0;").unwrap();
            writeln!(out, "        return _assetBalance[asset_id];").unwrap();
            writeln!(out, "    }}").unwrap();
            writeln!(out, "").unwrap();
            writeln!(out, "    function _asset_owner(uint256 asset_id) internal view returns (uint256) {{").unwrap();
            writeln!(out, "        if (_assetBurned[asset_id]) return 0;").unwrap();
            writeln!(out, "        return _assetOwner[asset_id];").unwrap();
            writeln!(out, "    }}").unwrap();
        }
        if f.needs_to_tsynq {
            writeln!(out, "").unwrap();
            writeln!(out, "    // SynQ Bech32m builtin: to_tsynq — full Bech32m encoding (matches QVM)").unwrap();
            writeln!(out, "    function _toSyna(address addr) internal pure returns (string memory) {{").unwrap();
            writeln!(out, "        // Build 41-byte internal address: version(1) + network_id(2) + algo_id(2) + pk_hash(32) + checksum(4)").unwrap();
            writeln!(out, "        bytes memory inner = new bytes(37);").unwrap();
            writeln!(out, "        inner[0] = 0x01;                       // version").unwrap();
            writeln!(out, "        inner[1] = 0x04; inner[2] = 0xf0;      // network_id (chain 1264 testnet)").unwrap();
            writeln!(out, "        inner[3] = 0x01; inner[4] = 0x02;      // algo_id (ML-DSA-65)").unwrap();
            writeln!(out, "        // pk_hash = 20-byte address zero-padded to 32 bytes").unwrap();
            writeln!(out, "        for (uint i = 0; i < 20; i++) inner[5 + i] = bytes20(addr)[i];").unwrap();
            writeln!(out, "        // bytes 25..37 are already zero (padding)").unwrap();
            writeln!(out, "        bytes32 chkHash = sha256(inner);").unwrap();
            writeln!(out, "        bytes memory full = new bytes(41);").unwrap();
            writeln!(out, "        for (uint i = 0; i < 37; i++) full[i] = inner[i];").unwrap();
            writeln!(out, "        full[37] = chkHash[0]; full[38] = chkHash[1]; full[39] = chkHash[2]; full[40] = chkHash[3];").unwrap();
            writeln!(out, "        // Convert 41 bytes to 5-bit groups").unwrap();
            writeln!(out, "        uint8[66] memory data5;").unwrap();
            writeln!(out, "        uint acc; uint bits; uint idx;").unwrap();
            writeln!(out, "        for (uint i = 0; i < 41; i++) {{").unwrap();
            writeln!(out, "            acc = (acc << 8) | uint8(full[i]);").unwrap();
            writeln!(out, "            bits += 8;").unwrap();
            writeln!(out, "            while (bits >= 5) {{").unwrap();
            writeln!(out, "                bits -= 5;").unwrap();
            writeln!(out, "                data5[idx++] = uint8((acc >> bits) & 0x1f);").unwrap();
            writeln!(out, "            }}").unwrap();
            writeln!(out, "        }}").unwrap();
            writeln!(out, "        if (bits > 0) data5[idx++] = uint8((acc << (5 - bits)) & 0x1f);").unwrap();
            writeln!(out, "        uint dataLen = idx;").unwrap();
            writeln!(out, "        // Bech32m checksum: polymod(hrp_expand ++ data ++ [0,0,0,0,0,0]) ^ 0x2bc830a3").unwrap();
            writeln!(out, "        // HRP = \"tsynq\" → hrp_expand = [20,19,14,17,16, 0, 24,23,14,13,18,16] (high||low bits)").unwrap();
            writeln!(out, "        uint8[11] memory hrpExp = [3,3,3,3,3, 0, 20,19,25,14,17];").unwrap();
            writeln!(out, "        uint chk = 1;").unwrap();
            writeln!(out, "        for (uint i = 0; i < 11; i++) {{").unwrap();
            writeln!(out, "            uint b = chk >> 25;").unwrap();
            writeln!(out, "            chk = ((chk & 0x1ffffff) << 5) ^ hrpExp[i];").unwrap();
            writeln!(out, "            for (uint j = 0; j < 5; j++) if ((b >> j) & 1 != 0) chk ^= [uint(0x3b6a57b2),0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3][j];").unwrap();
            writeln!(out, "        }}").unwrap();
            writeln!(out, "        for (uint i = 0; i < dataLen; i++) {{").unwrap();
            writeln!(out, "            uint b = chk >> 25;").unwrap();
            writeln!(out, "            chk = ((chk & 0x1ffffff) << 5) ^ data5[i];").unwrap();
            writeln!(out, "            for (uint j = 0; j < 5; j++) if ((b >> j) & 1 != 0) chk ^= [uint(0x3b6a57b2),0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3][j];").unwrap();
            writeln!(out, "        }}").unwrap();
            writeln!(out, "        for (uint i = 0; i < 6; i++) {{").unwrap();
            writeln!(out, "            uint b = chk >> 25;").unwrap();
            writeln!(out, "            chk = ((chk & 0x1ffffff) << 5) ^ 0;").unwrap();
            writeln!(out, "            for (uint j = 0; j < 5; j++) if ((b >> j) & 1 != 0) chk ^= [uint(0x3b6a57b2),0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3][j];").unwrap();
            writeln!(out, "        }}").unwrap();
            writeln!(out, "        chk ^= 0x2bc830a3;").unwrap();
            writeln!(out, "        // Build output string: \"tsynq\" + \"1\" + data5 + checksum(6) + charset").unwrap();
            writeln!(out, "        bytes memory charset = \"qpzry9x8gf2tvdw0s3jn54khce6mua7l\";").unwrap();
            writeln!(out, "        uint totalLen = 5 + 1 + dataLen + 6;").unwrap();
            writeln!(out, "        bytes memory result = new bytes(totalLen);").unwrap();
            writeln!(out, "        result[0]=bytes1(uint8(0x74)); result[1]=bytes1(uint8(0x73)); result[2]=bytes1(uint8(0x79)); result[3]=bytes1(uint8(0x6e)); result[4]=bytes1(uint8(0x71)); result[5]=bytes1(uint8(0x31));").unwrap();
            writeln!(out, "        for (uint i = 0; i < dataLen; i++) result[6 + i] = charset[data5[i]];").unwrap();
            writeln!(out, "        for (uint i = 0; i < 6; i++) {{").unwrap();
            writeln!(out, "            uint8 cv = uint8((chk >> (5 * (5 - i))) & 0x1f);").unwrap();
            writeln!(out, "            result[6 + dataLen + i] = charset[cv];").unwrap();
            writeln!(out, "        }}").unwrap();
            writeln!(out, "        return string(result);").unwrap();
            writeln!(out, "    }}").unwrap();
        }
        if f.needs_from_tsynq {
            writeln!(out, "").unwrap();
            writeln!(out, "    // SynQ Bech32m builtin: from_tsynq — decode Bech32m to 20-byte address (matches QVM)").unwrap();
            writeln!(out, "    function _fromSyna(string memory s) internal pure returns (uint256) {{").unwrap();
            writeln!(out, "        bytes memory b = bytes(s);").unwrap();
            writeln!(out, "        bytes memory charset = \"qpzry9x8gf2tvdw0s3jn54khce6mua7l\";").unwrap();
            writeln!(out, "        // Find separator 1").unwrap();
            writeln!(out, "        uint sep = 0;").unwrap();
            writeln!(out, "        for (uint i = 0; i < b.length; i++) if (b[i] == bytes1(uint8(0x31))) sep = i;").unwrap();
            writeln!(out, "        // Decode data chars after separator (skip last 6 = checksum)").unwrap();
            writeln!(out, "        uint dataLen = b.length - sep - 1 - 6;").unwrap();
            writeln!(out, "        uint8[] memory data5 = new uint8[](dataLen);").unwrap();
            writeln!(out, "        for (uint i = 0; i < dataLen; i++) {{").unwrap();
            writeln!(out, "            uint8 c = uint8(b[sep + 1 + i]);").unwrap();
            writeln!(out, "            for (uint j = 0; j < 32; j++) {{").unwrap();
            writeln!(out, "                if (uint8(charset[j]) == c) {{ data5[i] = uint8(j); break; }}").unwrap();
            writeln!(out, "            }}").unwrap();
            writeln!(out, "        }}").unwrap();
            writeln!(out, "        // Convert 5-bit groups back to 8-bit bytes").unwrap();
            writeln!(out, "        uint acc; uint bits; uint idx;").unwrap();
            writeln!(out, "        bytes memory decoded = new bytes(41);").unwrap();
            writeln!(out, "        for (uint i = 0; i < dataLen; i++) {{").unwrap();
            writeln!(out, "            acc = (acc << 5) | data5[i];").unwrap();
            writeln!(out, "            bits += 5;").unwrap();
            writeln!(out, "            while (bits >= 8) {{").unwrap();
            writeln!(out, "                bits -= 8;").unwrap();
            writeln!(out, "                decoded[idx++] = bytes1(uint8((acc >> bits) & 0xff));").unwrap();
            writeln!(out, "            }}").unwrap();
            writeln!(out, "        }}").unwrap();
            writeln!(out, "        // Extract 20-byte address from pk_hash (bytes 5..24, first 20 of 32)").unwrap();
            writeln!(out, "        uint256 result = 0;").unwrap();
            writeln!(out, "        for (uint i = 0; i < 20; i++) result = (result << 8) | uint8(decoded[5 + i]);").unwrap();
            writeln!(out, "        return result;").unwrap();
            writeln!(out, "    }}").unwrap();
        }
        if f.needs_contract_addr {
            writeln!(out, "").unwrap();
            writeln!(out, "    // SynQ Bech32 builtin: contract_address — EVM approximation (CREATE2-style)").unwrap();
            writeln!(out, "    function _contractAddress(uint256 deployer, uint256 nonce, uint256 artifactHash) internal pure returns (string memory) {{").unwrap();
            writeln!(out, "        bytes32 h = keccak256(abi.encodePacked(deployer, nonce, artifactHash));").unwrap();
            writeln!(out, "        return _toSyna(address(uint160(uint256(h))));").unwrap();
            writeln!(out, "    }}").unwrap();
        }
    });

    // Reset flags for next compilation
    BUILTIN_FLAGS.with(|f| *f.borrow_mut() = BuiltinFlags::default());

    writeln!(out, "}}").unwrap();
    out
}

fn transpile_function(out: &mut String, f: &FunctionDefinition, contract: &ContractDefinition) {
    // Build type context: state vars + function params
    TYPE_CTX.with(|ctx| ctx.borrow_mut().clear());
    for part in &contract.parts {
        if let ContractPart::StateVariable(sv) = part {
            set_type(&sv.name, sv.ty.clone());
        }
    }
    for p in &f.params {
        set_type(&p.name, p.ty.clone());
    }
    // Store return type for return casting
    if let Some(ret_ty) = &f.returns {
        set_type("__return_type__", ret_ty.clone());
    }
    let vis = "public";

    // Map attributes to Solidity modifiers/comments
    let mut modifiers = Vec::new();
    for attr in &f.attributes {
        match attr {
            Attribute::Authority(scope) => {
                modifiers.push(format!("// @authority(\"{}\") — requires SXCP authority bridge", scope));
            }
            Attribute::Governance(scope) => {
                modifiers.push(format!("// @governance(\"{}\") — requires SXCP governance bridge", scope));
            }
            Attribute::Effects(vs) => {
                modifiers.push(format!("// @effects({})", vs.join(", ")));
            }
            Attribute::Requires(e) => {
                modifiers.push(format!("// @requires({})", e));
            }
            Attribute::Ensures(e) => {
                modifiers.push(format!("// @ensures({})", e));
            }
            Attribute::Fails(n) => {
                modifiers.push(format!("// @fails({})", n));
            }
            Attribute::Bounded(b) => {
                modifiers.push(format!("// @bounded({})", b));
            }
            Attribute::Manifest => {
                modifiers.push("// @manifest".to_string());
            }
            Attribute::Ai => {
                modifiers.push("// @ai — requires SXCP AI inference bridge".to_string());
            }
            Attribute::Public => {}
        }
    }

    let params: Vec<String> = f.params.iter()
        .map(|p| {
            let ty_str = ty_to_sol(&p.ty);
            let needs_memory = matches!(p.ty, Type::Named(_) | Type::Str | Type::Bytes);
            if needs_memory {
                format!("{} memory {}", ty_str, sol_identifier(&p.name))
            } else {
                format!("{} {}", ty_str, sol_identifier(&p.name))
            }
        }).collect();

    let returns = match &f.returns {
        Some(ty) => {
            let ty_str = ty_to_sol(ty);
            if matches!(ty, Type::Named(_) | Type::Str | Type::Bytes) {
                format!(" returns ({} memory)", ty_str)
            } else if matches!(ty, Type::Tuple(_)) {
                format!(" returns {}", ty_str)
            } else {
                format!(" returns ({})", ty_str)
            }
        }
        None => {
            // Infer return type from return statements if any exist
            let inferred = infer_function_return_type(&f.body);
            match inferred {
                Some(ty) => {
                    let ty_str = ty_to_sol(&ty);
                    set_type("__return_type__", ty.clone());
                    if matches!(ty, Type::Named(_) | Type::Str | Type::Bytes) {
                        format!(" returns ({} memory)", ty_str)
                    } else if matches!(ty, Type::Tuple(_)) {
                        format!(" returns {}", ty_str)
                    } else {
                        format!(" returns ({})", ty_str)
                    }
                }
                None => String::new(),
            }
        }
    };

    // Detect view: a function is view iff it does NOT modify state.
    // Check three signals: @effects attr, explicit modifies list, and
    // actual assignments to state variables in the body (direct assignment,
    // field assignment, map assignment, or set op).
    let has_effects = f.attributes.iter().any(|a| matches!(a, Attribute::Effects(_)));
    let has_modifies = !f.modifies.is_empty();
    let state_var_names: std::collections::HashSet<String> = contract.parts.iter()
        .filter_map(|p| if let ContractPart::StateVariable(sv) = p { Some(sv.name.clone()) } else { None })
        .collect();
    fn body_writes_state(block: &Block, state_vars: &std::collections::HashSet<String>) -> bool {
        for stmt in &block.statements {
            match stmt {
                Statement::Assignment(name, _) => {
                    if state_vars.contains(name) { return true; }
                }
                Statement::FieldAssignment { .. } | Statement::MapAssignment { .. } | Statement::SetOp { .. } => {
                    return true; // field/map/set writes always touch state
                }
                Statement::If { then_block, else_block, .. } => {
                    if body_writes_state(then_block, state_vars) { return true; }
                    if let Some(e) = else_block {
                        if body_writes_state(e, state_vars) { return true; }
                    }
                }
                Statement::While { body, .. } => {
                    if body_writes_state(body, state_vars) { return true; }
                }
                _ => {}
            }
        }
        false
    }
    /// Detect calls to state-changing builtins: asset_create, asset_transfer,
    /// asset_burn, and extern_call (cross-contract calls may mutate state).
    fn body_calls_state_changing_builtin(block: &Block) -> bool {
        for stmt in &block.statements {
            match stmt {
                Statement::Expression(e) | Statement::Let { value: e, .. } => {
                    if expr_calls_state_builtin(e) { return true; }
                }
                Statement::Assignment(_, e) => {
                    if expr_calls_state_builtin(e) { return true; }
                }
                Statement::Require(cond, _) => {
                    if expr_calls_state_builtin(cond) { return true; }
                }
                Statement::Return(Some(e)) => {
                    if expr_calls_state_builtin(e) { return true; }
                }
                Statement::ExternCall { .. } => return true,
                Statement::Emit { .. } => return true,
                Statement::If { condition, then_block, else_block, .. } => {
                    if expr_calls_state_builtin(condition) { return true; }
                    if body_calls_state_changing_builtin(then_block) { return true; }
                    if let Some(eb) = else_block {
                        if body_calls_state_changing_builtin(eb) { return true; }
                    }
                }
                Statement::While { condition, body } => {
                    if expr_calls_state_builtin(condition) { return true; }
                    if body_calls_state_changing_builtin(body) { return true; }
                }
                _ => {}
            }
        }
        false
    }
    fn expr_calls_state_builtin(e: &Expression) -> bool {
        match e {
            Expression::Call(name, _) => {
                matches!(name.as_str(),
                    "asset_create" | "asset_transfer" | "asset_burn" |
                    "extern_call"
                )
            }
            Expression::BinaryOp(a, _, b) => {
                expr_calls_state_builtin(a) || expr_calls_state_builtin(b)
            }
            Expression::UnaryOp(_, a) => expr_calls_state_builtin(a),
            Expression::Tuple(exprs) => exprs.iter().any(expr_calls_state_builtin),
            Expression::Some(e) | Expression::Ok(e) | Expression::Err(e) => expr_calls_state_builtin(e),
            Expression::FieldAccess { object, .. } => expr_calls_state_builtin(object),
            Expression::TupleIndex { object, .. } => expr_calls_state_builtin(object),
            Expression::MapMethod { .. } | Expression::MapIndex(..) => false,
            Expression::SetMethod { .. } => false,
            Expression::StructLiteral { fields, .. } => {
                fields.iter().any(|(_, v)| expr_calls_state_builtin(v))
            }
            _ => false,
        }
    }
    let writes_state = body_writes_state(&f.body, &state_var_names);
    let calls_state_builtin = body_calls_state_changing_builtin(&f.body);
    let is_view = !has_effects && !has_modifies && !writes_state && !calls_state_builtin;

    let view_modifier = if is_view { " view" } else { "" };

    let mut sig = format!("    function {}({}) {}{}{}", f.name, params.join(", "), vis, view_modifier, returns);
    if f.requires_caller {
        sig.push_str(" /* as caller */");
    }

    for m in &modifiers {
        writeln!(out, "{}", m).unwrap();
    }
    writeln!(out, "{} {{", sig).unwrap();

    if !f.requires_state.is_empty() {
        writeln!(out, "        // requires: {}", f.requires_state.join(", ")).unwrap();
    }
    if !f.modifies.is_empty() {
        writeln!(out, "        // modifies: {}", f.modifies.join(", ")).unwrap();
    }

    transpile_block(out, &f.body, 2);

    // If function declares returns but has no actual return statement
    // (e.g. all returns are via extern_call comments), add a default return
    if f.returns.is_some() || infer_function_return_type(&f.body).is_some() {
        if !block_has_return(&f.body) {
            let ret_ty = f.returns.clone().or_else(|| infer_function_return_type(&f.body));
            let default_val = match &ret_ty {
                Some(Type::Bool) => "false",
                Some(Type::UInt256) | Some(Type::UInt128) => "0",
                Some(Type::Int32) | Some(Type::Int256) => "0",
                Some(Type::Address) => "address(0)",
                _ => "0",
            };
            writeln!(out, "        return {};", default_val).unwrap();
        }
    }

    writeln!(out, "    }}").unwrap();
}

/// Infer the return type of a function by examining its return statements.
pub fn infer_function_return_type(block: &Block) -> Option<Type> {
    for stmt in &block.statements {
        match stmt {
            Statement::Return(Some(expr)) => {
                return Some(infer_expr_type(expr));
            }
            Statement::If { then_block, else_block, .. } => {
                if let Some(ty) = infer_function_return_type(then_block) {
                    return Some(ty);
                }
                if let Some(eb) = else_block {
                    if let Some(ty) = infer_function_return_type(eb) {
                        return Some(ty);
                    }
                }
            }
            Statement::While { body, .. } => {
                if let Some(ty) = infer_function_return_type(body) {
                    return Some(ty);
                }
            }
            _ => {}
        }
    }
    None
}

/// Determine if a function should be marked `view` in Solidity.
/// A function is view iff it does NOT modify state, does NOT have @effects,
/// does NOT call state-changing builtins, and does NOT write to state vars.
pub fn is_function_view(f: &FunctionDefinition, contract: &ContractDefinition) -> bool {
    let has_effects = f.attributes.iter().any(|a| matches!(a, Attribute::Effects(_)));
    let has_modifies = !f.modifies.is_empty();
    let state_var_names: std::collections::HashSet<String> = contract.parts.iter()
        .filter_map(|p| if let ContractPart::StateVariable(sv) = p { Some(sv.name.clone()) } else { None })
        .collect();
    fn body_writes_state(block: &Block, state_vars: &std::collections::HashSet<String>) -> bool {
        for stmt in &block.statements {
            match stmt {
                Statement::Assignment(name, _) => {
                    if state_vars.contains(name) { return true; }
                }
                Statement::FieldAssignment { .. } | Statement::MapAssignment { .. } | Statement::SetOp { .. } => {
                    return true;
                }
                Statement::If { then_block, else_block, .. } => {
                    if body_writes_state(then_block, state_vars) { return true; }
                    if let Some(e) = else_block {
                        if body_writes_state(e, state_vars) { return true; }
                    }
                }
                Statement::While { body, .. } => {
                    if body_writes_state(body, state_vars) { return true; }
                }
                _ => {}
            }
        }
        false
    }
    fn body_calls_state_changing_builtin(block: &Block) -> bool {
        for stmt in &block.statements {
            match stmt {
                Statement::Expression(e) | Statement::Let { value: e, .. } => {
                    if expr_calls_state_builtin(e) { return true; }
                }
                Statement::Assignment(_, e) => {
                    if expr_calls_state_builtin(e) { return true; }
                }
                Statement::Require(cond, _) => {
                    if expr_calls_state_builtin(cond) { return true; }
                }
                Statement::Return(Some(e)) => {
                    if expr_calls_state_builtin(e) { return true; }
                }
                Statement::ExternCall { .. } => return true,
                Statement::Emit { .. } => return true,
                Statement::If { condition, then_block, else_block, .. } => {
                    if expr_calls_state_builtin(condition) { return true; }
                    if body_calls_state_changing_builtin(then_block) { return true; }
                    if let Some(eb) = else_block {
                        if body_calls_state_changing_builtin(eb) { return true; }
                    }
                }
                Statement::While { condition, body } => {
                    if expr_calls_state_builtin(condition) { return true; }
                    if body_calls_state_changing_builtin(body) { return true; }
                }
                _ => {}
            }
        }
        false
    }
    fn expr_calls_state_builtin(e: &Expression) -> bool {
        match e {
            Expression::Call(name, _) => {
                matches!(name.as_str(),
                    "asset_create" | "asset_transfer" | "asset_burn" |
                    "extern_call"
                )
            }
            Expression::BinaryOp(a, _, b) => {
                expr_calls_state_builtin(a) || expr_calls_state_builtin(b)
            }
            Expression::UnaryOp(_, a) => expr_calls_state_builtin(a),
            Expression::Tuple(exprs) => exprs.iter().any(expr_calls_state_builtin),
            Expression::Some(e) | Expression::Ok(e) | Expression::Err(e) => expr_calls_state_builtin(e),
            Expression::FieldAccess { object, .. } => expr_calls_state_builtin(object),
            Expression::TupleIndex { object, .. } => expr_calls_state_builtin(object),
            _ => false,
        }
    }
    let writes_state = body_writes_state(&f.body, &state_var_names);
    let calls_state_builtin = body_calls_state_changing_builtin(&f.body);
    !has_effects && !has_modifies && !writes_state && !calls_state_builtin
}

/// Check if a block has any actual return statement (not just extern_call comments).
pub fn block_has_return(block: &Block) -> bool {
    for stmt in &block.statements {
        match stmt {
            Statement::Return(_) => return true,
            Statement::If { then_block, else_block, .. } => {
                if block_has_return(then_block) { return true; }
                if let Some(eb) = else_block {
                    if block_has_return(eb) { return true; }
                }
            }
            Statement::While { body, .. } => {
                if block_has_return(body) { return true; }
            }
            _ => {}
        }
    }
    false
}

fn transpile_block(out: &mut String, block: &Block, indent: usize) {
    let pad = "    ".repeat(indent);
    for stmt in &block.statements {
        transpile_statement(out, stmt, indent);
        let _ = pad; // suppress unused warning
    }
}

fn transpile_statement(out: &mut String, stmt: &Statement, indent: usize) {
    let pad = "    ".repeat(indent);
    match stmt {
        Statement::Expression(expr) => {
            writeln!(out, "{}{};", pad, transpile_expr(expr)).unwrap();
        }
        Statement::Require(cond, msg) => {
            writeln!(out, "{}require({}, \"{}\");", pad, transpile_expr(cond), msg).unwrap();
        }
        Statement::RevertNamed { error, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            writeln!(out, "{}revert {}({});", pad, error, a.join(", ")).unwrap();
        }
        Statement::RevertEnum { enum_name, error, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            // SynQ enum-based revert -> Solidity custom error
            // revert EnumName::VariantName(args) -> revert EnumName_VariantName(args)
            writeln!(out, "{}revert {}_{}({});", pad, enum_name, error, a.join(", ")).unwrap();
        }
        Statement::Assignment(name, expr) => {
            let target_ty = get_type(name);
            let expr_ty = infer_expr_type(expr);
            let val_str = transpile_expr(expr);
            // Cast if assigning bool to uint256 or vice versa
            let cast_val = match (&target_ty.as_ref().map(resolve_type_alias), &expr_ty) {
                (Some(Type::UInt256), Type::Bool) => format!("({} ? uint256(1) : uint256(0))", val_str),
                (Some(Type::Address), Type::UInt256) => format!("address(uint160({}))", val_str),
                (Some(Type::Bytes), Type::UInt256) => format!("bytes20(uint160({}))", val_str),
                (Some(Type::BytesN(n)), Type::UInt256) => format!("bytes{}(uint160({}))", n, val_str),
                (Some(Type::Hash32), Type::UInt256) => format!("bytes32(uint256({}))", val_str),
                _ => val_str,
            };
            let cast_val = simplify_redundant_casts(&cast_val);
            writeln!(out, "{}{} = {};", pad, sol_identifier(name), cast_val).unwrap();
        }
        Statement::FieldAssignment { object, field, value } => {
            writeln!(out, "{}{}.{} = {};", pad, object, field, transpile_expr(value)).unwrap();
        }
        Statement::MapAssignment { map, keys, value } => {
            let mut index_sol = String::new();
            let mut current_type = get_type(map);
            for key in keys.iter() {
                let key_str = transpile_expr(key);
                let key_sol = match &current_type {
                    Some(Type::Mapping(k, _)) if matches!(k.as_ref(), Type::Address) => {
                        match key {
                            Expression::Caller => "address(uint160(msg.sender))".to_string(),
                            _ => format!("address(uint160({}))", key_str)
                        }
                    }
                    _ => key_str
                };
                index_sol.push_str(&format!("[{}]", key_sol));
                current_type = match &current_type {
                    Some(Type::Mapping(_, v)) => Some((**v).clone()),
                    _ => None,
                };
            }
            writeln!(out, "{}{}{} = {};", pad, map, index_sol, transpile_expr(value)).unwrap();
        }
        Statement::SetOp { set, op, value } => {
            let val_str = transpile_expr(value);
            match op {
                SetOpKind::Add => writeln!(out, "{}{}[{}] = true;", pad, set, val_str).unwrap(),
                SetOpKind::Remove => writeln!(out, "{}{}[{}] = false;", pad, set, val_str).unwrap(),
            }
        }
        Statement::Let { name, ty, value } => {
            let (ty_str, needs_memory) = if let Some(t) = ty {
                let mem = matches!(t, Type::Named(_) | Type::Str | Type::Bytes);
                (ty_to_sol(t), mem)
            } else {
                // Infer from expression using type context
                let inferred = infer_expr_type(value);
                set_type(name, inferred.clone());
                let mem = matches!(inferred, Type::Named(_) | Type::Str | Type::Bytes);
                (ty_to_sol(&inferred), mem)
            };
            if !ty.is_some() {
                // Register inferred type for later statements
            }
            if needs_memory {
                writeln!(out, "{}{} memory {} = {};", pad, ty_str, sol_identifier(name), transpile_expr(value)).unwrap();
            } else {
                writeln!(out, "{}{} {} = {};", pad, ty_str, sol_identifier(name), transpile_expr(value)).unwrap();
            }
        }
        Statement::LetDestructure { names, value } => {
            // Infer tuple types from the RHS expression
            let val_ty = infer_expr_type(value);
            let val_ty = resolve_type_alias(&val_ty);
            let type_strs: Vec<String> = match &val_ty {
                Type::Tuple(ts) => ts.iter().map(ty_to_sol).collect(),
                _ => names.iter().map(|_| ty_to_sol(&val_ty)).collect(),
            };
            let vars: Vec<String> = names.iter().enumerate()
                .map(|(i, n)| format!("{} {}", type_strs.get(i).unwrap_or(&"uint256".to_string()), sol_identifier(n)))
                .collect();
            writeln!(out, "{}({}) = {};", pad, vars.join(", "), transpile_expr(value)).unwrap();
        }
        Statement::Return(None) => {
            writeln!(out, "{}return;", pad).unwrap();
        }
        Statement::Return(Some(expr)) => {
            let val_str = transpile_expr(expr);
            let expr_ty = infer_expr_type(expr);
            let expr_ty = resolve_type_alias(&expr_ty);
            let ret_ty = get_type("__return_type__");
            // Only cast bool→uint256 when function returns uint256
            let cast_val = match (&ret_ty.as_ref().map(resolve_type_alias), &expr_ty) {
                (Some(Type::UInt256), Type::Bool) => format!("({} ? uint256(1) : uint256(0))", val_str),
                (Some(Type::UInt256), Type::Address) => format!("uint256(uint160({}))", val_str),
                (Some(Type::UInt256), Type::BytesN(_)) => format!("uint256(uint160({}))", val_str),
                (Some(Type::UInt256), Type::Hash32) => format!("uint256({})", val_str),
                (Some(Type::UInt256), Type::Bytes) => format!("uint256(uint160({}))", val_str),
                _ => val_str,
            };
            let cast_val = simplify_redundant_casts(&cast_val);
            writeln!(out, "{}return {};", pad, cast_val).unwrap();
        }
        Statement::ExternCall { contract, function, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            writeln!(out, "{}// extern_call {}.{}({}) — requires SXCP cross-contract bridge", pad, contract, function, a.join(", ")).unwrap();
        }
        Statement::Emit { event, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            writeln!(out, "{}emit {}({});", pad, event, a.join(", ")).unwrap();
        }
        Statement::If { condition, then_block, else_block } => {
            writeln!(out, "{}if ({}) {{", pad, transpile_expr(condition)).unwrap();
            transpile_block(out, then_block, indent + 1);
            if let Some(eb) = else_block {
                writeln!(out, "{}}} else {{", pad).unwrap();
                transpile_block(out, eb, indent + 1);
            }
            writeln!(out, "{}}}", pad).unwrap();
        }
        Statement::While { condition, body } => {
            writeln!(out, "{}while ({}) {{", pad, transpile_expr(condition)).unwrap();
            transpile_block(out, body, indent + 1);
            writeln!(out, "{}}}", pad).unwrap();
        }
        Statement::Break => {
            writeln!(out, "{}break;", pad).unwrap();
        }
        Statement::Continue => {
            writeln!(out, "{}continue;", pad).unwrap();
        }
    }
}

fn transpile_expr(expr: &Expression) -> String {
    match expr {
        Expression::Call(name, args) => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            // Map SynQ builtins to Solidity equivalents
            match name.as_str() {

                "str_len" => format!("bytes({}).length", transpile_expr(&args[0])),
                "str_concat" => format!("string.concat({})", a.join(", ")),
                "str_eq" => format!("(keccak256(bytes({})) == keccak256(bytes({})))", transpile_expr(&args[0]), transpile_expr(&args[1])),
                "dilithium_verify" | "falcon_verify" | "sphincs_verify" |
                "aegis_verify" | "ai_verify_proof" =>
                    format!("false /* SXCP bridge stub: {} */", name),
                "kyber_decaps" | "kyber_encaps" =>
                    format!("bytes(new bytes(0)) /* SXCP bridge stub: {} */", name),
                "asset_create" | "asset_transfer" | "asset_burn" |
                "asset_balance" | "asset_owner" => {
                    BUILTIN_FLAGS.with(|f| f.borrow_mut().needs_asset = true);
                    format!("_{}({})", name, a.join(", "))
                }
                "aegis_call" | "aegis_decaps" |
                "authority_envelope" | "authority_require" |
                "ai_infer" =>
                    format!("uint256(0) /* SXCP bridge stub: {} */", name),
                "authority_identity" =>
                    format!("uint256(uint160(msg.sender)) /* EVM approximation: authority_identity = msg.sender */"),
                "to_tsynq" | "to_syna" => {
                    BUILTIN_FLAGS.with(|f| f.borrow_mut().needs_to_tsynq = true);
                    format!("_toSyna(address(uint160({})))", transpile_expr(&args[0]))
                }
                "contract_address" => {
                    BUILTIN_FLAGS.with(|f| f.borrow_mut().needs_contract_addr = true);
                    format!("_contractAddress({}, {}, {})",
                        transpile_expr(&args[0]),
                        transpile_expr(&args[1]),
                        transpile_expr(&args[2]))
                },
                "from_tsynq" | "from_syna" | "from_syn" => {
                    BUILTIN_FLAGS.with(|f| f.borrow_mut().needs_from_tsynq = true);
                    format!("_fromSyna({})", transpile_expr(&args[0]))
                },
                "extern_call" => {
                    // extern_call in expression context — comment for SXCP bridge
                    let contract = match &args[0] {
                        Expression::Literal(Literal::String(s)) => s.as_str(),
                        _ => "unknown",
                    };
                    let function = match &args[1] {
                        Expression::Literal(Literal::String(s)) => s.as_str(),
                        _ => "unknown",
                    };
                    let call_args: Vec<String> = args[2..].iter().map(transpile_expr).collect();
                    format!("uint256(0) /* extern_call {}.{}({}) — SXCP bridge */", contract, function, call_args.join(", "))
                }
                "map_get" => {
                    // map_get(map_name, key) — transpile to map_name[key]
                    let map_name = match &args[0] {
                        Expression::Identifier(n) => n.clone(),
                        _ => "unknown".to_string(),
                    };
                    format!("{}[{}]", map_name, transpile_expr(&args[1]))
                }
                "map_set" => {
                    // map_set(map_name, key, value) — as expression statement, transpile inline
                    let map_name = match &args[0] {
                        Expression::Identifier(n) => n.clone(),
                        _ => "unknown".to_string(),
                    };
                    format!("/* {}[{}] = {} */", map_name, transpile_expr(&args[1]), transpile_expr(&args[2]))
                }
                _ => format!("{}({})", name, a.join(", ")),
            }
        }
        Expression::Literal(lit) => literal_to_sol(lit),
        Expression::Identifier(name) => sol_identifier(name),
        Expression::BinaryOp(l, op, r) => {
            let ls = transpile_expr(l);
            let rs = transpile_expr(r);
            match op {
                BinaryOperator::Add => {
                    // String concatenation: a + b → string.concat(a, b)
                    let lt = infer_expr_type(l);
                    if matches!(lt, Type::Str) {
                        format!("string.concat({}, {})", ls, rs)
                    } else {
                        format!("({} + {})", ls, rs)
                    }
                }
                _ => format!("({} {} {})", ls, binop_to_sol(op), rs),
            }
        }
        Expression::UnaryOp(op, val) => {
            format!("{}{}", unop_to_sol(op), transpile_expr(val))
        }
        Expression::Caller => "uint256(uint160(msg.sender))".to_string(),
        Expression::MapIndex(map, keys) => {
            let mut index_str = String::new();
            let mut current_type = get_type(map);
            for key in keys.iter() {
                let key_str = transpile_expr(key);
                let is_address_key = match &current_type {
                    Some(Type::Mapping(k, _)) => matches!(k.as_ref(), Type::Address),
                    _ => false,
                };
                if is_address_key {
                    match key {
                        Expression::Caller => index_str.push_str("[address(uint160(msg.sender))]"),
                        _ => index_str.push_str(&format!("[address(uint160({}))]", key_str)),
                    }
                } else {
                    index_str.push_str(&format!("[{}]", key_str));
                }
                current_type = match &current_type {
                    Some(Type::Mapping(_, v)) => Some((**v).clone()),
                    _ => None,
                };
            }
            format!("{}{}", sol_identifier(map), index_str)
        }
        Expression::MapMethod { map, method, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            match method.as_str() {
                "get" => format!("{}[{}]", map, a.join(", ")),
                "contains" => format!("({}[{}] != address(0))", map, a.join(", ")),
                "len" => format!("/* {}.len() — no native Solidity equivalent */", map),
                _ => format!("{}.{}({})", map, method, a.join(", ")),
            }
        }
        Expression::SetMethod { set, method, args } => {
            let a: Vec<String> = args.iter().map(transpile_expr).collect();
            match method.as_str() {
                "contains" => format!("{}[{}]", set, a.join(", ")),
                "len" => format!("/* {}.len() — use counter */", set),
                _ => format!("{}[{}]", set, a.join(", ")),
            }
        }
        Expression::Tuple(exprs) => {
            let items: Vec<String> = exprs.iter().map(transpile_expr).collect();
            format!("({})", items.join(", "))
        }
        Expression::Some(val) => format!("({})", transpile_expr(val)), // Solidity has no Option — unwrap directly
        Expression::None => "address(0)".to_string(), // Best-effort mapping
        Expression::Ok(val) => transpile_expr(val), // Unwrap Result to value
        Expression::Err(val) => format!("revert({})", transpile_expr(val)),
        Expression::FieldAccess { object, field } => {
            format!("{}.{}", transpile_expr(object), field)
        }
        Expression::TupleIndex { object, index } => {
            format!("{}.{}", transpile_expr(object), index) // Solidity tuple access
        }
        Expression::EnumAccess { enum_name, variant_name } => {
            format!("{}.{}", enum_name, variant_name)
        }
        Expression::StructLiteral { type_name, fields } => {
            let fs: Vec<String> = fields.iter()
                .map(|(n, v)| format!("{}: {}", n, transpile_expr(v))).collect();
            format!("{}({{{}}})", type_name, fs.join(", "))
        }
    }
}

fn ty_to_sol(ty: &Type) -> String {
    match ty {
        Type::Bool => "bool".into(),
        Type::UInt8 => "uint8".into(),
        Type::UInt16 => "uint16".into(),
        Type::UInt32 => "uint32".into(),
        Type::UInt64 => "uint64".into(),
        Type::UInt128 => "uint128".into(),
        Type::UInt256 => "uint256".into(),
        Type::Int8 => "int8".into(),
        Type::Int16 => "int16".into(),
        Type::Int32 => "int32".into(),
        Type::Int64 => "int64".into(),
        Type::Int128 => "int128".into(),
        Type::Int256 => "int256".into(),
        Type::Bytes => "bytes".into(),
        Type::Str => "string".into(),
        Type::Address => "address".into(),
        Type::Mapping(k, v) => format!("mapping({} => {})", ty_to_sol(k), ty_to_sol(v)),
        Type::Array(t) => format!("{}[]", ty_to_sol(t)),
        Type::Option(t) => ty_to_sol(t), // No Solidity Option — use the inner type + null check
        Type::Result(o, _) => ty_to_sol(o), // No Solidity Result — use the Ok type + revert on Err
        Type::Tuple(ts) => {
            let items: Vec<String> = ts.iter().map(ty_to_sol).collect();
            format!("({})", items.join(", "))
        }
        Type::Named(s) => s.clone(),
        Type::BytesN(n) => format!("bytes{}", n),
        Type::DilithiumPublicKey | Type::FalconPublicKey | Type::KyberPublicKey =>
            "bytes memory /* PQC pubkey — SXCP bridge */".into(),
        Type::DilithiumSignature | Type::FalconSignature =>
            "bytes memory /* PQC signature — SXCP bridge */".into(),
        Type::Asset(_) => "address /* asset — SXCP bridge */".into(),
        Type::Hash32 => "bytes32".into(),
        Type::Hash64 => "bytes64".into(),
        Type::UMAIdentity => "address /* UMA identity — SXCP bridge */".into(),
        Type::Height => "uint256 /* block height */".into(),
        Type::ModelId => "uint256 /* AI model ID */".into(),
    }
}

fn binop_to_sol(op: &BinaryOperator) -> &'static str {
    match op {
        BinaryOperator::Add => "+", BinaryOperator::Sub => "-",
        BinaryOperator::Mul => "*", BinaryOperator::Div => "/",
        BinaryOperator::Mod => "%", BinaryOperator::Eq => "==",
        BinaryOperator::Ne => "!=", BinaryOperator::Lt => "<",
        BinaryOperator::Le => "<=", BinaryOperator::Gt => ">",
        BinaryOperator::Ge => ">=", BinaryOperator::And => "&&",
        BinaryOperator::Or => "||",
    }
}

fn unop_to_sol(op: &UnaryOperator) -> &'static str {
    match op { UnaryOperator::Neg => "-", UnaryOperator::Not => "!" }
}

/// Resolve SynQ type aliases to their underlying Solidity type.
fn resolve_type_alias(ty: &Type) -> Type {
    match ty {
        Type::UMAIdentity => Type::Address,
        Type::Height => Type::UInt256,
        _ => ty.clone(),
    }
}

/// Strip redundant nested Solidity casts produced when an expression already
/// contains a cast that the assignment/return cast wraps again.
/// e.g. bytes20(uint160(uint256(uint160(msg.sender)))) -> bytes20(uint160(msg.sender))
fn simplify_redundant_casts(s: &str) -> String {
    // Strip T1(T2(T1(T2(X)))) -> T1(T2(X)) for known cast patterns.
    const PATTERNS: &[(&str, &str)] = &[
        ("bytes20(uint160(uint256(uint160(", "bytes20(uint160("),
        ("uint256(uint160(bytes20(uint160(", "uint256(uint160("),
        ("uint256(uint160(uint256(uint160(", "uint256(uint160("),
        ("bytes32(uint256(bytes32(uint256(", "bytes32(uint256("),
        ("address(uint160(uint256(uint160(", "address(uint160("),
    ];
    let mut out = s.to_string();
    for _ in 0..3 {
        let before = out.clone();
        for (pat, repl) in PATTERNS {
            if let Some(idx) = out.find(pat) {
                let after = &out[idx + pat.len()..];
                // Find the inner expression content (up to first unmatched ')')
                let mut depth = 0i32;
                let mut content_end = 0;
                for (i, c) in after.char_indices() {
                    match c {
                        '(' => depth += 1,
                        ')' => {
                            if depth == 0 {
                                content_end = i;
                                break;
                            }
                            depth -= 1;
                        }
                        _ => {}
                    }
                }
                if content_end > 0 {
                    let inner = &after[..content_end];
                    // Original: pat + inner + "))))" + suffix (4 closes from pattern)
                    // New: repl + inner + "))" + suffix (2 closes from replacement)
                    let suffix = &after[content_end + 4..];
                    out = format!("{}{}{})){}", &out[..idx], repl, inner, suffix);
                }
            }
        }
        if out == before { break; }
    }
    out
}


/// Rename SynQ identifiers that conflict with Solidity reserved words.
fn sol_identifier(name: &str) -> String {
    match name {
        "msg" => "msg_".to_string(),      // msg is a global in Solidity
        "this" => "this_".to_string(),     // this is a keyword
        "block" => "block_".to_string(),   // block is a global
        "tx" => "tx_".to_string(),         // tx is a global
        "revert" => "revert_".to_string(), // revert is a keyword
        "require" => "require_".to_string(),
        "assert" => "assert_".to_string(),
        "emit" => "emit_".to_string(),
        "new" => "new_".to_string(),
        "delete" => "delete_".to_string(),
        _ => name.to_string(),
    }
}

fn literal_to_sol(lit: &Literal) -> String {
    match lit {
        Literal::String(s) => format!("\"{}\"", s),
        Literal::Number(n) => n.to_string(),
        Literal::BigNumber(s) => s.clone(),
        Literal::Hex(bytes) => format!("hex\"{}\"", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>()),
        Literal::Bool(b) => b.to_string(),
    }
}
