use pest::Parser;
use pest::iterators::Pair;
use super::ast::*;

#[derive(Parser)]
#[grammar = "synq.pest"]
pub struct SynQParser;

// ── Top-level entry point ─────────────────────────────────────────────────────
pub fn parse(source: &str) -> Result<Vec<SourceUnit>, String> {
    let pairs = SynQParser::parse(Rule::source_file, source)
        .map_err(|e| format!("{}", e))?;
    use std::collections::HashSet;
    let mut ast = vec![];
    let mut contract_names: HashSet<String> = HashSet::new();
    let mut iface_names: HashSet<String>    = HashSet::new();
    for pair in pairs.into_iter().next().unwrap().into_inner() {
        match pair.as_rule() {
            Rule::top_level_item => {
                let inner = pair.into_inner().next().unwrap();
                match inner.as_rule() {
                    Rule::pragma_directive    => {}
                    Rule::synq_pragma         => {}
                    Rule::struct_definition   => ast.push(SourceUnit::Struct(parse_struct(inner))),
                    Rule::interface_definition => {
                        let iface = parse_interface(inner)?;
                        if !iface_names.insert(iface.name.clone()) {
                            return Err(format!("duplicate interface '{}'", iface.name));
                        }
                        ast.push(SourceUnit::Interface(iface));
                    }
                    Rule::contract_definition => {
                        let c = parse_contract(inner)?;
                        if !contract_names.insert(c.name.clone()) {
                            return Err(format!("duplicate contract '{}'", c.name));
                        }
                        ast.push(SourceUnit::Contract(c));
                    }
                    _ => {}
                }
            }
            Rule::EOI => {}
            _ => {}
        }
    }
    Ok(ast)
}

// ── Struct ────────────────────────────────────────────────────────────────────
fn parse_struct(pair: Pair<Rule>) -> StructDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let fields = inner.map(|p| {
        let mut fi = p.into_inner();
        let n = fi.next().unwrap().as_str().to_string();
        let t = parse_type(fi.next().unwrap());
        Parameter { name: n, ty: t, is_indexed: false }
    }).collect();
    StructDefinition { name, fields }
}

// ── Interface ─────────────────────────────────────────────────────────────────
fn parse_interface(pair: Pair<Rule>) -> Result<InterfaceDefinition, String> {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut functions = vec![];
    for p in inner {
        if p.as_rule() == Rule::interface_fn {
            let mut fi = p.into_inner();
            let fn_name = fi.next().unwrap().as_str().to_string();
            let mut params = vec![];
            let mut returns = None;
            for fp in fi {
                match fp.as_rule() {
                    Rule::param_list => {
                        for param in fp.into_inner() {
                            if param.as_rule() == Rule::param {
                                let mut pi = param.into_inner();
                                let pn = pi.next().unwrap().as_str().to_string();
                                let pt = parse_type(pi.next().unwrap());
                                params.push(Parameter { name: pn, ty: pt, is_indexed: false });
                            }
                        }
                    }
                    Rule::type_decl => { returns = Some(parse_type(fp)); }
                    _ => {}
                }
            }
            functions.push(InterfaceFunction { name: fn_name, params, returns });
        }
    }
    Ok(InterfaceDefinition { name, functions })
}

// ── Contract ──────────────────────────────────────────────────────────────────
fn parse_contract(pair: Pair<Rule>) -> Result<ContractDefinition, String> {
    use std::collections::HashSet;
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();

    let mut implements: Vec<String> = vec![];
    let mut parts:      Vec<ContractPart> = vec![];
    let mut metadata:   Vec<MetadataEntry> = vec![];
    let mut roles:      Vec<RoleDefinition> = vec![];
    let mut error_defs: Vec<ErrorDefinition> = vec![];
    let mut event_defs: Vec<EventDefinition> = vec![];
    let mut test_fns:   Vec<FunctionDefinition> = vec![];

    let mut fn_names: HashSet<String> = HashSet::new();
    let mut sv_names: HashSet<String> = HashSet::new();

    for p in inner {
        match p.as_rule() {
            Rule::implements_clause => {
                for ident in p.into_inner() {
                    implements.push(ident.as_str().to_string());
                }
            }
            Rule::contract_section => {
                let section = p.into_inner().next().unwrap();
                match section.as_rule() {
                    // ── state { } ──────────────────────────────────────────
                    Rule::state_section => {
                        for sv in section.into_inner() {
                            if sv.as_rule() == Rule::state_variable_declaration {
                                let svd = parse_state_var(sv)?;
                                if !sv_names.insert(svd.name.clone()) {
                                    return Err(format!("duplicate state variable '{}' in '{}'", svd.name, name));
                                }
                                parts.push(ContractPart::StateVariable(svd));
                            }
                        }
                    }
                    // ── events { } ────────────────────────────────────────
                    Rule::events_section => {
                        for ev in section.into_inner() {
                            if ev.as_rule() == Rule::event_definition {
                                event_defs.push(parse_event(ev));
                            }
                        }
                    }
                    // ── errors { } ────────────────────────────────────────
                    Rule::errors_section => {
                        for er in section.into_inner() {
                            if er.as_rule() == Rule::error_definition {
                                error_defs.push(parse_error_def(er));
                            }
                        }
                    }
                    // ── roles { } ─────────────────────────────────────────
                    Rule::roles_section => {
                        for rl in section.into_inner() {
                            if rl.as_rule() == Rule::role_definition {
                                roles.push(parse_role_def(rl));
                            }
                        }
                    }
                    // ── metadata { } ──────────────────────────────────────
                    Rule::metadata_section => {
                        for me in section.into_inner() {
                            if me.as_rule() == Rule::metadata_entry {
                                metadata.push(parse_metadata_entry(me));
                            }
                        }
                    }
                    // ── impl { } ──────────────────────────────────────────
                    Rule::impl_section => {
                        for fn_p in section.into_inner() {
                            if fn_p.as_rule() == Rule::function_definition {
                                let f = parse_function(fn_p)?;
                                if !fn_names.insert(f.name.clone()) {
                                    return Err(format!("duplicate function '{}' in '{}'", f.name, name));
                                }
                                parts.push(ContractPart::Function(f));
                            }
                        }
                    }
                    // ── tests { } ─────────────────────────────────────────
                    Rule::tests_section => {
                        for fn_p in section.into_inner() {
                            if fn_p.as_rule() == Rule::function_definition {
                                let f = parse_function(fn_p)?;
                                test_fns.push(f);
                            }
                        }
                    }
                    // ── flat state_variable_declaration (legacy) ──────────
                    Rule::state_variable_declaration => {
                        let svd = parse_state_var(section)?;
                        if !sv_names.insert(svd.name.clone()) {
                            return Err(format!("duplicate state variable '{}' in '{}'", svd.name, name));
                        }
                        parts.push(ContractPart::StateVariable(svd));
                    }
                    // ── flat function_definition (legacy) ─────────────────
                    Rule::function_definition => {
                        let f = parse_function(section)?;
                        if !fn_names.insert(f.name.clone()) {
                            return Err(format!("duplicate function '{}' in '{}'", f.name, name));
                        }
                        parts.push(ContractPart::Function(f));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    Ok(ContractDefinition { name, implements, parts, metadata, roles, error_defs, event_defs, test_fns })
}

fn parse_state_var(pair: Pair<Rule>) -> Result<StateVariableDeclaration, String> {
    let mut si = pair.into_inner();
    let n = si.next().unwrap().as_str().to_string();
    let t = parse_type(si.next().unwrap());
    Ok(StateVariableDeclaration { name: n, ty: t, is_public: false })
}

fn parse_event(pair: Pair<Rule>) -> EventDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut params = vec![];
    if let Some(pl) = inner.next() {
        for ep in pl.into_inner() {
            if ep.as_rule() == Rule::event_param {
                let raw = ep.as_str();
                let is_indexed = raw.starts_with("indexed");
                let mut epi = ep.into_inner();
                // Skip "indexed" keyword token if present — the grammar
                // keeps it as a silent rule shift; just read name + type.
                let pname = epi.next().unwrap().as_str().to_string();
                let pty   = parse_type(epi.next().unwrap());
                params.push(EventParam { name: pname, ty: pty, is_indexed });
            }
        }
    }
    EventDefinition { name, params }
}

fn parse_error_def(pair: Pair<Rule>) -> ErrorDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut params = vec![];
    for p in inner {
        if p.as_rule() == Rule::param_list {
            for param in p.into_inner() {
                if param.as_rule() == Rule::param {
                    let mut pi = param.into_inner();
                    let pn = pi.next().unwrap().as_str().to_string();
                    let pt = parse_type(pi.next().unwrap());
                    params.push(Parameter { name: pn, ty: pt, is_indexed: false });
                }
            }
        }
    }
    ErrorDefinition { name, params }
}

fn parse_role_def(pair: Pair<Rule>) -> RoleDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut caps = vec![];
    // cap_list_expr -> cap_item*
    if let Some(cle) = inner.next() {
        for item in cle.into_inner() {
            if item.as_rule() == Rule::cap_item {
                let raw = item.as_str(); // "cap::Minter"
                let cap_name = raw.splitn(2, "::").nth(1).unwrap_or(raw).to_string();
                caps.push(cap_name);
            }
        }
    }
    RoleDefinition { name, caps }
}

fn parse_metadata_entry(pair: Pair<Rule>) -> MetadataEntry {
    let mut inner = pair.into_inner();
    let key = inner.next().unwrap().as_str().to_string();
    let val_pair = inner.next().unwrap();
    let value = match val_pair.as_rule() {
        Rule::string_literal => MetadataValue::Str(val_pair.as_str().trim_matches('"').to_string()),
        Rule::number_literal => MetadataValue::Num(val_pair.as_str().parse::<u128>().unwrap_or(0)),
        _ => MetadataValue::Str(val_pair.as_str().to_string()),
    };
    MetadataEntry { key, value }
}

// ── Function ──────────────────────────────────────────────────────────────────
fn parse_function(pair: Pair<Rule>) -> Result<FunctionDefinition, String> {
    use std::collections::HashSet;
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut params       = vec![];
    let mut returns      = None;
    let mut body_stmts   = vec![];
    let mut param_names: HashSet<String> = HashSet::new();
    let mut requires_caller = false;
    let mut capabilities: Vec<String> = vec![];

    for p in inner {
        match p.as_rule() {
            Rule::param_list => {
                for param in p.into_inner() {
                    if param.as_rule() == Rule::param {
                        let mut pi = param.into_inner();
                        let pn = pi.next().unwrap().as_str().to_string();
                        let pt = parse_type(pi.next().unwrap());
                        if !param_names.insert(pn.clone()) {
                            return Err(format!("duplicate parameter '{}' in function '{}'", pn, name));
                        }
                        params.push(Parameter { name: pn, ty: pt, is_indexed: false });
                    }
                }
            }
            Rule::type_decl | Rule::return_type => {
                returns = Some(parse_type(p));
            }
            Rule::identity_clause => {
                requires_caller = true;
            }
            Rule::capability_clause => {
                // access_req_list -> access_req_item -> cap_item | role_item
                for item in p.into_inner() {
                    if item.as_rule() == Rule::access_req_list {
                        for req in item.into_inner() {
                            match req.as_rule() {
                                Rule::access_req_item => {
                                    let inner_req = req.into_inner().next().unwrap();
                                    match inner_req.as_rule() {
                                        Rule::cap_item => {
                                            let raw = inner_req.as_str();
                                            let cap = raw.splitn(2, "::").nth(1).unwrap_or(raw).to_string();
                                            capabilities.push(cap);
                                        }
                                        Rule::role_item => {
                                            // role_item text: "role::Admin"
                                            // Store as "role::<name>" — codegen expands via role table
                                            let raw = inner_req.as_str();
                                            capabilities.push(raw.to_string());
                                        }
                                        _ => {}
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            Rule::block => {
                for stmt_pair in p.into_inner() {
                    if stmt_pair.as_rule() == Rule::statement {
                        body_stmts.push(parse_statement(stmt_pair.into_inner().next().unwrap())?);
                    }
                }
            }
            _ => {}
        }
    }

    Ok(FunctionDefinition {
        name, params, returns,
        body: Block { statements: body_stmts },
        is_public: false, requires_caller, capabilities,
    })
}

// ── Statements ────────────────────────────────────────────────────────────────
fn parse_statement(pair: Pair<Rule>) -> Result<Statement, String> {
    Ok(match pair.as_rule() {
        Rule::return_statement => {
            let inner = pair.into_inner().next();
            Statement::Return(inner.map(parse_expression))
        }
        Rule::require_statement => {
            let mut inner = pair.into_inner();
            let cond = parse_expression(inner.next().unwrap());
            let msg = inner.next()
                .map(|p| p.as_str().trim_matches('"').to_string())
                .unwrap_or_default();
            Statement::Require(cond, msg)
        }
        Rule::revert_statement => {
            let mut inner = pair.into_inner();
            let error = inner.next().unwrap().as_str().to_string();
            let args = if let Some(arg_list) = inner.next() {
                arg_list.into_inner().map(parse_expression).collect()
            } else { vec![] };
            Statement::RevertNamed { error, args }
        }
        Rule::emit_statement => {
            let mut inner = pair.into_inner();
            let event = inner.next().unwrap().as_str().to_string();
            let args = if let Some(arg_list) = inner.next() {
                arg_list.into_inner().map(parse_expression).collect()
            } else { vec![] };
            Statement::Emit { event, args }
        }
        Rule::extern_call_statement => {
            let mut inner = pair.into_inner();
            let contract = inner.next().unwrap().as_str().trim_matches('"').to_string();
            let function = inner.next().unwrap().as_str().trim_matches('"').to_string();
            let args = inner.map(parse_expression).collect();
            Statement::ExternCall { contract, function, args }
        }
        Rule::if_statement => {
            let mut inner = pair.into_inner();
            let condition = parse_expression(inner.next().unwrap());
            let then_block = parse_block(inner.next().unwrap())?;
            let else_block = if let Some(else_p) = inner.next() {
                match else_p.as_rule() {
                    Rule::block      => Some(parse_block(else_p)?),
                    Rule::if_statement => {
                        // else if — wrap in a block containing the if statement
                        let nested = parse_statement(else_p)?;
                        Some(Block { statements: vec![nested] })
                    }
                    _ => None,
                }
            } else { None };
            Statement::If { condition, then_block, else_block }
        }
        Rule::while_statement => {
            let mut inner = pair.into_inner();
            let condition = parse_expression(inner.next().unwrap());
            let body_stmts: Vec<Statement> = inner.next().unwrap().into_inner()
                .filter(|p| p.as_rule() == Rule::statement)
                .filter_map(|p| parse_statement(p.into_inner().next().unwrap()).ok())
                .collect();
            Statement::While { condition, body: Block { statements: body_stmts } }
        }
        Rule::break_statement    => Statement::Break,
        Rule::continue_statement => Statement::Continue,
        Rule::let_statement => {
            let mut inner = pair.into_inner();
            let var_name = inner.next().unwrap().as_str().to_string();
            // Optional type annotation, then expression
            let mut ty = None;
            let mut expr_opt = None;
            for p in inner {
                match p.as_rule() {
                    Rule::type_decl => { ty = Some(parse_type(p)); }
                    _ => { expr_opt = Some(parse_expression(p)); }
                }
            }
            let value = expr_opt.unwrap_or(Expression::Literal(Literal::Number(0)));
            Statement::Let { name: var_name, ty, value }
        }
        Rule::map_assign_statement => {
            let mut inner = pair.into_inner();
            let map_name = inner.next().unwrap().as_str().to_string();
            let key_expr = parse_expression(inner.next().unwrap());
            let val_expr = parse_expression(inner.next().unwrap());
            Statement::MapAssignment { map: map_name, key: key_expr, value: val_expr }
        }
        Rule::set_op_statement => {
            // Grammar: IDENT ~ "." ~ ("add"|"remove") ~ "(" ~ expression ~ ")" ~ ";"
            // Only IDENT and expression are child pairs; op is inlined in source text.
            let raw_text = pair.as_str();
            let op = if raw_text.contains(".add(") { SetOpKind::Add } else { SetOpKind::Remove };
            let mut inner = pair.into_inner();
            let set_name = inner.next().unwrap().as_str().to_string();
            let val_expr = parse_expression(inner.next().unwrap());
            Statement::SetOp { set: set_name, op, value: val_expr }
        }
        Rule::assignment_statement => {
            let mut inner = pair.into_inner();
            let name = inner.next().unwrap().as_str().to_string();
            let expr = parse_expression(inner.next().unwrap());
            Statement::Assignment(name, expr)
        }
        Rule::expr_statement => {
            Statement::Expression(parse_expression(pair.into_inner().next().unwrap()))
        }
        _ => Statement::Expression(Expression::Literal(Literal::Number(0))),
    })
}

fn parse_block(pair: Pair<Rule>) -> Result<Block, String> {
    let mut stmts = vec![];
    for sp in pair.into_inner() {
        if sp.as_rule() == Rule::statement {
            stmts.push(parse_statement(sp.into_inner().next().unwrap())?);
        }
    }
    Ok(Block { statements: stmts })
}

// ── Expressions ───────────────────────────────────────────────────────────────
fn parse_expression(pair: Pair<Rule>) -> Expression {
    match pair.as_rule() {
        Rule::expression => parse_expression(pair.into_inner().next().unwrap()),
        Rule::logical | Rule::comparison | Rule::additive | Rule::multiplicative => {
            let mut inner = pair.into_inner();
            let mut left = parse_expression(inner.next().unwrap());
            while let Some(op_pair) = inner.next() {
                let op = parse_binop(&op_pair);
                let right = parse_expression(inner.next().unwrap());
                left = Expression::BinaryOp(Box::new(left), op, Box::new(right));
            }
            left
        }
        Rule::unary => {
            let raw = pair.as_str();
            let mut inner = pair.into_inner();
            let first = inner.next().unwrap();
            if raw.starts_with('-') && first.as_rule() == Rule::unary {
                let operand = parse_expression(first);
                Expression::UnaryOp(UnaryOperator::Neg, Box::new(operand))
            } else if raw.starts_with('!') && first.as_rule() == Rule::unary {
                let operand = parse_expression(first);
                Expression::UnaryOp(UnaryOperator::Not, Box::new(operand))
            } else {
                parse_expression(first)
            }
        }
        Rule::primary   => parse_expression(pair.into_inner().next().unwrap()),
        Rule::call_expr => {
            let mut inner = pair.into_inner();
            let name = inner.next().unwrap().as_str().to_string();
            let args = if let Some(arg_list) = inner.next() {
                arg_list.into_inner().map(parse_expression).collect()
            } else { vec![] };
            Expression::Call(name, args)
        }
        Rule::literal        => parse_expression(pair.into_inner().next().unwrap()),
        Rule::number_literal => {
            let s = pair.as_str();
            match s.parse::<u128>() {
                Ok(n)  => Expression::Literal(Literal::Number(n)),
                Err(_) => Expression::Literal(Literal::BigNumber(s.to_string())),
            }
        }
        Rule::hex_literal => {
            let s = pair.as_str(); // "0x..."
            let bytes = hex::decode(&s[2..]).unwrap_or_default();
            Expression::Literal(Literal::Hex(bytes))
        }
        Rule::string_literal => Expression::Literal(Literal::String(
            pair.as_str().trim_matches('"').to_string()
        )),
        Rule::bool_literal => Expression::Literal(Literal::Bool(pair.as_str() == "true")),
        Rule::map_index_expr => {
            let mut inner = pair.into_inner();
            let map_name = inner.next().unwrap().as_str().to_string();
            let key_expr = parse_expression(inner.next().unwrap());
            Expression::MapIndex(map_name, Box::new(key_expr))
        }
        Rule::method_call_expr => {
            let mut inner = pair.into_inner();
            let receiver = inner.next().unwrap().as_str().to_string();
            let method = inner.next().unwrap().as_str().to_string();
            let args: Vec<Expression> = if let Some(arg_list) = inner.next() {
                arg_list.into_inner().map(parse_expression).collect()
            } else { vec![] };
            // Route to MapMethod for known map/set operations
            Expression::MapMethod { map: receiver, method, args }
        }
        Rule::IDENT => match pair.as_str() {
            "caller" => Expression::Caller,
            name     => Expression::Identifier(name.to_string()),
        },
        _ => Expression::Literal(Literal::Number(0)),
    }
}

fn parse_binop(pair: &Pair<Rule>) -> BinaryOperator {
    match pair.as_str() {
        "+"  => BinaryOperator::Add,
        "-"  => BinaryOperator::Sub,
        "*"  => BinaryOperator::Mul,
        "/"  => BinaryOperator::Div,
        "==" => BinaryOperator::Eq,
        "!=" => BinaryOperator::Ne,
        "<"  => BinaryOperator::Lt,
        "<=" => BinaryOperator::Le,
        ">"  => BinaryOperator::Gt,
        ">=" => BinaryOperator::Ge,
        "%"  => BinaryOperator::Mod,
        "&&" => BinaryOperator::And,
        "||" => BinaryOperator::Or,
        _    => BinaryOperator::Add,
    }
}

// ── Types ─────────────────────────────────────────────────────────────────────
fn parse_type(pair: Pair<Rule>) -> Type {
    match pair.as_rule() {
        Rule::type_decl | Rule::return_type => parse_type(pair.into_inner().next().unwrap()),
        Rule::mapping_type => {
            let mut inner = pair.into_inner();
            let k = parse_type(inner.next().unwrap());
            let v = parse_type(inner.next().unwrap());
            Type::Mapping(Box::new(k), Box::new(v))
        }
        Rule::option_type => {
            let inner = pair.into_inner().next().unwrap();
            Type::Option(Box::new(parse_type(inner)))
        }
        Rule::result_type => {
            let mut inner = pair.into_inner();
            let ok  = parse_type(inner.next().unwrap());
            let err = parse_type(inner.next().unwrap());
            Type::Result(Box::new(ok), Box::new(err))
        }
        Rule::tuple_type => {
            let types: Vec<Type> = pair.into_inner().map(parse_type).collect();
            Type::Tuple(types)
        }
        Rule::set_type => {
            let inner = pair.into_inner().next().unwrap();
            Type::Array(Box::new(parse_type(inner)))
        }
        Rule::array_type => {
            let inner = pair.into_inner().next().unwrap();
            Type::Array(Box::new(parse_type(inner)))
        }
        Rule::IDENT => match pair.as_str() {
            // Address
            "address" | "Address" => Type::Address,
            // Unsigned integers
            "u8"  | "UInt8"  | "uint8"  => Type::UInt8,
            "u16" | "UInt16" | "uint16" => Type::UInt16,
            "u32" | "UInt32" | "uint32" => Type::UInt32,
            "u64" | "UInt64" | "uint64" => Type::UInt64,
            "u128"| "UInt128"| "uint128"=> Type::UInt128,
            "u256"| "UInt256"| "uint256"| "uint" => Type::UInt256,
            // Signed integers
            "i8"  | "Int8"  | "int8"  => Type::Int8,
            "i16" | "Int16" | "int16" => Type::Int16,
            "i32" | "Int32" | "int32" => Type::Int32,
            "i64" | "Int64" | "int64" => Type::Int64,
            "i128"| "Int128"| "int128"=> Type::Int128,
            "i256"| "Int256"| "int256"| "int" => Type::Int256,
            // Primitives
            "bool" | "Bool"   => Type::Bool,
            "bytes"| "Bytes"  => Type::Bytes,
            "string"| "String"| "str" => Type::Str,
            // PQC
            "DilithiumPublicKey"  => Type::DilithiumPublicKey,
            "FalconPublicKey"     => Type::FalconPublicKey,
            "KyberPublicKey"      => Type::KyberPublicKey,
            "DilithiumSignature"  => Type::DilithiumSignature,
            "FalconSignature"     => Type::FalconSignature,
            // User-defined
            other => Type::Named(other.to_string()),
        },
        _ => Type::UInt256,
    }
}
