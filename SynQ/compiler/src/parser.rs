use pest::Parser;
use pest::iterators::Pair;
use crate::ast::*;

#[derive(Parser)]
#[grammar = "synq.pest"]
pub struct SynQParser;

pub fn parse(source: &str) -> Result<Vec<SourceUnit>, String> {
    let pairs = SynQParser::parse(Rule::source_file, source)
        .map_err(|e| format!("{}", e))?;
    use std::collections::HashSet;
    let mut ast = vec![];
    let mut contract_names: HashSet<String> = HashSet::new();
    for pair in pairs.into_iter().next().unwrap().into_inner() {
        match pair.as_rule() {
            Rule::top_level_item => {
                let inner = pair.into_inner().next().unwrap();
                match inner.as_rule() {
                    Rule::pragma_directive => {} // standard pragma -- consumed silently
                    Rule::synq_pragma      => {} // `pragma synq ^x.y;` -- consumed silently
                    Rule::struct_definition   => ast.push(SourceUnit::Struct(parse_struct(inner))),
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

fn parse_contract(pair: Pair<Rule>) -> Result<ContractDefinition, String> {
    use std::collections::HashSet;
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut parts = vec![];
    let mut fn_names: HashSet<String> = HashSet::new();
    let mut sv_names: HashSet<String> = HashSet::new();
    for section in inner {
        // Peel contract_section wrapper; the inner rule is the actual content.
        let p = if section.as_rule() == Rule::contract_section {
            match section.into_inner().next() {
                Some(inner_p) => inner_p,
                None => continue,
            }
        } else {
            section
        };
        match p.as_rule() {
            Rule::state_variable_declaration => {
                let mut si = p.into_inner();
                let n = si.next().unwrap().as_str().to_string();
                let t = parse_type(si.next().unwrap());
                if !sv_names.insert(n.clone()) {
                    return Err(format!("duplicate state variable '{}' in contract '{}'", n, name));
                }
                parts.push(ContractPart::StateVariable(StateVariableDeclaration {
                    name: n, ty: t, is_public: false
                }));
            }
            Rule::function_definition => {
                let f = parse_function(p)?;
                if !fn_names.insert(f.name.clone()) {
                    return Err(format!("duplicate function '{}' in contract '{}'", f.name, name));
                }
                parts.push(ContractPart::Function(f));
            }
            Rule::state_section => {
                for sv_pair in p.into_inner() {
                    if sv_pair.as_rule() == Rule::state_variable_declaration {
                        let mut si = sv_pair.into_inner();
                        let n = si.next().unwrap().as_str().to_string();
                        let t = parse_type(si.next().unwrap());
                        if !sv_names.insert(n.clone()) {
                            return Err(format!("duplicate state variable '{}' in contract '{}'", n, name));
                        }
                        parts.push(ContractPart::StateVariable(StateVariableDeclaration {
                            name: n, ty: t, is_public: false
                        }));
                    }
                }
            }
            Rule::impl_section | Rule::tests_section => {
                for fn_pair in p.into_inner() {
                    if fn_pair.as_rule() == Rule::function_definition {
                        let f = parse_function(fn_pair)?;
                        if !fn_names.insert(f.name.clone()) {
                            return Err(format!("duplicate function '{}' in contract '{}'", f.name, name));
                        }
                        parts.push(ContractPart::Function(f));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(ContractDefinition {
        name,
        parts,
        implements: vec![],
        metadata:   vec![],
        roles:      vec![],
        error_defs: vec![],
        event_defs: vec![],
        test_fns:   vec![],
    })
}

fn parse_function(pair: Pair<Rule>) -> Result<FunctionDefinition, String> {
    use std::collections::HashSet;
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut params = vec![];
    let mut returns: Option<Type> = None;
    let mut body_stmts = vec![];
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
                // "as caller" — mark function as requiring authenticated caller
                requires_caller = true;
            }
            Rule::capability_clause => {
                // "requires cap::X, role::Y"
                for item in p.into_inner() {
                    match item.as_rule() {
                        Rule::cap_item  => {
                            if let Some(name_pair) = item.into_inner().next() {
                                capabilities.push(format!("cap::{}", name_pair.as_str()));
                            }
                        }
                        Rule::role_item => {
                            if let Some(name_pair) = item.into_inner().next() {
                                capabilities.push(format!("role::{}", name_pair.as_str()));
                            }
                        }
                        _ => {}
                    }
                }
            }
            Rule::block => {
                for stmt_pair in p.into_inner() {
                    if stmt_pair.as_rule() == Rule::statement {
                        body_stmts.push(parse_statement(stmt_pair.into_inner().next().unwrap()));
                    }
                }
            }
            _ => {}
        }
    }

    Ok(FunctionDefinition {
        name,
        params,
        returns,
        body: Block { statements: body_stmts },
        is_public: false,
        requires_caller,
        capabilities,
    })
}

fn parse_statement(pair: Pair<Rule>) -> Statement {
    match pair.as_rule() {
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
        Rule::let_statement => {
            let mut inner = pair.into_inner();
            let name = inner.next().unwrap().as_str().to_string();
            let mut ty: Option<Type> = None;
            let mut value_pair = inner.next().unwrap();
            if value_pair.as_rule() == Rule::type_decl {
                ty = Some(parse_type(value_pair));
                value_pair = inner.next().unwrap();
            }
            Statement::Let { name, ty, value: parse_expression(value_pair) }
        }
        Rule::revert_statement => {
            let mut inner = pair.into_inner();
            let error = inner.next().unwrap().as_str().to_string();
            let args: Vec<Expression> = inner.map(parse_expression).collect();
            Statement::RevertNamed { error, args }
        }
        Rule::emit_statement => {
            let mut inner = pair.into_inner();
            let event = inner.next().unwrap().as_str().to_string();
            let args: Vec<Expression> = inner.map(parse_expression).collect();
            Statement::Emit { event, args }
        }
        Rule::if_statement => {
            let mut inner = pair.into_inner();
            let condition = parse_expression(inner.next().unwrap());
            let then_pairs: Vec<Statement> = inner.next().unwrap().into_inner()
                .filter(|p| p.as_rule() == Rule::statement)
                .map(|p| parse_statement(p.into_inner().next().unwrap()))
                .collect();
            let else_block = inner.next().map(|eb| Block {
                statements: eb.into_inner()
                    .filter(|p| p.as_rule() == Rule::statement)
                    .map(|p| parse_statement(p.into_inner().next().unwrap()))
                    .collect()
            });
            Statement::If { condition, then_block: Block { statements: then_pairs }, else_block }
        }
        Rule::while_statement => {
            let mut inner = pair.into_inner();
            let condition = parse_expression(inner.next().unwrap());
            let body_stmts: Vec<Statement> = inner.next().unwrap().into_inner()
                .filter(|p| p.as_rule() == Rule::statement)
                .map(|p| parse_statement(p.into_inner().next().unwrap()))
                .collect();
            Statement::While { condition, body: Block { statements: body_stmts } }
        }
        Rule::break_statement    => Statement::Break,
        Rule::continue_statement => Statement::Continue,

        Rule::extern_call_statement => {
            let mut inner = pair.into_inner();
            let contract = inner.next().unwrap().as_str().trim_matches('"').to_string();
            let function = inner.next().unwrap().as_str().trim_matches('"').to_string();
            let args: Vec<Expression> = inner.map(parse_expression).collect();
            Statement::ExternCall { contract, function, args }
        }
        Rule::expr_statement => {
            Statement::Expression(parse_expression(pair.into_inner().next().unwrap()))
        }
        _ => Statement::Expression(Expression::Literal(Literal::Number(0))),
    }
}

fn parse_expression(pair: Pair<Rule>) -> Expression {
    match pair.as_rule() {
        Rule::expression | Rule::logical => parse_expression(pair.into_inner().next().unwrap()),
        Rule::comparison | Rule::additive | Rule::multiplicative => {
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
            let mut inner = pair.into_inner();
            let first = inner.next().unwrap();
            if first.as_str() == "-" {
                let operand = parse_expression(inner.next().unwrap());
                Expression::BinaryOp(
                    Box::new(Expression::Literal(Literal::Number(0))),
                    BinaryOperator::Sub,
                    Box::new(operand),
                )
            } else if first.as_str() == "!" {
                let operand = parse_expression(inner.next().unwrap());
                Expression::UnaryOp(UnaryOperator::Not, Box::new(operand))
            } else {
                parse_expression(first)
            }
        }
        Rule::primary  => parse_expression(pair.into_inner().next().unwrap()),
        Rule::call_expr => {
            let mut inner = pair.into_inner();
            let name = inner.next().unwrap().as_str().to_string();
            let args = if let Some(arg_list) = inner.next() {
                arg_list.into_inner().map(parse_expression).collect()
            } else {
                vec![]
            };
            Expression::Call(name, args)
        }
        Rule::literal         => parse_expression(pair.into_inner().next().unwrap()),
        Rule::number_literal  => {
            let s = pair.as_str();
            // Try u128 first; if it overflows, keep as BigNumber string for full U256.
            match s.parse::<u128>() {
                Ok(n)  => Expression::Literal(Literal::Number(n)),
                Err(_) => Expression::Literal(Literal::BigNumber(s.to_string())),
            }
        }
        Rule::string_literal  => Expression::Literal(Literal::String(
            pair.as_str().trim_matches('"').to_string()
        )),
        Rule::hex_literal => {
            let s = pair.as_str().trim_start_matches("0x").trim_start_matches("0X");
            let bytes: Vec<u8> = (0..s.len()).step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap_or(0))
                .collect();
            Expression::Literal(Literal::Hex(bytes))
        }
        Rule::bool_literal    => Expression::Literal(Literal::Bool(pair.as_str() == "true")),
        Rule::map_index_expr  => {
            let mut inner = pair.into_inner();
            let map_name = inner.next().unwrap().as_str().to_string();
            let key_expr = parse_expression(inner.next().unwrap());
            Expression::MapIndex(map_name, Box::new(key_expr))
        }
        Rule::method_call_expr => {
            let mut inner = pair.into_inner();
            let obj_name = inner.next().unwrap().as_str().to_string();
            let method   = inner.next().unwrap().as_str().to_string();
            // The remaining child is an optional arg_list node — unwrap it to get
            // the individual expression children (same pattern as call_expr).
            let args: Vec<Expression> = if let Some(arg_list) = inner.next() {
                arg_list.into_inner().map(parse_expression).collect()
            } else {
                vec![]
            };
            match method.as_str() {
                "get" | "contains" | "len" => Expression::MapMethod { map: obj_name, method, args },
                "add" | "remove"           => Expression::SetMethod { set: obj_name, method, args },
                _                          => Expression::MapMethod { map: obj_name, method, args },
            }
        }
        Rule::IDENT => match pair.as_str() {
            "caller" => Expression::Caller,
            "None"   => Expression::None,
            name     => Expression::Identifier(name.to_string()),
        }
        Rule::none_expr     => Expression::None,
        Rule::tuple_literal => {
            let exprs = pair.into_inner().map(parse_expression).collect();
            Expression::Tuple(exprs)
        }
        Rule::some_expr => {
            let inner = pair.into_inner().next().unwrap();
            Expression::Some(Box::new(parse_expression(inner)))
        }
        Rule::ok_expr => {
            let inner = pair.into_inner().next().unwrap();
            Expression::Ok(Box::new(parse_expression(inner)))
        }
        Rule::err_expr => {
            let inner = pair.into_inner().next().unwrap();
            Expression::Err(Box::new(parse_expression(inner)))
        }
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
        _    => BinaryOperator::Add,
    }
}

fn parse_type(pair: Pair<Rule>) -> Type {
    match pair.as_rule() {
        Rule::type_decl | Rule::return_type => parse_type(pair.into_inner().next().unwrap()),
        Rule::mapping_type => {
            let mut inner = pair.into_inner();
            let k = parse_type(inner.next().unwrap());
            let v = parse_type(inner.next().unwrap());
            Type::Mapping(Box::new(k), Box::new(v))
        }
        Rule::set_type => {
            let inner = pair.into_inner().next().unwrap();
            Type::Array(Box::new(parse_type(inner)))
        }
        Rule::IDENT => match pair.as_str() {
            "address" | "Address"                         => Type::Address,
            "u8"  | "UInt8"  | "uint8"                   => Type::UInt8,
            "u16" | "UInt16" | "uint16"                   => Type::UInt16,
            "u32" | "UInt32" | "uint32"                   => Type::UInt32,
            "u64" | "UInt64" | "uint64"                   => Type::UInt64,
            "u128"| "UInt128"| "uint128"                  => Type::UInt128,
            "u256"| "UInt256"| "uint256"| "uint"          => Type::UInt256,
            "i8"  | "Int8"   | "int8"                     => Type::Int8,
            "i16" | "Int16"  | "int16"                    => Type::Int16,
            "i32" | "Int32"  | "int32"                    => Type::Int32,
            "i64" | "Int64"  | "int64"                    => Type::Int64,
            "i128"| "Int128" | "int128"                   => Type::Int128,
            "i256"| "Int256" | "int256"| "int"            => Type::Int256,
            "bool"| "Bool"                                => Type::Bool,
            "bytes"| "Bytes"                              => Type::Bytes,
            "string"| "String"| "str"                     => Type::Str,
            "DilithiumPublicKey"                          => Type::DilithiumPublicKey,
            "FalconPublicKey"                             => Type::FalconPublicKey,
            "KyberPublicKey"                              => Type::KyberPublicKey,
            "DilithiumSignature"                          => Type::DilithiumSignature,
            "FalconSignature"                             => Type::FalconSignature,
            other                                         => Type::Named(other.to_string()),
        },
        _ => Type::UInt256,
    }
}
