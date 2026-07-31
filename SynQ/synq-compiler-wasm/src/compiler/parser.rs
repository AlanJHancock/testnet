use pest::Parser;
use pest::iterators::Pair;
use crate::compiler::ast::*;

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
                    Rule::enum_definition    => ast.push(SourceUnit::Enum(parse_enum(inner))),
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
    // The first inner pair may be attribute_list (if present) or IDENT (if not).
    // We need to save attribute_list for processing in the loop below.
    let mut saved_attr_list: Option<Pair<Rule>> = None;
    let name = {
        let first = inner.next().unwrap();
        match first.as_rule() {
            Rule::attribute_list => {
                // Save it for later processing, get the next pair (IDENT)
                let name = inner.next().unwrap().as_str().to_string();
                saved_attr_list = Some(first);
                name
            }
            _ => first.as_str().to_string()
        }
    };
    let fields = inner.map(|p| {
        let mut fi = p.into_inner();
        let n = fi.next().unwrap().as_str().to_string();
        let t = parse_type(fi.next().unwrap());
        Parameter { name: n, ty: t, is_indexed: false }
    }).collect();
    StructDefinition { name, fields }
}


fn parse_enum(pair: Pair<Rule>) -> EnumDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut variants = vec![];
    for p in inner {
        if p.as_rule() == Rule::enum_variant {
            let mut vi = p.into_inner();
            let vname = vi.next().unwrap().as_str().to_string();
            let mut fields = vec![];
            // Check if there's a param_list (algebraic variant)
            for sub in vi {
                if sub.as_rule() == Rule::param_list {
                    for param in sub.into_inner() {
                        if param.as_rule() == Rule::param {
                            let mut pi = param.into_inner();
                            let pn = pi.next().unwrap().as_str().to_string();
                            let pt = parse_type(pi.next().unwrap());
                            fields.push(Parameter { name: pn, ty: pt, is_indexed: false });
                        }
                    }
                }
            }
            variants.push(EnumVariant { name: vname, fields });
        }
    }
    EnumDefinition { name, variants }
}

fn parse_contract(pair: Pair<Rule>) -> Result<ContractDefinition, String> {
    use std::collections::HashSet;
    let mut inner = pair.into_inner();
    // The first inner pair may be attribute_list (if present) or IDENT (if not).
    // We need to save attribute_list for processing in the loop below.
    let mut saved_attr_list: Option<Pair<Rule>> = None;
    let name = {
        let first = inner.next().unwrap();
        match first.as_rule() {
            Rule::attribute_list => {
                // Save it for later processing, get the next pair (IDENT)
                let name = inner.next().unwrap().as_str().to_string();
                saved_attr_list = Some(first);
                name
            }
            _ => first.as_str().to_string()
        }
    };
    let mut parts = vec![];
    let mut contract_enums = vec![];
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
            Rule::enum_definition => {
                contract_enums.push(parse_enum(p));
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
        enums: contract_enums,
        event_defs: vec![],
        test_fns:   vec![],
    })
}

fn parse_function(pair: Pair<Rule>) -> Result<FunctionDefinition, String> {
    use std::collections::HashSet;
    let mut inner = pair.into_inner();
    // The first inner pair may be attribute_list (if present) or IDENT (if not).
    // We need to save attribute_list for processing in the loop below.
    let mut saved_attr_list: Option<Pair<Rule>> = None;
    let name = {
        let first = inner.next().unwrap();
        match first.as_rule() {
            Rule::attribute_list => {
                // Save it for later processing, get the next pair (IDENT)
                let name = inner.next().unwrap().as_str().to_string();
                saved_attr_list = Some(first);
                name
            }
            _ => first.as_str().to_string()
        }
    };
    let mut params = vec![];
    let mut returns: Option<Type> = None;
    let mut body_stmts = vec![];
    let mut param_names: HashSet<String> = HashSet::new();

    let mut requires_caller = false;
    let mut capabilities: Vec<String> = vec![];
    let mut requires_state: Vec<String> = vec![];
    let mut modifies: Vec<String> = vec![];
    let mut attributes: Vec<Attribute> = vec![];

    // Process saved attribute_list first
    if let Some(attr_pair) = saved_attr_list {
        for attr_item in attr_pair.into_inner() {
            if attr_item.as_rule() == Rule::attribute {
                let mut ai = attr_item.into_inner();
                let attr_name = ai.next().map(|p| p.as_str().to_string()).unwrap_or_default();
                let attr_args = ai.next()
                    .map(|p| p.as_str().trim().to_string())
                    .unwrap_or_default();
                let attr = match attr_name.as_str() {
                    "public" => Attribute::Public,
                    "authority" => Attribute::Authority(attr_args.trim_matches('"').to_string()),
                    "effects" => Attribute::Effects(
                        attr_args.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
                    ),
                    "requires" => Attribute::Requires(attr_args.to_string()),
                    "ensures" => Attribute::Ensures(attr_args.to_string()),
                    "fails" => Attribute::Fails(attr_args.trim_matches('"').to_string()),
                    "bounded" => Attribute::Bounded(attr_args.to_string()),
                    "manifest" => Attribute::Manifest,
                    "ai" => Attribute::Ai,
                    "governance" => Attribute::Governance(attr_args.trim_matches('"').to_string()),
                    other => {
                        return Err(format!("unknown attribute: @{}", other));
                    }
                };
                attributes.push(attr);
            }
        }
    }

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
            Rule::requires_clauses => {
                // One or more "requires" lines — each is either cap/role or state condition
                for req_line in p.into_inner() {
                    match req_line.as_rule() {
                        Rule::req_body => {
                            let inner = req_line.into_inner().next();
                            if let Some(body) = inner {
                                match body.as_rule() {
                                    Rule::access_req_list => {
                                        for item in body.into_inner() {
                                            match item.as_rule() {
                                                Rule::cap_item => {
                                                    if let Some(np) = item.into_inner().next() {
                                                        capabilities.push(format!("cap::{}", np.as_str()));
                                                    }
                                                }
                                                Rule::role_item => {
                                                    if let Some(np) = item.into_inner().next() {
                                                        capabilities.push(format!("role::{}", np.as_str()));
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                    Rule::state_condition_list => {
                                        for cond in body.into_inner() {
                                            if cond.as_rule() == Rule::state_condition {
                                                let raw = cond.as_str().trim().to_string();
                                                if !raw.is_empty() {
                                                    requires_state.push(raw);
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            Rule::modifies_clauses => {
                // One or more "modifies" lines
                for mod_line in p.into_inner() {
                    if mod_line.as_rule() == Rule::modifies_list {
                        for item in mod_line.into_inner() {
                            if item.as_rule() == Rule::modifies_item {
                                let mut mi = item.into_inner();
                                let var_name = mi.next().map(|p| p.as_str().to_string()).unwrap_or_default();
                                let mut full = var_name;
                                for sub in mi {
                                    if sub.as_rule() == Rule::expression {
                                        full.push('[');
                                        full.push_str(sub.as_str());
                                        full.push(']');
                                    }
                                }
                                if !full.is_empty() {
                                    modifies.push(full);
                                }
                            }
                        }
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

    // Process attributes: derive is_public, merge with legacy clauses
    let is_public = attributes.iter().any(|a| matches!(a, Attribute::Public));
    // @effects merges with modifies
    for attr in &attributes {
        if let Attribute::Effects(vars) = attr {
            for v in vars {
                if !modifies.contains(v) {
                    modifies.push(v.clone());
                }
            }
        }
        if let Attribute::Requires(expr) = attr {
            if !requires_state.contains(expr) {
                requires_state.push(expr.clone());
            }
        }
    }

    Ok(FunctionDefinition {
        name,
        params,
        returns,
        body: Block { statements: body_stmts },
        is_public,
        requires_caller,
        capabilities,
        requires_state,
        modifies,
        attributes,
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
        Rule::field_assign_statement => {
            let mut inner = pair.into_inner();
            let object = inner.next().unwrap().as_str().to_string();
            let field = inner.next().unwrap().as_str().to_string();
            let value = parse_expression(inner.next().unwrap());
            Statement::FieldAssignment { object, field, value }
        }
        Rule::let_destructure => {
            let inner: Vec<_> = pair.into_inner().collect();
            let mut names = Vec::new();
            let mut value_idx = None;
            for (i, p) in inner.iter().enumerate() {
                match p.as_rule() {
                    Rule::IDENT => names.push(p.as_str().to_string()),
                    _ => { value_idx = Some(i); }
                }
            }
            let value_pair = inner.into_iter().nth(value_idx.unwrap()).unwrap();
            Statement::LetDestructure {
                names,
                value: Box::new(parse_expression(value_pair)),
            }
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
        Rule::revert_enum_statement => {
            let mut inner = pair.into_inner();
            let enum_name = inner.next().unwrap().as_str().to_string();
            let error = inner.next().unwrap().as_str().to_string();
            let args: Vec<Expression> = inner.map(parse_expression).collect();
            Statement::RevertEnum { enum_name, error, args }
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
            // pest string terminals ("-", "!") are NOT returned as inner pairs —
            // only named rules produce pairs. So for ("!" ~ unary), into_inner()
            // yields just the single unary child, and first.as_str() is the full
            // text e.g. "!done". We detect the operator from pair.as_str() instead.
            let full = pair.as_str();
            let mut inner = pair.into_inner();
            let operand_pair = inner.next().unwrap();
            if full.starts_with('!') {
                let operand = parse_expression(operand_pair);
                Expression::UnaryOp(UnaryOperator::Not, Box::new(operand))
            } else if full.starts_with('-') {
                let operand = parse_expression(operand_pair);
                Expression::BinaryOp(
                    Box::new(Expression::Literal(Literal::Number(0))),
                    BinaryOperator::Sub,
                    Box::new(operand),
                )
            } else {
                parse_expression(operand_pair)
            }
        }
        Rule::postfix => {
            let mut inner = pair.into_inner();
            // First child is the primary expression
            let base = parse_expression(inner.next().unwrap());
            // Remaining children are postfix suffixes (IDENT, optionally with arg_list)
            let mut expr = base;
            for suffix in inner {
                let mut suffix_inner = suffix.into_inner();
                let field_or_method = suffix_inner.next().unwrap().as_str().to_string();
                // Check if this is a numeric tuple index (e.g., t.0, t.1)
                if let Ok(index) = field_or_method.parse::<usize>() {
                    expr = Expression::TupleIndex {
                        object: Box::new(expr),
                        index,
                    };
                } else if let Some(arg_list) = suffix_inner.next() {
                    let args: Vec<Expression> = arg_list.into_inner().map(parse_expression).collect();
                    // Method call on a map/set — build from the expression
                    // For now, only support method calls on identifiers (map/set state vars)
                    if let Expression::Identifier(ref map_name) = expr {
                        match field_or_method.as_str() {
                            "unwrap" | "is_some" | "is_none" | "is_ok" | "is_err" => {
                                expr = Expression::MapMethod {
                                    map: map_name.clone(), method: field_or_method, args
                                };
                            }
                            "add" | "remove" => expr = Expression::SetMethod {
                                set: map_name.clone(), method: field_or_method, args
                            },
                            _ => expr = Expression::MapMethod {
                                map: map_name.clone(), method: field_or_method, args
                            },
                        }
                    } else {
                        // Method call on non-identifier expression — not supported yet
                        // This would need a general method call AST variant
                        return Expression::Literal(Literal::Number(0));
                    }
                } else {
                    // Field access (no parens)
                    expr = Expression::FieldAccess {
                        object: Box::new(expr),
                        field: field_or_method,
                    };
                }
            }
            expr
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
        Rule::struct_literal => {
            let mut inner = pair.into_inner();
            let type_name = inner.next().unwrap().as_str().to_string();
            let mut fields: Vec<(String, Expression)> = Vec::new();
            for field_pair in inner {
                // Each field_pair is a struct_field_init: IDENT ~ ":" ~ expression
                let mut fi = field_pair.into_inner();
                let fname = fi.next().unwrap().as_str().to_string();
                let fval  = parse_expression(fi.next().unwrap());
                fields.push((fname, fval));
            }
            Expression::StructLiteral { type_name, fields }
        }
        Rule::enum_access_expr => {
            let mut inner = pair.into_inner();
            let enum_name = inner.next().unwrap().as_str().to_string();
            let variant   = inner.next().unwrap().as_str().to_string();
            Expression::EnumAccess { enum_name, variant_name: variant }
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
        Rule::asset_type => {
            let inner = pair.into_inner().next().unwrap();
            Type::Asset(Box::new(parse_type(inner)))
        }
        Rule::tuple_type => {
            let types: Vec<Type> = pair.into_inner().map(parse_type).collect();
            Type::Tuple(types)
        }
        Rule::option_type => {
            let inner = pair.into_inner().next().unwrap();
            Type::Option(Box::new(parse_type(inner)))
        }
        Rule::result_type => {
            let mut inner = pair.into_inner();
            let ok = parse_type(inner.next().unwrap());
            let err = parse_type(inner.next().unwrap());
            Type::Result(Box::new(ok), Box::new(err))
        }
        Rule::bytes_type => {
            let n_str = pair.into_inner().next().unwrap().as_str();
            let n: usize = n_str.parse().unwrap_or(0);
            Type::BytesN(n)
        }
        Rule::hash_type => {
            match pair.as_str() {
                "Hash32" => Type::Hash32,
                "Hash64" => Type::Hash64,
                _ => Type::Bytes,
            }
        }
        Rule::uma_type => {
            match pair.as_str() {
                "UMAIdentity" => Type::UMAIdentity,
                "ModelId" => Type::Named("ModelId".to_string()),
                "Height" => Type::Height,
                _ => Type::Named(pair.as_str().to_string()),
            }
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


#[cfg(test)]
mod attribute_parse_tests {
    use crate::parser::parse;

    #[test]
    fn test_minimal_attribute() {
        let src = "pragma synq ^0.9;\ncontract T {\n  state { x: u256; }\n  impl {\n    @public\n    function get_x() -> u256 { return x; }\n  }\n}\n";
        let result = parse(src);
        if let Err(ref e) = result {
            eprintln!("PARSE ERROR: {}", e);
        }
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
    }

    #[test]
    fn test_attribute_with_args() {
        let src = "pragma synq ^0.9;\ncontract T {\n  state { x: u256; }\n  impl {\n    @public\n    @authority(Admin)\n    function set_x(v: u256) -> bool { x = v; return true; }\n  }\n}\n";
        let result = parse(src);
        if let Err(ref e) = result {
            eprintln!("PARSE ERROR: {}", e);
        }
        assert!(result.is_ok(), "parse failed: {:?}", result.err());
    }
}
