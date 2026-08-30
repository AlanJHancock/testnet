use pest::Parser;
use pest::iterators::Pair;
use crate::ast::*;

#[derive(Parser)]
#[grammar = "synq.pest"]
pub struct SynQParser;

/// Parses every `Rule::statement` child of a `Rule::block`/`Rule::if_body`-
/// shaped pair into (statements, spans), spans[i] being the (line, column)
/// of statements[i] captured from pest's own span tracking. Used at every
/// site that builds an `ast::Block` so Block.statements and Block.spans
/// stay in lockstep -- see ast::Block's doc comment.
fn parse_statement_list_with_spans(block_pair: Pair<Rule>) -> (Vec<Statement>, Vec<Span>) {
    let mut statements = Vec::new();
    let mut spans = Vec::new();
    for stmt_pair in block_pair.into_inner() {
        if stmt_pair.as_rule() == Rule::statement {
            let (line, column) = stmt_pair.as_span().start_pos().line_col();
            spans.push(Span { line: line as u32, column: column as u32 });
            statements.push(parse_statement(stmt_pair.into_inner().next().unwrap()));
        }
    }
    (statements, spans)
}

/// Hard cap on bracket/paren/brace nesting depth, enforced BEFORE the pest
/// grammar ever sees the source.
///
/// Why this exists: the expression grammar (expression -> logical ->
/// comparison -> additive -> multiplicative -> unary -> postfix -> primary
/// -> "(" expression ")") re-walks the full precedence chain for every
/// nested paren, and pest does not memoize PEG alternatives. That makes
/// parse time exponential in nesting depth for pathological input, not
/// polynomial: measured on this exact grammar, nested "(" N times is ~0.01s
/// at N=10, ~0.5s at N=16, ~1.8s at N=18, ~7.4s at N=20, and >15s at N=22 -
/// from a single ~250-byte request. Beyond a few thousand levels it instead
/// blows the native call stack and aborts the whole process (SIGABRT),
/// which is worse: that kills every in-flight request on the server, not
/// just the pathological one. Every public endpoint that compiles
/// user-submitted SynQ source (/compile, /compile-aivm, /compile-wasm,
/// /aivm/estimate-gas, /diff-test, /bench-compile, /deploy-evm*, ...) calls
/// synq_compiler::parser::parse() on raw untrusted text, so this one guard
/// closes the hole everywhere at once.
///
/// 16 is chosen with real margin below both failure modes (legitimate SynQ
/// contracts essentially never nest brackets/parens past single digits)
/// while keeping worst-case rejected-input parse cost at "instant" (this is
/// a single linear scan over the source, no pest involved).
const MAX_NESTING_DEPTH: usize = 16;

/// Scans raw source for bracket/paren/brace nesting depth, skipping content
/// inside string literals, char literals, and comments so a long comment or
/// string containing many parens isn't mistaken for pathological nesting.
/// Combined (not per-bracket-type) depth is tracked since the vulnerable
/// grammar chain is reachable through any of them.
fn check_nesting_depth(source: &str) -> Result<(), String> {
    let mut depth: usize = 0;
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                while let Some(&nc) = chars.peek() {
                    if nc == '\n' { break; }
                    chars.next();
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                while let Some(nc) = chars.next() {
                    if nc == '*' && chars.peek() == Some(&'/') {
                        chars.next();
                        break;
                    }
                }
            }
            '"' => {
                while let Some(nc) = chars.next() {
                    if nc == '\\' { chars.next(); continue; }
                    if nc == '"' { break; }
                }
            }
            '\'' => {
                // Char literal, e.g. 'a' or '\n' - consume up to the closing
                // quote. Bails after a few chars if this doesn't look like
                // one, which only risks a false negative on depth counting
                // for stray apostrophes, never a false positive.
                let mut consumed = 0;
                while let Some(&nc) = chars.peek() {
                    if consumed > 4 { break; }
                    chars.next();
                    consumed += 1;
                    if nc == '\\' { chars.next(); consumed += 1; continue; }
                    if nc == '\'' { break; }
                }
            }
            '(' | '{' | '[' => {
                depth += 1;
                if depth > MAX_NESTING_DEPTH {
                    return Err(format!(
                        "expression/block nesting too deep (depth {} exceeds max {}) - this is almost \
                         always a mistake or a malformed contract, not legitimate code",
                        depth, MAX_NESTING_DEPTH
                    ));
                }
            }
            ')' | '}' | ']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn parse(source: &str) -> Result<Vec<SourceUnit>, String> {
    check_nesting_depth(source)?;
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
    // attribute_list / visibility_keyword (if present) are only used to skip
    // past them to reach the IDENT below -- neither struct nor contract
    // definitions currently carry attribute/visibility info in the AST.
    let name = {
        let first = inner.next().unwrap();
        match first.as_rule() {
            Rule::attribute_list => {
                // After attributes, we might have visibility_keyword or IDENT
                let second = inner.next().unwrap();
                match second.as_rule() {
                    Rule::visibility_keyword => {
                        inner.next().unwrap().as_str().to_string() // IDENT
                    }
                    _ => second.as_str().to_string()
                }
            }
            Rule::visibility_keyword => {
                inner.next().unwrap().as_str().to_string() // IDENT
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
    // attribute_list / visibility_keyword (if present) are only used to skip
    // past them to reach the IDENT below -- neither struct nor contract
    // definitions currently carry attribute/visibility info in the AST.
    let name = {
        let first = inner.next().unwrap();
        match first.as_rule() {
            Rule::attribute_list => {
                // After attributes, we might have visibility_keyword or IDENT
                let second = inner.next().unwrap();
                match second.as_rule() {
                    Rule::visibility_keyword => {
                        inner.next().unwrap().as_str().to_string() // IDENT
                    }
                    _ => second.as_str().to_string()
                }
            }
            Rule::visibility_keyword => {
                inner.next().unwrap().as_str().to_string() // IDENT
            }
            _ => first.as_str().to_string()
        }
    };
    let mut parts = vec![];
    let mut contract_enums = vec![];
    let mut fn_names: HashSet<String> = HashSet::new();
    let mut sv_names: HashSet<String> = HashSet::new();
    let mut ev_names: HashSet<String> = HashSet::new();
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
            Rule::event_definition => {
                let ev = parse_event(p);
                if !ev_names.insert(ev.name.clone()) {
                    return Err(format!("duplicate event '{}' in contract '{}'", ev.name, name));
                }
                parts.push(ContractPart::Event(ev));
            }
            Rule::events_section => {
                for ev_pair in p.into_inner() {
                    if ev_pair.as_rule() == Rule::event_definition {
                        let ev = parse_event(ev_pair);
                        if !ev_names.insert(ev.name.clone()) {
                            return Err(format!("duplicate event '{}' in contract '{}'", ev.name, name));
                        }
                        parts.push(ContractPart::Event(ev));
                    }
                }
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
            Rule::security_section => {
                // Security section is metadata-only — parsed but not compiled
                // Could store on contract in the future
            }
            Rule::enum_definition => {
                contract_enums.push(parse_enum(p));
            }
            _ => {}
        }
    }
    let event_defs: Vec<EventDefinition> = parts.iter()
        .filter_map(|p| if let ContractPart::Event(e) = p { Some(e.clone()) } else { None })
        .collect();
    Ok(ContractDefinition {
        name,
        parts,
        implements: vec![],
        metadata:   vec![],
        roles:      vec![],
        error_defs: vec![],
        enums: contract_enums,
        event_defs,
        test_fns:   vec![],
    })
}

/// Parses a single event_definition pair (whether it appeared flat in the
/// contract body or nested inside an events-section) into an
/// EventDefinition AST node. indexed_keyword is a silent (_) grammar rule,
/// so we detect it via the raw source text of each event_param rather than
/// as a child pair.
fn parse_event(pair: Pair<Rule>) -> EventDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string(); // IDENT
    let mut params = vec![];
    if let Some(list) = inner.next() {
        if list.as_rule() == Rule::event_param_list {
            for param_pair in list.into_inner() {
                let raw = param_pair.as_str().trim_start();
                let is_indexed = raw.starts_with("indexed");
                let mut pi = param_pair.into_inner();
                let pname = pi.next().unwrap().as_str().to_string();
                let ty = parse_type(pi.next().unwrap());
                params.push(EventParam { name: pname, ty, is_indexed });
            }
        }
    }
    EventDefinition { name, params }
}

fn parse_function(pair: Pair<Rule>) -> Result<FunctionDefinition, String> {
    use std::collections::HashSet;
    let mut inner = pair.into_inner();
    // The first inner pair may be attribute_list (if present) or IDENT (if not).
    // We need to save attribute_list for processing in the loop below.
    let mut saved_attr_list: Option<Pair<Rule>> = None;
    let mut visibility_kw: Option<String> = None;
    let name = {
        let first = inner.next().unwrap();
        match first.as_rule() {
            Rule::attribute_list => {
                saved_attr_list = Some(first);
                // After attributes, we might have visibility_keyword or IDENT
                let second = inner.next().unwrap();
                match second.as_rule() {
                    Rule::visibility_keyword => {
                        visibility_kw = Some(second.as_str().to_string());
                        inner.next().unwrap().as_str().to_string() // IDENT
                    }
                    _ => second.as_str().to_string()
                }
            }
            Rule::visibility_keyword => {
                visibility_kw = Some(first.as_str().to_string());
                inner.next().unwrap().as_str().to_string() // IDENT
            }
            _ => first.as_str().to_string()
        }
    };
    let mut params = vec![];
    let mut returns: Option<Type> = None;
    let mut body_stmts = vec![];
    let mut body_spans: Vec<Span> = vec![];
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
                let (stmts, spans) = parse_statement_list_with_spans(p);
                body_stmts = stmts;
                body_spans = spans;
            }
            _ => {}
        }
    }

    // Process attributes: derive is_public, merge with legacy clauses
    let mut is_public = attributes.iter().any(|a| matches!(a, Attribute::Public));

    // Handle spec-style visibility keywords (pub/priv/view/external/internal)
    if let Some(ref vis) = visibility_kw {
        match vis.as_str() {
            "pub" | "external" => {
                is_public = true;
                if !attributes.iter().any(|a| matches!(a, Attribute::Public)) {
                    attributes.push(Attribute::Public);
                }
            }
            "priv" | "internal" => {
                is_public = false;
            }
            "view" => {
                is_public = true;
                if !attributes.iter().any(|a| matches!(a, Attribute::Public)) {
                    attributes.push(Attribute::Public);
                }
                // view functions are read-only — could add a View attribute here
            }
            _ => {}
        }
    }
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
        body: Block { statements: body_stmts, spans: body_spans },
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
            // With ("[" ~ expression ~ "]")+ ~ "=" ~ expression ~ ";"
            // inner pairs: IDENT, key1_expr, key2_expr, ..., val_expr
            let all_exprs: Vec<_> = inner.map(parse_expression).collect();
            let val_expr = all_exprs.last().unwrap().clone();
            let keys = all_exprs[..all_exprs.len()-1].to_vec();
            Statement::MapAssignment { map: map_name, keys, value: val_expr }
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
        Rule::self_field_assign_statement => {
            // self.field = expr  =>  Assignment to state variable "field"
            let mut inner = pair.into_inner();
            let field = inner.next().unwrap().as_str().to_string();
            let val = parse_expression(inner.next().unwrap());
            Statement::Assignment(field, val)
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
            let args: Vec<Expression> = inner
                .next()
                .map(|al| al.into_inner().map(parse_expression).collect())
                .unwrap_or_default();
            Statement::RevertNamed { error, args }
        }
        Rule::revert_enum_statement => {
            let mut inner = pair.into_inner();
            let enum_name = inner.next().unwrap().as_str().to_string();
            let error = inner.next().unwrap().as_str().to_string();
            let args: Vec<Expression> = inner
                .next()
                .map(|al| al.into_inner().map(parse_expression).collect())
                .unwrap_or_default();
            Statement::RevertEnum { enum_name, error, args }
        }
        Rule::trap_statement => {
            // trap is spec-style revert — maps to RevertNamed
            let inner = pair.into_inner().next();
            let code = inner.map(|p| p.as_str().to_string()).unwrap_or_default();
            Statement::RevertNamed {
                error: format!("Trap({})", code),
                args: vec![],
            }
        }
        Rule::emit_statement => {
            let mut inner = pair.into_inner();
            let event = inner.next().unwrap().as_str().to_string();
            let args: Vec<Expression> = inner
                .next()
                .map(|al| al.into_inner().map(parse_expression).collect())
                .unwrap_or_default();
            Statement::Emit { event, args }
        }
        Rule::if_statement => {
            let mut inner = pair.into_inner();
            let condition = parse_expression(inner.next().unwrap());
            let (then_pairs, then_spans) = parse_statement_list_with_spans(inner.next().unwrap());
            let else_block = inner.next().map(|eb| {
                let (statements, spans) = parse_statement_list_with_spans(eb);
                Block { statements, spans }
            });
            Statement::If { condition, then_block: Block { statements: then_pairs, spans: then_spans }, else_block }
        }
        Rule::while_statement => {
            let mut inner = pair.into_inner();
            let condition = parse_expression(inner.next().unwrap());
            let (body_stmts, body_spans) = parse_statement_list_with_spans(inner.next().unwrap());
            Statement::While { condition, body: Block { statements: body_stmts, spans: body_spans } }
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
        Rule::expression => parse_expression(pair.into_inner().next().unwrap()),
        Rule::logical | Rule::comparison | Rule::bitor | Rule::bitxor | Rule::bitand
        | Rule::shift | Rule::additive | Rule::multiplicative => {
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
            } else if full.starts_with('~') {
                let operand = parse_expression(operand_pair);
                Expression::UnaryOp(UnaryOperator::BitNot, Box::new(operand))
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
                            "add" | "remove" | "contains" => expr = Expression::SetMethod {
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
        Rule::self_access => {
            // self.field → identifier "field" (state variables are accessed by name)
            let field = pair.into_inner().next().unwrap().as_str().to_string();
            Expression::Identifier(field)
        }
        Rule::map_index_expr  => {
            let mut inner = pair.into_inner();
            let map_name = inner.next().unwrap().as_str().to_string();
            let keys: Vec<Expression> = inner.map(parse_expression).collect();
            Expression::MapIndex(map_name, keys)
        }
        Rule::IDENT => match pair.as_str() {
            "caller" => Expression::Caller,
            "call_sender" => Expression::CallSender,
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
        "||" => BinaryOperator::Or,
        "&&" => BinaryOperator::And,
        "|"  => BinaryOperator::BitOr,
        "^"  => BinaryOperator::BitXor,
        "&"  => BinaryOperator::BitAnd,
        "<<" => BinaryOperator::Shl,
        ">>" => BinaryOperator::Shr,
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
