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
    for p in inner {
        match p.as_rule() {
            Rule::contract_part => {
                let inner2 = p.into_inner().next().unwrap();
                match inner2.as_rule() {
                    Rule::state_variable_declaration => {
                        let mut si = inner2.into_inner();
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
                        let f = parse_function(inner2)?;
                        if !fn_names.insert(f.name.clone()) {
                            return Err(format!("duplicate function '{}' in contract '{}'", f.name, name));
                        }
                        parts.push(ContractPart::Function(f));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    Ok(ContractDefinition { name, parts })
}

fn parse_function(pair: Pair<Rule>) -> Result<FunctionDefinition, String> {
    use std::collections::HashSet;
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut params = vec![];
    let mut returns: Option<Type> = None;
    let mut body_stmts = vec![];
    let mut param_names: HashSet<String> = HashSet::new();

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
    }
}

fn parse_expression(pair: Pair<Rule>) -> Expression {
    match pair.as_rule() {
        Rule::expression => parse_expression(pair.into_inner().next().unwrap()),
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
        Rule::bool_literal    => Expression::Literal(Literal::Bool(pair.as_str() == "true")),
        Rule::IDENT           => Expression::Identifier(pair.as_str().to_string()),
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
        Rule::IDENT => match pair.as_str() {
            "address" | "Address"                  => Type::Address,
            "UInt256" | "uint256" | "uint" | "u256"=> Type::UInt256,
            "bool" | "Bool"                        => Type::Bool,
            "bytes" | "Bytes"                      => Type::Bytes,
            "DilithiumPublicKey"                   => Type::DilithiumPublicKey,
            "FalconPublicKey"                      => Type::FalconPublicKey,
            "KyberPublicKey"                       => Type::KyberPublicKey,
            "DilithiumSignature"                   => Type::DilithiumSignature,
            "FalconSignature"                      => Type::FalconSignature,
            _                                      => Type::UInt256, // default unknown to UInt256
        },
        _ => Type::UInt256,
    }
}
