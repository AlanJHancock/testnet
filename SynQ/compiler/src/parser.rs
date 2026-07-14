use pest::Parser;
use pest::iterators::Pair;
use crate::ast::*;

#[derive(Parser)]
#[grammar = "synq.pest"]
pub struct SynQParser;

pub fn parse(source: &str) -> Result<Vec<SourceUnit>, String> {
    let pairs = SynQParser::parse(Rule::source_file, source)
        .map_err(|e| format!("{}", e))?;
    let mut ast = vec![];
    for pair in pairs.into_iter().next().unwrap().into_inner() {
        match pair.as_rule() {
            Rule::top_level_item => {
                let inner = pair.into_inner().next().unwrap();
                match inner.as_rule() {
                    Rule::pragma_directive => ast.push(SourceUnit::Pragma(parse_pragma(inner))),
                    Rule::synq_pragma => {} // `pragma synq ^x.y;` -- consumed silently
                    Rule::struct_definition => ast.push(SourceUnit::Struct(parse_struct(inner))),
                    Rule::contract_definition => ast.push(SourceUnit::Contract(parse_contract(inner))),
                    _ => {}
                }
            }
            Rule::EOI => {}
            _ => {}
        }
    }
    Ok(ast)
}

fn parse_pragma(pair: Pair<Rule>) -> PragmaDirective {
    let mut inner = pair.into_inner();
    let key = inner.next().unwrap().as_str().to_string();
    let value = inner.next().unwrap().as_str().trim_matches('"').to_string();
    PragmaDirective { key, value }
}

fn parse_struct(pair: Pair<Rule>) -> StructDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let fields = inner.map(|p| {
        let mut fi = p.into_inner();
        let n = fi.next().unwrap().as_str().to_string();
        let t = parse_type(fi.next().unwrap());
        Parameter { name: n, ty: t }
    }).collect();
    StructDefinition { name, fields }
}

fn parse_contract(pair: Pair<Rule>) -> ContractDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut parts = vec![];
    for p in inner {
        match p.as_rule() {
            Rule::contract_part => {
                let inner2 = p.into_inner().next().unwrap();
                match inner2.as_rule() {
                    Rule::state_variable_declaration => {
                        let mut si = inner2.into_inner();
                        let n = si.next().unwrap().as_str().to_string();
                        let t = parse_type(si.next().unwrap());
                        parts.push(ContractPart::StateVariable(StateVariable { name: n, ty: t }));
                    }
                    Rule::function_definition => {
                        parts.push(ContractPart::Function(parse_function(inner2)));
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    ContractDefinition { name, parts }
}

fn parse_function(pair: Pair<Rule>) -> FunctionDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let mut params = vec![];
    let mut return_type = None;
    let mut body = vec![];

    for p in inner {
        match p.as_rule() {
            Rule::param_list => {
                for param in p.into_inner() {
                    if param.as_rule() == Rule::param {
                        let mut pi = param.into_inner();
                        let pn = pi.next().unwrap().as_str().to_string();
                        let pt = parse_type(pi.next().unwrap());
                        params.push(Parameter { name: pn, ty: pt });
                    }
                }
            }
            Rule::type_decl => {
                return_type = Some(parse_type(p));
            }
            Rule::block => {
                for stmt_pair in p.into_inner() {
                    if stmt_pair.as_rule() == Rule::statement {
                        body.push(parse_statement(stmt_pair.into_inner().next().unwrap()));
                    }
                }
            }
            _ => {}
        }
    }
    FunctionDefinition { name, params, return_type, body }
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
            let msg = inner.next().unwrap().as_str().trim_matches('"').to_string();
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
        _ => Statement::Expression(Expression::Number(0)),
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
                    Box::new(Expression::Number(0)),
                    BinaryOperator::Sub,
                    Box::new(operand),
                )
            } else {
                parse_expression(first)
            }
        }
        Rule::primary => parse_expression(pair.into_inner().next().unwrap()),
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
        Rule::literal => parse_expression(pair.into_inner().next().unwrap()),
        Rule::number_literal => Expression::Number(pair.as_str().parse().unwrap_or(0)),
        Rule::string_literal => Expression::StringLit(pair.as_str().trim_matches('"').to_string()),
        Rule::bool_literal => Expression::Bool(pair.as_str() == "true"),
        Rule::IDENT => Expression::Identifier(pair.as_str().to_string()),
        _ => Expression::Number(0),
    }
}

fn parse_binop(pair: &Pair<Rule>) -> BinaryOperator {
    match pair.as_str() {
        "+" => BinaryOperator::Add,
        "-" => BinaryOperator::Sub,
        "*" => BinaryOperator::Mul,
        "/" => BinaryOperator::Div,
        "%" => BinaryOperator::Mod,
        "==" => BinaryOperator::Eq,
        "!=" => BinaryOperator::Ne,
        "<" => BinaryOperator::Lt,
        "<=" => BinaryOperator::Le,
        ">" => BinaryOperator::Gt,
        ">=" => BinaryOperator::Ge,
        _ => BinaryOperator::Add,
    }
}

fn parse_type(pair: Pair<Rule>) -> TypeDecl {
    match pair.as_rule() {
        Rule::type_decl => parse_type(pair.into_inner().next().unwrap()),
        Rule::mapping_type => {
            let mut inner = pair.into_inner();
            let k = parse_type(inner.next().unwrap());
            let v = parse_type(inner.next().unwrap());
            TypeDecl::Mapping(Box::new(k), Box::new(v))
        }
        Rule::IDENT => TypeDecl::Simple(pair.as_str().to_string()),
        _ => TypeDecl::Simple("Unknown".to_string()),
    }
}
