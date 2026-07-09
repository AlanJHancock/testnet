use pest::Parser;
use pest::iterators::Pair;
use crate::ast::*;

#[derive(Parser)]
#[grammar = "synq.pest"]
pub struct SynQParser;

pub fn parse(source: &str) -> Result<Vec<SourceUnit>, pest::error::Error<Rule>> {
    let pairs = SynQParser::parse(Rule::source_file, source)?;
    let mut ast = vec![];

    for pair in pairs.into_iter().next().unwrap().into_inner() {
        match pair.as_rule() {
            Rule::item => {
                let item = pair.into_inner().next().unwrap();
                match item.as_rule() {
                    Rule::struct_definition => {
                        ast.push(SourceUnit::Struct(parse_struct(item)));
                    }
                    Rule::contract_definition => {
                        ast.push(SourceUnit::Contract(parse_contract(item)));
                    }
                    _ => unreachable!(),
                }
            }
            Rule::EOI => (),
            _ => {} // Ignore whitespace and comments
        }
    }

    Ok(ast)
}

fn parse_struct(pair: Pair<Rule>) -> StructDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let fields = inner.map(parse_struct_field).collect();
    StructDefinition { name, fields }
}

fn parse_struct_field(pair: Pair<Rule>) -> Parameter {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let ty = parse_type(inner.next().unwrap());
    Parameter { ty, name, is_indexed: false }
}

fn parse_contract(pair: Pair<Rule>) -> ContractDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let parts = inner.map(parse_contract_part).collect();
    ContractDefinition { name, parts }
}

fn parse_contract_part(pair: Pair<Rule>) -> ContractPart {
    let item = pair.into_inner().next().unwrap();
    match item.as_rule() {
        Rule::state_variable_declaration => {
            ContractPart::StateVariable(parse_state_variable(item))
        }
        Rule::function_definition => {
            ContractPart::Function(parse_function(item))
        }
        _ => unreachable!(),
    }
}

fn parse_state_variable(pair: Pair<Rule>) -> StateVariableDeclaration {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let ty = parse_type(inner.next().unwrap());
    let is_public = inner.next().is_some();
    StateVariableDeclaration { ty, name, is_public }
}

fn parse_function(pair: Pair<Rule>) -> FunctionDefinition {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let params: Vec<Parameter> = inner
        .clone()
        .take_while(|p| p.as_rule() == Rule::param)
        .map(parse_param)
        .collect();
    // The final pair (after all params) is always the block.
    let block_pair = inner.find(|p| p.as_rule() == Rule::block).unwrap();
    let body = parse_block(block_pair);
    FunctionDefinition {
        name,
        params,
        returns: None,
        body,
        is_public: false,
    }
}

fn parse_param(pair: Pair<Rule>) -> Parameter {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let ty = parse_type(inner.next().unwrap());
    Parameter { ty, name, is_indexed: false }
}

fn parse_block(pair: Pair<Rule>) -> Block {
    let statements = pair.into_inner().map(parse_statement).collect();
    Block { statements }
}

fn parse_statement(pair: Pair<Rule>) -> Statement {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::require_statement => {
            let mut parts = inner.into_inner();
            let cond = parse_expression(parts.next().unwrap());
            let msg_pair = parts.next().unwrap();
            let msg = unquote(msg_pair.as_str());
            Statement::Require(cond, msg)
        }
        Rule::return_statement => {
            let expr = inner.into_inner().next().map(parse_expression);
            Statement::Return(expr)
        }
        Rule::assignment_statement => {
            let mut parts = inner.into_inner();
            let name = parts.next().unwrap().as_str().to_string();
            let expr = parse_expression(parts.next().unwrap());
            Statement::Assignment(name, expr)
        }
        Rule::expr_statement => {
            let expr = parse_expression(inner.into_inner().next().unwrap());
            Statement::Expression(expr)
        }
        _ => unreachable!("unexpected statement rule: {:?}", inner.as_rule()),
    }
}

fn unquote(s: &str) -> String {
    s.trim_matches('"').to_string()
}

// expression -> comparison_expr
fn parse_expression(pair: Pair<Rule>) -> Expression {
    let inner = pair.into_inner().next().unwrap();
    parse_comparison_expr(inner)
}

fn parse_comparison_expr(pair: Pair<Rule>) -> Expression {
    let mut inner = pair.into_inner();
    let mut left = parse_additive_expr(inner.next().unwrap());
    while let Some(op_pair) = inner.next() {
        let op = parse_comparison_op(op_pair.as_str());
        let right_pair = inner.next().unwrap();
        let right = parse_additive_expr(right_pair);
        left = Expression::BinaryOp(Box::new(left), op, Box::new(right));
    }
    left
}

fn parse_additive_expr(pair: Pair<Rule>) -> Expression {
    let mut inner = pair.into_inner();
    let mut left = parse_multiplicative_expr(inner.next().unwrap());
    while let Some(op_pair) = inner.next() {
        let op = parse_additive_op(op_pair.as_str());
        let right_pair = inner.next().unwrap();
        let right = parse_multiplicative_expr(right_pair);
        left = Expression::BinaryOp(Box::new(left), op, Box::new(right));
    }
    left
}

fn parse_multiplicative_expr(pair: Pair<Rule>) -> Expression {
    let mut inner = pair.into_inner();
    let mut left = parse_primary_expr(inner.next().unwrap());
    while let Some(op_pair) = inner.next() {
        let op = parse_multiplicative_op(op_pair.as_str());
        let right_pair = inner.next().unwrap();
        let right = parse_primary_expr(right_pair);
        left = Expression::BinaryOp(Box::new(left), op, Box::new(right));
    }
    left
}

fn parse_primary_expr(pair: Pair<Rule>) -> Expression {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::call_expr => parse_call_expr(inner),
        Rule::number_literal => Expression::Literal(Literal::Number(inner.as_str().parse().unwrap())),
        Rule::string_literal => Expression::Literal(Literal::String(unquote(inner.as_str()))),
        Rule::bool_literal => Expression::Literal(Literal::Bool(inner.as_str() == "true")),
        Rule::identifier_expr => Expression::Identifier(inner.as_str().to_string()),
        Rule::expression => parse_expression(inner),
        _ => unreachable!("unexpected primary rule: {:?}", inner.as_rule()),
    }
}

fn parse_call_expr(pair: Pair<Rule>) -> Expression {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str().to_string();
    let args = inner.map(parse_expression).collect();
    Expression::Call(name, args)
}

fn parse_comparison_op(s: &str) -> BinaryOperator {
    match s {
        "==" => BinaryOperator::Eq,
        "!=" => BinaryOperator::Ne,
        "<=" => BinaryOperator::Le,
        ">=" => BinaryOperator::Ge,
        "<" => BinaryOperator::Lt,
        ">" => BinaryOperator::Gt,
        _ => unreachable!("unknown comparison operator: {}", s),
    }
}

fn parse_additive_op(s: &str) -> BinaryOperator {
    match s {
        "+" => BinaryOperator::Add,
        "-" => BinaryOperator::Sub,
        _ => unreachable!("unknown additive operator: {}", s),
    }
}

fn parse_multiplicative_op(s: &str) -> BinaryOperator {
    match s {
        "*" => BinaryOperator::Mul,
        "/" => BinaryOperator::Div,
        _ => unreachable!("unknown multiplicative operator: {}", s),
    }
}

fn parse_type(pair: Pair<Rule>) -> Type {
    let mut inner = pair.into_inner();
    let name = inner.next().unwrap().as_str();
    match name {
        "Address" => Type::Address,
        "UInt256" => Type::UInt256,
        "Bool" => Type::Bool,
        "Bytes" => Type::Bytes,
        "DilithiumPublicKey" => Type::DilithiumPublicKey,
        "FalconPublicKey" => Type::FalconPublicKey,
        "KyberPublicKey" => Type::KyberPublicKey,
        "DilithiumSignature" => Type::DilithiumSignature,
        "FalconSignature" => Type::FalconSignature,
        _ => Type::Address, // Placeholder
    }
}
