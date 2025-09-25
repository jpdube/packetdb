// use chrono::{Local, TimeZone};
use std::fmt::Display;

use crate::packet_ptr::PacketPtr;
use crate::parse::{Expression, Operator, PqlStatement};
use crate::seek_packet::SeekPacket;
use frame::ipv4_address::IPv4;
use frame::packet::Packet;
use frame::pfield::FieldType;
use regex::Regex;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Object {
    Integer(u64),
    Boolean(bool),
    IPv4(u32, u8),
    Timestamp(u32),
    MacAddress(u64),
    _Label(String),
    ByteArray(Vec<u8>),
    LongArray(Vec<u64>),
    String(String),
    // _Label(String),
    Null,
}

// pub const NULL: Object = Object::Null;
pub const TRUE: Object = Object::Boolean(true);
pub const FALSE: Object = Object::Boolean(false);

impl Display for Object {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match self {
            Object::Integer(value) => write!(f, "Int:{}", value),
            Object::IPv4(addr, mask) => write!(f, "IPv4: {}/{}", addr, mask),
            Object::Boolean(value) => write!(f, "Bool: {}", value),
            Object::_Label(value) => write!(f, "Label: {}", value),
            Object::ByteArray(value) => write!(f, "Byte array: {:?}", value),
            Object::LongArray(value) => write!(f, "Long array: {:?}", value),
            Object::Timestamp(value) => write!(f, "Timestamp: {:x}", value),
            Object::MacAddress(mac) => write!(f, "Mac: {:x}", mac),
            Object::String(str) => write!(f, "String: {}", str),
            Object::Null => write!(f, "null"),
        }
    }
}

impl Object {
    pub fn debug_type(&self) -> String {
        match self {
            Object::Integer(_) => "Integer",
            Object::IPv4(_, _) => "IPv4",
            Object::Boolean(_) => "Boolean",
            Object::_Label(_) => "Label",
            Object::Timestamp(_) => "Timestamp",
            Object::MacAddress(_) => "MacAddress",
            Object::ByteArray(_) => "ByteArray",
            Object::LongArray(_) => "LongArray",
            Object::String(_) => "String",
            Object::Null => "Null",
        }
        .to_string()
    }

    pub fn get_bool(b: bool) -> Object {
        if b {
            TRUE
        } else {
            FALSE
        }
    }

    fn get_ip_in_range(sa: u32, ip: u32, mask: u8) -> Object {
        if IPv4::new(ip, mask).is_in_subnet(sa) {
            TRUE
        } else {
            FALSE
        }
    }

    fn get_ip_not_in_range(sa: u32, ip: u32, mask: u8) -> Object {
        if IPv4::new(ip, mask).is_in_subnet(sa) {
            FALSE
        } else {
            TRUE
        }
    }
}

pub struct Interpreter {
    model: PqlStatement,
    // model: Expression,
}

impl Interpreter {
    pub fn new(model: PqlStatement) -> Self {
        // pub fn new(model: Expression) -> Self {
        Self { model }
    }

    pub fn run_pgm_seek(&self, packet_list: &PacketPtr, top_limit: usize) -> (usize, Vec<Packet>) {
        let mut seek_pkt = SeekPacket::new(packet_list);
        let mut counter: usize = 0;
        // let mut packet_ptr: Vec<Record> = Vec::new();
        let mut result: Vec<Packet> = Vec::new();
        let mut nbr_searched: usize = 0;

        while let Some(pkt) = seek_pkt.next() {
            nbr_searched += 1;
            if self.eval(&pkt) {
                result.push(pkt);

                if !self.model.has_aggregate() {
                    counter += 1;
                    if top_limit == counter {
                        // if self.model.top == counter {
                        break;
                    }
                }
            }
        }

        (nbr_searched, result)
    }

    pub fn eval(&self, pkt: &Packet) -> bool {
        let result = self.eval_expression(&self.model.filter, &pkt).unwrap();
        result == TRUE
    }

    fn eval_expression(&self, expression: &Expression, pkt: &Packet) -> Result<Object, EvalError> {
        match expression {
            Expression::Integer(i) => Ok(Object::Integer(*i as u64)),
            Expression::ArrayLong(values) => Ok(Object::LongArray(values.clone())),
            Expression::Long(i) => Ok(Object::Integer(*i as u64)),
            Expression::String(s) => Ok(Object::String(s.clone())),
            Expression::Timestamp(t) => Ok(Object::Timestamp(*t)),
            Expression::Label(value) => {
                // debug!("Label: {}", value);
                let field_value = pkt.get_field(value.clone()).unwrap();
                match field_value.field {
                    FieldType::Int8(_) => Ok(Object::Integer(field_value.to_u64())),
                    FieldType::Int16(_) => Ok(Object::Integer(field_value.to_u64())),
                    FieldType::Int32(_) => Ok(Object::Integer(field_value.to_u64())),
                    FieldType::Int64(_) => Ok(Object::Integer(field_value.to_u64())),
                    FieldType::String(_) => Ok(Object::String(field_value.to_string())),

                    _ => Ok(Object::Integer(field_value.to_u64())),
                }
            }
            Expression::LabelByte(field, offset, len) => Ok(Object::ByteArray(pkt.get_field_byte(
                field.clone(),
                *offset,
                *len,
            ))),
            Expression::Array(array_values) => Ok(Object::ByteArray(array_values.clone())),
            Expression::IPv4(addr, mask) => Ok(Object::IPv4(*addr, *mask)),
            Expression::MacAddress(addr) => Ok(Object::MacAddress(*addr)),
            Expression::Boolean(b) => Ok(Object::Boolean(*b)),
            Expression::Group(expr) => self.eval_expression(expr, &pkt),
            Expression::NoOp => Ok(Object::Null),
            Expression::BinOp(operator, left, right) => {
                let left = self.eval_expression(left, &pkt)?;
                let right = self.eval_expression(right, &pkt)?;
                self.eval_infix_expression(operator, left, right)
            } // _ => Ok(Object::Null),
        }
    }

    fn eval_infix_expression(
        &self,
        operator: &Operator,
        left: Object,
        right: Object,
    ) -> Result<Object, EvalError> {
        match (&left, &right) {
            (Object::Integer(i), Object::Integer(j)) => {
                self.eval_integer_infix_expression(operator, *i, *j)
            }
            (Object::String(i), Object::String(j)) => {
                self.eval_string_infix_expression(operator, i, j)
            }
            (Object::Integer(i), Object::LongArray(j)) => {
                self.eval_larray_infix_expression(operator, *i, j.clone())
            }
            (Object::Boolean(b0), Object::Boolean(b1)) => {
                self.eval_boolean_infix_expression(operator, *b0, *b1)
            }
            (Object::Integer(sa), Object::IPv4(ip, mask)) => {
                self.eval_ipv4_infix_expression(operator, *sa as u32, *ip, *mask)
            }
            (Object::Integer(sa), Object::MacAddress(addr)) => {
                self.eval_integer_infix_expression(operator, *sa, *addr)
            }
            (Object::Integer(pts), Object::Timestamp(ts)) => {
                self.eval_integer_infix_expression(operator, *pts as u64, *ts as u64)
            }
            (Object::ByteArray(pts), Object::ByteArray(ts)) => {
                self.eval_array_infix_expression(operator, pts.clone(), ts.clone())
            }
            (Object::Integer(b0), Object::Boolean(b1)) => {
                let lb = if *b0 == 1 { true } else { false };
                self.eval_boolean_infix_expression(operator, lb, *b1)
            }
            // (Object::Str(s0), Object::Str(s1)) => eval_string_infix_expression(operator, s0, s1),
            (_, _) => Err(EvalError::TypeMismatch(
                format!("{} {} {}", left.debug_type(), operator, right.debug_type()),
                "eval_infix_expression".to_string(),
            )),
        }
    }

    fn value_in_long_array(&self, target: u64, long_array: Vec<u64>) -> bool {
        long_array.contains(&target)
    }

    fn eval_larray_infix_expression(
        &self,
        operator: &Operator,
        left_array: u64,
        right_array: Vec<u64>,
    ) -> Result<Object, EvalError> {
        match operator {
            Operator::In => Ok(Object::get_bool(
                self.value_in_long_array(left_array, right_array),
            )),
            Operator::NotIn => Ok(Object::get_bool(
                !self.value_in_long_array(left_array, right_array),
            )),
            _ => Err(EvalError::UnknownOperator(
                format!("{}", operator),
                "eval_integer_infix_expression".to_string(),
            )),
        }
    }

    fn compare_array(&self, left_array: Vec<u8>, right_array: Vec<u8>) -> bool {
        if left_array.len() != right_array.len() {
            return false;
        }

        for i in 0..left_array.len() {
            if left_array[i] != right_array[i] {
                return false;
            }
        }

        true
    }

    fn eval_array_infix_expression(
        &self,
        operator: &Operator,
        left_array: Vec<u8>,
        right_array: Vec<u8>,
    ) -> Result<Object, EvalError> {
        match operator {
            Operator::Equal => Ok(Object::get_bool(
                self.compare_array(left_array, right_array),
            )),
            Operator::NE => Ok(Object::get_bool(
                !self.compare_array(left_array, right_array),
            )),
            _ => Err(EvalError::UnknownOperator(
                format!("{}", operator),
                "eval_integer_infix_expression".to_string(),
            )),
        }
    }

    fn eval_ipv4_infix_expression(
        &self,
        operator: &Operator,
        sa: u32,
        ip: u32,
        mask: u8,
    ) -> Result<Object, EvalError> {
        match operator {
            Operator::Equal => Ok(Object::get_ip_in_range(sa, ip, mask)),
            Operator::NE => Ok(Object::get_ip_not_in_range(sa, ip, mask)),
            _ => Err(EvalError::UnknownOperator(
                format!("{}", operator),
                "eval_integer_infix_expression".to_string(),
            )),
        }
    }

    fn eval_integer_infix_expression(
        &self,
        operator: &Operator,
        i: u64,
        j: u64,
    ) -> Result<Object, EvalError> {
        match operator {
            Operator::LT => Ok(Object::get_bool(i < j)),
            Operator::LE => Ok(Object::get_bool(i <= j)),
            Operator::GT => Ok(Object::get_bool(i > j)),
            Operator::GE => Ok(Object::get_bool(i >= j)),
            Operator::Equal => Ok(Object::get_bool(i == j)),
            Operator::NE => Ok(Object::get_bool(i != j)),
            Operator::BAND => Ok(Object::Integer(i & j)),
            Operator::BOR => Ok(Object::Integer(i | j)),
            Operator::BXOR => Ok(Object::Integer(i ^ j)),
            Operator::BitShiftRight => Ok(Object::Integer(i >> j)),
            Operator::BitShiftLeft => Ok(Object::Integer(i << j)),
            _ => Err(EvalError::UnknownOperator(
                format!("{}", operator),
                "eval_integer_infix_expression".to_string(),
            )),
        }
    }

    fn eval_string_infix_expression(
        &self,
        operator: &Operator,
        i: &String,
        j: &String,
    ) -> Result<Object, EvalError> {
        match operator {
            Operator::Equal => Ok(Object::get_bool(i == j)),
            Operator::NE => Ok(Object::get_bool(i != j)),
            Operator::In => Ok(Object::get_bool(i.contains(j))),
            Operator::NotIn => Ok(Object::get_bool(!i.contains(j))),
            Operator::Like => Ok(Object::get_bool(self.like_string(i, j))),
            _ => Err(EvalError::UnknownOperator(
                format!("{}", operator),
                "eval_string_infix_expression".to_string(),
            )),
        }
    }

    fn like_string(&self, source: &String, target: &String) -> bool {
        let pattern = Regex::new(target).unwrap();

        pattern.is_match(source)
    }

    fn eval_boolean_infix_expression(
        &self,
        operator: &Operator,
        b0: bool,
        b1: bool,
    ) -> Result<Object, EvalError> {
        match operator {
            Operator::Equal => Ok(Object::get_bool(b0 == b1)),
            Operator::NE => Ok(Object::get_bool(b0 != b1)),
            Operator::LAND => Ok(Object::get_bool(b0 && b1)),
            Operator::LOR => Ok(Object::get_bool(b0 || b1)),
            _ => Err(EvalError::UnknownOperator(
                format!("{}", operator),
                "eval_boolean_infix_expression".to_string(),
            )),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum EvalError {
    TypeMismatch(String, String),
    UnknownOperator(String, String),
    // SyntaxError(String, String),
    _IdentifierNotFound(String, String),
    _ExpectedIdentifier(String, String),
    _WrongNumberOfArguments(String, String),
    _IndexOutOfBounds(String, String),
}

impl Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::result::Result<(), std::fmt::Error> {
        match self {
            EvalError::TypeMismatch(s, func) => write!(f, "type mismatch: {} in {}", s, func),
            EvalError::UnknownOperator(s, func) => write!(f, "unknown operator: {} in {}", s, func),
            // EvalError::SyntaxError(s, func) => write!(f, "syntax error: {} in {}", s, func),
            EvalError::_IdentifierNotFound(s, func) => {
                write!(f, "identifier not found: {} in {}", s, func)
            }
            EvalError::_ExpectedIdentifier(s, func) => {
                write!(f, "expected identifier: {} in {}", s, func)
            }
            EvalError::_WrongNumberOfArguments(s, func) => {
                write!(f, "wrong number of arguments: {} in {}", s, func)
            }
            EvalError::_IndexOutOfBounds(s, func) => {
                write!(f, "index out of bounds: {} in {}", s, func)
            }
        }
    }
}
