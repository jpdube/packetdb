// use chrono::{Local, TimeZone};
use std::fmt::Display;

use crate::config;
use crate::packet_ptr::PacketPtr;
use crate::parse::{Expression, Operator, PqlStatement};
use crate::pcapfile::PcapFile;
use crate::seek_packet::SeekPacket;
use frame::ipv4_address::is_ip_in_range;
use frame::packet::Packet;
use rayon::prelude::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Object {
    Integer(u64),
    Boolean(bool),
    IPv4(u32, u8),
    Timestamp(u32),
    MacAddress(u64),
    _Label(u32),
    ByteArray(Vec<u8>),
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
            Object::_Label(value) => write!(f, "Label: {:x}", value),
            Object::ByteArray(value) => write!(f, "Byte array: {:?}", value),
            Object::Timestamp(value) => write!(f, "Timestamp: {:x}", value),
            Object::MacAddress(mac) => write!(f, "Mac: {:x}", mac),
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
        if is_ip_in_range(sa, ip, mask) {
            TRUE
        } else {
            FALSE
        }
    }

    fn get_ip_not_in_range(sa: u32, ip: u32, mask: u8) -> Object {
        if is_ip_in_range(sa, ip, mask) {
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

    pub fn _run_pgm_seek(&self, packet_list: &PacketPtr, top_limit: usize) -> PacketPtr {
        let mut seek_pkt = SeekPacket::new(packet_list.clone());
        let mut packet_ptr = PacketPtr::default();
        let mut counter: usize = 0;
        let mut completed: bool = false;

        packet_ptr.file_id = packet_list.file_id;

        while let Some(pkt) = seek_pkt.next_chunk(4) {
            let result: Vec<Option<u32>> = pkt
                .into_par_iter()
                .map(|p| {
                    // println!("Packet: {:?}", &p);
                    if self.eval(&p) {
                        // println!("Found packet");
                        Some(p.pkt_ptr)
                    } else {
                        None
                    }
                })
                .collect();

            // println!("RESULT: {:?}", result);

            for r in result {
                if let Some(pkt) = r {
                    packet_ptr.pkt_ptr.push(pkt);
                    if !self.model.aggregate {
                        counter += 1;
                        // println!("TOP: {top_limit}, Counter: {counter}");
                        if top_limit == counter {
                            // if self.model.top == counter {
                            completed = true;
                        }
                    }
                }
            }

            if completed {
                break;
            }
            // if self.eval(&self.model.filter.to_owned(), &pkt) {
            //     packet_ptr.pkt_ptr.push(pkt.pkt_ptr);
            //     if !self.model.aggregate {
            //         counter += 1;
            //         if top_limit == counter {
            //             // if self.model.top == counter {
            //             break;
            //         }
            //     }
            // }
        }

        packet_ptr
    }
    pub fn run_pgm_seek(&self, packet_list: &PacketPtr, top_limit: usize) -> PacketPtr {
        let mut seek_pkt = SeekPacket::new(packet_list.clone());
        let mut packet_ptr = PacketPtr::default();
        let mut counter: usize = 0;

        packet_ptr.file_id = packet_list.file_id;

        while let Some(pkt) = seek_pkt.next() {
            if self.eval(&pkt) {
                packet_ptr.pkt_ptr.push(pkt.pkt_ptr);
                if !self.model.aggregate {
                    counter += 1;
                    if top_limit == counter {
                        // if self.model.top == counter {
                        break;
                    }
                }
            }
        }

        packet_ptr
    }

    pub fn _run_pgm(&self, filename: u32) -> PacketPtr {
        let mut pfile = PcapFile::new(filename, &config::CONFIG.db_path);
        // let mut total = 0;
        let mut packet_ptr = PacketPtr::default();
        packet_ptr.file_id = filename;

        while let Some(pkt) = pfile.next() {
            if self.eval(&pkt) {
                // if self.eval(&self.model.filter.to_owned(), &pkt) {
                packet_ptr.pkt_ptr.push(pkt.pkt_ptr);
            }
        }

        packet_ptr
    }

    pub fn eval(&self, pkt: &Packet) -> bool {
        let result = self.eval_expression(&self.model.filter, &pkt).unwrap();
        result == TRUE
    }
    // pub fn eval(&self, expr: &Expression, pkt: &Packet) -> bool {
    //     let result = self.eval_expression(&expr, &pkt).unwrap();
    //     result == TRUE
    // }

    fn eval_expression(&self, expression: &Expression, pkt: &Packet) -> Result<Object, EvalError> {
        match expression {
            Expression::Integer(i) => Ok(Object::Integer(*i as u64)),
            Expression::Timestamp(t) => Ok(Object::Timestamp(*t)),
            Expression::Label(value) => Ok(Object::Integer(pkt.get_field(*value) as u64)),
            Expression::LabelByte(field, offset, len) => {
                Ok(Object::ByteArray(pkt.get_field_byte(*field, *offset, *len)))
            }
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
            _ => Err(EvalError::UnknownOperator(
                format!("{}", operator),
                "eval_integer_infix_expression".to_string(),
            )),
        }
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

// pub type Result<T> = std::result::Result<T, EvalError>;
