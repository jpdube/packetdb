#![allow(dead_code)]

use crate::aggregate::Aggregate;
use crate::index_manager::IndexField;
use crate::keywords::Keyword;
use crate::lexer::Lexer;
use crate::token::Token;
use chrono::{prelude::*, Duration};
use chrono::{Local, TimeZone};
use frame::constant::NetConstant;
use frame::fields::string_to_int;
use frame::ipv4_address::{from_string_to_ip, IPv4};
use frame::mac_address::MacAddr;

use log::debug;
use std::collections::HashSet;
use std::{fmt, usize};

#[derive(Debug, Clone, PartialEq)]
pub enum Operator {
    Add,
    Substract,
    Multiply,
    Mask,
    Equal,
    In,
    NotIn,
    NE,
    LT,
    LE,
    GT,
    GE,
    LAND,
    LOR,
    BAND,
    BOR,
    BXOR,
    BitShiftLeft,
    BitShiftRight,
}

impl Operator {}

impl fmt::Display for Operator {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Add => write!(f, " + "),
            Self::Substract => write!(f, " - "),
            Self::Multiply => write!(f, " * "),
            Self::Mask => write!(f, " / "),
            Self::LAND => write!(f, " AND "),
            Self::LOR => write!(f, " OR "),
            Self::Equal => write!(f, " == "),
            Self::In => write!(f, " IN "),
            Self::NotIn => write!(f, " NOT IN "),
            Self::NE => write!(f, " != "),
            Self::LT => write!(f, " < "),
            Self::LE => write!(f, " <= "),
            Self::GT => write!(f, " > "),
            Self::GE => write!(f, " => "),
            Self::BAND => write!(f, " & "),
            Self::BOR => write!(f, " | "),
            Self::BXOR => write!(f, " ^ "),
            Self::BitShiftLeft => write!(f, " << "),
            Self::BitShiftRight => write!(f, " >> "),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Interval {
    pub from: u32,
    pub to: u32,
}

impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x} to {:x}", self.from, self.to)
    }
}

#[derive(Default, Clone, Debug)]
pub struct SelectField {
    pub name: String,
    pub id: u32,
}

#[derive(Debug, Clone)]
pub struct PqlStatement {
    pub select: Vec<SelectField>,
    pub filter_fields: Vec<SelectField>,
    pub from: Vec<String>,
    pub filter: Expression,
    pub top: usize,
    pub offset: usize,
    pub interval: Option<Interval>,
    pub search_type: HashSet<IndexField>,
    pub ip_list: Vec<IPv4>,
    pub has_distinct: bool,
    pub aggr_list: Vec<Aggregate>,
    pub groupby_fields: Vec<SelectField>,
    pub id_search: Vec<u64>,
    prev_label: String,
    prev_op: Operator,
}

impl PqlStatement {
    pub fn has_groupby(&self) -> bool {
        self.groupby_fields.len() != 0
    }

    pub fn has_aggregate(&self) -> bool {
        self.aggr_list.len() != 0
    }

    pub fn has_id_search(&self) -> bool {
        self.id_search.len() > 0
    }
}

impl fmt::Display for PqlStatement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(interval) = &self.interval {
            write!(
                f,
                "Select {}{:?} From: {:?} Where: {:?} [{:?}] Interval: {} Top: {} Offset: {}",
                if self.has_distinct { "DISTINCT" } else { "" },
                self.select,
                self.from,
                self.filter,
                self.filter_fields,
                interval,
                self.top,
                self.offset
            )
        } else {
            write!(
                f,
                "Select {} {:?}  From: {:?} Where: {:?} {:?} Top: {} Offset: {} Group By: {:?} Aggregate: {:?}",
                if self.has_distinct {"DISTINCT"} else {""}, self.select, self.from, self.filter, self.filter_fields, self.top, self.offset, self.groupby_fields, self.aggr_list,
            )
        }
    }
}

impl Default for PqlStatement {
    fn default() -> Self {
        Self {
            select: Vec::new(),
            filter_fields: Vec::new(),
            from: Vec::new(),
            filter: Expression::NoOp,
            top: 0,
            offset: 0,
            interval: None,
            search_type: HashSet::new(),
            has_distinct: false,
            ip_list: Vec::new(),
            aggr_list: Vec::new(),
            groupby_fields: Vec::new(),
            id_search: Vec::new(),
            prev_label: String::new(),
            prev_op: Operator::NotIn,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Expression {
    BinOp(Operator, Box<Expression>, Box<Expression>),
    Group(Box<Expression>),
    Label(u32),
    LabelByte(u32, usize, usize),
    Array(Vec<u8>),
    ArrayLong(Vec<u64>),
    Boolean(bool),
    Integer(u32),
    Long(u64),
    IPv4(u32, u8),
    Timestamp(u32),
    MacAddress(u64),
    NoOp,
}

impl Default for Expression {
    fn default() -> Self {
        Self::NoOp
    }
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BinOp(op, lhs, rhs) => {
                write!(f, "BinOp(OP:{}, LEFT:{}, RIGHT:{})", op, lhs, rhs)
            }
            Self::Group(expr) => write!(f, "Group({})", expr),
            Self::Label(lbl) => write!(f, "Label({:x})", lbl),
            Self::LabelByte(lbl, offset, length) => {
                write!(f, "Label byte({},{},{})", lbl, offset, length)
            }
            Self::Integer(value) => write!(f, "Integer({})", value),
            Self::Long(value) => write!(f, "Logn({})", value),
            Self::Timestamp(value) => write!(f, "Timestamp({})", value),
            Self::IPv4(ip_addr, cidr) => write!(f, "IPv4({})", IPv4::new(*ip_addr, *cidr as u8)),
            Self::Boolean(value) => write!(f, "Bool: {}", value),
            Self::MacAddress(mac_addr) => write!(f, "Mac({})", MacAddr::set_from_int(mac_addr)),
            Self::Array(array_bytes) => write!(f, "Array({:?})", array_bytes),
            Self::ArrayLong(values) => write!(f, "Array Long({:?})", values),
            // Self::ArrayIpv4(array_value) => write!(f, "Array of IPV4({:?})", array_value),
            Self::NoOp => write!(f, "NoOp"),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct ErrorMsg {
    pub message: String,
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for ErrorMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} at line: {}, column: {}",
            self.message, self.line, self.column
        )
    }
}

pub struct Parse {
    token_list: Vec<Token>,
    index: usize,
    lookahead: Option<Token>,
    prev_token: Option<Token>,
    peek_keyword: Option<Keyword>,
    has_error: bool,
    field_type: HashSet<IndexField>,
    error_list: Vec<ErrorMsg>,
    query: PqlStatement,
}

impl Parse {
    pub fn new() -> Self {
        Self {
            token_list: Vec::new(),
            index: 0,
            lookahead: None,
            prev_token: None,
            peek_keyword: None,
            has_error: false,
            field_type: HashSet::new(),
            error_list: Vec::new(),
            query: PqlStatement::default(),
        }
    }

    fn next(&mut self) -> Option<Token> {
        if self.index < self.token_list.len() {
            let result = Some(self.token_list[self.index].clone());
            self.index += 1;
            result
        } else {
            None
        }
    }

    fn peek(&mut self, keyword: Keyword) -> bool {
        self.peek_keyword = Some(keyword.to_owned());
        if self.lookahead.is_none() {
            self.lookahead = self.next();
            self.prev_token = self.lookahead.to_owned();
        }

        if self.lookahead.as_mut().unwrap().token == keyword {
            true
        } else {
            false
        }
    }

    fn accept(&mut self, keyword: Keyword) -> Option<Token> {
        if self.peek(keyword) {
            self.prev_token = self.lookahead.to_owned();
            self.lookahead = None;
            self.prev_token.clone()
        } else {
            None
        }
    }

    fn expect(&mut self, keyword: Keyword) -> Option<Token> {
        if self.peek(keyword.to_owned()) {
            let ret_tok = self.lookahead.clone();
            self.lookahead = None;
            ret_tok
        } else {
            self.has_error = true;
            let msg = format!(
                "Error expected: [{:?}]",
                self.peek_keyword.as_ref().unwrap(),
            );
            self.error_list.push(ErrorMsg {
                message: msg,
                line: self.lookahead.as_ref().unwrap().line,
                column: self.lookahead.as_ref().unwrap().column,
            });

            None
        }
    }

    pub fn print(&self) {
        println!("------- Tokens ---------");
        for i in self.token_list.iter() {
            println!("{}", i);
        }
        println!("------- Aggregates ---------");
        println!("{:#?}", self.query.aggr_list);
    }

    pub fn parse(&mut self, pql: &str) -> Option<Expression> {
        let mut lexer = Lexer::new();

        self.token_list = lexer.tokenize(&pql).clone();

        let result = self.parse_stmt().unwrap();
        if !self.has_error {
            println!("Expression: {:?}", &result);
            Some(result)
        } else {
            println!("Has error: {}", self.has_error);
            None
        }
    }

    fn parse_aggregate(&mut self) -> Option<Aggregate> {
        if self.accept(Keyword::Count).is_some() {
            let as_tok = self.expect(Keyword::As).unwrap();
            return Some(Aggregate::Count(as_tok.value));
        } else if let Some(tok) = self.accept(Keyword::Max) {
            let as_tok = self.expect(Keyword::As).unwrap();
            return Some(Aggregate::Max(
                string_to_int(&tok.value).unwrap(),
                as_tok.value,
            ));
        } else if let Some(tok) = self.accept(Keyword::Min) {
            let as_tok = self.expect(Keyword::As).unwrap();
            return Some(Aggregate::Min(
                string_to_int(&tok.value).unwrap(),
                as_tok.value,
            ));
        } else if let Some(tok) = self.accept(Keyword::Sum) {
            debug!("In sum: {:?}", tok);
            let as_tok = self.expect(Keyword::As).unwrap();
            let result = Aggregate::Sum(string_to_int(&tok.value).unwrap(), as_tok.value);
            debug!("SUM Result: {:?}", result);
            return Some(result);
        } else if let Some(tok) = self.accept(Keyword::Average) {
            let as_tok = self.expect(Keyword::As).unwrap();
            return Some(Aggregate::Avg(
                string_to_int(&tok.value).unwrap(),
                as_tok.value,
            ));
        } else if let Some(tok) = self.accept(Keyword::Bandwidth) {
            let as_tok = self.expect(Keyword::As).unwrap();
            return Some(Aggregate::Bandwidth(
                string_to_int(&tok.value).unwrap(),
                as_tok.value,
            ));
        }

        None
    }

    pub fn parse_select(&mut self, pql: &str) -> Result<PqlStatement, Vec<ErrorMsg>> {
        let mut tokenizer = Lexer::new();

        self.token_list = tokenizer.tokenize(&pql).clone();

        if self.expect(Keyword::Select).is_some() {
            loop {
                if self.accept(Keyword::Distinct).is_some() {
                    self.query.has_distinct = true;
                }
                if let Some(aggr) = self.parse_aggregate() {
                    println!("AGGREGATE: {:?}", aggr);
                    self.query.aggr_list.push(aggr);
                } else if let Some(sfield) = self.expect(Keyword::Identifier) {
                    if let Some(field) = string_to_int(&sfield.value) {
                        self.query.select.push(SelectField {
                            name: sfield.value,
                            id: field,
                        });
                    }
                }
                if self.peek(Keyword::Comma) {
                    self.accept(Keyword::Comma);
                } else {
                    break;
                }
            }

            if self.expect(Keyword::From).is_some() {
                debug!("From");
                while let Some(ffield) = self.expect(Keyword::Identifier) {
                    self.query.from.push(ffield.value);
                    if self.peek(Keyword::Comma) {
                        self.accept(Keyword::Comma);
                    } else {
                        break;
                    }
                }
            }

            if self.expect(Keyword::Where).is_some() {
                debug!("Where");
                self.query.filter = self.parse_expression().unwrap();
            }

            //--- Interval
            if self.peek(Keyword::Interval) {
                debug!("Interval");
                self.accept(Keyword::Interval);
                let mut ts_start: u32 = 0;
                let mut ts_end: u32 = 0;
                if self.peek(Keyword::Timestamp) {
                    if let Some(_start_ts) = self.expect(Keyword::Timestamp) {
                        self.accept(Keyword::Timestamp);
                        if let Some(start_ts) = self.get_timestamp(&_start_ts.value) {
                            ts_start = start_ts;
                        }
                    }
                }
                if self.peek(Keyword::Now) {
                    self.accept(Keyword::Now);
                    ts_start = self.get_now();
                }

                self.expect(Keyword::To);

                if self.peek(Keyword::Timestamp) {
                    let _end_ts = self.expect(Keyword::Timestamp).unwrap();
                    if let Some(end_ts) = self.get_timestamp(&_end_ts.value) {
                        ts_end = end_ts;
                    }
                }

                if self.peek(Keyword::Now) {
                    self.accept(Keyword::Now);
                    // ts_end = self.get_now();

                    if self.peek(Keyword::Minus) {
                        self.accept(Keyword::Minus);
                        if self.peek(Keyword::Integer) {
                            let ts_value = self.expect(Keyword::Integer).unwrap();
                            let offset = ts_value.value.parse::<u8>().unwrap();
                            if self.peek(Keyword::Identifier) {
                                let ts_modifier = self.expect(Keyword::Identifier).unwrap();
                                ts_end = self.get_now_ts(offset, &ts_modifier.value);
                            }
                        }
                    }
                }

                self.query.interval = Some(Interval {
                    from: ts_start,
                    to: ts_end,
                });
            }

            if self.peek(Keyword::GroupBy) {
                debug!("Group By");
                self.accept(Keyword::GroupBy);

                loop {
                    if let Some(sfield) = self.expect(Keyword::Identifier) {
                        if let Some(field) = string_to_int(&sfield.value) {
                            self.query.groupby_fields.push(SelectField {
                                name: sfield.value,
                                id: field,
                            });
                        }
                    }
                    if self.peek(Keyword::Comma) {
                        self.accept(Keyword::Comma);
                    } else {
                        break;
                    }
                }
            }

            if self.peek(Keyword::Offset) {
                self.accept(Keyword::Offset);
                if let Some(tok) = self.accept(Keyword::Integer) {
                    println!("Offset: {:?}", tok);
                    self.query.offset = tok.value.parse::<usize>().unwrap();
                } else {
                    println!("Expected integer");
                }
            }
            if self.peek(Keyword::Top) {
                self.accept(Keyword::Top);
                if let Some(tok) = self.accept(Keyword::Integer) {
                    self.query.top = tok.value.parse::<usize>().unwrap();
                } else {
                    self.query.top = 5;
                    println!("Expected integer");
                }
            }

            debug!("End of process for select");
            self.query.search_type = self.field_type.clone();
        }

        if self.error_list.len() == 0 {
            Ok(self.query.clone())
        } else {
            debug!("Select parse error: {:#?}", &self.error_list);
            Err(self.error_list.clone())
        }
    }

    fn get_now(&self) -> u32 {
        return Local::now().timestamp() as u32;
    }

    fn get_now_ts(&self, offset: u8, modifier: &str) -> u32 {
        let result = Local::now();
        let duration: Duration;

        match modifier {
            "s" => duration = Duration::seconds(offset as i64),
            "m" => duration = Duration::minutes(offset as i64),
            "h" => duration = Duration::hours(offset as i64),
            "d" => duration = Duration::days(offset as i64),
            "w" => duration = Duration::weeks(offset as i64),
            _ => duration = Duration::seconds(0),
        }

        return (result - duration).timestamp() as u32;
    }

    fn get_timestamp(&self, timestamp: &str) -> Option<u32> {
        let ts_result = NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d %H:%M:%S");

        match ts_result {
            Ok(ts) => {
                let rawts = Local.from_local_datetime(&ts).unwrap();
                Some(rawts.timestamp() as u32)
            }
            Err(_) => None,
        }
    }

    fn parse_stmt(&mut self) -> Option<Expression> {
        let expr = self.parse_expression();
        self.expect(Keyword::EOF);
        expr
    }

    pub fn parse_expression(&mut self) -> Option<Expression> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Option<Expression> {
        let mut leftval = self.parse_and().unwrap();

        loop {
            if self.accept(Keyword::Lor).is_some() {
                leftval = Expression::BinOp(
                    Operator::LOR,
                    Box::new(leftval),
                    Box::new(self.parse_and().unwrap()),
                );
            } else {
                break;
            }
        }

        Some(leftval)
    }

    fn parse_and(&mut self) -> Option<Expression> {
        let mut leftval = self.parse_relation().unwrap();

        loop {
            if self.accept(Keyword::Land).is_some() {
                leftval = Expression::BinOp(
                    Operator::LAND,
                    Box::new(leftval),
                    Box::new(self.parse_and().unwrap()),
                );
            } else {
                break;
            }
        }
        Some(leftval)
    }

    fn parse_relation(&mut self) -> Option<Expression> {
        let leftval = self.parse_factor().unwrap();

        if self.accept(Keyword::Equal).is_some() {
            Some(Expression::BinOp(
                Operator::Equal,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::In).is_some() {
            debug!("IN Operator");
            self.query.prev_op = Operator::In;
            Some(Expression::BinOp(
                Operator::In,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::NotIn).is_some() {
            debug!("NOT IN Operator");
            Some(Expression::BinOp(
                Operator::NotIn,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::Lt).is_some() {
            Some(Expression::BinOp(
                Operator::LT,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::Gt).is_some() {
            Some(Expression::BinOp(
                Operator::GT,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::Le).is_some() {
            Some(Expression::BinOp(
                Operator::LE,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::Ge).is_some() {
            Some(Expression::BinOp(
                Operator::GE,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::Ne).is_some() {
            Some(Expression::BinOp(
                Operator::NE,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::BitAnd).is_some() {
            Some(Expression::BinOp(
                Operator::BAND,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::BitOr).is_some() {
            Some(Expression::BinOp(
                Operator::BOR,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::BitXor).is_some() {
            Some(Expression::BinOp(
                Operator::BXOR,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::BitShiftRight).is_some() {
            Some(Expression::BinOp(
                Operator::BitShiftRight,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else if self.accept(Keyword::BitShiftLeft).is_some() {
            Some(Expression::BinOp(
                Operator::BitShiftLeft,
                Box::new(leftval),
                Box::new(self.parse_factor().unwrap()),
            ))
        } else {
            Some(leftval)
        }
    }

    fn parse_factor(&mut self) -> Option<Expression> {
        if self.peek(Keyword::Integer) {
            self.parse_int()
        } else if self.peek(Keyword::Timestamp) {
            self.parse_timestamp()
        } else if self.peek(Keyword::IndexStart) {
            self.parse_array()
        } else if self.peek(Keyword::Constant) {
            self.parse_constant()
        } else if self.peek(Keyword::IpV4) {
            self.parse_ipv4()
        } else if self.peek(Keyword::MacAddress) {
            self.parse_mac_address()
        } else if self.peek(Keyword::Identifier) {
            self.parse_label()
        } else if self.peek(Keyword::True) {
            self.parse_bool_true()
        } else if self.peek(Keyword::False) {
            self.parse_bool_false()
        } else if self.peek(Keyword::Lparen) {
            // println!("Grouping");
            self.parse_grouping()
        } else {
            None
        }
    }

    fn parse_bool_true(&mut self) -> Option<Expression> {
        if self.accept(Keyword::True).is_some() {
            Some(Expression::Boolean(true))
        } else {
            None
        }
    }

    fn parse_bool_false(&mut self) -> Option<Expression> {
        if self.accept(Keyword::False).is_some() {
            Some(Expression::Boolean(false))
        } else {
            None
        }
    }

    fn parse_int(&mut self) -> Option<Expression> {
        if let Some(tok) = self.accept(Keyword::Integer) {
            if let Ok(int_val) = tok.value.parse::<u32>() {
                return Some(Expression::Integer(int_val));
            } else if let Ok(long_val) = tok.value.parse::<u64>() {
                debug!("Found Long: {}", long_val);
                return Some(Expression::Long(long_val));
            } else {
                return None;
            }
            // Expression::Integer(tok.value.parse().unwrap())
            // Some(Expression::Integer(tok.value.parse().unwrap()))
        } else {
            None
        }
    }

    fn parse_constant(&mut self) -> Option<Expression> {
        if let Some(tok) = self.accept(Keyword::Constant) {
            match tok.value.as_str() {
                "ETH_IPV4" => Some(Expression::Integer(NetConstant::EthIPv4 as u32)),
                "IPV4_TCP" => Some(Expression::Integer(NetConstant::Ipv4Tcp as u32)),
                "IPV4_UDP" => Some(Expression::Integer(NetConstant::Ipv4Udp as u32)),
                "IPV4_ICMP" => Some(Expression::Integer(NetConstant::Ipv4Icmp as u32)),
                "HTTPS" => {
                    self.field_type.insert(IndexField::Https);
                    Some(Expression::Integer(NetConstant::Https as u32))
                }
                "DNS" => {
                    self.field_type.insert(IndexField::Dns);
                    Some(Expression::Integer(NetConstant::Dns as u32))
                }
                "DHCP_SERVER" => {
                    self.field_type.insert(IndexField::Dhcp);
                    Some(Expression::Integer(NetConstant::DhcpServer as u32))
                }
                "DHCP_CLIENT" => {
                    self.field_type.insert(IndexField::Dhcp);
                    Some(Expression::Integer(NetConstant::DhcpClient as u32))
                }
                _ => None,
            }
        } else {
            None
        }
    }

    fn parse_mac_address(&mut self) -> Option<Expression> {
        if let Some(tok) = self.accept(Keyword::MacAddress) {
            Some(Expression::MacAddress(
                MacAddr::set_from_str(&tok.value).address,
            ))
        } else {
            None
        }
    }

    fn parse_timestamp(&mut self) -> Option<Expression> {
        if let Some(tok) = self.accept(Keyword::Timestamp) {
            let ts = DateTime::parse_from_str(&tok.value, "%Y-%m-%d %H:%M:%S").unwrap();

            Some(Expression::Timestamp(ts.timestamp() as u32))
        } else {
            None
        }
    }

    fn parse_ipv4(&mut self) -> Option<Expression> {
        let mut cidr: u8 = 32;
        if let Some(tok) = self.accept(Keyword::IpV4) {
            if self.peek(Keyword::Mask) {
                self.accept(Keyword::Mask);
                if let Some(mask) = self.accept(Keyword::Integer) {
                    cidr = mask.value.parse().unwrap();
                }
            }

            let ipv4 = IPv4::new(from_string_to_ip(&tok.value), cidr);

            self.query.ip_list.push(ipv4.clone());

            Some(Expression::IPv4(ipv4.address, ipv4.mask))
        } else {
            None
        }
    }

    // fn parse_list(&mut self) -> Option<Expression> {
    //     // let mut index_values: Vec<u8> = Vec::new();

    //     let mut index_values: Vec<Box<Expression>> = Vec::new();
    //     if self.accept(Keyword::IndexStart).is_some() {
    //         loop {
    //             if self.peek(Keyword::IpV4) {
    //                 if let Some(ipv4) = self.parse_ipv4() {
    //                     index_values.push(Box::new(ipv4));
    //                 }
    //                 if !self.peek(Keyword::Comma) {
    //                     _ = self.expect(Keyword::IndexEnd);
    //                     break;
    //                 } else {
    //                     self.expect(Keyword::Comma);
    //                 }
    //             }
    //         }

    //         return Some(Expression::ArrayIpv4(index_values.clone()));
    //     } else {
    //         None
    //     }
    // }

    fn parse_array(&mut self) -> Option<Expression> {
        if self.query.prev_label == "frame.id" {
            return self.parse_long_array();
        }
        let mut index_values: Vec<u8> = Vec::new();

        if self.accept(Keyword::IndexStart).is_some() {
            loop {
                if let Some(tok) = self.accept(Keyword::Integer) {
                    index_values.push(tok.value.parse::<u8>().unwrap());
                }
                if !self.peek(Keyword::Comma) {
                    _ = self.expect(Keyword::IndexEnd);
                    break;
                } else {
                    self.expect(Keyword::Comma);
                }
            }

            return Some(Expression::Array(index_values.clone()));
        } else {
            None
        }
    }

    fn parse_long_array(&mut self) -> Option<Expression> {
        let mut index_values: Vec<u64> = Vec::new();

        if self.accept(Keyword::IndexStart).is_some() {
            loop {
                if let Some(tok) = self.accept(Keyword::Integer) {
                    let long_value = tok.value.parse::<u64>().unwrap();
                    index_values.push(long_value);

                    if self.query.prev_label == "frame.id" && self.query.prev_op == Operator::In {
                        self.query.id_search.push(long_value);
                    }
                }
                if !self.peek(Keyword::Comma) {
                    _ = self.expect(Keyword::IndexEnd);
                    break;
                } else {
                    self.expect(Keyword::Comma);
                }
            }

            debug!(
                "LONG Array list:  {}:{:?}",
                self.query.prev_label, self.query.id_search
            );

            return Some(Expression::ArrayLong(index_values));
        } else {
            None
        }
    }

    fn parse_label_byte(&mut self, tok: Token) -> Option<Expression> {
        let label: u32;
        let mut offset: usize = 0;
        let mut length: usize = 0;

        self.add_type(&tok.value);
        label = string_to_int(&tok.value).unwrap();
        if self.accept(Keyword::IndexStart).is_some() {
            if let Some(tok_offset) = self.expect(Keyword::Integer) {
                offset = tok_offset.value.parse::<usize>().unwrap();
            }

            _ = self.expect(Keyword::Colon);

            if let Some(tok_len) = self.expect(Keyword::Integer) {
                length = tok_len.value.parse::<usize>().unwrap();
            }

            _ = self.expect(Keyword::IndexEnd);

            return Some(Expression::LabelByte(label, offset, length));
        }

        None
    }

    fn parse_label(&mut self) -> Option<Expression> {
        println!("In label -->");
        if let Some(tok) = self.accept(Keyword::Identifier) {
            if let Some(field) = string_to_int(&tok.value) {
                self.query.filter_fields.push(SelectField {
                    name: tok.value.clone(),
                    id: field,
                });
            }
            if self.peek(Keyword::IndexStart) {
                return self.parse_label_byte(tok);
            }
            self.add_type(&tok.value);
            if let Some(field) = string_to_int(&tok.value) {
                self.query.prev_label = tok.value.clone();
                debug!("PREV LABEL: {}", self.query.prev_label);
                return Some(Expression::Label(field));
            }
        }

        return None;
    }

    fn add_type(&mut self, field: &str) {
        if field.find('.').is_some() {
            let field_type: Vec<&str> = field.split(".").collect();
            match field_type[0] {
                "eth" => self.field_type.insert(IndexField::Ethernet),
                "arp" => self.field_type.insert(IndexField::Arp),
                "ipv4" => self.field_type.insert(IndexField::IpV4),
                "icmp" => self.field_type.insert(IndexField::Icmp),
                "udp" => self.field_type.insert(IndexField::Udp),
                "tcp" => self.field_type.insert(IndexField::Tcp),
                _ => false,
            };
        }
    }

    fn parse_grouping(&mut self) -> Option<Expression> {
        if self.accept(Keyword::Lparen).is_some() {
            let expr = self.parse_expression().unwrap();
            if self.accept(Keyword::Rparen).is_some() {
                return Some(Expression::Group(Box::new(expr)));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_multi_fields() {
        let mut parse = Parse::new();
        let pql_test = r#"
        select a,b,c 
        from s1,s2 
        where ip.src == 192.168.242.1 
        top  200
        "#;
        let sql = parse.parse_select(pql_test).unwrap();
        println!("Select parse result: {:?}", sql);

        assert_eq!(3, sql.select.len(), "Select");
        assert_eq!(2, sql.from.len(), "From");
    }
    #[test]
    fn test_select_single_fields() {
        let mut parse = Parse::new();
        let pql_test = r#"
        select a
        from s1
        where ip.src == 192.168.242.1 
        top  200
        offset 15
        "#;
        let sql = parse.parse_select(pql_test).unwrap();
        println!("Select parse result: {:?}", sql);

        assert_eq!(1, sql.select.len(), "Select");
        assert_eq!(1, sql.from.len(), "From");
    }
}
