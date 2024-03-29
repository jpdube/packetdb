#![allow(dead_code)]

use crate::index_manager::IndexField;
// use crate::tokenizer::{Keyword, Token, Tokenizer};
use crate::lexer::Lexer;
use crate::token::{Keyword, Token};
use chrono::{prelude::*, Duration};
use chrono::{Local, TimeZone};
use frame::constant::NetConstant;
use frame::fields;
use frame::ipv4_address::IPv4;
use frame::ipv4_address::{ipv4_to_string, string_ipv4_to_int};
use frame::mac_address::{mac_to_string, string_mac_to_int};

use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone)]
pub enum Operator {
    Add,
    Substract,
    Multiply,
    Mask,
    Equal,
    NE,
    LT,
    LE,
    GT,
    GE,
    LAND,
    LOR,
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
            Self::NE => write!(f, " != "),
            Self::LT => write!(f, " < "),
            Self::LE => write!(f, " <= "),
            Self::GT => write!(f, " > "),
            Self::GE => write!(f, " => "),
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
    pub from: Vec<String>,
    pub filter: Expression,
    pub top: usize,
    pub offset: usize,
    pub interval: Option<Interval>,
    pub search_type: HashSet<IndexField>,
    pub aggregate: bool,
    pub ip_list: HashMap<String, Vec<IPv4>>,
}

impl fmt::Display for PqlStatement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(interval) = &self.interval {
            write!(
                f,
                "Select {:?} From: {:?} Where: {:?} Interval: {} Top: {} Offset: {}",
                self.select, self.from, self.filter, interval, self.top, self.offset
            )
        } else {
            write!(
                f,
                "Select {:?} From: {:?} Where: {:?} Top: {} Offset: {}",
                self.select, self.from, self.filter, self.top, self.offset
            )
        }
    }
}

impl Default for PqlStatement {
    fn default() -> Self {
        let mut hm: HashMap<String, Vec<IPv4>> = HashMap::new();
        hm.insert("ip.dst".to_string(), Vec::new());
        hm.insert("ip.src".to_string(), Vec::new());

        let st: HashSet<IndexField> = HashSet::new();
        // st.insert(IndexField::Dns);

        Self {
            select: Vec::new(),
            from: Vec::new(),
            filter: Expression::NoOp,
            top: 10,
            offset: 0,
            interval: None,
            search_type: st,
            aggregate: false,
            ip_list: hm,
            // ip_list: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Expression {
    BinOp(Operator, Box<Expression>, Box<Expression>),
    Group(Box<Expression>),
    Label(u32),
    LabelByte(u32, usize, usize),
    Boolean(bool),
    // Const(String),
    Integer(u32),
    // Float(f32),
    IPv4(u32, u8),
    Timestamp(u32),
    MacAddress(u64),
    ByteArray(Vec<u8>),
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
            Self::LabelByte(lbl, start, length) => {
                write!(f, "Label byte({:x},{},{})", lbl, start, length)
            }
            Self::Integer(value) => write!(f, "Integer({})", value),
            Self::Timestamp(value) => write!(f, "Timestamp({})", value),
            // Self::Float(value) => write!(f, "Float({})", value),
            Self::IPv4(ip_addr, cidr) => write!(f, "IPv4({},{})", ipv4_to_string(*ip_addr), cidr),
            Self::Boolean(value) => write!(f, "Bool: {}", value),
            // Self::Const(const_str) => write!(f, "Const({})", const_str),
            Self::MacAddress(mac_addr) => write!(f, "Mac({})", mac_to_string(*mac_addr)),
            Self::ByteArray(byte_array) => write!(f, "Byte array({:?})", byte_array),
            Self::NoOp => write!(f, "NoOp"),
            // _ => write!(f, "Undefined"),
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
    prev_ip_label: String,
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
            prev_ip_label: String::new(),
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

    fn peek(&mut self, keyword: Keyword) -> Option<Token> {
        self.peek_keyword = Some(keyword.to_owned());
        if self.lookahead.is_none() {
            self.lookahead = self.next();
            self.prev_token = self.lookahead.to_owned();
        }

        if self.lookahead.as_mut().unwrap().token == keyword {
            self.lookahead.clone()
        } else {
            None
        }
    }

    fn accept(&mut self, keyword: Keyword) -> Option<Token> {
        let tok = self.peek(keyword);
        if let Some(token) = &tok {
            self.prev_token = self.lookahead.to_owned();
            self.lookahead = None;

            if token.value == "ip.dst" || token.value == "ip.src" {
                self.prev_ip_label = token.value.clone();
            }
        }
        tok
    }

    fn expect(&mut self, keyword: Keyword) -> Option<Token> {
        let tok = self.peek(keyword.to_owned());
        if tok.is_some() {
            self.lookahead = None;
            tok
        } else {
            self.has_error = true;
            let msg = format!(
                "Error expected: [{:?}] found: [{:?}]",
                self.peek_keyword.as_ref().unwrap(),
                self.lookahead.as_ref().unwrap().token
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
        for i in self.token_list.iter() {
            println!("{}", i);
        }
    }

    pub fn parse(&mut self, pql: &str) -> Option<Expression> {
        let mut lexer = Lexer::new(pql);
        // let mut tokenizer = Tokenizer::new();

        self.token_list = lexer.run().clone();
        // self.token_list = tokenizer.tokenize(&pql).clone();

        let result = self.parse_stmt().unwrap();
        if !self.has_error {
            println!("Expression: {:?}", &result);
            Some(result)
        } else {
            println!("Has error: {}", self.has_error);
            None
        }
    }

    pub fn parse_select(&mut self, pql: &str) -> Result<PqlStatement, Vec<ErrorMsg>> {
        let mut lexer = Lexer::new(pql);
        // let mut tokenizer = Tokenizer::new();

        self.token_list = lexer.run().clone();
        self.print();
        // self.token_list = tokenizer.tokenize(&pql).clone();
        // let mut query = PqlStatement::default();

        if self.accept(Keyword::Select).is_some() {
            while let Some(sfield) = self.expect(Keyword::Identifier) {
                if let Some(field) = fields::string_to_int(&sfield.value) {
                    self.query.select.push(SelectField {
                        name: sfield.value,
                        id: field,
                    });
                }
                if self.peek(Keyword::Comma).is_some() {
                    self.accept(Keyword::Comma);
                } else {
                    break;
                }
            }

            if self.expect(Keyword::From).is_some() {
                while let Some(ffield) = self.expect(Keyword::Identifier) {
                    self.query.from.push(ffield.value);
                    if self.peek(Keyword::Comma).is_some() {
                        self.accept(Keyword::Comma);
                    } else {
                        break;
                    }
                }
            }

            if self.expect(Keyword::Where).is_some() {
                self.query.filter = self.parse_expression().unwrap();
            }

            //--- Interval
            if self.peek(Keyword::Interval).is_some() {
                self.accept(Keyword::Interval);
                let mut ts_start: u32 = 0;
                let mut ts_end: u32 = 0;
                if let Some(_start_ts) = self.peek(Keyword::Timestamp) {
                    self.accept(Keyword::Timestamp);
                    if let Some(start_ts) = self.get_timestamp(&_start_ts.value) {
                        ts_start = start_ts;
                    }
                }

                if let Some(_start_ts) = self.peek(Keyword::Now) {
                    self.accept(Keyword::Now);
                    ts_start = self.get_now();
                }

                self.expect(Keyword::To);

                if let Some(_end_ts) = self.peek(Keyword::Timestamp) {
                    self.accept(Keyword::Timestamp);
                    if let Some(end_ts) = self.get_timestamp(&_end_ts.value) {
                        ts_end = end_ts;
                    }
                }

                if self.peek(Keyword::Now).is_some() {
                    self.accept(Keyword::Now);
                    // ts_end = self.get_now();

                    if self.peek(Keyword::Minus).is_some() {
                        self.accept(Keyword::Minus);
                        if let Some(ts_value) = self.peek(Keyword::Integer) {
                            self.accept(Keyword::Integer);
                            let offset = ts_value.value.parse::<u8>().unwrap();
                            if let Some(ts_modifier) = self.peek(Keyword::Identifier) {
                                self.accept(Keyword::Identifier);
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

            if self.peek(Keyword::Top).is_some() {
                self.accept(Keyword::Top);
                if let Some(tok) = self.accept(Keyword::Integer) {
                    self.query.top = tok.value.parse::<usize>().unwrap();
                } else {
                    println!("Expected integer");
                }
            }
            if self.peek(Keyword::Offset).is_some() {
                self.accept(Keyword::Offset);
                if let Some(tok) = self.accept(Keyword::Integer) {
                    println!("Offset: {:?}", tok);
                    self.query.offset = tok.value.parse::<usize>().unwrap();
                } else {
                    println!("Expected integer");
                }
            }

            self.query.search_type = self.field_type.clone();
        }
        if self.error_list.len() == 0 {
            println!("Expr: {}", self.query.filter);
            Ok(self.query.clone())
        } else {
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
        } else {
            Some(leftval)
        }
    }

    fn parse_factor(&mut self) -> Option<Expression> {
        if self.peek(Keyword::Integer).is_some() {
            self.parse_int()
        } else if self.peek(Keyword::Timestamp).is_some() {
            self.parse_timestamp()
        } else if self.peek(Keyword::Constant).is_some() {
            // println!("Factor,Constant");
            self.parse_constant()
        } else if self.peek(Keyword::IpV4).is_some() {
            self.parse_ipv4()
        } else if self.peek(Keyword::MacAddress).is_some() {
            self.parse_mac_address()
        } else if self.peek(Keyword::Identifier).is_some() {
            println!("+++ Identifier");
            self.parse_label()
        } else if self.peek(Keyword::IndexStart).is_some() {
            println!("+++ Array");
            self.parse_array()
        } else if self.peek(Keyword::True).is_some() {
            self.parse_bool_true()
        } else if self.peek(Keyword::False).is_some() {
            self.parse_bool_false()
        } else if self.peek(Keyword::Lparen).is_some() {
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
            Some(Expression::Integer(tok.value.parse().unwrap()))
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
                "SSH" => {
                    self.field_type.insert(IndexField::Ssh);
                    Some(Expression::Integer(NetConstant::Ssh as u32))
                }
                "RDP" => {
                    self.field_type.insert(IndexField::Rdp);
                    Some(Expression::Integer(NetConstant::Rdp as u32))
                }
                "TELNET" => {
                    self.field_type.insert(IndexField::Telnet);
                    Some(Expression::Integer(NetConstant::Telnet as u32))
                }
                "HTTP" => {
                    self.field_type.insert(IndexField::Http);
                    Some(Expression::Integer(NetConstant::Http as u32))
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
            // Some(Expression::Integer(tok.value.parse().unwrap()))
        } else {
            None
        }
    }

    fn parse_mac_address(&mut self) -> Option<Expression> {
        if let Some(tok) = self.accept(Keyword::MacAddress) {
            Some(Expression::MacAddress(string_mac_to_int(
                tok.value.parse().unwrap(),
            )))
        } else {
            None
        }
    }

    fn parse_timestamp(&mut self) -> Option<Expression> {
        if let Some(tok) = self.accept(Keyword::Timestamp) {
            let ts = Local
                .datetime_from_str(&tok.value, "%Y-%m-%d %H:%M:%S")
                .unwrap();

            Some(Expression::Timestamp(ts.timestamp() as u32))
        } else {
            None
        }
    }

    fn parse_ipv4(&mut self) -> Option<Expression> {
        let mut cidr: u8 = 32;
        if let Some(tok) = self.accept(Keyword::IpV4) {
            if self.peek(Keyword::Mask).is_some() {
                self.accept(Keyword::Mask);
                if let Some(mask) = self.accept(Keyword::Integer) {
                    cidr = mask.value.parse().unwrap();
                }
            }
            println!(
                "Search IP: label: {}, ip: {}",
                self.prev_ip_label, &tok.value
            );
            self.query
                .ip_list
                .get_mut(&self.prev_ip_label)
                .unwrap()
                .push(IPv4 {
                    address: string_ipv4_to_int(&tok.value),
                    mask: cidr,
                });
            Some(Expression::IPv4(string_ipv4_to_int(&tok.value), cidr))
        } else {
            None
        }
    }

    // fn parse_float(&mut self) -> Option<Expression> {
    //     // println!("Parse FLOAT");
    //     if let Some(tok) = self.accept(Keyword::Float) {
    //         Some(Expression::Float(tok.value.parse().unwrap()))
    //     } else {
    //         None
    //     }
    // }

    fn parse_array(&mut self) -> Option<Expression> {
        let mut array_values: Vec<u8> = Vec::new();

        if self.expect(Keyword::IndexStart).is_none() {
            return None;
        }

        loop {
            if let Some(tok_int) = self.expect(Keyword::Integer) {
                array_values.push(tok_int.value.parse::<u8>().unwrap());
            } else {
                return None;
            }

            if self.peek(Keyword::Comma).is_some() {
                self.accept(Keyword::Comma);
            }

            if self.peek(Keyword::IndexEnd).is_some() {
                self.accept(Keyword::IndexEnd);
                break;
            }
        }

        return Some(Expression::ByteArray(array_values));
    }

    fn parse_label(&mut self) -> Option<Expression> {
        let mut start: usize = 0;
        let mut end: usize = 0;

        if let Some(tok) = self.accept(Keyword::Identifier) {
            self.add_type(&tok.value);
            if let Some(field) = fields::string_to_int(&tok.value) {
                println!("+++ Label: [{}]", &tok.value);
                if [
                    fields::ETH_BASE,
                    fields::IPV4_BASE,
                    fields::TCP_BASE,
                    fields::TCP_PAYLOAD,
                    fields::UDP_BASE,
                    fields::UDP_PAYLOAD,
                ]
                .contains(&field)
                {
                    if self.accept(Keyword::IndexStart).is_some() {
                        if let Some(offset_tok) = self.expect(Keyword::Integer) {
                            start = offset_tok.value.parse::<usize>().unwrap();
                        }
                        if self.accept(Keyword::Colon).is_some() {
                            if let Some(end_tok) = self.expect(Keyword::Integer) {
                                end = end_tok.value.parse::<usize>().unwrap();
                            }
                        }

                        self.expect(Keyword::IndexEnd);
                    }
                    return Some(Expression::LabelByte(field, start, end));
                } else {
                    return Some(Expression::Label(field));
                }
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
        select ip.src, ip.dst, tcp.dport

        from s1,s2 
        where ip.src == 192.168.242.1 
        top  200;
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
        select ip.dst
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

    #[test]
    fn test_arrays() {
        let mut parse = Parse::new();
        let pql_test = r#"
        select ip.dst
        from s1
        where tcp[0:3] == [1, 2, 3] 
        top  200;
        "#;
        let sql = parse.parse_select(pql_test).unwrap();
        println!("Select parse result: {:?}", sql);

        // BinOp(OP: == , LEFT:Label byte(40000,0,3), RIGHT:Byte array([1, 2, 3]))

        // assert_eq!(sql.filter, Expression;
        // assert!(
        //     Expression::BinOp(
        //         Operator::Equal,
        //         Box::new(Expression::LabelByte(4000, 0, 3)),
        //         Box::new(Expression::ByteArray(vec![1, 2, 3]))
        //     ),
        //     sql.filter,
        //     "Byte array"
        // );
    }
}
