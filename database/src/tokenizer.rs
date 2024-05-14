#![allow(dead_code)]

use regex::Regex;
use std::fmt;
use std::io::Read;
use std::iter::FromIterator;

#[derive(Debug, Copy, Clone, Default, PartialEq)]
pub enum Keyword {
    #[default]
    Select,
    From,
    Where,
    Offset,
    Now,
    Interval,
    To,
    Land,
    Lor,
    Band,
    Bor,
    Equal,
    Ne,
    Mask,
    Minus,
    Plus,
    Star,
    Lt,
    Gt,
    Lparen,
    Rparen,
    Comma,
    Le,
    Ge,
    IpV4,
    Float,
    Integer,
    Date,
    Time,
    Timestamp,
    Semi,
    EOF,
    Wildcard,
    Identifier,
    OrderAsc,
    OrderDesc,
    True,
    False,
    MacAddress,
    Constant,
    Top,
}

impl fmt::Display for Keyword {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Token {
    pub token: Keyword,
    pub value: String,
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Token: {:?}, Value: {}, Line: {}, Column: {}",
            self.token, self.value, self.line, self.column
        )
    }
}

pub struct Tokenizer {
    token_list: Vec<Token>,
    index: usize,
}

impl Tokenizer {
    pub fn new() -> Self {
        Self {
            token_list: Vec::new(),
            index: 0,
        }
    }

    // Load the file to parse
    pub fn load(&self, filename: &str) -> String {
        let mut file = std::fs::File::open(filename).unwrap();
        let mut lines = String::new();
        file.read_to_string(&mut lines).unwrap();

        return lines;
    }

    fn get_token_one(&self, str_token: &str) -> Option<Keyword> {
        match str_token {
            "/" => Some(Keyword::Mask),
            ";" => Some(Keyword::Semi),
            "-" => Some(Keyword::Minus),
            "+" => Some(Keyword::Plus),
            "*" => Some(Keyword::Wildcard),
            "<" => Some(Keyword::Lt),
            ">" => Some(Keyword::Gt),
            "(" => Some(Keyword::Lparen),
            ")" => Some(Keyword::Rparen),
            "," => Some(Keyword::Comma),
            _ => None,
        }
    }

    fn get_token_two(&self, str_token: &str) -> Option<Keyword> {
        match str_token {
            "<=" => Some(Keyword::Le),
            ">=" => Some(Keyword::Ge),
            "==" => Some(Keyword::Equal),
            "!=" => Some(Keyword::Ne),
            _ => None,
        }
    }

    fn get_keywords(&self, str_token: &str) -> Option<Keyword> {
        match str_token {
            "select" => Some(Keyword::Select),
            "from" => Some(Keyword::From),
            "where" => Some(Keyword::Where),
            "and" => Some(Keyword::Land),
            "or" => Some(Keyword::Lor),
            "offset" => Some(Keyword::Offset),
            "now" => Some(Keyword::Now),
            "order_asc" => Some(Keyword::OrderAsc),
            "order_desc" => Some(Keyword::OrderDesc),
            "true" => Some(Keyword::True),
            "false" => Some(Keyword::False),
            "top" => Some(Keyword::Top),
            "interval" => Some(Keyword::Interval),
            "to" => Some(Keyword::To),

            _ => None,
        }
    }

    fn get_constants(&self, str_token: &str) -> Option<Keyword> {
        match str_token {
            "ETH_IPV4" | "ETH_IPV6" | "ETH_ARP" | "IPV4_TCP" | "IPV4_UDP" | "IPV4_ICMP"
            | "TCP_PUSH" | "HTTPS" | "DNS" | "DHCP_SERVER" | "DHCP_CLIENT" => {
                Some(Keyword::Constant)
            }
            _ => None,
        }
    }

    pub fn tokenize(&mut self, lines: &str) -> &Vec<Token> {
        self.index = 0;
        let s: Vec<_> = lines.chars().collect();
        // let mut token_list: Vec<Token> = Vec::new();

        let mut line: usize = 1;
        let mut line_offset: usize = 0;

        while self.index < s.len() {
            if s[self.index].is_whitespace() {
                if s[self.index] == '\n' {
                    line += 1;
                    line_offset = self.index + 1;
                }
                self.index += 1;
            } else if (self.index + 2) <= s.len()
                && self
                    .get_token_two(&String::from_iter(s[self.index..self.index + 2].to_vec()))
                    .is_some()
            {
                let stoken: &str = &String::from_iter(s[self.index..self.index + 2].to_vec());
                let tok = self.get_token_two(stoken).unwrap();
                let token = Token {
                    token: tok.to_owned(),
                    value: String::from(stoken),
                    column: (self.index + 1) - line_offset,
                    line,
                };
                self.token_list.push(token);

                self.index += 2;
            } else if let Some(ts) = self.is_timestamp(&String::from(lines)) {
                let token = Token {
                    token: Keyword::Timestamp,
                    value: ts,
                    column: (self.index + 1) - line_offset,
                    line,
                };
                // println!("TIMESTAMP >> {}", token);
                self.token_list.push(token);
                self.index += 19;
            } else if self
                .get_token_one(&String::from(s[self.index]) as &str)
                .is_some()
            {
                let tok = self
                    .get_token_one(&String::from(s[self.index]) as &str)
                    .unwrap();
                let token = Token {
                    token: tok.to_owned(),
                    value: String::from(s[self.index]),
                    column: (self.index + 1) - line_offset,
                    line,
                };
                self.token_list.push(token);

                if s[self.index] == ';' {
                    line += 1;
                }

                self.index += 1;
            } else if let Some(mac) = self.is_mac_addr(&lines) {
                let token = Token {
                    token: Keyword::MacAddress,
                    value: mac,
                    column: (self.index + 1) - line_offset,
                    line,
                };
                self.token_list.push(token);
                self.index += 17;
            } else if s[self.index].is_numeric()
                || s[self.index] == '.'
                || s[self.index] == '-'
                || s[self.index] == ':'
            {
                let start = self.index;

                while self.index < s.len()
                    && (s[self.index].is_numeric()
                        || s[self.index] == '.'
                        || s[self.index] == '-'
                        || s[self.index] == ':')
                {
                    self.index += 1;
                }

                let number = String::from_iter(s[start..self.index].to_vec());
                if number.matches(".").count() == 3 {
                    let token = Token {
                        token: Keyword::IpV4,
                        value: number,
                        column: (start + 1) - line_offset,
                        line,
                    };
                    self.token_list.push(token);
                } else if number.contains(".") {
                    let token = Token {
                        token: Keyword::Float,
                        value: number,
                        column: (start + 1) - line_offset,
                        line,
                    };
                    self.token_list.push(token);
                } else if number.matches("-").count() == 2 {
                    let token = Token {
                        token: Keyword::Date,
                        value: number,
                        column: (start + 1) - line_offset,
                        line,
                    };
                    self.token_list.push(token);
                } else if number.matches(":").count() == 2 {
                    let token = Token {
                        token: Keyword::Time,
                        value: number,
                        column: (start + 1) - line_offset,
                        line,
                    };
                    self.token_list.push(token);
                } else {
                    let token = Token {
                        token: Keyword::Integer,
                        value: number,
                        column: (start + 1) - line_offset,
                        line,
                    };
                    self.token_list.push(token);
                }
            } else if s[self.index].is_alphabetic() || s[self.index] == '_' || s[self.index] == '.'
            {
                let start = self.index;
                while self.index < s.len()
                    && (s[self.index].is_alphabetic()
                        || s[self.index].is_numeric()
                        || s[self.index] == '_'
                        || s[self.index] == '.')
                {
                    self.index += 1;
                }
                let keyword: &str = &String::from_iter(s[start..self.index].to_vec());
                if self.get_keywords(keyword).is_some() {
                    // if keywords.contains_key(keyword) {
                    let tok = self.get_keywords(keyword).unwrap();
                    let token = Token {
                        token: tok.to_owned(),
                        value: String::from(keyword),
                        column: (start + 1) - line_offset,
                        line,
                    };
                    self.token_list.push(token);
                } else if self.get_constants(keyword).is_some() {
                    let tok = self.get_constants(keyword).unwrap();
                    let token = Token {
                        token: tok.to_owned(),
                        value: String::from(keyword),
                        column: (start + 1) - line_offset,
                        line,
                    };
                    self.token_list.push(token);
                } else {
                    let token = Token {
                        token: Keyword::Identifier,
                        value: String::from(keyword),
                        column: (start + 1) - line_offset,
                        line,
                    };
                    self.token_list.push(token);
                }
            } else {
                self.index += 1;
            }
        }

        let token = Token {
            token: Keyword::EOF,
            value: String::from("eof"),
            column: (self.index + 1) - line_offset,
            // column: s.len() + 1,
            line,
        };
        self.token_list.push(token);

        return &self.token_list;
    }

    fn is_mac_addr(&self, lines: &str) -> Option<String> {
        if (self.index + 17) <= lines.len() {
            let mac = lines[self.index..self.index + 17].to_string();
            // println!("MAC IS: {}", mac);
            if mac.matches(":").count() == 5 {
                return Some(mac);
            }
        }
        None
    }

    fn is_token_two(self, value: &str) -> Option<Keyword> {
        if let Some(tk) = self.get_token_two(value) {
            Some(tk)
        } else {
            None
        }
    }

    fn is_timestamp(&self, lines: &String) -> Option<String> {
        if self.index + 19 <= lines.len() {
            let re = Regex::new(r"^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}$").unwrap();
            let target: String = lines[self.index..self.index + 19].to_string();
            if re.is_match(&target) {
                Some(target)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn print(&self) {
        println!("Tokenizer print-out");
        for t in &self.token_list {
            println!("{}", t);
        }
        println!("Tokenizer end");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp() {
        let mut t = Tokenizer::new();
        let line = "2022-11-25 11:01:02";
        let token_list: &Vec<Token> = t.tokenize(line);
        println!("Timestamp token len: {:?}", token_list);
        // assert!(token_list.len() == 1);
        assert!(token_list[0].token == Keyword::Timestamp);
    }
    #[test]
    fn count_token() {
        let mut t = Tokenizer::new();
        let line = "select ip_src, ip_dst from sniffer_01";
        let token_list: &Vec<Token> = t.tokenize(line);
        assert!(token_list.len() == 7);
    }
    #[test]
    fn date_token() {
        let mut t = Tokenizer::new();
        let line = "12-01-2022";
        let token_list: &Vec<Token> = t.tokenize(line);

        assert!(token_list[0].token == Keyword::Date);
    }

    #[test]
    fn time_token() {
        let mut t = Tokenizer::new();
        let line = "14:33:56";
        let token_list: &Vec<Token> = t.tokenize(line);

        assert!(token_list[0].token == Keyword::Time);
    }

    #[test]
    fn true_token() {
        let mut t = Tokenizer::new();
        let line = "true";
        let token_list: &Vec<Token> = t.tokenize(line);

        assert!(token_list[0].token == Keyword::True);
    }

    #[test]
    fn false_token() {
        let mut t = Tokenizer::new();
        let line = "false";
        let token_list: &Vec<Token> = t.tokenize(line);

        assert!(token_list[0].token == Keyword::False);
    }

    #[test]
    fn ipv4_cidr_mask() {
        let mut t = Tokenizer::new();
        let line = "192.168.0.0/24";
        let token_list: &Vec<Token> = t.tokenize(line);
        assert!(token_list.len() == 4);

        assert!(token_list[0].token == Keyword::IpV4);
        assert!(token_list[1].token == Keyword::Mask);
        assert!(token_list[2].token == Keyword::Integer);
    }

    #[test]
    fn ipv4_byte_mask() {
        let mut t = Tokenizer::new();
        let line = "192.168.0.0 / 255.255.255.0";
        let token_list: &Vec<Token> = t.tokenize(line);
        assert!(token_list.len() == 4);

        assert!(token_list[0].token == Keyword::IpV4);
        assert!(token_list[1].token == Keyword::Mask);
        assert!(token_list[2].token == Keyword::IpV4);
    }

    #[test]
    fn column_no() {
        let mut t = Tokenizer::new();
        let line = "select ip_dst, ip_src from sniffer_01 where dport == 443";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 11);

        assert!(tl[0].token == Keyword::Select && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Identifier && tl[1].column == 8 && tl[1].line == 1);
        assert!(tl[4].token == Keyword::From && tl[4].column == 23 && tl[4].line == 1);
        assert!(tl[6].token == Keyword::Where && tl[6].column == 39 && tl[6].line == 1);
    }

    #[test]
    fn multiline() {
        let mut t = Tokenizer::new();
        let line = "select ip_dst, ip_src\nfrom sniffer_01\nwhere dport == 443";
        let tl: &Vec<Token> = t.tokenize(line);
        println!("{:#?}", tl);
        assert!(tl.len() == 11);

        assert!(tl[0].token == Keyword::Select && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Identifier && tl[1].column == 8 && tl[1].line == 1);
        assert!(tl[4].token == Keyword::From && tl[4].column == 1 && tl[4].line == 2);
        assert!(tl[6].token == Keyword::Where && tl[6].column == 1 && tl[6].line == 3);
    }

    #[test]
    fn two_chars_tokens() {
        let mut t = Tokenizer::new();
        let line = ">= <=";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 3);

        assert!(tl[0].token == Keyword::Ge && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Le && tl[1].column == 4 && tl[1].line == 1);
    }

    #[test]
    fn one_chars_tokens() {
        let mut t = Tokenizer::new();
        let line = "< > - + * / , ;";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 9);

        assert!(tl[0].token == Keyword::Lt && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Gt && tl[1].column == 3 && tl[1].line == 1);
        assert!(tl[2].token == Keyword::Minus && tl[2].column == 5 && tl[2].line == 1);
        assert!(tl[3].token == Keyword::Plus && tl[3].column == 7 && tl[3].line == 1);
        assert!(tl[4].token == Keyword::Wildcard && tl[4].column == 9 && tl[4].line == 1);
        assert!(tl[5].token == Keyword::Mask && tl[5].column == 11 && tl[5].line == 1);
        assert!(tl[6].token == Keyword::Comma && tl[6].column == 13 && tl[6].line == 1);
        assert!(tl[7].token == Keyword::Semi && tl[7].column == 15 && tl[7].line == 1);
    }

    #[test]
    fn grouping() {
        let mut t = Tokenizer::new();
        let line = "()";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 3);

        assert!(tl[0].token == Keyword::Lparen && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Rparen && tl[1].column == 2 && tl[1].line == 1);
    }

    #[test]
    fn test_select() {
        let mut t = Tokenizer::new();
        let line = "select";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Select && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_from() {
        let mut t = Tokenizer::new();
        let line = "from";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::From && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_where() {
        let mut t = Tokenizer::new();
        let line = "where";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Where && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_order_asc() {
        let mut t = Tokenizer::new();
        let line = "order_asc";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::OrderAsc && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_order_desc() {
        let mut t = Tokenizer::new();
        let line = "order_desc";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::OrderDesc && tl[0].column == 1 && tl[0].line == 1);
    }
}
