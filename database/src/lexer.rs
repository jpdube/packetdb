#![allow(dead_code)]

use crate::preparser::LexerPhase2;
use crate::token::{Keyword, Token};

pub struct Lexer {
    token_list: Vec<Token>,
    p2_result: Vec<Token>,
    index: usize,
    char_list: Vec<char>,
    len: usize,
    line: usize,
    column: usize,
    hex_digit: [char; 7],
}

impl Lexer {
    pub fn new(pql: &str) -> Self {
        Self {
            token_list: Vec::new(),
            p2_result: Vec::new(),
            index: 0,
            char_list: pql.chars().collect(),
            len: pql.len(),
            line: 1,
            column: 1,
            hex_digit: ['a', 'b', 'c', 'd', 'e', 'f', 'x'],
        }
    }

    fn get_token_one(&self, str_token: &char) -> Option<Keyword> {
        match str_token {
            '/' => Some(Keyword::Mask),
            ';' => Some(Keyword::Semi),
            '-' => Some(Keyword::Minus),
            '+' => Some(Keyword::Plus),
            '*' => Some(Keyword::Wildcard),
            '<' => Some(Keyword::Lt),
            '>' => Some(Keyword::Gt),
            '(' => Some(Keyword::Lparen),
            ')' => Some(Keyword::Rparen),
            ',' => Some(Keyword::Comma),
            '.' => Some(Keyword::Period),
            '[' => Some(Keyword::IndexStart),
            ']' => Some(Keyword::IndexEnd),
            ':' => Some(Keyword::Colon),
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
            | "TCP_PUSH" | "HTTPS" | "DNS" | "DHCP_SERVER" | "DHCP_CLIENT" | "SSH" | "TELNET"
            | "HTTP" | "RDP" => Some(Keyword::Constant),
            _ => None,
        }
    }

    fn advance(&mut self) -> Option<char> {
        if self.at_end() {
            return None;
        }

        let result = Some(self.char_list[self.index]);
        self.index += 1;
        result
    }

    fn peek(&self) -> Option<char> {
        if self.at_end() {
            return None;
        }
        Some(self.char_list[self.index])
    }

    fn at_end(&self) -> bool {
        self.index >= self.len
    }

    fn add_token(&mut self, token: Keyword, value: String) {
        let token = Token {
            token,
            value: value.clone(),
            column: self.column,
            line: self.line,
        };

        self.column += value.len();

        self.token_list.push(token);
    }

    fn tokenize(&mut self) {
        while let Some(chr) = self.advance() {
            if chr.is_whitespace() {
                if chr == '\n' {
                    self.line += 1;
                    self.column = 0;
                }

                self.column += 1;
                continue;
            }

            if let Some(next_chr) = self.peek() {
                let two_chars = format!("{}{}", chr, next_chr);
                if let Some(token) = self.get_token_two(&two_chars) {
                    self.add_token(token, two_chars);
                    self.advance();
                    continue;
                }
            }

            if let Some(token1) = self.get_token_one(&chr) {
                self.add_token(token1, chr.to_string());
                continue;
            }

            //--- Check for hex value 0xaabbccdd
            if chr == '0' {
                if let Some(x) = self.peek() {
                    if x == 'x' {
                        let mut number = chr.to_string();

                        // let hex_digit = ['a', 'b', 'c', 'd', 'e', 'f', 'x'];
                        while let Some(next_chr) = self.peek() {
                            if next_chr.is_numeric() || self.hex_digit.contains(&next_chr) {
                                number.push(self.advance().unwrap());
                            } else {
                                break;
                            }
                        }

                        let hex_conv = u32::from_str_radix(&number[2..], 16).unwrap();

                        self.add_token(Keyword::Integer, format!("{}", hex_conv));
                        continue;
                    }
                }
            }

            if chr.is_numeric() {
                let mut number = chr.to_string();
                while let Some(next_chr) = self.peek() {
                    if next_chr.is_numeric() {
                        number.push(self.advance().unwrap());
                    } else {
                        break;
                    }
                }

                self.add_token(Keyword::Integer, number);
                continue;
            }

            if chr.is_alphabetic() || chr == '_' {
                let mut text = chr.to_string();
                while let Some(next_chr) = self.peek() {
                    if next_chr.is_alphanumeric() || next_chr == '_' {
                        text.push(self.advance().unwrap());
                    } else {
                        break;
                    }
                }

                // println!("String: {}", text);
                if let Some(keyword) = self.get_keywords(&text) {
                    self.add_token(keyword, text);
                } else if self.get_constants(&text).is_some() {
                    self.add_token(Keyword::Constant, text);
                } else {
                    self.add_token(Keyword::Identifier, text);
                }
                continue;
            }
        }

        self.add_token(Keyword::EOF, String::from("eof"));

        // return &self.token_list;
    }

    pub fn run(&mut self) -> &Vec<Token> {
        self.tokenize();

        let mut pre_parser = LexerPhase2::new(self.token_list.clone());
        self.p2_result = pre_parser.tokenize().clone();
        // println!("P2 result: {:#?}", self.p2_result);
        return &self.p2_result;
    }

    pub fn print(&self) {
        println!("Tokenizer print-out");
        for t in &self.p2_result {
            println!("{}", t);
        }
        println!("Tokenizer end");
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn hex_number_token() {
        let line = "0xff";
        let mut t = Lexer::new(line);
        let token_list: &Vec<Token> = t.run();
        assert!(token_list[0].token == Keyword::Integer);
        println!("Hex conv: {}", token_list[0].value);
    }

    #[test]
    fn single_index_token() {
        let line = "[245]";
        let mut t = Lexer::new(line);
        let token_list: &Vec<Token> = t.run();
        assert!(token_list[0].token == Keyword::IndexStart);
        assert!(token_list[1].token == Keyword::Integer);
        assert!(token_list[2].token == Keyword::IndexEnd);
    }

    #[test]
    fn range_index_token() {
        let line = "[2:4]";
        let mut t = Lexer::new(line);
        let token_list: &Vec<Token> = t.run();
        assert!(token_list[0].token == Keyword::IndexStart);
        assert!(token_list[1].token == Keyword::Integer);
        assert!(token_list[2].token == Keyword::Colon);
        assert!(token_list[3].token == Keyword::Integer);
        assert!(token_list[4].token == Keyword::IndexEnd);
    }

    #[test]
    fn range_index_token_with_identifier() {
        let line = "tcp[2:4]";
        let mut t = Lexer::new(line);
        let token_list: &Vec<Token> = t.run();
        println!("Index with ident: {:#?}", token_list);
        assert!(token_list[0].token == Keyword::Identifier);
        assert!(token_list[1].token == Keyword::IndexStart);
        assert!(token_list[2].token == Keyword::Integer);
        assert!(token_list[3].token == Keyword::Colon);
        assert!(token_list[4].token == Keyword::Integer);
        assert!(token_list[5].token == Keyword::IndexEnd);
    }

    #[test]
    fn range_index_token_with_identifier_space() {
        let line = "tcp [2:4]";
        let mut t = Lexer::new(line);
        let token_list: &Vec<Token> = t.run();
        println!("Index with ident: {:#?}", token_list);
        assert!(token_list[0].token == Keyword::Identifier);
        assert!(token_list[1].token == Keyword::IndexStart);
        assert!(token_list[2].token == Keyword::Integer);
        assert!(token_list[3].token == Keyword::Colon);
        assert!(token_list[4].token == Keyword::Integer);
        assert!(token_list[5].token == Keyword::IndexEnd);
    }

    #[test]
    fn identifier() {
        let line = "ip_dst";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Identifier && tl[0].column == 1 && tl[0].line == 1);
    }

    // #[test]
    // fn timestamp() {
    //     let mut t = Tokenizer::new();
    //     let line = "2022-11-25 11:01:02";
    //     let token_list: &Vec<Token> = t.tokenize(line);
    //     println!("Timestamp token len: {:?}", token_list);
    //     // assert!(token_list.len() == 1);
    //     assert!(token_list[0].token == Keyword::Timestamp);
    // }
    #[test]
    fn count_token() {
        let line = "select ip_src, ip_dst from sniffer_01";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 7);
    }
    #[test]
    fn date_token() {
        let line = "12-01-2022";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();

        assert!(tl[0].token == Keyword::Date);
    }

    #[test]
    fn time_token() {
        let line = "14:33:56";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        println!("Time: {:#?}", tl);

        assert!(tl[0].token == Keyword::Time);
    }

    #[test]
    fn true_token() {
        let line = "true";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();

        assert!(tl[0].token == Keyword::True);
    }

    #[test]
    fn false_token() {
        let line = "false";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();

        assert!(tl[0].token == Keyword::False);
    }

    #[test]
    fn ipv4() {
        let line = "192.168.0.0/24";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 4);

        assert!(tl[0].token == Keyword::IpV4);
        assert!(tl[1].token == Keyword::Mask);
        assert!(tl[2].token == Keyword::Integer);
    }

    #[test]
    fn ipv4_cidr_mask() {
        let line = "192.168.0.0/24";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 4);

        assert!(tl[0].token == Keyword::IpV4);
        assert!(tl[1].token == Keyword::Mask);
        assert!(tl[2].token == Keyword::Integer);
    }

    #[test]
    fn ipv4_byte_mask() {
        let line = "192.168.0.0 / 255.255.255.0";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        println!("ipv4_byte_mask: {:#?}", tl);
        assert!(tl.len() == 4);

        assert!(tl[0].token == Keyword::IpV4);
        assert!(tl[1].token == Keyword::Mask);
        assert!(tl[2].token == Keyword::IpV4);
    }

    #[test]
    fn mac_address() {
        let line = "00:01:02:03:04:05";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::MacAddress);
    }

    #[test]
    fn column_no() {
        let line = "select ip_dst, ip_src from sniffer_01 where dport == 443";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 11);

        assert!(tl[0].token == Keyword::Select && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Identifier && tl[1].column == 8 && tl[1].line == 1);
        assert!(tl[4].token == Keyword::From && tl[4].column == 23 && tl[4].line == 1);
        assert!(tl[6].token == Keyword::Where && tl[6].column == 39 && tl[6].line == 1);
    }

    #[test]
    fn multiline() {
        let line = "select ip_dst, ip_src\nfrom sniffer_01\nwhere dport == 443";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        println!("{:#?}", tl);
        assert!(tl.len() == 11);

        assert!(tl[0].token == Keyword::Select && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Identifier && tl[1].column == 8 && tl[1].line == 1);
        assert!(tl[4].token == Keyword::From && tl[4].column == 1 && tl[4].line == 2);
        assert!(tl[6].token == Keyword::Where && tl[6].column == 1 && tl[6].line == 3);
    }

    #[test]
    fn two_chars_tokens() {
        let line = ">= <=";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 3);

        assert!(tl[0].token == Keyword::Ge && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Le && tl[1].column == 4 && tl[1].line == 1);
    }

    #[test]
    fn one_chars_tokens() {
        let line = "< > - + * / , ;";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
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
        let line = "()";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 3);

        assert!(tl[0].token == Keyword::Lparen && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Rparen && tl[1].column == 2 && tl[1].line == 1);
    }

    #[test]
    fn test_select() {
        let line = "select";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Select && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_from() {
        let line = "from";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::From && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_where() {
        let line = "where";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Where && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_order_asc() {
        let line = "order_asc";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::OrderAsc && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_order_desc() {
        let line = "order_desc";
        let mut t = Lexer::new(line);
        let tl: &Vec<Token> = t.run();
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::OrderDesc && tl[0].column == 1 && tl[0].line == 1);
    }
}
