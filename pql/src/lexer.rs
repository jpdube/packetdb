use crate::keywords::Keyword;
use crate::preparser::Preparser;
use crate::token::{Token, get_constants, get_keywords, get_token_one, get_token_two};
use std::io::Read;

#[derive(Default)]
pub struct Lexer {
    token_list: Vec<Token>,
    index: usize,
    line: usize,
    line_offset: usize,
    s: Vec<char>,
}

impl Lexer {
    pub fn new() -> Self {
        Self {
            token_list: Vec::new(),
            index: 0,
            line: 1,
            line_offset: 0,
            s: Vec::new(),
        }
    }

    // Load the file to parse
    pub fn load(&self, filename: &str) -> String {
        let mut file = std::fs::File::open(filename).unwrap();
        let mut lines = String::new();
        file.read_to_string(&mut lines).unwrap();

        lines
    }

    pub fn tokenize(&mut self, lines: &str) -> &Vec<Token> {
        self.index = 0;
        self.s = lines.chars().collect();
        let mut preparser = Preparser::default();

        while self.index < self.s.len() {
            if let Some(tok) = self.match_any() {
                self.token_list.push(tok);
            } else {
                self.index += 1;
            }
        }

        let token = Token {
            token: Keyword::EOF,
            value: String::from("eof"),
            column: (self.index + 1) - self.line_offset,
            line: self.line,
        };
        self.token_list.push(token);

        self.token_list = preparser.parse(self.token_list.clone());
        &self.token_list
    }

    fn get_hex_digit(&mut self) -> Option<Token> {
        if (self.index + 1 < self.s.len())
            && self.s[self.index] == '0'
            && self.s[self.index + 1] == 'x'
        {
            self.index += 2;
            let start_pos = self.index;
            while self.index < self.s.len() && self.s[self.index].is_ascii_hexdigit() {
                self.index += 1;
            }

            println!("HEX conv: start:{start_pos}, end: {}", self.index);
            let str_value = String::from_iter(self.s[start_pos..self.index].to_vec());
            let value: u32 = u32::from_str_radix(&str_value, 16).unwrap();

            let token = Token {
                token: Keyword::Integer,
                value: value.to_string(),
                column: (self.index + 1) - self.line_offset,
                line: self.line,
            };
            return Some(token);
        }

        None
    }

    fn match_any(&mut self) -> Option<Token> {
        self.get_whitespace();

        //--- Comments
        self.get_comments();

        //--- Token 2 characters
        if let Some(tok) = self.get_two_chars() {
            return Some(tok);
        }

        //--- Token one character
        if let Some(tok) = self.get_one_char() {
            return Some(tok);
        }

        //--- Hex digit
        if let Some(tok) = self.get_hex_digit() {
            return Some(tok);
        }

        //--- Scan for numbers
        if let Some(tok) = self.get_number() {
            return Some(tok);
        }

        //--- Scan for Alphanum
        if let Some(tok) = self.get_alphanum() {
            return Some(tok);
        }

        //--- Scan for String
        if let Some(tok) = self.get_string() {
            return Some(tok);
        }

        None
    }

    fn get_comments(&mut self) {
        if self.s[self.index] == '#' && self.index < self.s.len() {
            while self.s[self.index] != '\n' && self.index < self.s.len() {
                self.index += 1;
            }
            self.index += 1;
        }
    }

    fn get_whitespace(&mut self) {
        if self.s[self.index].is_whitespace() {
            if self.s[self.index] == '\n' {
                self.line += 1;
                self.line_offset = self.index + 1;
            }
            self.index += 1;
        }
    }
    fn get_two_chars(&mut self) -> Option<Token> {
        if (self.index + 2) <= self.s.len()
            && get_token_two(&String::from_iter(
                self.s[self.index..self.index + 2].to_vec(),
            ))
            .is_some()
        {
            let stoken: &str = &String::from_iter(self.s[self.index..self.index + 2].to_vec());
            if let Some(tok) = get_token_two(stoken) {
                let token = Token {
                    token: tok.to_owned(),
                    value: String::from(stoken),
                    column: (self.index + 1) - self.line_offset,
                    line: self.line,
                };
                self.index += 2;
                return Some(token);
            }
        }

        None
    }

    fn get_one_char(&mut self) -> Option<Token> {
        if let Some(tok) = get_token_one(&String::from(self.s[self.index]) as &str) {
            let token = Token {
                token: tok.to_owned(),
                value: String::from(self.s[self.index]),
                column: (self.index + 1) - self.line_offset,
                line: self.line,
            };
            self.index += 1;

            return Some(token);
        }

        None
    }

    fn get_string(&mut self) -> Option<Token> {
        if self.s[self.index] == '"' {
            self.index += 1;
            let start = self.index;

            while self.index < self.s.len() && self.s[self.index] != '"' {
                self.index += 1;
            }

            let str = String::from_iter(self.s[start..self.index].to_vec());
            let token = Token {
                token: Keyword::String,
                value: str,
                column: start - self.line_offset,
                line: self.line,
            };
            self.index += 1;

            return Some(token);
        }

        None
    }

    fn get_number(&mut self) -> Option<Token> {
        if self.s[self.index].is_numeric() {
            let start = self.index;

            while self.index < self.s.len() && self.s[self.index].is_numeric() {
                self.index += 1;
            }

            let number = String::from_iter(self.s[start..self.index].to_vec());

            let mut token = Token {
                token: Keyword::Integer,
                value: number,
                column: start - self.line_offset,
                line: self.line,
            };

            token.column = (start + 1) - self.line_offset;
            token.line = self.line;

            return Some(token);
        }

        None
    }

    fn get_alphanum(&mut self) -> Option<Token> {
        if self.s[self.index].is_alphabetic() || self.s[self.index] == '_' {
            let start = self.index;
            while self.index < self.s.len()
                && (self.s[self.index].is_alphabetic()
                    || self.s[self.index].is_numeric()
                    || self.s[self.index] == '_')
            {
                self.index += 1;
            }
            let keyword: &str = &String::from_iter(self.s[start..self.index].to_vec());
            if let Some(tok) = get_keywords(keyword) {
                let token = Token {
                    token: tok.to_owned(),
                    value: String::from(keyword),
                    column: (start + 1) - self.line_offset,
                    line: self.line,
                };
                return Some(token);
            } else if let Some(tok) = get_constants(keyword) {
                let token = Token {
                    token: tok.to_owned(),
                    value: String::from(keyword),
                    column: (start + 1) - self.line_offset,
                    line: self.line,
                };
                return Some(token);
            } else {
                let token = Token {
                    token: Keyword::Identifier,
                    value: String::from(keyword),
                    column: (start + 1) - self.line_offset,
                    line: self.line,
                };

                return Some(token);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string() {
        let mut t = Lexer::new();
        let line = "\"Hello World\"";
        let tl: &Vec<Token> = t.tokenize(line);
        println!(">>>String: {} {:?}", tl.len(), tl);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::String && tl[0].column == 1 && tl[0].line == 1);
    }

    #[test]
    fn test_print() {
        let mut t = Lexer::new();
        let line = "print";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Print && tl[0].column == 1 && tl[0].line == 1);
    }

    #[test]
    fn test_var_keyword() {
        let mut t = Lexer::new();
        let line = "var";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Var && tl[0].column == 1 && tl[0].line == 1);
    }

    #[test]
    fn test_var_assign_int() {
        let mut t = Lexer::new();
        let line = "var a = 10;";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 6);

        assert!(tl[0].token == Keyword::Var);
        assert!(tl[1].token == Keyword::Identifier);
        assert!(tl[2].token == Keyword::Assign);
        assert!(tl[3].token == Keyword::Integer);
        assert!(tl[3].value == format!("{}", 10));
    }
    #[test]
    fn test_var_assign_string() {
        let mut t = Lexer::new();
        let line = "var a = \"PQL rocks\";";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 6);

        assert!(tl[0].token == Keyword::Var);
        assert!(tl[1].token == Keyword::Identifier);
        assert!(tl[2].token == Keyword::Assign);
        assert!(tl[3].token == Keyword::String);
        assert!(tl[3].value == "PQL rocks");
    }
    #[test]
    fn ipv4_tokens() {
        let mut t = Lexer::new();
        let line = "192.168.3.0";
        let token_list: &Vec<Token> = t.tokenize(line);
        assert!(token_list.len() == 2);
        assert!(token_list[0].value == "192.168.3.0");
        assert!(token_list[0].token == Keyword::IpV4);
    }
    #[test]
    fn hex_1_digit_digit_tokens() {
        let mut t = Lexer::new();
        let line = "0x8";
        let token_list: &Vec<Token> = t.tokenize(line);
        assert!(token_list.len() == 2);
        assert!(token_list[0].value == "8");
        assert!(token_list[0].token == Keyword::Integer);
    }

    #[test]
    fn hex_1_digit_tokens() {
        let mut t = Lexer::new();
        let line = "0xc";
        let token_list: &Vec<Token> = t.tokenize(line);
        assert!(token_list.len() == 2);
        assert!(token_list[0].value == "12");
        assert!(token_list[0].token == Keyword::Integer);
    }
    #[test]
    fn hex_2_digit_tokens() {
        let mut t = Lexer::new();
        let line = "0xc0";
        let token_list: &Vec<Token> = t.tokenize(line);
        assert!(token_list.len() == 2);
        assert!(token_list[0].value == "192");
        assert!(token_list[0].token == Keyword::Integer);
    }

    #[test]
    fn hex_4_digit_tokens() {
        let mut t = Lexer::new();
        let line = "0xc0a8";
        let token_list: &Vec<Token> = t.tokenize(line);
        assert!(token_list.len() == 2);
        assert!(token_list[0].value == "49320");
        assert!(token_list[0].token == Keyword::Integer);
    }

    #[test]
    fn count_token() {
        let mut t = Lexer::new();
        let line = "select ip_src, ip_dst from sniffer_01";
        let token_list: &Vec<Token> = t.tokenize(line);
        assert!(token_list.len() == 7);
    }

    #[test]
    fn true_token() {
        let mut t = Lexer::new();
        let line = "true";
        let token_list: &Vec<Token> = t.tokenize(line);

        assert!(token_list[0].token == Keyword::True);
    }

    #[test]
    fn false_token() {
        let mut t = Lexer::new();
        let line = "false";
        let token_list: &Vec<Token> = t.tokenize(line);

        assert!(token_list[0].token == Keyword::False);
    }

    #[test]
    fn column_no() {
        let mut t = Lexer::new();
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
        let mut t = Lexer::new();
        let line = "select ip_dst, ip_src\nfrom sniffer_01\nwhere dport == 443";
        let tl: &Vec<Token> = t.tokenize(line);
        // println!("{:#?}", tl);
        assert!(tl.len() == 11);

        assert!(tl[0].token == Keyword::Select && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Identifier && tl[1].column == 8 && tl[1].line == 1);
        assert!(tl[4].token == Keyword::From && tl[4].column == 1 && tl[4].line == 2);
        assert!(tl[6].token == Keyword::Where && tl[6].column == 1 && tl[6].line == 3);
    }

    #[test]
    fn two_chars_tokens() {
        let mut t = Lexer::new();
        let line = ">= <= == !=";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 5);

        assert!(tl[0].token == Keyword::Ge && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Le && tl[1].column == 4 && tl[1].line == 1);
        assert!(tl[2].token == Keyword::Equal && tl[2].column == 7 && tl[1].line == 1);
        assert!(tl[3].token == Keyword::Ne && tl[3].column == 10 && tl[1].line == 1);
    }

    #[test]
    fn one_chars_tokens() {
        let mut t = Lexer::new();
        let line = "< > - + * / , ; & | ^ [ ] :";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 15);

        assert!(tl[0].token == Keyword::Lt && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Gt && tl[1].column == 3 && tl[1].line == 1);
        assert!(tl[2].token == Keyword::Minus && tl[2].column == 5 && tl[2].line == 1);
        assert!(tl[3].token == Keyword::Plus && tl[3].column == 7 && tl[3].line == 1);
        assert!(tl[4].token == Keyword::Wildcard && tl[4].column == 9 && tl[4].line == 1);
        assert!(tl[5].token == Keyword::Mask && tl[5].column == 11 && tl[5].line == 1);
        assert!(tl[6].token == Keyword::Comma && tl[6].column == 13 && tl[6].line == 1);
        assert!(tl[7].token == Keyword::Semi && tl[7].column == 15 && tl[7].line == 1);
        assert!(tl[8].token == Keyword::BitAnd && tl[8].column == 17 && tl[8].line == 1);
        assert!(tl[9].token == Keyword::BitOr && tl[9].column == 19 && tl[9].line == 1);
        assert!(tl[10].token == Keyword::BitXor && tl[10].column == 21 && tl[10].line == 1);
        assert!(tl[11].token == Keyword::IndexStart && tl[11].column == 23 && tl[11].line == 1);
        assert!(tl[12].token == Keyword::IndexEnd && tl[12].column == 25 && tl[12].line == 1);
        assert!(tl[13].token == Keyword::Colon && tl[13].column == 27 && tl[13].line == 1);
    }

    #[test]
    fn grouping() {
        let mut t = Lexer::new();
        let line = "()";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 3);

        assert!(tl[0].token == Keyword::Lparen && tl[0].column == 1 && tl[0].line == 1);
        assert!(tl[1].token == Keyword::Rparen && tl[1].column == 2 && tl[1].line == 1);
    }

    #[test]
    fn test_select() {
        let mut t = Lexer::new();
        let line = "select";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Select && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_from() {
        let mut t = Lexer::new();
        let line = "from";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::From && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_where() {
        let mut t = Lexer::new();
        let line = "where";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Where && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_order_asc() {
        let mut t = Lexer::new();
        let line = "order_asc";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::OrderAsc && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_order_desc() {
        let mut t = Lexer::new();
        let line = "order_desc";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::OrderDesc && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_constants() {
        let mut t = Lexer::new();
        let line = "DNS";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Constant && tl[0].column == 1 && tl[0].line == 1);
    }
    #[test]
    fn test_float() {
        let mut t = Lexer::new();
        let line = "2.5";
        let tl: &Vec<Token> = t.tokenize(line);
        assert!(tl.len() == 2);

        assert!(tl[0].token == Keyword::Float && tl[0].column == 1 && tl[0].line == 1);
    }
}
