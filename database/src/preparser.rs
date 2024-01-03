use crate::token::{Keyword, Token};

pub struct LexerPhase2 {
    tok_list: Vec<Token>,
    tok_result: Vec<Token>,
    ptr: usize,
}

impl LexerPhase2 {
    pub fn new(tok_list: Vec<Token>) -> Self {
        Self {
            tok_list,
            tok_result: Vec::new(),
            ptr: 0,
        }
    }

    fn advance(&mut self) -> Option<Token> {
        if self.at_end() {
            return None;
        }
        let result = Some(self.tok_list[self.ptr].clone());
        self.ptr += 1;
        return result;
    }

    fn _peek(&self) -> Option<Token> {
        if self.ptr + 1 < self.tok_list.len() {
            return Some(self.tok_list[self.ptr + 1].clone());
        }

        None
    }

    fn peek_at(&self, offset: usize, search_tok: Keyword) -> Option<Token> {
        if self.ptr + offset < self.tok_list.len() {
            if self.tok_list[self.ptr + offset].token == search_tok {
                return Some(self.tok_list[self.ptr + offset].clone());
            }
        }

        None
    }

    fn at_end(&self) -> bool {
        self.ptr >= self.tok_list.len()
    }

    pub fn tokenize(&mut self) -> &Vec<Token> {
        loop {
            self.get_ip_address();
            self.get_mac_address();
            self.get_timestamp();
            self.get_date();
            self.get_time();
            self.get_identifier();
            // self.get_array();

            if let Some(token) = self.advance() {
                self.tok_result.push(token);
            } else {
                break;
            }
        }

        &self.tok_result
    }

    // fn get_array(&mut self) {
    //     let mut array = String::new();
    //     let column_no: usize;
    //     let line_no: usize;

    //     if self.peek_at(0, Keyword::IndexStart).is_some() {
    //         let tok = self.advance().unwrap();
    //         column_no = tok.column;
    //         line_no = tok.line;
    //         while let Some(tok) = self.peek() {
    //             if tok.token == Keyword::IndexEnd
    //                 || (tok.token != Keyword::Integer || tok.token != Keyword::Comma)
    //             {
    //                 break;
    //             }
    //             let token = self.advance().unwrap();
    //             array.push_str(&token.value);
    //         }

    //         let ident_token = Token {
    //             token: Keyword::Array,
    //             value: array,
    //             line: line_no,
    //             column: column_no,
    //         };

    //         self.tok_result.push(ident_token.clone());
    //     }
    // }

    fn get_identifier(&mut self) {
        let mut identifier = String::new();
        let mut column_no: usize = 0;
        let mut line_no: usize = 0;

        if self.peek_at(0, Keyword::Identifier).is_some()
            && self.peek_at(1, Keyword::Period).is_some()
            && self.peek_at(2, Keyword::Identifier).is_some()
        {
            for i in 0..3 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column_no = tok.column;
                        line_no = tok.line;
                    }

                    identifier.push_str(&tok.value);
                }
            }

            let ident_token = Token {
                token: Keyword::Identifier,
                value: identifier,
                line: line_no,
                column: column_no,
            };

            self.tok_result.push(ident_token.clone());
        }
    }

    fn get_ip_address(&mut self) {
        let mut ip_address = String::new();
        let mut column_no: usize = 0;
        let mut line_no: usize = 0;

        if self.peek_at(0, Keyword::Integer).is_some()
            && self.peek_at(1, Keyword::Period).is_some()
            && self.peek_at(2, Keyword::Integer).is_some()
            && self.peek_at(3, Keyword::Period).is_some()
            && self.peek_at(4, Keyword::Integer).is_some()
            && self.peek_at(5, Keyword::Period).is_some()
            && self.peek_at(6, Keyword::Integer).is_some()
        {
            for i in 0..7 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column_no = tok.column;
                        line_no = tok.line;
                    }

                    ip_address.push_str(&tok.value);
                }
            }

            let ip_token = Token {
                token: Keyword::IpV4,
                value: ip_address,
                line: line_no,
                column: column_no,
            };

            self.tok_result.push(ip_token.clone());
        }
    }

    fn get_mac_address(&mut self) {
        let mut mac_address = String::new();
        let mut column_no: usize = 0;
        let mut line_no: usize = 0;

        if self.peek_at(0, Keyword::Integer).is_some()
            && self.peek_at(1, Keyword::Colon).is_some()
            && self.peek_at(2, Keyword::Integer).is_some()
            && self.peek_at(3, Keyword::Colon).is_some()
            && self.peek_at(4, Keyword::Integer).is_some()
            && self.peek_at(5, Keyword::Colon).is_some()
            && self.peek_at(6, Keyword::Integer).is_some()
            && self.peek_at(7, Keyword::Colon).is_some()
            && self.peek_at(8, Keyword::Integer).is_some()
            && self.peek_at(9, Keyword::Colon).is_some()
            && self.peek_at(10, Keyword::Integer).is_some()
        {
            for i in 0..11 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column_no = tok.column;
                        line_no = tok.line;
                    }

                    mac_address.push_str(&tok.value);
                }
            }

            let ip_token = Token {
                token: Keyword::MacAddress,
                value: mac_address,
                line: line_no,
                column: column_no,
            };

            self.tok_result.push(ip_token.clone());
        }
    }

    fn get_timestamp(&mut self) {
        let mut timestamp = String::new();
        let mut column_no: usize = 0;
        let mut line_no: usize = 0;

        if self.peek_at(0, Keyword::Integer).is_some()
            && self.peek_at(1, Keyword::Minus).is_some()
            && self.peek_at(2, Keyword::Integer).is_some()
            && self.peek_at(3, Keyword::Minus).is_some()
            && self.peek_at(4, Keyword::Integer).is_some()
            && self.peek_at(5, Keyword::Integer).is_some()
            && self.peek_at(6, Keyword::Colon).is_some()
            && self.peek_at(7, Keyword::Integer).is_some()
            && self.peek_at(8, Keyword::Colon).is_some()
            && self.peek_at(9, Keyword::Integer).is_some()
        {
            for i in 0..10 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column_no = tok.column;
                        line_no = tok.line;
                    }

                    if i == 5 {
                        timestamp.push_str(" ");
                    }
                    timestamp.push_str(&tok.value);
                }
            }

            let timestamp_token = Token {
                token: Keyword::Timestamp,
                value: timestamp,
                line: line_no,
                column: column_no,
            };

            self.tok_result.push(timestamp_token.clone());
        }
    }

    fn get_date(&mut self) {
        let mut date = String::new();
        let mut column_no: usize = 0;
        let mut line_no: usize = 0;

        if self.peek_at(0, Keyword::Integer).is_some()
            && self.peek_at(1, Keyword::Minus).is_some()
            && self.peek_at(2, Keyword::Integer).is_some()
            && self.peek_at(3, Keyword::Minus).is_some()
            && self.peek_at(4, Keyword::Integer).is_some()
        {
            for i in 0..5 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column_no = tok.column;
                        line_no = tok.line;
                    }

                    date.push_str(&tok.value);
                }
            }

            let date_token = Token {
                token: Keyword::Date,
                value: date,
                line: line_no,
                column: column_no,
            };

            self.tok_result.push(date_token.clone());
        }
    }

    fn get_time(&mut self) {
        let mut date = String::new();
        let mut column_no: usize = 0;
        let mut line_no: usize = 0;

        if self.peek_at(0, Keyword::Integer).is_some()
            && self.peek_at(1, Keyword::Colon).is_some()
            && self.peek_at(2, Keyword::Integer).is_some()
            && self.peek_at(3, Keyword::Colon).is_some()
            && self.peek_at(4, Keyword::Integer).is_some()
        {
            for i in 0..5 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column_no = tok.column;
                        line_no = tok.line;
                    }

                    date.push_str(&tok.value);
                }
            }

            let date_token = Token {
                token: Keyword::Time,
                value: date,
                line: line_no,
                column: column_no,
            };

            self.tok_result.push(date_token.clone());
        }
    }
}
