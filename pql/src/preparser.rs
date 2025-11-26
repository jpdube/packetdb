use crate::{keywords::Keyword, token::Token};

#[derive(Default)]
pub struct Preparser {
    token_src: Vec<Token>,
    token_list: Vec<Token>,
    index: usize,
    len: usize,
}

impl Preparser {
    pub fn advance(&mut self) -> Option<Token> {
        if self.at_end() {
            return None;
        }

        let result = self.token_src[self.index].clone();
        self.index += 1;

        Some(result)
    }

    pub fn peek_at(&self, offset: usize, search_tok: Keyword) -> Option<&Token> {
        if (self.index + offset) < self.len
            && self.token_src[self.index + offset].token == search_tok
        {
            return Some(&self.token_src[self.index + offset]);
        }

        None
    }

    pub fn peek(&self) -> Option<&Token> {
        if self.at_end() {
            return None;
        }

        Some(&self.token_src[self.index])
    }

    pub fn at_end(&self) -> bool {
        self.index >= self.len
    }

    pub fn parse(&mut self, token_list: Vec<Token>) -> Vec<Token> {
        self.token_src = token_list;
        self.len = self.token_src.len();

        while !self.at_end() {
            self.get_float();
            self.get_ip_address();
            self.get_mac_address();
            self.get_timestamp();
            self.get_date();
            self.get_time();
            self.get_count();
            self.get_max();
            self.get_bandwidth();
            self.get_min();
            self.get_average();
            self.get_sum();
            self.get_as();
            self.get_groupby();
            self.get_label();
            self.not_in();

            if let Some(tok) = self.advance() {
                self.token_list.push(tok.clone());
            }
        }

        self.token_list.clone()
    }

    fn not_in(&mut self) {
        let column;
        let line;

        if self.peek_at(0, Keyword::Not).is_some() && self.peek_at(1, Keyword::In).is_some() {
            let tok = self.advance().unwrap();
            column = tok.column;
            line = tok.line;

            self.advance();

            let token = Token {
                token: Keyword::NotIn,
                value: "not in".to_string(),
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_count(&mut self) {
        let column;
        let line;

        if self.peek_at(0, Keyword::Count).is_some()
            && self.peek_at(1, Keyword::Lparen).is_some()
            && self.peek_at(2, Keyword::Rparen).is_some()
        {
            let tok = self.advance().unwrap();
            column = tok.column;
            line = tok.line;

            self.advance();
            self.advance();

            let token = Token {
                token: Keyword::Count,
                value: tok.value,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_sum(&mut self) {
        let sum_str;
        let column;
        let line;

        if self.peek_at(0, Keyword::Sum).is_some()
            && self.peek_at(1, Keyword::Lparen).is_some()
            && self.peek_at(2, Keyword::Identifier).is_some()
            && self.peek_at(3, Keyword::Period).is_some()
            && self.peek_at(4, Keyword::Identifier).is_some()
            && self.peek_at(5, Keyword::Rparen).is_some()
        {
            let max_tok = self.advance().unwrap();
            column = max_tok.column;
            line = max_tok.line;

            self.advance();
            let name1 = self.advance().unwrap();
            self.advance();
            let name2 = self.advance().unwrap();
            sum_str = format!("{}.{}", name1.value, name2.value);
            self.advance();

            let token = Token {
                token: Keyword::Sum,
                value: sum_str,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }
    fn get_average(&mut self) {
        let avg_str;
        let column;
        let line;

        if self.peek_at(0, Keyword::Average).is_some()
            && self.peek_at(1, Keyword::Lparen).is_some()
            && self.peek_at(2, Keyword::Identifier).is_some()
            && self.peek_at(3, Keyword::Period).is_some()
            && self.peek_at(4, Keyword::Identifier).is_some()
            && self.peek_at(5, Keyword::Rparen).is_some()
        {
            let max_tok = self.advance().unwrap();
            column = max_tok.column;
            line = max_tok.line;

            self.advance();
            let name1 = self.advance().unwrap();
            self.advance();
            let name2 = self.advance().unwrap();
            avg_str = format!("{}.{}", name1.value, name2.value);
            self.advance();

            let token = Token {
                token: Keyword::Average,
                value: avg_str,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }
    fn get_min(&mut self) {
        let min_str;
        let column;
        let line;

        if self.peek_at(0, Keyword::Min).is_some()
            && self.peek_at(1, Keyword::Lparen).is_some()
            && self.peek_at(2, Keyword::Identifier).is_some()
            && self.peek_at(3, Keyword::Period).is_some()
            && self.peek_at(4, Keyword::Identifier).is_some()
            && self.peek_at(5, Keyword::Rparen).is_some()
        {
            let max_tok = self.advance().unwrap();
            column = max_tok.column;
            line = max_tok.line;

            self.advance();
            let name1 = self.advance().unwrap();
            self.advance();
            let name2 = self.advance().unwrap();
            min_str = format!("{}.{}", name1.value, name2.value);
            self.advance();

            let token = Token {
                token: Keyword::Min,
                value: min_str,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }
    fn get_max(&mut self) {
        let max_str;
        let column;
        let line;

        if self.peek_at(0, Keyword::Max).is_some()
            && self.peek_at(1, Keyword::Lparen).is_some()
            && self.peek_at(2, Keyword::Identifier).is_some()
            && self.peek_at(3, Keyword::Period).is_some()
            && self.peek_at(4, Keyword::Identifier).is_some()
            && self.peek_at(5, Keyword::Rparen).is_some()
        {
            let max_tok = self.advance().unwrap();
            column = max_tok.column;
            line = max_tok.line;

            self.advance();
            let name1 = self.advance().unwrap();
            self.advance();
            let name2 = self.advance().unwrap();
            max_str = format!("{}.{}", name1.value, name2.value);
            self.advance();

            let token = Token {
                token: Keyword::Max,
                value: max_str,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_bandwidth(&mut self) {
        let bw_str;
        let column;
        let line;

        if self.peek_at(0, Keyword::Bandwidth).is_some()
            && self.peek_at(1, Keyword::Lparen).is_some()
            && self.peek_at(2, Keyword::Identifier).is_some()
            && self.peek_at(3, Keyword::Period).is_some()
            && self.peek_at(4, Keyword::Identifier).is_some()
            && self.peek_at(5, Keyword::Rparen).is_some()
        {
            let max_tok = self.advance().unwrap();
            column = max_tok.column;
            line = max_tok.line;

            self.advance();
            let name1 = self.advance().unwrap();
            self.advance();
            let name2 = self.advance().unwrap();
            bw_str = format!("{}.{}", name1.value, name2.value);
            self.advance();

            let token = Token {
                token: Keyword::Bandwidth,
                value: bw_str,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_float(&mut self) {
        let mut float_str = String::new();
        let mut column = 0;
        let mut line = 0;

        if self.peek_at(0, Keyword::Integer).is_some()
            && self.peek_at(1, Keyword::Period).is_some()
            && self.peek_at(2, Keyword::Integer).is_some()
            && self.peek_at(3, Keyword::Period).is_none()
        {
            for i in 0..3 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column = tok.column;
                        line = tok.line;
                    }

                    float_str.push_str(&tok.value);
                }
            }

            let token = Token {
                token: Keyword::Float,
                value: float_str,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_as(&mut self) {
        let mut label = String::new();
        let mut column = 0;
        let mut line = 0;

        if self.peek_at(0, Keyword::As).is_some() && self.peek_at(1, Keyword::Identifier).is_some()
        {
            if let Some(tok) = self.advance() {
                column = tok.column;
                line = tok.line;
            }

            if let Some(tok_label) = self.advance() {
                label = tok_label.value;
            }

            let token = Token {
                token: Keyword::As,
                value: label,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }
    fn get_groupby(&mut self) {
        let mut column = 0;
        let mut line = 0;

        if self.peek_at(0, Keyword::GroupBy).is_some() && self.peek_at(1, Keyword::By).is_some() {
            if let Some(tok) = self.advance() {
                column = tok.column;
                line = tok.line;
            }

            _ = self.advance();

            let token = Token {
                token: Keyword::GroupBy,
                value: String::new(),
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_label(&mut self) {
        let mut label = String::new();
        let mut column = 0;
        let mut line = 0;

        if self.peek_at(0, Keyword::Identifier).is_some()
            && self.peek_at(1, Keyword::Period).is_some()
            && self.peek_at(2, Keyword::Identifier).is_some()
        {
            for i in 0..3 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column = tok.column;
                        line = tok.line;
                    }

                    label.push_str(&tok.value);
                }
            }

            let token = Token {
                token: Keyword::Identifier,
                value: label,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_ip_address(&mut self) {
        let mut ip_str = String::new();
        let mut column = 0;
        let mut line = 0;

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
                        column = tok.column;
                        line = tok.line;
                    }

                    ip_str.push_str(&tok.value);
                }
            }

            let token = Token {
                token: Keyword::IpV4,
                value: ip_str,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_mac_address(&mut self) {
        let mut mac_addr = String::new();
        let mut column = 0;
        let mut line = 0;

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
                        column = tok.column;
                        line = tok.line;
                    }

                    mac_addr.push_str(&tok.value);
                }
            }

            let token = Token {
                token: Keyword::MacAddress,
                value: mac_addr,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_time(&mut self) {
        let mut str_time = String::new();
        let mut column = 0;
        let mut line = 0;

        if self.peek_at(0, Keyword::Integer).is_some()
            && self.peek_at(1, Keyword::Colon).is_some()
            && self.peek_at(2, Keyword::Integer).is_some()
            && self.peek_at(3, Keyword::Colon).is_some()
            && self.peek_at(4, Keyword::Integer).is_some()
        {
            for i in 0..5 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column = tok.column;
                        line = tok.line;
                    }

                    str_time.push_str(&tok.value);
                }
            }

            let token = Token {
                token: Keyword::Time,
                value: str_time,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_date(&mut self) {
        let mut str_date = String::new();
        let mut column = 0;
        let mut line = 0;

        if self.peek_at(0, Keyword::Integer).is_some()
            && self.peek_at(1, Keyword::Minus).is_some()
            && self.peek_at(2, Keyword::Integer).is_some()
            && self.peek_at(3, Keyword::Minus).is_some()
            && self.peek_at(4, Keyword::Integer).is_some()
        {
            for i in 0..5 {
                if let Some(tok) = self.advance() {
                    if i == 0 {
                        column = tok.column;
                        line = tok.line;
                    }

                    str_date.push_str(&tok.value);
                }
            }

            let token = Token {
                token: Keyword::Date,
                value: str_date,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }

    fn get_timestamp(&mut self) {
        let mut timestamp = String::new();
        let mut column = 0;
        let mut line = 0;

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
                        column = tok.column;
                        line = tok.line;
                    }

                    timestamp.push_str(&tok.value);
                }
            }

            let token = Token {
                token: Keyword::Timestamp,
                value: timestamp,
                column,
                line,
            };

            self.token_list.push(token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keywords::Keyword, lexer::Lexer};

    #[test]
    fn count_token() {
        let mut t = Lexer::new();
        let line = "select ip.src, ip.dst from sniffer_01";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        assert!(result.len() == 7);
    }

    #[test]
    fn advance_token() {
        let mut t = Lexer::new();
        let line = "select ip_src, ip_dst from sniffer_01";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        assert!(result.len() == 7);
    }

    #[test]
    fn as_token() {
        let mut t = Lexer::new();
        let line = "as nbr_packets";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        println!("{:?}", result);
        assert!(result.len() == 2);
        assert!(result[0].token == Keyword::As);
        assert!(result[0].value == "nbr_packets");
    }

    #[test]
    fn groupby_token() {
        let mut t = Lexer::new();
        let line = "group by";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        println!("{:?}", result);
        assert!(result.len() == 2);
        assert!(result[0].token == Keyword::GroupBy);
    }

    #[test]
    fn date_token() {
        let mut t = Lexer::new();
        let line = "2024-02-01";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        println!("{:?}", result);
        assert!(result.len() == 2);
        assert!(result[0].token == Keyword::Date);
    }

    #[test]
    fn time_token() {
        let mut t = Lexer::new();
        let line = "14:35:00";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        println!("{:?}", result);
        assert!(result.len() == 2);
        assert!(result[0].token == Keyword::Time);
    }

    #[test]
    fn timestamp_token() {
        let mut t = Lexer::new();
        let line = "2024-02-01 14:35:00";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        println!("{:?}", result);
        assert!(result.len() == 2);
        assert!(result[0].token == Keyword::Timestamp);
    }
    #[test]
    fn ipv4_token() {
        let mut t = Lexer::new();
        let line = "192.168.3.0";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        println!("{:?}", result);
        assert!(result.len() == 2);
        assert!(result[0].token == Keyword::IpV4);
    }

    #[test]
    fn mac_addr_token() {
        let mut t = Lexer::new();
        let line = "01:02:03:04:05:06";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        println!("{:?}", result);
        assert!(result.len() == 2);
        assert!(result[0].token == Keyword::MacAddress);
    }

    #[test]
    fn identifier_token() {
        let mut t = Lexer::new();
        let line = "ip.src";
        let token_list: &Vec<Token> = t.tokenize(line);
        let mut parser = Preparser::default();
        let result = parser.parse(token_list.clone());
        println!("{:?}", result);
        assert!(result.len() == 2);
        assert!(result[0].token == Keyword::Identifier);
    }
}
