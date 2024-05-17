use crate::keywords::Keyword;
use crate::preparser::Preparser;
use crate::token::{get_constants, get_keywords, get_token_one, get_token_two, Token};
use std::io::Read;

pub struct Lexer {
    token_list: Vec<Token>,
    index: usize,
}

impl Lexer {
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

    pub fn tokenize(&mut self, lines: &str) -> &Vec<Token> {
        self.index = 0;
        let s: Vec<_> = lines.chars().collect();
        let mut preparser = Preparser::default();

        let mut line: usize = 1;
        let mut line_offset: usize = 0;

        while self.index < s.len() {
            if s[self.index].is_whitespace() {
                if s[self.index] == '\n' {
                    line += 1;
                    line_offset = self.index + 1;
                }
                self.index += 1;
            } else if s[self.index] == '#' {
                if let Some(eol) = String::from_iter(s[self.index + 1..].to_vec()).find('\n') {
                    self.index = eol + 1;
                    println!("Found EOL: {eol}");
                }
            } else if (self.index + 2) <= s.len()
                && get_token_two(&String::from_iter(s[self.index..self.index + 2].to_vec()))
                    .is_some()
            {
                let stoken: &str = &String::from_iter(s[self.index..self.index + 2].to_vec());
                let tok = get_token_two(stoken).unwrap();
                let token = Token {
                    token: tok.to_owned(),
                    value: String::from(stoken),
                    column: (self.index + 1) - line_offset,
                    line,
                };
                self.token_list.push(token);

                self.index += 2;
            } else if get_token_one(&String::from(s[self.index]) as &str).is_some() {
                let tok = get_token_one(&String::from(s[self.index]) as &str).unwrap();
                let token = Token {
                    token: tok.to_owned(),
                    value: String::from(s[self.index]),
                    column: (self.index + 1) - line_offset,
                    line,
                };
                self.token_list.push(token);

                // if s[self.index] == ';' {
                //     line += 1;
                // }

                self.index += 1;
            } else if s[self.index].is_numeric() {
                let start = self.index;

                while self.index < s.len() && s[self.index].is_numeric() {
                    self.index += 1;
                }

                let number = String::from_iter(s[start..self.index].to_vec());
                let token = Token {
                    token: Keyword::Integer,
                    value: number,
                    column: (start + 1) - line_offset,
                    line,
                };
                self.token_list.push(token);
            } else if s[self.index].is_alphabetic() || s[self.index] == '_' {
                let start = self.index;
                while self.index < s.len()
                    && (s[self.index].is_alphabetic()
                        || s[self.index].is_numeric()
                        || s[self.index] == '_')
                {
                    self.index += 1;
                }
                let keyword: &str = &String::from_iter(s[start..self.index].to_vec());
                if get_keywords(keyword).is_some() {
                    // if keywords.contains_key(keyword) {
                    let tok = get_keywords(keyword).unwrap();
                    let token = Token {
                        token: tok.to_owned(),
                        value: String::from(keyword),
                        column: (start + 1) - line_offset,
                        line,
                    };
                    self.token_list.push(token);
                } else if get_constants(keyword).is_some() {
                    let tok = get_constants(keyword).unwrap();
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

        self.token_list = preparser.parse(self.token_list.clone());
        return &self.token_list;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_tokens() {
        let mut t = Lexer::new();
        let line = "192.168.3.0";
        let token_list: &Vec<Token> = t.tokenize(line);
        println!("IP tokens: {:?}", token_list);
        assert!(token_list.len() == 8);
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
        println!("{:#?}", tl);
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
}
