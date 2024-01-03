use std::fmt;

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
    Period,
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
    IndexStart,
    IndexEnd,
    Colon,
    Array,
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
