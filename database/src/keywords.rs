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
    BitAnd,
    BitOr,
    BitXor,
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
    IndexStart,
    IndexEnd,
    Colon,
    Distinct,
}

impl fmt::Display for Keyword {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
