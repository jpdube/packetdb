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
    BitShiftRight,
    BitShiftLeft,
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
    Distinct,
    As,
    By,
    GroupBy,
    Sum,
    Count,
    Min,
    Max,
    Bandwidth,
    String,
    Var,
    Assign,
    Print,
}

impl fmt::Display for Keyword {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}
