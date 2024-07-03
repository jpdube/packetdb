use crate::keywords::Keyword;
use std::fmt;

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

pub fn get_token_one(str_token: &str) -> Option<Keyword> {
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
        "." => Some(Keyword::Period),
        "[" => Some(Keyword::IndexStart),
        "]" => Some(Keyword::IndexEnd),
        ":" => Some(Keyword::Colon),
        "&" => Some(Keyword::BitAnd),
        "|" => Some(Keyword::BitOr),
        "^" => Some(Keyword::BitXor),
        "=" => Some(Keyword::Assign),
        _ => None,
    }
}

pub fn get_token_two(str_token: &str) -> Option<Keyword> {
    match str_token {
        "<=" => Some(Keyword::Le),
        ">=" => Some(Keyword::Ge),
        "==" => Some(Keyword::Equal),
        "!=" => Some(Keyword::Ne),
        _ => None,
    }
}

pub fn get_keywords(str_token: &str) -> Option<Keyword> {
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
        "distinct" => Some(Keyword::Distinct),
        "group" => Some(Keyword::GroupBy),
        "by" => Some(Keyword::By),
        "as" => Some(Keyword::As),
        "var" => Some(Keyword::Var),
        "print" => Some(Keyword::Print),

        _ => None,
    }
}

pub fn get_constants(str_token: &str) -> Option<Keyword> {
    match str_token {
        "ETH_IPV4" | "ETH_IPV6" | "ETH_ARP" | "IPV4_TCP" | "IPV4_UDP" | "IPV4_ICMP"
        | "TCP_PUSH" | "HTTPS" | "DNS" | "DHCP_SERVER" | "DHCP_CLIENT" => Some(Keyword::Constant),
        _ => None,
    }
}
