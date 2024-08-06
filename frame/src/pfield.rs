use crate::ipv4_address::IPv4;
use crate::mac_address::MacAddr;
use ::chrono::prelude::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::fmt;

#[derive(Debug, Serialize, Clone)]
#[serde(untagged)]
pub enum FieldType {
    Number(usize),
    Ipv4(u32),
    Timestamp(usize),
    Str(String),
    MacAddr(u64),
    Binary(Vec<u8>),
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Number(value) => write!(f, "{}", value),
            Self::Ipv4(address) => write!(f, "{}", IPv4::new(*address, 32)),
            Self::MacAddr(address) => write!(f, "{}", MacAddr::set_from_int(address)),
            Self::Timestamp(ts) => write!(f, "{}", timestamp_str(ts)),
            Self::Str(value) => write!(f, "{}", value),
            Self::Binary(value) => write!(f, "{:?}", value),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct Field {
    pub field_type: FieldType,
    pub name: String,
    pub field_id: usize,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.field_type)
    }
}

impl Field {
    pub fn new(field_type: FieldType, name: String, field_id: usize) -> Self {
        Self {
            field_type,
            name,
            field_id,
        }
    }

    fn _to_json(&self) -> Value {
        match &self.field_type {
            FieldType::Number(value) => json!(value),
            FieldType::Ipv4(value) => json!(IPv4::new(*value, 32).to_string()),
            FieldType::MacAddr(value) => json!(MacAddr::set_from_int(value).to_string()),
            FieldType::Str(value) => json!(value),
            FieldType::Timestamp(value) => json!(timestamp_str(&value)),
            FieldType::Binary(value) => json!(value),
        }
    }
}

fn timestamp_str(ts: &usize) -> String {
    let naive = Utc.timestamp_opt(*ts as i64, 0).unwrap();
    let timestamp = naive.format("%Y-%m-%d %H:%M:%S");
    format!("{}", timestamp)
}
