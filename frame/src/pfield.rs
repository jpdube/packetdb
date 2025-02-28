use crate::fields;
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
    Bool(bool),
    ByteArray(Vec<u8>),
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Number(value) => write!(f, "{}", value),
            Self::Ipv4(address) => write!(f, "{}", IPv4::new(*address, 32).to_string()),
            Self::MacAddr(address) => write!(f, "{}", MacAddr::set_from_int(address)),
            Self::Timestamp(ts) => write!(f, "{}", timestamp_str(ts)),
            Self::Str(value) => write!(f, "{}", value),
            Self::Bool(value) => write!(f, "{}", value),
            Self::ByteArray(value) => write!(f, "{:?}", value),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct Field {
    pub field: FieldType,
    pub name: String,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.field)
    }
}

impl Field {
    pub fn to_json(&self) -> Value {
        match &self.field {
            FieldType::Number(value) => json!(value),
            FieldType::Ipv4(value) => json!(IPv4::new(*value, 32).to_string()),
            FieldType::MacAddr(value) => json!(MacAddr::set_from_int(value).to_string()),
            FieldType::Str(value) => json!(value),
            FieldType::Timestamp(value) => json!(timestamp_str(&value)),
            FieldType::Bool(value) => json!(value),
            FieldType::ByteArray(value) => json!(value),
        }
    }
}

pub fn get_field_type(field_id: u32, value: usize) -> Option<FieldType> {
    match field_id {
        fields::IPV4_DST_ADDR | fields::IPV4_SRC_ADDR | fields::ARP_TPA | fields::ARP_SPA => {
            Some(FieldType::Ipv4(value as u32))
        }
        fields::FRAME_TIMESTAMP => Some(FieldType::Timestamp(value)),
        fields::ETH_DST_MAC | fields::ETH_SRC_MAC | fields::ARP_SHA | fields::ARP_THA => {
            Some(FieldType::MacAddr(value as u64))
        }
        _ => Some(FieldType::Number(value)),
    }
}
fn timestamp_str(ts: &usize) -> String {
    let naive = Utc.timestamp_opt(*ts as i64, 0).unwrap();
    let timestamp = naive.format("%Y-%m-%d %H:%M:%S");
    format!("{}", timestamp)
}
