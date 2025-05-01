use crate::ipv4_address::IPv4;
use crate::ipv6_address::IPv6;
use crate::mac_address::MacAddr;
use ::chrono::prelude::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::fmt;

#[derive(Debug, Serialize, Clone)]
#[serde(untagged)]
pub enum FieldType {
    Int64(u64),
    Int32(u32),
    Int16(u16),
    Int8(u8),
    Ipv4(u32, u8),
    Ipv6(u128, u8),
    Timestamp(u32),
    String(String),
    MacAddr(u64),
    Bool(bool),
    ByteArray(Vec<u8>),
    FieldArray(Vec<Box<FieldType>>),
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Int64(value) => write!(f, "{}", value),
            Self::Int32(value) => write!(f, "{}", value),
            Self::Int16(value) => write!(f, "{}", value),
            Self::Int8(value) => write!(f, "{}", value),
            Self::Ipv4(address, mask) => write!(f, "{}", IPv4::new(*address, *mask).to_string()),
            Self::Ipv6(address, mask) => write!(f, "{}", IPv6::new(*address, *mask).to_string()),
            Self::MacAddr(address) => write!(f, "{}", MacAddr::set_from_int(address)),
            Self::Timestamp(ts) => write!(f, "{}", timestamp_str(ts)),
            Self::String(value) => write!(f, "{}", value),
            Self::Bool(value) => write!(f, "{}", value),
            Self::ByteArray(value) => write!(f, "{:?}", value),
            Self::FieldArray(value) => write!(f, "{:?}", value),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct Field {
    pub field: FieldType,
    pub name: String,
    pub field_id: u32,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.field)
    }
}

impl Field {
    pub fn set_field(field_type: FieldType, field_id: u32) -> Self {
        Self {
            field: field_type,
            field_id,
            name: String::new(),
        }
    }

    pub fn set_field_with_name(field_type: FieldType, name: String) -> Self {
        Self {
            field: field_type,
            field_id: 0,
            name,
        }
    }

    pub fn to_json(&self) -> Value {
        match &self.field {
            FieldType::Int64(value) => json!(value),
            FieldType::Int32(value) => json!(value),
            FieldType::Int16(value) => json!(value),
            FieldType::Int8(value) => json!(value),
            FieldType::Ipv4(address, mask) => json!(IPv4::new(*address, *mask).to_string()),
            FieldType::Ipv6(address, mask) => json!(IPv6::new(*address, *mask).to_string()),
            FieldType::MacAddr(value) => json!(MacAddr::set_from_int(value).to_string()),
            FieldType::String(value) => json!(value),
            FieldType::Timestamp(value) => json!(timestamp_str(&value)),
            FieldType::Bool(value) => json!(value),
            FieldType::ByteArray(value) => json!(value),
            FieldType::FieldArray(value) => json!(self.format_array(value.clone())),
        }
    }

    fn format_array(&self, value: Vec<Box<FieldType>>) -> Vec<String> {
        let mut result: Vec<String> = Vec::new();

        for field in value {
            match *field {
                FieldType::Ipv4(adr, mask) => result.push(IPv4::new(adr, mask).to_string()),
                FieldType::Ipv6(adr, mask) => result.push(IPv6::new(adr, mask).to_string()),
                FieldType::MacAddr(addr) => result.push(MacAddr::set_from_int(&addr).to_string()),
                _ => result.push(field.to_string()),
            }
        }

        result
    }

    pub fn to_u8(&self) -> u8 {
        match self.field {
            FieldType::Int8(value) => value,
            _ => 0,
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self.field {
            FieldType::Int16(value) => value,
            _ => 0,
        }
    }

    pub fn to_u32(&self) -> u32 {
        match self.field {
            FieldType::Int32(value) => value,
            _ => 0,
        }
    }

    pub fn to_u64(&self) -> u64 {
        match self.field {
            FieldType::Int8(value) => value as u64,
            FieldType::Int16(value) => value as u64,
            FieldType::Int32(value) => value as u64,
            FieldType::Int64(value) => value,
            FieldType::Bool(value) => value as u64,
            FieldType::Ipv4(value, _) => value as u64,
            FieldType::MacAddr(value) => value as u64,
            _ => 0,
        }
    }

    pub fn to_usize(&self) -> usize {
        match self.field {
            FieldType::Int8(value) => value as usize,
            FieldType::Int16(value) => value as usize,
            FieldType::Int32(value) => value as usize,
            FieldType::Int64(value) => value as usize,
            _ => 0,
        }
    }

    pub fn to_bool(&self) -> bool {
        match self.field {
            FieldType::Bool(value) => value,
            _ => false,
        }
    }

    pub fn to_ipv4(&self) -> IPv4 {
        match self.field {
            FieldType::Ipv4(ip, mask) => IPv4::new(ip, mask),
            _ => IPv4::new(0, 0),
        }
    }

    pub fn to_mac(&self) -> u64 {
        match self.field {
            FieldType::MacAddr(addr) => addr,
            _ => 0,
        }
    }

    pub fn to_string(&self) -> String {
        match &self.field {
            FieldType::String(value) => value.clone(),
            _ => String::new(),
        }
    }
}

fn timestamp_str(ts: &u32) -> String {
    let naive = Utc.timestamp_opt(*ts as i64, 0).unwrap();
    let timestamp = naive.format("%Y-%m-%d %H:%M:%S");
    format!("{}", timestamp)
}
