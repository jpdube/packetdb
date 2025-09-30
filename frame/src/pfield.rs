use crate::ipv4_address::IPv4;
use crate::ipv6_address::IPv6;
use crate::mac_address::MacAddr;
use crate::to_binary::ToBinary;
use ::chrono::prelude::*;
use byteorder::BigEndian;
use byteorder::WriteBytesExt;
use serde::Serialize;
use serde_json::{json, Value};
use std::fmt;
use std::io::Write;

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
    TimeValue(u32),
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
            Self::TimeValue(tv) => write!(f, "{}", timevalue_str(tv)),
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
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.field)
    }
}

impl ToBinary for Field {
    fn field_def_to_binary(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.write_u16::<BigEndian>(self.get_int_type()).unwrap();
        result.write_u16::<BigEndian>(self.get_type_len()).unwrap();
        result
            .write_u16::<BigEndian>(self.name.len() as u16)
            .unwrap();
        result.write(&self.name.clone().into_bytes()).unwrap();

        result
    }

    fn field_to_binary(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        match &self.field {
            FieldType::Int64(value) => {
                result.write_u64::<BigEndian>(*value).unwrap();
            }
            FieldType::Int32(value) => {
                result.write_u32::<BigEndian>(*value).unwrap();
            }
            FieldType::Int16(value) => {
                result.write_u16::<BigEndian>(*value).unwrap();
            }
            FieldType::Int8(value) => {
                result.write_u8(*value).unwrap();
            }
            FieldType::Ipv4(address, mask) => {
                result.write_u32::<BigEndian>(*address).unwrap();
                result.write_u8(*mask).unwrap();
            }
            FieldType::Ipv6(address, mask) => {
                result.write_u128::<BigEndian>(*address).unwrap();
                result.write_u8(*mask).unwrap();
            }
            FieldType::MacAddr(value) => {
                result.write_u64::<BigEndian>(*value << 16).unwrap();
                result = result[0..6].to_vec();
            }
            FieldType::String(value) => {
                result.write_u16::<BigEndian>(value.len() as u16).unwrap();
                result.write_all(value.as_bytes()).unwrap();
            }
            FieldType::Timestamp(value) => {
                result.write_u32::<BigEndian>(*value).unwrap();
            }
            FieldType::TimeValue(value) => {
                result.write_u32::<BigEndian>(*value).unwrap();
            }
            FieldType::Bool(value) => {
                if *value {
                    result.write_u8(1).unwrap();
                } else {
                    result.write_u8(0).unwrap();
                }
            }
            FieldType::ByteArray(value) => {
                result.write_u16::<BigEndian>(value.len() as u16).unwrap();
                result.write_all(&value).unwrap();
            }
            // FieldType::FieldArray(value) => json!(self.format_array(value.clone())),
            _ => {}
        };

        result
    }
}

impl Field {
    pub fn set_field(field_type: FieldType, field_id: String) -> Self {
        Self {
            field: field_type,
            name: field_id,
        }
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_type_len(&self) -> u16 {
        match &self.field {
            FieldType::Bool(_) => 1 as u16,
            FieldType::Int8(_) => 1 as u16,
            FieldType::Int16(_) => 2 as u16,
            FieldType::Int32(_) => 4 as u16,
            FieldType::Int64(_) => 8 as u16,
            FieldType::Ipv4(_, _) => 4 as u16,
            FieldType::MacAddr(_) => 6 as u16,
            FieldType::Timestamp(_) => 4 as u16,
            FieldType::TimeValue(_) => 4 as u16,
            FieldType::Ipv6(_, _) => 8 as u16,
            FieldType::ByteArray(value) => value.len() as u16,
            FieldType::String(value) => value.len() as u16,
            FieldType::FieldArray(value) => value.len() as u16,
        }
    }

    pub fn get_int_type(&self) -> u16 {
        match &self.field {
            FieldType::Bool(_) => 0 as u16,
            FieldType::Int8(_) => 1 as u16,
            FieldType::Int16(_) => 2 as u16,
            FieldType::Int32(_) => 3 as u16,
            FieldType::Int64(_) => 4 as u16,
            FieldType::Ipv4(_, _) => 5 as u16,
            FieldType::MacAddr(_) => 6 as u16,
            FieldType::Timestamp(_) => 7 as u16,
            FieldType::TimeValue(_) => 8 as u16,
            FieldType::Ipv6(_, _) => 9 as u16,
            FieldType::ByteArray(_) => 0x0a as u16,
            FieldType::String(_) => 0x0b as u16,
            FieldType::FieldArray(_) => 0x0c as u16,
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
            FieldType::TimeValue(value) => json!(timevalue_str(value)),
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
                FieldType::Timestamp(ts) => result.push(timestamp_str(&ts)),
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
            FieldType::Ipv4(value, _) => value,
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

fn timevalue_str(tv: &u32) -> String {
    let days: u32;
    let mut hours: u32 = 0;

    let result: u32 = tv / 360 / 24;
    days = result;

    if tv % 360 != 0 {
        hours = tv % 360 * 60;
    }

    format!("Days: {}, hours: {}, value: {}", days, hours, tv)
}

fn timestamp_str(ts: &u32) -> String {
    let naive = Utc.timestamp_opt(*ts as i64, 0).unwrap();
    let timestamp = naive.format("%Y-%m-%d %H:%M:%S");
    format!("{}", timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_bool_false() {
        let field = Field::set_field(FieldType::Bool(false), "bool_value".to_string());

        let bin_value = field.field_to_binary();
        println!("Bin value Bool: {}:{:?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[0], 0x00, "Bool serialized");
        assert_eq!(bin_value.len(), 1, "Bool serialized len");
    }

    #[test]
    fn test_write_bool_true() {
        let field = Field::set_field(FieldType::Bool(true), "bool_value".to_string());

        let bin_value = field.field_to_binary();
        println!("Bin value Bool: {}:{:?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[0], 0x01, "Bool serialized");
        assert_eq!(bin_value.len(), 1, "Bool serialized len");
    }

    #[test]
    fn test_write_u8() {
        let field = Field::set_field(FieldType::Int8(0xc0), "byte_value".to_string());

        let bin_value = field.field_to_binary();
        println!("Bin value U8: {}:{:?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[0], 0xc0, "U8 serialized");
        assert_eq!(bin_value.len(), 1, "U8 serialized len");
    }

    #[test]
    fn test_write_u16() {
        let field = Field::set_field(FieldType::Int16(0xc0a8), "short_value".to_string());

        let bin_value = field.field_to_binary();
        println!("Bin value U16: {}:{:?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[0], 0xc0, "U16 serialized");
        assert_eq!(bin_value.len(), 2, "U16 serialized len");
    }

    #[test]
    fn test_write_mac() {
        let field = Field::set_field(
            FieldType::MacAddr(0xa0b1c2d3e4f5 as u64),
            "mac_value".to_string(),
        );

        let bin_value = field.field_to_binary();
        println!("Bin value Mac Addr: {}:{:x?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[0], 0xa0, "MacAddr byte 1 serialized");
        assert_eq!(bin_value[1], 0xb1, "MacAddr byte 2 serialized");
        assert_eq!(bin_value[2], 0xc2, "MacAddr byte 3 serialized");
        assert_eq!(bin_value[3], 0xd3, "MacAddr byte 4 serialized");
        assert_eq!(bin_value[4], 0xe4, "MacAddr byte 5 serialized");
        assert_eq!(bin_value[5], 0xf5, "MacAddr byte 6 serialized");
        assert_eq!(bin_value.len(), 6, "MacAddr serialized len");
    }

    #[test]
    fn test_write_ipv4() {
        let field = Field::set_field(FieldType::Ipv4(0xc0a80301, 24), "ipv4_value".to_string());

        let bin_value = field.field_to_binary();
        println!("Bin value IPv4: {}:{:?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[0], 0xc0, "IpV4 byte 1 serialized");
        assert_eq!(bin_value[1], 0xa8, "IpV4 byte 2 serialized");
        assert_eq!(bin_value[2], 0x03, "IpV4 byte 3 serialized");
        assert_eq!(bin_value[3], 0x01, "IpV4 byte 4 serialized");
        assert_eq!(bin_value[4], 0x18, "IpV4 byte mask serialized");
        assert_eq!(bin_value.len(), 5, "IPv4 serialized len");
    }

    #[test]
    fn test_write_u32() {
        let field = Field::set_field(FieldType::Int32(0xc0a80301), "big_value".to_string());

        let bin_value = field.field_to_binary();
        println!("Bin value U32: {}:{:?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[0], 0xc0, "U32 serialized");
        assert_eq!(bin_value.len(), 4, "U32 serialized len");
    }

    #[test]
    fn test_write_u64() {
        let field = Field::set_field(
            FieldType::Int64(0xa0b1c2d3e4f50010),
            "big_value".to_string(),
        );

        let bin_value = field.field_to_binary();
        println!("Bin value U64: {}:{:?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[0], 0xa0, "U64 serialized");
        assert_eq!(bin_value.len(), 8, "U64 serialized len");
    }

    #[test]
    fn test_write_string() {
        let field = Field::set_field(
            FieldType::String("athis is a string of 24".to_string()),
            "string_value".to_string(),
        );

        let bin_value = field.field_to_binary();
        println!("String value: {}:{:x?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[2], 0x61, "String serialized");
        assert_eq!(bin_value.len(), 25, "String serialized len");
    }

    #[test]
    fn test_write_byte_array() {
        let bytes: Vec<u8> = vec![0, 1, 2, 3, 4, 5];
        let field = Field::set_field(FieldType::ByteArray(bytes), "byte_array_value".to_string());

        let bin_value = field.field_to_binary();
        println!("ByteArray value: {}:{:x?}", bin_value.len(), bin_value);

        assert_eq!(bin_value[3], 0x01, "Byte array serialized");
        assert_eq!(bin_value[1], 0x06, "Byte array serialized");
        assert_eq!(bin_value.len(), 8, "Byte array serialized len");
    }

    #[test]
    fn test_write_field_def() {
        let field = Field::set_field(FieldType::Int32(0xc0a80301), "U32_values".to_string());

        let bin_value = field.field_def_to_binary();
        println!(
            "Field definition value: {}:{:x?}",
            bin_value.len(),
            bin_value
        );

        assert_eq!(bin_value[1], 0x03, "Int field type");
        assert_eq!(bin_value[3], 0x04, "Field type len");
        assert_eq!(bin_value[5], 0x0a, "Field name len");
        assert_eq!(
            String::from_utf8(bin_value[6..].to_vec()).unwrap(),
            "U32_values".to_string(),
            "Field name"
        );
        assert_eq!(bin_value.len(), 16, "Result len");
    }
}
