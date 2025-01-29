use ::chrono::prelude::*;
use frame::fields;
use frame::ipv4_address::IPv4;
use frame::mac_address::MacAddr;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
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
    // Binary(Vec<u8>),
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
            // Self::Binary(value) => write!(f, "{:?}", value),
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
    fn to_json(&self) -> Value {
        match &self.field {
            FieldType::Number(value) => json!(value),
            FieldType::Ipv4(value) => json!(IPv4::new(*value, 32).to_string()),
            FieldType::MacAddr(value) => json!(MacAddr::set_from_int(value).to_string()),
            FieldType::Str(value) => json!(value),
            FieldType::Timestamp(value) => json!(timestamp_str(&value)),
            FieldType::Bool(value) => json!(value),
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

#[derive(Debug, Default, Serialize, Clone)]
pub struct Record {
    field_list: HashMap<String, Field>,
    // field_list: Vec<Field>,
}

impl Record {
    pub fn add_field(&mut self, field: Field) {
        self.field_list.insert(field.name.to_owned(), field);
    }

    pub fn get(&self, fieldname: String) -> Option<Field> {
        if let Some(field) = self.field_list.get(&fieldname) {
            return Some(field.clone());
        }

        None
    }

    pub fn to_json(&self) -> BTreeMap<&str, Value> {
        let mut result: BTreeMap<&str, Value> = BTreeMap::new();
        for f in self.field_list.values() {
            result.insert(&f.name, f.to_json());
        }

        result
    }
}

#[derive(Debug, Default, Clone)]
pub struct Cursor {
    record_list: Vec<Record>,
}

impl Cursor {
    pub fn add_record(&mut self, new_record: Record) {
        self.record_list.push(new_record);
    }

    pub fn append_records(&mut self, record_list: Vec<Record>) {
        for r in record_list {
            self.record_list.push(r.clone());
        }
    }

    pub fn to_json(&self) -> Vec<BTreeMap<&str, Value>> {
        let mut json_result: Vec<BTreeMap<&str, Value>> = Vec::new();
        for r in &self.record_list {
            json_result.push(r.to_json());
        }

        json_result
    }

    pub fn len(&self) -> usize {
        self.record_list.len()
    }

    pub fn print(&self) {
        println!("Record count: {}", self.record_list.len());
        let mut first_line = true;
        for f in &self.record_list {
            if first_line {
                for h in f.field_list.values() {
                    // for h in &f.field_list {
                    print!("{}\t\t", h.name);
                }
                println!();
                println!("----------------------------------------------------------");
                first_line = false;
            }
            for r in f.field_list.values() {
                // for r in &f.field_list {
                print!("{}\t", r.field);
            }
            println!();
        }
    }
}

fn timestamp_str(ts: &usize) -> String {
    let naive = Utc.timestamp_opt(*ts as i64, 0).unwrap();
    let timestamp = naive.format("%Y-%m-%d %H:%M:%S");
    format!("{}", timestamp)
}
