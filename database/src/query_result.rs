use ::chrono::prelude::*;
use frame::fields;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Serialize, Clone)]
#[serde(untagged)]
pub enum FieldType {
    Number(usize),
    Ipv4(u32),
    Timestamp(usize),
    Str(String),
    // Binary(Vec<u8>),
}

impl fmt::Display for FieldType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Number(value) => write!(f, "{}", value),
            Self::Ipv4(address) => write!(f, "{}", ipv4_str(address)),
            Self::Timestamp(ts) => write!(f, "{}", timestamp_str(ts)),
            Self::Str(value) => write!(f, "{}", value),
            // Self::Binary(value) => write!(f, "{:?}", value),
        }
    }
}

#[derive(Debug, Serialize)]
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

            FieldType::Ipv4(value) => json!(ipv4_str(&value)),
            FieldType::Str(value) => json!(value),
            FieldType::Timestamp(value) => json!(timestamp_str(&value)),
        }
    }
}

pub fn get_field_type(field_id: u32, value: usize) -> Option<FieldType> {
    match field_id {
        fields::IPV4_DST_ADDR | fields::IPV4_SRC_ADDR => Some(FieldType::Ipv4(value as u32)),
        fields::FRAME_TIMESTAMP => Some(FieldType::Timestamp(value)),
        _ => Some(FieldType::Number(value)),
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Record {
    field_list: Vec<Field>,
}

impl Record {
    pub fn add_field(&mut self, field: Field) {
        self.field_list.push(field);
    }

    pub fn to_json(&self) -> BTreeMap<&str, Value> {
        let mut result: BTreeMap<&str, Value> = BTreeMap::new();
        for f in self.field_list.iter() {
            result.insert(&f.name, f.to_json());
        }

        result
    }
}

#[derive(Debug, Default)]
pub struct QueryResult {
    pub record_list: Vec<Record>,
}

impl QueryResult {
    pub fn add_record(&mut self, new_record: Record) {
        self.record_list.push(new_record);
    }

    pub fn to_json(&self) -> Vec<BTreeMap<&str, Value>> {
        let mut json_result: Vec<BTreeMap<&str, Value>> = Vec::new();
        for r in &self.record_list {
            json_result.push(r.to_json());
        }

        json_result
    }

    pub fn print(&self) {
        println!("Record count: {}", self.record_list.len());
        let mut first_line = true;
        for f in &self.record_list {
            if first_line {
                for h in &f.field_list {
                    print!("{}\t\t", h.name);
                }
                println!();
                println!("----------------------------------------------------------");
                first_line = false;
            }
            for r in &f.field_list {
                print!("{}\t", r.field);
            }
            println!();
        }
    }
}

fn ipv4_str(address: &u32) -> String {
    format!(
        "{}.{}.{}.{}",
        (address >> 24) & 0xff,
        (address >> 16) & 0xff,
        (address >> 8) & 0xff,
        address & 0xff
    )
}

fn timestamp_str(ts: &usize) -> String {
    let naive = Utc.timestamp_opt(*ts as i64, 0).unwrap();
    let timestamp = naive.format("%Y-%m-%d %H:%M:%S");
    format!("{}", timestamp)
}
