use frame::pfield::Field;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Default, Serialize, Clone)]
pub struct Record {
    field_list: HashMap<String, Field>,
}

impl Record {
    pub fn add_field(&mut self, field: Field) {
        self.field_list.insert(field.get_name(), field);
    }

    pub fn get(&self, fieldname: String) -> Option<Field> {
        if let Some(field) = self.field_list.get(&fieldname) {
            return Some(field.clone());
        }

        None
    }

    pub fn to_json(&self) -> BTreeMap<String, Value> {
        let mut result: BTreeMap<String, Value> = BTreeMap::new();
        for f in self.field_list.values() {
            result.insert(f.get_name(), f.to_json());
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

    pub fn to_json(&self) -> Vec<BTreeMap<String, Value>> {
        let mut json_result: Vec<BTreeMap<String, Value>> = Vec::new();
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
                    print!("{}\t\t", h.get_name());
                }
                println!();
                println!("----------------------------------------------------------");
                first_line = false;
            }
            for r in f.field_list.values() {
                print!("{}\t", r.field);
            }
            println!();
        }
    }
}
