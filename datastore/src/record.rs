use field::pfield::Field;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Default, Serialize, Clone)]
pub struct Record {
    field_list: Vec<Field>,
}

impl Record {
    pub fn add(&mut self, field: Field) {
        self.field_list.push(field);
    }

    pub fn get(&self, fieldname: &str) -> Option<Field> {
        for f in &self.field_list {
            if f.get_name() == fieldname.to_string() {
                return Some(f.clone());
            }
        }

        None
    }

    pub fn get_fields(&self) -> Vec<Field> {
        self.field_list.clone()
    }

    pub fn to_json(&self) -> BTreeMap<String, Value> {
        let mut result: BTreeMap<String, Value> = BTreeMap::new();
        for f in &self.field_list {
            result.insert(f.get_name(), f.to_json());
        }

        result
    }
}
