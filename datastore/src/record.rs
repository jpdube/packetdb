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
        self.field_list
            .iter()
            .find(|f| f.get_name() == fieldname)
            .cloned()
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
