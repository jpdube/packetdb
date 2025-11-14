use byteorder::{BigEndian, WriteBytesExt};
use field::field_type;
use std::io::Write;

#[derive(Debug)]
pub struct Schema {
    pub ftype: u16,
    pub type_len: u16,
    pub name: String,
}

impl Schema {
    pub fn new(ftype: u16, name: &str) -> Self {
        Self {
            ftype,
            type_len: field_type::get_type_len(ftype),
            name: name.to_string(),
        }
    }

    pub fn to_binary(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.write_u16::<BigEndian>(self.ftype).unwrap();
        // result.write_u16::<BigEndian>(self.type_len).unwrap();
        result
            .write_u16::<BigEndian>(self.name.len() as u16)
            .unwrap();
        result.write(&self.name.clone().into_bytes()).unwrap();

        result
    }
}
