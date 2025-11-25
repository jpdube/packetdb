use byteorder::{BigEndian, WriteBytesExt};
use field::field_type;
use std::fmt;
use std::io::Write;

#[derive(Debug, Clone)]
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

    pub fn into_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.write_u16::<BigEndian>(self.ftype).unwrap();
        // result.write_u16::<BigEndian>(self.type_len).unwrap();
        result
            .write_u16::<BigEndian>(self.name.len() as u16)
            .unwrap();
        result.write_all(&self.name.clone().into_bytes()).unwrap();

        result
    }
}

impl fmt::Display for Schema {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SCHEMA: Type: {}, Length: {}, Name: {}",
            self.ftype, self.type_len, self.name
        )
    }
}
