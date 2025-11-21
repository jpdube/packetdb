use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};
use field::pfield::Field;
use field::serialize_field::SerializeField;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};

//                      Index file structure
// +------------------------------+--------------+---------------+
// |           Magic no           |   Version    |    Options    |
// |             u32              |     u16      |      u16      |
// |                              |              |               |
// +---------------+--------------+--------------+---------------+
// |  Field type   |   FieldLen   |          Fieldname           |
// |      u16      |     u16      |             [u8]             |
// |               |              |                              |
// +---------------+--------------+------------------------------+
// |        Index (1) size        |        Index (1) data        |
// |             u32              |             [u8]             |
// |                              |                              |
// +------------------------------+------------------------------+
// |        Index (n) size        |        Index (n) data        |
// |             u32              |             [u8]             |
// |                              |                              |
// +------------------------------+------------------------------+

struct Header {
    magic_no: u32,
    version: u16,
    options: u16,
}

impl Header {
    pub fn new() -> Self {
        Self {
            magic_no: 0x11223344,
            version: 1,
            options: 0,
        }
    }

    pub fn to_binary(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.write_u32::<BigEndian>(self.magic_no).unwrap();
        result.write_u16::<BigEndian>(self.version).unwrap();
        result.write_u16::<BigEndian>(self.options).unwrap();

        result
    }
}

pub struct StorageIndex {
    filename: String,
    fieldname: String,
    key_list: HashMap<Field, Vec<u32>>,
    write_ptr: usize,
    header: Header,
}

impl StorageIndex {
    pub fn new(filename: &str, fieldname: &str) -> Self {
        Self {
            filename: filename.to_string(),
            fieldname: fieldname.to_string(),
            key_list: HashMap::new(),
            write_ptr: 0,
            header: Header::new(),
        }
    }

    pub fn append(&mut self, field: Field, ptr: u32) {
        if let Some(key) = self.key_list.get_mut(&field) {
            key.push(ptr);
        } else {
            self.key_list.insert(field, vec![ptr]);
        }

        self.write_ptr += 1;
    }

    pub fn save(&mut self) -> Result<()> {
        println!("Saving index for: {}", self.fieldname);

        let mut writer = BufWriter::new(File::create(&self.filename)?);

        // Write the header of the index
        writer.write_all(&self.header.to_binary())?;

        writer.write_u16::<BigEndian>(self.fieldname.len() as u16)?;
        writer.write_all(&self.fieldname.clone().into_bytes())?;

        // Write the index to disk
        let mut buffer: Vec<u8> = Vec::new();
        let mut value_buffer: Vec<u8> = Vec::new();
        for (key, values) in self.key_list.iter() {
            // println!("INDEX Key: {key}, Value: {:?}", values);

            value_buffer.write_all(&key.field_to_binary())?;

            for v in values {
                value_buffer.write_u32::<BigEndian>(*v)?;
            }

            buffer.write_u32::<BigEndian>(value_buffer.len() as u32)?;
            buffer.write_all(&value_buffer)?;

            value_buffer.clear();
        }
        writer.write_all(&buffer)?;

        Ok(())
    }
}
