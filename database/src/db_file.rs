use crate::config::CONFIG;
use byteorder::{BigEndian, ByteOrder};
use frame::pfield::{Field, FieldType};
use frame::to_binary::ToBinary;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use anyhow::Result;
// #[derive(Debug, Clone)]
// pub struct Field {
//     ftype: u16,
//     fname_len: u16,
//     fname: String,
//     no: u16,
// }

// impl Field {
//     pub fn write_fields(&self) -> Vec<u8> {
//         let mut fields: Vec<u8> = Vec::new();

//         BigEndian::write_u16(&mut fields, self.no);
//         BigEndian::write_u16(&mut fields, self.ftype);
//         BigEndian::write_u16(&mut fields, self.fname_len);

//         fields.append(&mut self.fname.clone().into_bytes());

//         fields
//     }
// }

#[derive(Debug, Clone)]
pub struct Header {
    magic_no: u32,
    version: u16,
    nbr_fields: u16,
}

impl Header {
    pub fn new() -> Self {
        Self {
            magic_no: 0xc3d4e5f6,
            version: 1,
            nbr_fields: 0,
        }
    }

    fn write_header(&self) -> [u8; 8] {
        let mut header: [u8; 8] = [0; 8];

        BigEndian::write_u32(&mut header[0..4], self.magic_no);
        BigEndian::write_u16(&mut header[4..6], self.version);
        BigEndian::write_u16(&mut header[6..8], self.nbr_fields);

        // println!("HEADER: {:x?}", header);
        header
    }
}

#[derive(Debug, Clone)]
pub struct DBFile {
    fields_list: Vec<Field>,
    header: Header,
    file_name: String,
}

impl DBFile {
    pub fn new(file_name: String) -> Self {
        Self {
            fields_list: Vec::new(),
            header: Header::new(),
            file_name,
        }
    }

    #[allow(dead_code)]
    pub fn add_record(&mut self, _record: Vec<u8>) {}

    pub fn create_file(&mut self) -> Result<()> {
        let db_filename = &format!("{}/{}.pdb", &CONFIG.db_path, self.file_name);
        println!("Writing to file: {}", db_filename);

        let file = File::create(db_filename)?;
        let mut writer = BufWriter::new(file);

        // writer.write(&self.write_fields()).unwrap();
        self.fields_list.push(Field::set_field(
            FieldType::Ipv4(0xc0a80301, 32),
            "ip.src".to_string(),
        ));

        self.fields_list.push(Field::set_field(
            FieldType::Ipv4(0xc0a802b6, 32),
            "ip.dst".to_string(),
        ));

        self.fields_list.push(Field::set_field(
            FieldType::Int16(443),
            "tcp.dport".to_string(),
        ));

        self.fields_list.push(Field::set_field(
            FieldType::Int16(1443),
            "tcp.sport".to_string(),
        ));

        self.header.nbr_fields = self.fields_list.len() as u16;

        let now = Instant::now();
        writer.write(&self.header.write_header())?;

        for f in &self.fields_list {
            writer.write(&f.field_def_to_binary())?;
        }

        for _ in 0..8_000_000 {
            for f in &self.fields_list {
                writer.write(&f.field_to_binary())?;
            }
        }

        let elapsed = now.elapsed();
        println!("Elapsed: {:.2?}", elapsed);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_db_file() {
        let mut db_file = DBFile::new("test_db".to_string());
        db_file.create_file().unwrap();
    }
}
