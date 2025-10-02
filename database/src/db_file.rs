use crate::config::CONFIG;
use byteorder::{BigEndian, ByteOrder};
use frame::pfield::Field;
use frame::to_binary::ToBinary;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::time::Instant;

use anyhow::Result;

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

        header
    }
}

#[derive(Debug)]
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

    fn db_filename(&self) -> String {
        format!("{}/{}.pdb", &CONFIG.db_path, self.file_name)
    }

    pub fn create_file(&mut self) -> Result<()> {
        println!("Writing to file: {}", self.db_filename());

        let file = File::create(self.db_filename())?;
        let mut writer = BufWriter::new(file);

        self.header.nbr_fields = self.fields_list.len() as u16;

        writer.write_all(&self.header.write_header())?;

        Ok(())
    }

    pub fn append(&mut self) -> Result<()> {
        let fs = OpenOptions::new()
            // .create(true)
            .append(true)
            .open(self.db_filename())
            .unwrap();

        let mut writer = BufWriter::new(fs);

        let now = Instant::now();

        for f in &self.fields_list {
            writer.write(&f.field_def_to_binary())?;
        }

        for f in &self.fields_list {
            writer.write(&f.field_to_binary())?;
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
