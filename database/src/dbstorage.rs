use anyhow::Result;
use frame::field_type;
use frame::pfield::Field;
use frame::serialize_field::SerializeField;
use std::time::Instant;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};

#[derive(Clone)]
pub struct Row {
    pub row: Vec<Field>,
}

impl Row {
    pub fn new() -> Self {
        Self { row: Vec::new() }
    }

    pub fn add(&mut self, field: Field) {
        self.row.push(field);
    }
}

#[derive(Debug)]
pub struct FieldDefinition {
    pub ftype: u16,
    pub type_len: u16,
    pub name: String,
}

impl FieldDefinition {
    pub fn new(ftype: u16, name: String) -> Self {
        Self {
            ftype,
            type_len: field_type::get_type_len(ftype),
            name,
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

pub struct DBStorage {
    filename: String,
    magic_no: u32,
    version: u16,
    options: u16,
    fields_list: Vec<FieldDefinition>,
}

impl DBStorage {
    pub fn new(filename: String) -> Self {
        Self {
            filename,
            magic_no: 0xa1b2c3d4,
            version: 1,
            options: 0,
            fields_list: Vec::new(),
        }
    }

    pub fn define_fields(&mut self, fields: Vec<FieldDefinition>) {
        self.fields_list = fields;
    }

    fn read_header(&mut self) -> Result<()> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut reader = BufReader::new(File::open(&self.filename)?);

        buffer.resize(4, 0);
        reader.read_exact(&mut buffer)?;
        self.magic_no = BigEndian::read_u32(&buffer);

        buffer.resize(2, 0);
        reader.read_exact(&mut buffer)?;
        self.version = BigEndian::read_u16(&buffer);

        reader.read_exact(&mut buffer)?;
        self.options = BigEndian::read_u16(&buffer);

        reader.read_exact(&mut buffer)?;
        let header_size = BigEndian::read_u16(&buffer);

        reader.read_exact(&mut buffer)?;
        let nbr_fields = BigEndian::read_u16(&buffer);

        for i in 0..nbr_fields {
            buffer.resize(2, 0);
            reader.read_exact(&mut buffer)?;
            let ftype = BigEndian::read_u16(&buffer);

            // reader.read_exact(&mut buffer)?;
            // let flen = BigEndian::read_u16(&buffer);

            reader.read_exact(&mut buffer)?;
            let fname_len = BigEndian::read_u16(&buffer);

            buffer.resize(fname_len as usize, 0);
            reader.read_exact(&mut buffer)?;
            let fname = str::from_utf8(&buffer)?.to_string();

            println!(
                "{}:Type: {}, Header size: {}, Field name: {}",
                i, ftype, header_size, fname
            );

            let field = FieldDefinition::new(ftype, fname);

            println!("FIELD: {:?}", field);
        }

        Ok(())
    }

    pub fn read_record(&mut self) -> Result<()> {
        self.read_header()?;

        Ok(())
    }

    pub fn create(&mut self) -> Result<()> {
        let mut writer = BufWriter::new(File::create(&self.filename)?);
        let mut buffer: Vec<u8> = Vec::new();

        //--- Write header
        writer.write_u32::<BigEndian>(self.magic_no)?;
        writer.write_u16::<BigEndian>(self.version)?;
        writer.write_u16::<BigEndian>(self.options)?;

        buffer.write_u16::<BigEndian>(self.fields_list.len() as u16)?;

        for f in &self.fields_list {
            buffer.write(&f.to_binary())?;
        }

        writer.write_u16::<BigEndian>(buffer.len() as u16)?;
        writer.write_all(&buffer)?;

        Ok(())
    }

    pub fn append(&mut self, data: Vec<Row>) -> Result<()> {
        let start = Instant::now();
        let mut writer = BufWriter::new(
            fs::OpenOptions::new()
                // .create(true)
                .append(true)
                .open(&self.filename)
                .unwrap(),
        );

        for row in &data {
            for f in &row.row {
                writer.write(&f.field_to_binary())?;
            }
        }

        let duration = start.elapsed();

        println!(
            "Execution time: {}us per row: {}ns",
            duration.as_micros(),
            (duration.as_secs_f32() / data.len() as f32) * 1_000_000_000.0
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_db_insert() {
        let mut dbnode = DbSegment::new("/opt/pcapdb/test.db".to_string(), 0);

        dbnode.create().unwrap();
        dbnode.add_record().unwrap();
        assert_eq!(true, true, "Command options");
    }
}
