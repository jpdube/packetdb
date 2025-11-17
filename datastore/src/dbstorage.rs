use anyhow::Result;
use field::field_type;
use field::pfield::Field;
use field::pfield::FieldType;
use field::serialize_field::SerializeField;
use std::time::Instant;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, Write};

use crate::schema::Schema;
use crate::storage_index::StorageIndex;

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

pub struct DBStorage {
    filename: String,
    magic_no: u32,
    version: u16,
    options: u16,
    fields_list: Vec<Schema>,
    header_size: u16,
    data_ptr: usize,
    index: StorageIndex,
}

impl DBStorage {
    pub fn new(filename: &str, index_name: &str) -> Self {
        Self {
            filename: format!("{}.{}", filename, "pdb"),
            magic_no: 0xa1b2c3d4,
            version: 1,
            options: 0,
            fields_list: Vec::new(),
            header_size: 0,
            data_ptr: 0,
            index: StorageIndex::new(&format!("{}_{}.idx", filename, index_name), index_name),
        }
    }

    pub fn define_fields(&mut self, fields: Vec<Schema>) {
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
        self.header_size = BigEndian::read_u16(&buffer);
        self.data_ptr = self.header_size as usize + 10;

        reader.read_exact(&mut buffer)?;
        let nbr_fields = BigEndian::read_u16(&buffer);

        self.fields_list.clear();
        for _ in 0..nbr_fields {
            buffer.resize(2, 0);
            reader.read_exact(&mut buffer)?;
            let ftype = BigEndian::read_u16(&buffer);

            reader.read_exact(&mut buffer)?;
            let fname_len = BigEndian::read_u16(&buffer);

            buffer.resize(fname_len as usize, 0);
            reader.read_exact(&mut buffer)?;
            let fname = str::from_utf8(&buffer)?;

            let field = Schema::new(ftype, fname);
            self.fields_list.push(field);
        }
        println!("FIELD: {:#?}", self.fields_list);

        Ok(())
    }

    pub fn read_record(&mut self) -> Result<()> {
        if self.header_size == 0 {
            self.read_header()?;
        }

        let mut reader = BufReader::new(File::open(&self.filename)?);
        let mut buffer: Vec<u8> = Vec::new();
        let mut offset: usize;
        let mut field_len: usize;
        let mut rec_count: usize = 0;

        reader.seek_relative(self.data_ptr as i64)?;

        while let Ok(rec_size) = reader.read_u16::<BigEndian>() {
            buffer.resize(rec_size as usize, 0);
            reader.read_exact(&mut buffer)?;
            offset = 0;
            rec_count += 1;

            // println!("RECORD: {:x?}", &buffer);

            for field_def in &self.fields_list {
                if field_def.ftype == field_type::STRING {
                    field_len = BigEndian::read_u16(&buffer[offset..offset + 2]) as usize;
                    offset += 2;
                } else {
                    field_len = field_def.type_len as usize;
                }

                let field = Field::from_binary_to_field(
                    field_def.ftype,
                    &field_def.name,
                    buffer[offset..(offset + field_len)].to_vec(),
                );

                println!("Field read: {field}");

                offset += field_len;
            }
            println!("---------------------------------");
        }

        println!("READ {rec_count} Records");
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
        let fs = fs::OpenOptions::new().append(true).open(&self.filename)?;

        let mut writer = BufWriter::new(fs);

        let mut buffer: Vec<u8> = Vec::new();
        writer.seek(std::io::SeekFrom::End(0))?;
        for (index, row) in data.iter().enumerate() {
            buffer.clear();
            for f in &row.row {
                buffer.write(&f.field_to_binary())?;
            }
            let ptr = writer.stream_position()?;
            writer.write_u16::<BigEndian>(buffer.len() as u16)?;
            writer.write_all(&buffer)?;

            // let ptr = writer.stream_position()?;
            println!("Record PTR: {ptr}:{ptr:x}");
            if index % 2 == 0 {
                self.index.append(
                    Field::set_field(FieldType::Ipv4(0xc0a80311, 32), "ip.src"),
                    ptr as u32,
                );
            } else {
                self.index.append(
                    Field::set_field(FieldType::Ipv4(0xc0a8ea01, 32), "ip.src"),
                    ptr as u32,
                );
            }
        }

        self.index.save()?;

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
        assert_eq!(true, true, "Command options");
    }
}
