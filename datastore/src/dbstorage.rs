use anyhow::Result;
use field::field_type;
use field::pfield::Field;
use field::serialize_field::SerializeField;
use std::time::Instant;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
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
pub struct Schema {
    pub ftype: u16,
    pub type_len: u16,
    pub name: String,
}

impl Schema {
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
    fields_list: Vec<Schema>,
    header_size: u16,
    data_ptr: usize,
}

impl DBStorage {
    pub fn new(filename: String) -> Self {
        Self {
            filename,
            magic_no: 0xa1b2c3d4,
            version: 1,
            options: 0,
            fields_list: Vec::new(),
            header_size: 0,
            data_ptr: 0,
        }
    }

    pub fn define_fields(&mut self, fields: Vec<Schema>) {
        self.fields_list = fields;
    }

    // fn record_size(&self) -> usize {
    //     let mut count = 0;

    //     for f in &self.fields_list {
    //         count += f.type_len as usize
    //     }

    //     count
    // }

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

            // reader.read_exact(&mut buffer)?;
            // let flen = BigEndian::read_u16(&buffer);

            reader.read_exact(&mut buffer)?;
            let fname_len = BigEndian::read_u16(&buffer);

            buffer.resize(fname_len as usize, 0);
            reader.read_exact(&mut buffer)?;
            let fname = str::from_utf8(&buffer)?.to_string();

            // println!(
            //     "{}:Type: {}, Header size: {}, Field name: {}",
            //     i, ftype, header_size, fname
            // );

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

                // println!(
                //     "RECORD: {:x?}",
                //     Field::from_binary_to_field(
                //         field_def.ftype,
                //         field_def.name.clone(),
                //         buffer[offset..offset + field_len].to_vec()
                //     )
                // );

                offset += field_len;
            }
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
        let mut writer = BufWriter::new(
            fs::OpenOptions::new()
                // .create(true)
                .append(true)
                .open(&self.filename)
                .unwrap(),
        );

        let mut buffer: Vec<u8> = Vec::new();
        for row in &data {
            buffer.clear();
            for f in &row.row {
                buffer.write(&f.field_to_binary())?;
            }
            writer.write_u16::<BigEndian>(buffer.len() as u16)?;
            writer.write_all(&buffer)?;
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
