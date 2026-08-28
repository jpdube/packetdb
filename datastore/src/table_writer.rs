use anyhow::Result;
use field::serialize_field::SerializeField;

use byteorder::{BigEndian, WriteBytesExt};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufWriter, Seek, Write};

use crate::record::Record;
use crate::schema::Schema;
use crate::table_index::TableIndex;

// use memmap2::MmapMut;
use std::fs::OpenOptions;

use rayon::prelude::*;

const BLOCK_SIZE: usize = 1024;

pub struct DBTableWriter {
    filename: String,
    table_name: String,
    magic_no: u32,
    version: u16,
    options: u16,
    fields_list: Vec<Schema>,
    index_list: Vec<TableIndex>,
    record_list: VecDeque<Record>,
    // writer: MmapMut,
    writer: BufWriter<File>,
}

impl DBTableWriter {
    pub fn new(filename: &str) -> Self {
        let filename_str = format!("{}.{}", filename, "pdb");
        println!("Opening: {}", filename_str);
        // let file = OpenOptions::new()
        //     .read(true)
        //     .write(true)
        //     .create(true)
        //     // .truncate(true)
        //     .open(&filename_str)
        //     .unwrap();
        //
        // Set the file size
        // file.set_len(100 * (1024 * 1024)).unwrap();

        // SAFETY: We have exclusive access to the file
        // let mmap = unsafe { MmapMut::map_mut(&file).unwrap() };

        let writer = BufWriter::with_capacity(
            1024 * 1024,
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(&filename_str)
                .unwrap(),
        );

        let _self = Self {
            filename: filename_str.clone(),
            table_name: filename.to_string(),
            magic_no: 0xa1b2c3d4,
            version: 1,
            options: 0,
            fields_list: Vec::new(),
            index_list: Vec::new(),
            record_list: VecDeque::new(),
            writer: writer,
            // writer: mmap,
            // writer: BufWriter::with_capacity(
            //     1024 * 1024,
            //     fs::OpenOptions::new()
            //         .create(true)
            //         .append(true)
            //         .open(&filename_str)
            //         .unwrap(),
            // ),
        };

        _self
    }

    pub fn append(&mut self) -> Result<()> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut record: Vec<u8> = Vec::new();

        self.writer.seek(std::io::SeekFrom::End(0))?;

        let max_len = if self.record_list.len() < BLOCK_SIZE {
            self.record_list.len()
        } else {
            BLOCK_SIZE
        };

        for _ in 0..max_len - 1 {
            let ptr = self.writer.stream_position()?;
            buffer.clear();
            if let Some(row) = &self.record_list.pop_front() {
                for f in row.get_fields() {
                    buffer.write_all(&f.field_to_binary())?;
                }

                record.write_u16::<BigEndian>(buffer.len() as u16)?;
                record.write_all(&buffer)?;
                // self.writer.write_u16::<BigEndian>(buffer.len() as u16)?;
                // self.writer.write_all(&buffer)?;

                // self.writer.write_u16::<BigEndian>(buffer.len() as u16)?;
                // self.writer.write_all(&buffer)?;

                for idx in &mut self.index_list {
                    idx.append(row.clone(), ptr as u32);
                }
            }
        }

        self.writer.write_all(&record)?;

        Ok(())
    }

    // pub fn append(&mut self) -> Result<()> {
    //     let mut buffer: Vec<u8> = Vec::new();
    //     self.writer.seek(std::io::SeekFrom::End(0))?;

    //     let max_len = if self.record_list.len() < BLOCK_SIZE {
    //         self.record_list.len()
    //     } else {
    //         BLOCK_SIZE
    //     };

    //     self.writer[0] = 1;

    //     for _ in 0..max_len - 1 {
    //         let ptr = self.writer.stream_position()?;
    //         buffer.clear();
    //         if let Some(row) = &self.record_list.pop_front() {
    //             for f in row.get_fields() {
    //                 buffer.write_all(&f.field_to_binary())?;
    //             }

    //             self.writer.write_u16::<BigEndian>(buffer.len() as u16)?;
    //             self.writer.write_all(&buffer)?;

    //             for idx in &mut self.index_list {
    //                 idx.append(row.clone(), ptr as u32);
    //             }
    //         }
    //     }

    //     Ok(())
    // }
    pub fn add_record(&mut self, record: Record) -> Result<()> {
        if self.record_list.len() >= 2048 {
            self.append()?;

            Ok(())
        } else {
            self.record_list.push_back(record);
            Ok(())
        }
    }

    pub fn flush(&mut self) -> Result<()> {
        self.append()?;
        let _result: Vec<Result<(), anyhow::Error>> = self
            .index_list
            .clone()
            .into_par_iter()
            .map(|mut idx| idx.save())
            .collect();

        // println!("Save index result: {:?}", result);

        Ok(())
    }

    pub fn define_fields(&mut self, fields: Vec<Schema>) {
        self.fields_list = fields;
    }

    fn create_index(&mut self, index: Vec<Schema>) {
        for idx in index {
            let tbl = TableIndex::new(&self.table_name, &idx);
            self.index_list.push(tbl);
        }
    }

    pub fn create_table(&mut self, fields: Vec<Schema>, index: Vec<Schema>) -> Result<()> {
        self.create_index(index);
        self.fields_list = fields;
        self.record_list.clear();

        self.create()?;

        Ok(())
    }

    fn create(&mut self) -> Result<()> {
        let mut writer = BufWriter::new(File::create(&self.filename)?);
        let mut buffer: Vec<u8> = Vec::new();

        //--- Write header
        writer.write_u32::<BigEndian>(self.magic_no)?;
        writer.write_u16::<BigEndian>(self.version)?;
        writer.write_u16::<BigEndian>(self.options)?;

        buffer.write_u16::<BigEndian>(self.fields_list.len() as u16)?;

        for f in &self.fields_list {
            buffer.write_all(&f.into_bytes()?)?;
        }

        writer.write_u16::<BigEndian>(buffer.len() as u16)?;
        writer.write_all(&buffer)?;

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
