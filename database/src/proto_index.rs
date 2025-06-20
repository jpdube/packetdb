use crate::config::CONFIG;
use anyhow::{anyhow, Result};
use byteorder::ByteOrder;
use byteorder::{BigEndian, WriteBytesExt};
use log::info;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Seek;
use std::io::{BufReader, Read};

#[derive(Clone)]
struct ProtoHeader {
    magic_no: u32,
    version: u16,
    options: u16,
    count: u32,
}

#[derive(Clone)]
pub struct ProtoIndex {
    header: ProtoHeader,
    ptr_list: Vec<u32>,
    proto_id: u32,
    file_id: u32,
}

impl ProtoIndex {
    pub fn new(file_id: u32, proto_id: u32) -> Self {
        Self {
            header: ProtoHeader {
                magic_no: 0xa1b2c3d4,
                version: 1,
                options: 0,
                count: 0,
            },
            file_id,
            proto_id,
            ptr_list: Vec::new(),
        }
    }

    pub fn read(&mut self) -> Result<Vec<u32>> {
        let idx_filename = &format!(
            "{}/{}_{:x}.pidx",
            &CONFIG.proto_index_path, self.file_id, self.proto_id
        );

        info!("Loading proto index file: {}", idx_filename);

        let mut result: Vec<u32> = Vec::new();

        let file = File::open(idx_filename)?;
        let mut reader = BufReader::new(file);
        let mut buffer: Vec<u8> = Vec::new();

        buffer.resize(4, 0);
        reader.read_exact(&mut buffer)?;
        self.header.magic_no = BigEndian::read_u32(&buffer);

        if self.header.magic_no != 0xa1b2c3d4 {
            return Err(anyhow!("Invalid magic no: {}", self.header.magic_no));
        }

        buffer.resize(2, 0);
        reader.read_exact(&mut buffer)?;
        self.header.version = BigEndian::read_u16(&buffer);
        if self.header.version != 0x01 {
            return Err(anyhow!(
                "Invalid version was expecting 1 read {}",
                self.header.version
            ));
        }

        buffer.resize(2, 0);
        reader.read_exact(&mut buffer)?;
        self.header.options = BigEndian::read_u16(&buffer);

        buffer.resize(4, 0);
        reader.read_exact(&mut buffer)?;
        self.header.count = BigEndian::read_u32(&buffer);
        info!(
            "Found {:x} packets in index {}_{:x}",
            self.header.count, self.file_id, self.proto_id,
        );

        buffer.resize(4, 0);
        for _ in 0..self.header.count {
            reader.read_exact(&mut buffer)?;
            result.push(BigEndian::read_u32(&buffer));
        }

        Ok(result)
    }

    pub fn add(&mut self, ptr: &u32) {
        self.ptr_list.push(*ptr);
    }

    pub fn clear(&mut self) {
        self.ptr_list.clear();
        self.header.count = 0;
    }

    fn update_count(&mut self) {
        let idx_filename = &format!(
            "{}/{}_{}.pidx",
            &CONFIG.proto_index_path, self.file_id, self.proto_id
        );

        {
            let file = File::open(idx_filename).unwrap();
            let mut reader = BufReader::new(file);
            let mut buffer = [0; 4];
            reader.seek(std::io::SeekFrom::Start(8)).unwrap();
            reader.read_exact(&mut buffer).unwrap();
            let file_count = BigEndian::read_u32(&buffer);
            self.header.count = file_count + self.ptr_list.len() as u32;
            println!("Index count: {}", file_count);
        }

        println!("Stored Index count: {}", self.header.count);

        {
            println!("Filename: {}", idx_filename);

            let mut writer = fs::OpenOptions::new()
                .write(true)
                .open(idx_filename)
                .unwrap();

            writer.seek(std::io::SeekFrom::Start(8)).unwrap();
            writer.write_u32::<BigEndian>(self.header.count).unwrap();
        }
    }

    pub fn append(&mut self) {
        let idx_filename = &format!(
            "{}/{}_{}.pidx",
            &CONFIG.proto_index_path, self.file_id, self.proto_id
        );

        {
            let mut writer = fs::OpenOptions::new()
                // .create(true)
                .append(true)
                .open(idx_filename)
                .unwrap();

            for ptr in &self.ptr_list {
                writer.write_u32::<BigEndian>(*ptr).unwrap();
            }
        }
        self.update_count();
    }

    pub fn create_index(&mut self) {
        let idx_filename = &format!(
            "{}/{}_{:x}.pidx",
            &CONFIG.proto_index_path, self.file_id, self.proto_id
        );

        self.header.count = self.ptr_list.len() as u32;
        let mut writer = BufWriter::new(File::create(idx_filename).unwrap());

        //--- Write header
        writer.write_u32::<BigEndian>(self.header.magic_no).unwrap();
        writer.write_u16::<BigEndian>(self.header.version).unwrap();
        writer.write_u16::<BigEndian>(self.header.options).unwrap();
        writer.write_u32::<BigEndian>(self.header.count).unwrap();

        //--Write ptr list
        for ptr in &self.ptr_list {
            writer.write_u32::<BigEndian>(*ptr).unwrap();
        }
    }
    pub fn test_append() {
        let mut proto_index = ProtoIndex::new(99_999_999, 128);

        for i in 0..10 {
            proto_index.add(&(i as u32));
        }

        proto_index.create_index();

        assert_eq!(proto_index.header.count, 10, "10 elements appended");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_append() {
        let mut proto_index = ProtoIndex::new(99_999_999, 128);

        for i in 0..10 {
            proto_index.add(&(i as u32));
        }

        proto_index.create_index();

        assert_eq!(proto_index.header.count, 10, "10 elements appended");
    }
}

pub struct ProtoIndexMgr {
    index_list: HashMap<u32, ProtoIndex>,
    file_id: u32,
}

impl ProtoIndexMgr {
    pub fn new(file_id: u32) -> Self {
        Self {
            index_list: HashMap::new(),
            file_id,
        }
    }

    fn add_index(&mut self, proto_id: u32) {
        let index = ProtoIndex::new(self.file_id, proto_id);

        self.index_list.insert(proto_id, index);
    }

    pub fn add(&mut self, proto_id: u32, ptr: u32) {
        if let Some(index) = self.index_list.get_mut(&proto_id) {
            index.add(&ptr);
        } else {
            self.add_index(proto_id);
        }
    }

    pub fn save(&mut self) {
        for (_, idx) in &mut self.index_list {
            idx.create_index();
        }
    }
}
