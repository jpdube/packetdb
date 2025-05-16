use crate::config::CONFIG;
use byteorder::ByteOrder;
use byteorder::{BigEndian, WriteBytesExt};
use std::fs;
use std::fs::File;
use std::io::BufWriter;
use std::io::Seek;
use std::io::Write;
use std::io::{BufReader, Read};

struct ProtoHeader {
    magic_no: u32,
    version: u16,
    options: u16,
    count: u32,
}

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

    pub fn add(&mut self, ptr: &u32) {
        self.ptr_list.push(*ptr);
    }

    fn update_count(&mut self) {
        let idx_filename = &format!(
            "{}/{}_{}.pidx",
            &CONFIG.index_path, self.file_id, self.proto_id
        );

        let mut reader = BufReader::new(File::open(idx_filename).unwrap());
        let mut buffer = [0; 4];
        reader.seek(std::io::SeekFrom::Start(8)).unwrap();
        reader.read_exact(&mut buffer).unwrap();
        let file_count = BigEndian::read_u32(&buffer);

        self.header.count = file_count + self.ptr_list.len() as u32;

        let mut writer = BufWriter::new(File::open(idx_filename).unwrap());
        writer.seek(std::io::SeekFrom::Start(8)).unwrap();
        writer.write_u32::<BigEndian>(self.header.count).unwrap();
    }

    pub fn append(&mut self) {
        let idx_filename = &format!(
            "{}/{}_{}.pidx",
            &CONFIG.index_path, self.file_id, self.proto_id
        );
        let mut writer = fs::OpenOptions::new()
            // .create(true)
            .append(true)
            .open(idx_filename)
            .unwrap();

        for ptr in &self.ptr_list {
            writer.write_u32::<BigEndian>(*ptr).unwrap();
        }

        self.update_count();
    }

    pub fn create_index(&mut self) {
        let idx_filename = &format!(
            "{}/{}_{}.pidx",
            &CONFIG.index_path, self.file_id, self.proto_id
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
