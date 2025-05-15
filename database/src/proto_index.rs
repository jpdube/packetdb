use crate::config::CONFIG;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Write;

struct ProtoHeader {
    magic_no: u32,
    version: u16,
    options: u16,
    count: u32,
}

pub struct ProtoIndex {
    header: ProtoHeader,
    ptr_list: Vec<u8>,
    proto_id: u32,
    file_id: u32,
}

impl ProtoIndex {
    pub fn new() -> Self {
        Self {
            header: ProtoHeader {
                magic_no: 0xa1b2c3d4,
                version: 1,
                options: 0,
                count: 0,
            },
            file_id: 0,
            proto_id: 128,
            ptr_list: Vec::new(),
        }
    }

    pub fn create_index(&mut self, ptr_list: &Vec<u32>) {
        let idx_filename = &format!(
            "{}/{}_{}.pidx",
            &CONFIG.index_path, self.file_id, self.proto_id
        );

        let mut writer = BufWriter::new(File::create(idx_filename).unwrap());

        //--- Write header
        writer.write_u32::<BigEndian>(self.header.magic_no).unwrap();
        writer.write_u16::<BigEndian>(self.header.version).unwrap();
        writer.write_u16::<BigEndian>(self.header.options).unwrap();
        writer
            .write_u32::<BigEndian>(ptr_list.len() as u32)
            .unwrap();

        //--Write ptr list
        for ptr in ptr_list {
            writer.write_u32::<BigEndian>(*ptr).unwrap();
        }
    }
}
