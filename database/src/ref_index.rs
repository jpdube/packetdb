use crate::config;
use byteorder::ReadBytesExt;
use byteorder::{BigEndian, WriteBytesExt};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;

#[derive(Default)]
pub struct RefIndex {
    hash_index: HashMap<u32, Vec<u32>>,
    file_id: u32,
}

impl RefIndex {
    pub fn new(file_id: u32) -> Self {
        Self {
            hash_index: HashMap::new(),
            file_id,
        }
    }

    pub fn add_key(&mut self, pkt_index: u32, pkt_ptr: u32) {
        if self.hash_index.get(&pkt_index).is_none() {
            self.hash_index.insert(pkt_index, Vec::new());
        }

        self.hash_index.get_mut(&pkt_index).unwrap().push(pkt_ptr);
    }

    pub fn write_index(&self) {
        for key in self.hash_index.keys() {
            if let Some(ptr) = self.hash_index.get(key) {
                let idx_filename = &format!(
                    "{}/{}_{:x}.ridx",
                    &config::CONFIG.ref_index_path,
                    self.file_id,
                    key
                );
                let mut writer = BufWriter::new(File::create(idx_filename).unwrap());
                writer.write_u32::<BigEndian>(ptr.len() as u32).unwrap();
                for index in ptr {
                    writer.write_u32::<BigEndian>(*index).unwrap();
                }
            }
        }
    }

    pub fn read_index(&mut self, index: u32) -> Vec<u32> {
        let idx_filename = &format!(
            "{}/{}_{:x}.ridx",
            &config::CONFIG.ref_index_path,
            self.file_id,
            index
        );

        println!("Ref index opening file: {idx_filename}");

        let mut index_value: u32;
        let mut index_list: Vec<u32> = Vec::new();

        let mut file = BufReader::new(File::open(idx_filename).unwrap());

        if let Ok(index_size) = file.read_u32::<BigEndian>() {
            for _ in 0..index_size {
                index_value = file.read_u32::<BigEndian>().unwrap();

                index_list.push(index_value);
            }
        }

        index_list
    }

    pub fn print(&self) {
        for key in self.hash_index.keys() {
            println!(
                "Index: file_id: {} Keys: {:x?}, Key len: {}, Ptr len: {}, Ptr: {:?}",
                self.file_id,
                key,
                self.hash_index.keys().len(),
                self.hash_index.get(key).unwrap().len(),
                self.hash_index.get(key).unwrap(),
            );
        }
    }
}
