use byteorder::{BigEndian, ByteOrder, LittleEndian};
use frame::packet::Packet;
use memmap2::Mmap;
use std::fs::File;

const HEADER_BE: u32 = 0xa1b2c3d4;
const HEADER_LE: u32 = 0xd4c3b2a1;

pub struct PcapFile {
    _filename: String,
    file: Mmap,
    // file: BufReader<File>,
    header_read: bool,
    pkt_ptr: usize,
    file_id: u32,
    magic_no: u32,
}

impl PcapFile {
    pub fn new(file_id: u32, db_path: &str) -> Self {
        let fname = &format!("{}/{}.pcap", db_path, file_id);

        let file = File::open(fname).unwrap();
        let mmap = unsafe { Mmap::map(&file).unwrap() };

        let mut _self = Self {
            _filename: fname.to_owned(),
            file_id,
            file: mmap,
            // file: BufReader::new(File::open(fname).unwrap()),
            header_read: false,
            pkt_ptr: 0,
            magic_no: HEADER_LE,
        };

        _self
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Packet> {
        let mut little_endian: bool = true;

        let psize: usize;

        if !self.header_read {
            self.header_read = true;
            self.pkt_ptr += 24;
            self.magic_no = BigEndian::read_u32(&self.file[0..4]);
        }

        if self.pkt_ptr >= self.file.len() {
            return None;
        }

        //--- Must determine what to do when psize is zero. The file pointer will
        //--- not advance and we will spin on our self
        match self.magic_no {
            HEADER_LE => {
                psize = LittleEndian::read_u32(&self.file[self.pkt_ptr + 12..self.pkt_ptr + 16])
                    as usize;
                little_endian = true;
            }
            HEADER_BE => {
                psize =
                    BigEndian::read_u32(&self.file[self.pkt_ptr + 12..self.pkt_ptr + 16]) as usize;
                little_endian = false;
            }
            _ => {
                psize = LittleEndian::read_u32(&self.file[self.pkt_ptr + 12..self.pkt_ptr + 16])
                    as usize
            }
        }

        // data.resize(psize, 0);
        // self.file.read_exact(&mut data).unwrap();

        let mut pkt = Packet::new();
        pkt.set_packet(
            self.file[self.pkt_ptr + 16..self.pkt_ptr + 16 + psize].to_vec(),
            self.file[self.pkt_ptr..self.pkt_ptr + 16].to_vec(),
            self.file_id,
            self.pkt_ptr as u32,
            little_endian,
        );
        self.pkt_ptr += 16 + psize;

        Some(pkt)
    }

    pub fn seek(&mut self, ptr: u32) -> Option<Packet> {
        let mut little_endian: bool = true;

        let psize: usize;
        let index: usize = ptr as usize;

        if !self.header_read {
            self.header_read = true;
            self.pkt_ptr += 24;
            self.magic_no = BigEndian::read_u32(&self.file[0..4]);
        }

        // let _ = self.file.seek(seekfrom::start(ptr as u64));
        // if self.file.read_exact(&mut pheader).is_err() {
        //     return None;
        // }

        //--- Must determine what to do when psize is zero. The file pointer will
        //--- not advance and we will spin on our self
        match self.magic_no {
            HEADER_LE => {
                psize = LittleEndian::read_u32(&self.file[index + 12..index + 16]) as usize;
                little_endian = true;
            }
            HEADER_BE => {
                psize = BigEndian::read_u32(&self.file[index + 12..index + 16]) as usize;
                little_endian = false;
            }
            _ => psize = LittleEndian::read_u32(&self.file[index + 12..index + 16]) as usize,
        }

        // data.resize(psize, 0);
        // self.file.read_exact(&mut data).unwrap();

        let mut pkt = Packet::new();
        pkt.set_packet(
            self.file[index + 16..index + 16 + psize].to_vec(),
            self.file[index..index + 16].to_vec(),
            self.file_id,
            ptr,
            little_endian,
        );
        // self.pkt_ptr += 16 + (psize as u32);

        Some(pkt)
    }
}
