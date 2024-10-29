use byteorder::BigEndian;
use byteorder::{ByteOrder, LittleEndian};
use frame::packet::Packet;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

use crate::config;
use crate::packet_ptr::PacketPtr;

const HEADER_BE: u32 = 0xa1b2c3d4;
const HEADER_LE: u32 = 0xd4c3b2a1;

pub struct SeekPacket {
    file: BufReader<File>,
    index: usize,
    plist: PacketPtr,
    data: Vec<u8>,
    relative_ptr: u64,
    psize: usize,
    magic_no: u32,
}

impl SeekPacket {
    pub fn new(packet_list: PacketPtr) -> Self {
        let fname = &format!("{}/{}.pcap", config::CONFIG.db_path, packet_list.file_id);

        let mut magic_file = BufReader::new(File::open(fname).unwrap());
        let mut gheader = [0; 24];
        let magic_no: u32;
        if magic_file.read_exact(&mut gheader).is_ok() {
            magic_no = BigEndian::read_u32(&gheader[0..4]);
        } else {
            magic_no = HEADER_LE
        }

        let self_conf = Self {
            file: BufReader::new(File::open(fname).unwrap()),
            index: 0,
            plist: packet_list,
            data: Vec::new(),
            relative_ptr: 0,
            psize: 0,
            magic_no,
        };

        self_conf
    }

    pub fn next(&mut self) -> Option<Packet> {
        if self.index >= self.plist.pkt_ptr.len() || self.plist.pkt_ptr.len() == 0 {
            return None;
        }

        let mut pheader = [0; 16];
        let ptr = self.plist.pkt_ptr[self.index] as u64 - self.relative_ptr;

        self.file.seek_relative(ptr as i64).unwrap();

        if !self.file.read_exact(&mut pheader).is_ok() {
            return None;
        }

        //--- Must determine what to do when psize is zero. The file pointer will
        //--- not advance and we will spin on our self
        match self.magic_no {
            HEADER_LE => self.psize = LittleEndian::read_u32(&pheader[12..16]) as usize,
            HEADER_BE => self.psize = BigEndian::read_u32(&pheader[12..16]) as usize,
            _ => self.psize = 0,
        }

        // self.psize = BigEndian::read_u32(&pheader[12..16]) as usize;
        self.data.resize(self.psize, 0);
        self.file.read_exact(&mut self.data).unwrap();
        self.relative_ptr = self.file.stream_position().unwrap();

        let mut pkt = Packet::new();
        pkt.set_packet(
            self.data.clone(),
            pheader,
            self.plist.file_id,
            self.plist.pkt_ptr[self.index] as u32,
        );
        self.index += 1;

        Some(pkt)
    }

    pub fn next_chunk(&mut self, count: usize) -> Option<Vec<Packet>> {
        let mut result: Vec<Packet> = Vec::new();

        while let Some(pkt) = self.next() {
            if result.len() < count {
                result.push(pkt);
            } else {
                return Some(result);
            }
        }

        None
    }
}
