use byteorder::{BigEndian, ByteOrder};
use frame::packet::Packet;
use std::fs::File;
use std::io::{BufReader, Read};

pub struct PcapFile {
    _filename: String,
    file: BufReader<File>,
    // file: File,
    header_read: bool,
    pkt_ptr: u32,
    file_id: u32,
}

impl PcapFile {
    pub fn new(file_id: u32, db_path: &str) -> Self {
        // println!("Filename: {}", file_id);
        let fname = &format!("{}/{}.pcap", db_path, file_id);
        Self {
            _filename: fname.to_owned(),
            file_id,
            file: BufReader::new(File::open(fname).unwrap()),
            header_read: false,
            pkt_ptr: 0,
        }
    }

    pub fn next(&mut self) -> Option<Packet> {
        let mut gheader = [0; 24];
        let mut pheader = [0; 16];
        let mut data = Vec::new();

        let psize: usize;

        if !self.header_read {
            self.file.read_exact(&mut gheader).unwrap();
            self.header_read = true;
            self.pkt_ptr += 24;
        }

        if !self.file.read_exact(&mut pheader).is_ok() {
            return None;
        }

        psize = BigEndian::read_u32(&pheader[12..16]) as usize;
        data.resize(psize, 0);
        self.file.read_exact(&mut data).unwrap();

        let mut pkt = Packet::new();
        pkt.set_packet(data, pheader, self.file_id, self.pkt_ptr);
        self.pkt_ptr += 16 + (psize as u32);

        Some(pkt)
    }
}
