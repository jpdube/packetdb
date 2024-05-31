use crate::config;
use crate::pcapfile::PcapFile;
use crate::ref_index::RefIndex;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use frame::fields;
use frame::packet::Packet;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum IndexField {
    Ethernet = 0x01,
    Arp = 0x02,
    IpV4 = 0x04,
    Icmp = 0x08,
    Udp = 0x10,
    Tcp = 0x20,
    Dns = 0x40,
    Dhcp = 0x80,
    Https = 0x100,
    Http = 0x200,
    IpV6 = 0x400,
    Ssh = 0x800,
    Telnet = 0x1000,
}

#[derive(Default, Debug)]
pub struct MasterIndex {
    pub start_timestamp: u32,
    pub end_timestamp: u32,
    pub file_ptr: u32,
}

#[derive(Default, Debug)]
pub struct IndexManager {}

impl IndexManager {
    pub fn index_file(&self, filename: u32) -> MasterIndex {
        let mut pfile = PcapFile::new(filename, &config::CONFIG.db_path);
        let idx_filename = &format!("{}/{}.pidx", &config::CONFIG.index_path, filename);
        let mut writer = BufWriter::new(File::create(idx_filename).unwrap());
        let mut mindex = MasterIndex::default();
        let mut first_index = false;
        let mut ts: u32 = 0;
        let mut pkt_index: u32;
        let mut ref_index = RefIndex::new(filename);
        let mut pkt_counter: u32 = 0;

        while let Some(pkt) = pfile.next() {
            ts = pkt.get_field(fields::FRAME_TIMESTAMP) as u32;
            // println!("IP dst: {}", pkt.get_field(fields::IPV4_DST_ADDR));

            if !first_index {
                first_index = true;
                mindex.start_timestamp = ts
            }

            writer.write_u32::<BigEndian>(ts).unwrap();
            writer.write_u32::<BigEndian>(pkt.pkt_ptr).unwrap();

            pkt_index = self.build_index(&pkt);
            ref_index.add_key(pkt_index, pkt_counter);
            pkt_counter += 20;

            writer.write_u32::<BigEndian>(pkt_index).unwrap();

            writer
                .write_u32::<BigEndian>(pkt.get_field(fields::IPV4_DST_ADDR) as u32)
                .unwrap();
            writer
                .write_u32::<BigEndian>(pkt.get_field(fields::IPV4_SRC_ADDR) as u32)
                .unwrap();
        }

        mindex.end_timestamp = ts;
        mindex.file_ptr = filename;

        ref_index.write_index();
        // ref_index.print();

        mindex
    }

    fn build_index(&self, pkt: &Packet) -> u32 {
        let mut index: u32 = 0;

        if pkt.has_ethernet() {
            index += IndexField::Ethernet as u32
        }
        if pkt.has_ipv4() {
            index += IndexField::IpV4 as u32
        }
        if pkt.has_icmp() {
            index += IndexField::Icmp as u32
        }
        if pkt.has_udp() {
            index += IndexField::Udp as u32
        }
        if pkt.has_tcp() {
            index += IndexField::Tcp as u32
        }
        if pkt.has_https() {
            index += IndexField::Https as u32
        }
        if pkt.has_dns() {
            index += IndexField::Dns as u32
        }
        if pkt.has_dhcp() {
            index += IndexField::Dhcp as u32
        }
        if pkt.has_ssh() {
            index += IndexField::Ssh as u32
        }
        if pkt.has_telnet() {
            index += IndexField::Telnet as u32
        }
        if pkt.has_http() {
            index += IndexField::Http as u32
        }

        index
    }

    pub fn create_index(&self) {
        let result: Vec<MasterIndex> = (0..config::CONFIG.block_size)
            .into_par_iter()
            .map(|pkt| self.index_file(pkt as u32))
            .collect();

        self.save_master(result);
    }

    pub fn save_master(&self, master_index: Vec<MasterIndex>) {
        let mut writer = BufWriter::new(
            File::create(format!("{}/master.pidx", config::CONFIG.master_index_path)).unwrap(),
        );
        for p in master_index {
            writer.write_u32::<BigEndian>(p.start_timestamp).unwrap();
            writer.write_u32::<BigEndian>(p.end_timestamp).unwrap();
            writer.write_u32::<BigEndian>(p.file_ptr).unwrap();
        }
    }

    pub fn build_search_index(&self, search_type: &HashSet<IndexField>) -> u32 {
        let mut ret_type: u32 = 0;
        for stype in search_type {
            match stype {
                IndexField::Ethernet => ret_type += IndexField::Ethernet as u32,
                IndexField::Arp => ret_type += IndexField::Arp as u32,
                IndexField::IpV4 => ret_type += IndexField::IpV4 as u32,
                IndexField::Icmp => ret_type += IndexField::Icmp as u32,
                IndexField::Udp => ret_type += IndexField::Udp as u32,
                IndexField::Tcp => ret_type += IndexField::Tcp as u32,
                IndexField::Dns => ret_type += IndexField::Dns as u32,
                IndexField::Dhcp => ret_type += IndexField::Dhcp as u32,
                IndexField::Https => ret_type += IndexField::Https as u32,
                IndexField::Http => ret_type += IndexField::Http as u32,
                IndexField::Ssh => ret_type += IndexField::Ssh as u32,
                IndexField::Telnet => ret_type += IndexField::Telnet as u32,
                IndexField::IpV6 => ret_type += IndexField::IpV6 as u32,
            }
        }

        return ret_type;
    }

    pub fn search_master_index(&self, start_ts: u32, end_ts: u32) -> Vec<MasterIndex> {
        let mut index_list: Vec<MasterIndex> = Vec::new();

        let idx_filename = &format!("{}/master.pidx", &config::CONFIG.master_index_path);
        let mut file = BufReader::new(File::open(idx_filename).unwrap());
        let mut buffer = [0; 12];
        let mut start_found = false;

        loop {
            match file.read_exact(&mut buffer) {
                Ok(_) => {
                    let idx_start = BigEndian::read_u32(&buffer[0..4]);
                    let idx_end = BigEndian::read_u32(&buffer[4..8]);
                    // println!(
                    //     "Master search: {}/{}-{}",
                    //     idx_start,
                    //     idx_end,
                    //     BigEndian::read_u32(&buffer[8..12])
                    // );
                    if !start_found && (start_ts >= idx_start && start_ts <= idx_end) {
                        start_found = true;
                        let index = MasterIndex {
                            start_timestamp: idx_start,
                            end_timestamp: idx_end,
                            file_ptr: BigEndian::read_u32(&buffer[8..12]),
                        };
                        index_list.push(index);
                    } else if start_found && (idx_end <= end_ts) {
                        let index = MasterIndex {
                            start_timestamp: idx_start,
                            end_timestamp: idx_end,
                            file_ptr: BigEndian::read_u32(&buffer[8..12]),
                        };
                        index_list.push(index);
                    } else if start_found && (idx_end >= end_ts) {
                        let index = MasterIndex {
                            start_timestamp: idx_start,
                            end_timestamp: idx_end,
                            file_ptr: BigEndian::read_u32(&buffer[8..12]),
                        };
                        index_list.push(index);
                        break;
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }

        return index_list;
    }

    // pub fn _read_index(&self, index_file: u32) {
    //     let idx_filename = &format!("{}/{}.pidx", &config::CONFIG.index_path, index_file);
    //     let mut file = BufReader::new(File::open(idx_filename).unwrap());

    //     let mut buffer = [0; 12];
    //     let mut count: usize = 0;

    //     loop {
    //         match file.read_exact(&mut buffer) {
    //             Ok(_) => {
    //                 if self.match_index(&buffer, 0x120) {
    //                     count += 1;
    //                 }
    //             }
    //             Err(_) => {
    //                 break;
    //             }
    //         }
    //     }
    //     println!("{} count {}", index_file, count);
    // }

    // pub fn search(&self, pql: &PqlStatement) {
    //     let mut total = 0;

    //     for i in 0..1 {
    //         println!("Index: {}", i);
    //         // if total > 1 {
    //         //     return;
    //         // }
    //         let result = self.search_index(pql, i);
    //         total += result.pkt_ptr.len();
    //     }
    //     println!("Pakcet found: {}", total);
    // }

    // pub fn search_index(&self, pql: &PqlStatement, index_file: u32) -> PacketPtr {
    //     let idx_filename = &format!("{}/{}.pidx", &config::CONFIG.index_path, index_file);
    //     let mut file = BufReader::new(File::open(idx_filename).unwrap());
    //     let mut buffer = [0; 12];
    //     // let mut count: usize = 0;
    //     // let mut total: usize = 0;
    //     let mut packet_ptr = PacketPtr::default();
    //     packet_ptr.file_id = index_file;
    //     // let mut ip_dst: u32;
    //     // let mut ip_src: u32;
    //     let search_value = self.build_search_index(&pql.search_type);
    //     loop {
    //         match file.read_exact(&mut buffer) {
    //             Ok(_) => {
    //                 // ip_dst = BigEndian::read_u32(&buffer[12..16]);
    //                 // ip_src = BigEndian::read_u32(&buffer[16..20]);
    //                 if let Some(interval) = &pql.interval {
    //                     let timestamp = BigEndian::read_u32(&buffer[0..4]);
    //                     if timestamp >= interval.from
    //                         && timestamp <= interval.to
    //                         && self.match_index(&buffer, search_value)
    //                     {
    //                         packet_ptr.pkt_ptr.push(BigEndian::read_u32(&buffer[4..8]));
    //                     }
    //                 } else {
    //                     if self.match_index(&buffer, search_value)
    //                     // && (ip_dst == 0xc0a8036e || ip_src == 0xc0a8036e)
    //                     {
    //                         packet_ptr.pkt_ptr.push(BigEndian::read_u32(&buffer[4..8]));
    //                         // count += 1;
    //                     }
    //                 }

    //                 // total += 1;
    //             }
    //             Err(_) => {
    //                 break;
    //             }
    //         }
    //         // if total > 5000 {
    //         //     return packet_ptr;
    //         // }
    //     }

    //     packet_ptr
    // }

    // fn match_index(&self, buffer: &[u8], search_value: u32) -> bool {
    //     let cindex = BigEndian::read_u32(&buffer[8..12]);
    //     (cindex & search_value) == search_value
    // }
}
