use crate::config;
use crate::index_manager::IndexField;
use crate::packet_ptr::PacketPtr;
use crate::parse::PqlStatement;
use byteorder::{BigEndian, ByteOrder};
use frame::ipv4_address::{is_ip_in_range, IPv4};
// use log::info;
use crate::ref_index::RefIndex;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;

#[derive(Default)]
pub struct PktIndex {}

impl PktIndex {
    pub fn _search_index(&mut self, pql: &PqlStatement, file_id: u32) -> PacketPtr {
        let idx_filename = &format!("{}/{}.pidx", &config::CONFIG.index_path, file_id);
        let mut file = BufReader::new(File::open(idx_filename).unwrap());
        let mut buffer = [0; 20];
        let mut packet_ptr = PacketPtr::default();
        packet_ptr.file_id = file_id;
        println!("Search type: {:?}", &pql.search_type);

        let mut ref_index = RefIndex::new(file_id);

        let search_value = self.build_search_index(&pql.search_type);
        let index_list = ref_index.read_index(0x125);
        let mut file_pos: i64 = 0;

        for idx in index_list {
            file.seek_relative(idx as i64 - file_pos).unwrap();
            file_pos = idx as i64;
            match file.read_exact(&mut buffer) {
                Ok(_) => {
                    if let Some(interval) = &pql.interval {
                        let timestamp = BigEndian::read_u32(&buffer[0..4]);
                        if timestamp >= interval.from
                            && timestamp <= interval.to
                            && self.match_index(&buffer, search_value, &pql.ip_list)
                        {
                            packet_ptr.pkt_ptr.push(BigEndian::read_u32(&buffer[4..8]));
                        }
                    } else {
                        if self.match_index(&buffer, search_value, &pql.ip_list) {
                            packet_ptr.pkt_ptr.push(BigEndian::read_u32(&buffer[4..8]));
                        }
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }

        packet_ptr
    }

    pub fn search_index(&mut self, pql: &PqlStatement, file_id: u32) -> PacketPtr {
        let idx_filename = &format!("{}/{}.pidx", &config::CONFIG.index_path, file_id);
        let mut file = BufReader::new(File::open(idx_filename).unwrap());
        let mut buffer = [0; 20];
        let mut packet_ptr = PacketPtr::default();
        packet_ptr.file_id = file_id;
        println!("Search file: {}, type: {:?}", file_id, &pql.search_type);
        let search_value = self.build_search_index(&pql.search_type);

        loop {
            match file.read_exact(&mut buffer) {
                Ok(_) => {
                    if let Some(interval) = &pql.interval {
                        let timestamp = BigEndian::read_u32(&buffer[0..4]);
                        if timestamp >= interval.from
                            && timestamp <= interval.to
                            && self.match_index(&buffer, search_value, &pql.ip_list)
                        {
                            packet_ptr.pkt_ptr.push(BigEndian::read_u32(&buffer[4..8]));
                        }
                    } else {
                        if self.match_index(&buffer, search_value, &pql.ip_list) {
                            packet_ptr.pkt_ptr.push(BigEndian::read_u32(&buffer[4..8]));
                        }
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }

        packet_ptr
    }

    fn build_search_index(&self, search_type: &HashSet<IndexField>) -> u32 {
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

    fn match_index(&self, buffer: &[u8], search_value: u32, ip_list: &Vec<IPv4>) -> bool {
        let cindex = BigEndian::read_u32(&buffer[8..12]);
        let ip_dst = BigEndian::read_u32(&buffer[12..16]);
        let ip_src = BigEndian::read_u32(&buffer[16..20]);
        let mut ip_found = true;

        if ip_list.len() > 0 {
            ip_found = false;
            for ip in ip_list {
                if is_ip_in_range(ip_dst, ip.address, ip.mask)
                    || is_ip_in_range(ip_src, ip.address, ip.mask)
                {
                    ip_found = true;
                }
            }
        }

        ((cindex & search_value) == search_value) && ip_found
    }
}
