use crate::config;
use crate::index_manager::IndexField;
use crate::packet_ptr::PacketPtr;
use crate::parse::PqlStatement;
use byteorder::{BigEndian, ByteOrder};
use frame::ipv4_address::{is_ip_in_range, IPv4};
// use log::info;
use std::collections::HashSet;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;

pub const IDX_ETHERNET: u32 = 0x01;
pub const _IDX_ARP: u32 = 0x02;
pub const IDX_IPV4: u32 = 0x04;
pub const IDX_ICMP: u32 = 0x08;
pub const IDX_UDP: u32 = 0x10;
pub const IDX_TCP: u32 = 0x20;
pub const IDX_DNS: u32 = 0x40;
pub const IDX_DHCP: u32 = 0x80;
pub const IDX_HTTPS: u32 = 0x100;

#[derive(Default)]
pub struct PktIndex {}

impl PktIndex {
    pub fn search_index(&mut self, pql: &PqlStatement, file_id: u32) -> PacketPtr {
        let idx_filename = &format!("{}/{}.pidx", &config::CONFIG.index_path, file_id);
        let mut file = BufReader::new(File::open(idx_filename).unwrap());
        let mut buffer = [0; 20];
        let mut packet_ptr = PacketPtr::default();
        packet_ptr.file_id = file_id;
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