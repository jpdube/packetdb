use crate::config;
use crate::packet_ptr::PacketPtr;
use crate::parse::PqlStatement;
use crate::pcapfile::PcapFile;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use frame::fields;
use frame::ipv4_address::{is_ip_in_range, IPv4};
use frame::packet::Packet;
// use log::info;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
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
pub const IDX_SSH: u32 = 0x200;
pub const IDX_RDP: u32 = 0x400;
pub const IDX_TELNET: u32 = 0x800;
pub const IDX_HTTP: u32 = 0x1000;

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
    Ssh = 0x200,
    Rdp = 0x400,
    Telnet = 0x800,
    Http = 0x1000,
}

#[derive(Default, Debug)]
pub struct PacketIndex {
    pub timestamp: u32,
    pub pkt_ptr: u32,
    pub index: u32,
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

        while let Some(pkt) = pfile.next() {
            ts = pkt.get_field(fields::FRAME_TIMESTAMP) as u32;
            // println!("IP dst: {}", pkt.get_field(fields::IPV4_DST_ADDR));

            if !first_index {
                first_index = true;
                mindex.start_timestamp = ts
            }
            writer.write_u32::<BigEndian>(ts).unwrap();
            writer.write_u32::<BigEndian>(pkt.pkt_ptr).unwrap();
            writer
                .write_u32::<BigEndian>(self.build_index(&pkt))
                .unwrap();
            writer
                .write_u32::<BigEndian>(pkt.get_field(fields::IPV4_DST_ADDR) as u32)
                .unwrap();
            writer
                .write_u32::<BigEndian>(pkt.get_field(fields::IPV4_SRC_ADDR) as u32)
                .unwrap();
        }

        mindex.end_timestamp = ts;
        mindex.file_ptr = filename;

        mindex
    }

    fn build_index(&self, pkt: &Packet) -> u32 {
        let mut index: u32 = 0;

        if pkt.has_ethernet() {
            index += IDX_ETHERNET
        }
        if pkt.has_ipv4() {
            index += IDX_IPV4
        }
        if pkt.has_icmp() {
            index += IDX_ICMP
        }
        if pkt.has_udp() {
            index += IDX_UDP
        }
        if pkt.has_tcp() {
            index += IDX_TCP
        }
        if pkt.has_https() {
            index += IDX_HTTPS
        }
        if pkt.has_dns() {
            index += IDX_DNS
        }
        if pkt.has_dhcp() {
            index += IDX_DHCP
        }
        if pkt.has_ssh() {
            index += IDX_SSH
        }
        if pkt.has_rdp() {
            index += IDX_RDP
        }
        if pkt.has_telnet() {
            index += IDX_TELNET
        }
        if pkt.has_http() {
            index += IDX_HTTP
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
                IndexField::Ssh => ret_type += IndexField::Ssh as u32,
                IndexField::Rdp => ret_type += IndexField::Rdp as u32,
                IndexField::Telnet => ret_type += IndexField::Telnet as u32,
                IndexField::Http => ret_type += IndexField::Http as u32,
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

    pub fn search(&mut self, pql: &PqlStatement) {}

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

    fn match_index(
        &self,
        buffer: &[u8],
        search_value: u32,
        ip_list: &HashMap<String, Vec<IPv4>>,
    ) -> bool {
        let cindex = BigEndian::read_u32(&buffer[8..12]);
        let ip_dst = BigEndian::read_u32(&buffer[12..16]);
        let ip_src = BigEndian::read_u32(&buffer[16..20]);
        let ip_found = true;

        // ip_found = self.match_ip(ip_src, ip_dst, &ip_list);
        ((cindex & search_value) == search_value) && ip_found
    }

    fn match_ip(&self, ip_src: u32, ip_dst: u32, ip_list: &HashMap<String, Vec<IPv4>>) -> bool {
        // println!("{:?}", ip_list);
        if ip_list["ip.dst"].len() > 0 && ip_list["ip.src"].len() > 0 {
            self.match_ip_and(ip_src, ip_dst, ip_list)
        } else {
            self.match_ip_or(ip_src, ip_dst, ip_list)
        }
    }

    fn match_ip_and(
        &self,
        ip_src: u32,
        ip_dst: u32,
        ip_target: &HashMap<String, Vec<IPv4>>,
    ) -> bool {
        let ip_src_list = &ip_target["ip.src"];
        let mut found_src = false;
        for ip_src_target in ip_src_list {
            found_src = is_ip_in_range(ip_src, ip_src_target.address, ip_src_target.mask);
        }

        let ip_dst_list = &ip_target["ip.dst"];
        let mut found_dst = false;
        for ip_dst_target in ip_dst_list {
            found_dst = is_ip_in_range(ip_dst, ip_dst_target.address, ip_dst_target.mask);
        }

        // if found_src && found_dst {
        //     println!("Found: {}", found_src && found_dst);
        // }
        found_src && found_dst
    }

    fn match_ip_or(
        &self,
        ip_src: u32,
        ip_dst: u32,
        ip_target: &HashMap<String, Vec<IPv4>>,
    ) -> bool {
        let ip_src_list = &ip_target["ip.src"];
        let mut found_src = false;
        for ip_src_target in ip_src_list {
            found_src = is_ip_in_range(ip_src, ip_src_target.address, ip_src_target.mask);
        }

        let ip_dst_list = &ip_target["ip.dst"];
        let mut found_dst = false;
        for ip_dst_target in ip_dst_list {
            found_dst = is_ip_in_range(ip_dst, ip_dst_target.address, ip_dst_target.mask);
        }

        // let ip_src_target = ip_target["ip.src"].as_ref().unwrap();

        // if let Some(ip_dst_target) = ip_target["ip.dst"].as_ref() {
        //     found_src = is_ip_in_range(ip_dst, ip_dst_target.address, ip_dst_target.mask)
        // }
        // if let Some(ip_src_target) = ip_target["ip.src"].as_ref() {
        //     found_dst = is_ip_in_range(ip_src, ip_src_target.address, ip_src_target.mask)
        // }

        found_src || found_dst
    }
}
