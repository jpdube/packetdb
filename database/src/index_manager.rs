use crate::config::CONFIG;
use crate::packet_ptr::PacketPtr;
use crate::parse::PqlStatement;
use crate::pcapfile::PcapFile;
use crate::proto_index::ProtoIndex;
use anyhow::Result;
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use frame::fields;
use frame::ipv4_address::IPv4;
use frame::packet::Packet;
use log::{error, info};
use rayon::prelude::*;
use remove_dir_all::remove_dir_contents;
use rusqlite::Connection;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::path::Path;
use std::time::Instant;
use std::{f64, fmt};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum IndexField {
    Ethernet = 0x01,
    Arp = 0x02,
    IpV4 = 0x04,
    IpV6 = 0x08,
    Icmp = 0x10,
    Udp = 0x20,
    Tcp = 0x40,
    Dns = 0x80,
    Dhcp = 0x100,
    Https = 0x200,
    Http = 0x400,
    Ssh = 0x800,
    Telnet = 0x1000,
    Smtp = 0x2000,
    Imap = 0x4000,
    Imaps = 0x8000,
    Pop3 = 0x10_000,
    Pop3s = 0x20_000,
    Snmp = 0x40_000,
    Ftp = 0x80_000,
    Ntp = 0x100_000,
    Rtp = 0x200_000,
    RtpC = 0x400_000,
    Sip = 0x800_000,
    SipTls = 0x1_000_000,
    Bgp = 0x2_000_000,
    Smb = 0x4_000_000,
}

const STAT_SQL: &str =
    "INSERT INTO proto_stats (file_id, proto, count) values (:file_id, :proto, :count)";

#[derive(Debug)]
pub struct ProtoStat {
    file_id: u32,
    proto_count: HashMap<u32, u32>,
}

#[derive(Debug)]
struct StatCount {
    count: usize,
}

impl fmt::Display for ProtoStat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "File ID: {}, {:x?} ", self.file_id, self.proto_count)
    }
}

impl ProtoStat {
    pub fn new(file_id: u32) -> Self {
        Self {
            file_id,
            proto_count: HashMap::new(),
        }
    }

    pub fn add(&mut self, proto: u32) {
        if let Some(key) = self.proto_count.get_mut(&proto) {
            *key += 1;
        } else {
            self.proto_count.insert(proto, 1);
        }
    }

    pub fn save(&mut self) -> Result<()> {
        let mut conn = Connection::open(format!("{}/packetdb.db", &CONFIG.master_index_path))?;

        let tx = conn.transaction()?;
        tx.prepare(STAT_SQL)?;

        tx.execute_batch(
            "PRAGMA journal_mode = MEMORY;
                    PRAGMA cache_size = 1000000;
                    PRAGMA temp_store = MEMORY;
                    PRAGMA threads=4;", // PRAGMA locking_mode = EXCLUSIVE;",
        )
        .expect("PRAGMA");

        tx.execute("delete from proto_stats where file_id = ?", [self.file_id])?;

        for (proto, count) in self.proto_count.to_owned().into_iter() {
            tx.execute(
                "INSERT INTO proto_stats (file_id, proto, count) values (?, ?, ?);",
                [self.file_id, proto, count],
            )?;
        }

        tx.commit()?;

        Ok(())
    }

    pub fn get_count_stats(&self, proto: u32) -> usize {
        let conn = Connection::open(format!("{}/packetdb.db", &CONFIG.master_index_path)).unwrap();

        let mut stmt = conn
            .prepare("select cast (avg(count) as int) from proto_stats where (proto & ?) = ?;")
            .unwrap();

        let count_iter = stmt
            .query_map([proto, proto], |row| {
                Ok(StatCount {
                    count: row.get(0).unwrap(),
                })
            })
            .unwrap();

        let mut value: usize = 0;

        for c in count_iter {
            value = c.unwrap().count;
        }

        value
    }
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
    pub fn search_index(&mut self, pql: &PqlStatement, file_id: u32) -> PacketPtr {
        let idx_filename = &format!("{}/{}.pidx", &CONFIG.index_path, file_id);
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

    fn match_index(&self, buffer: &[u8], search_value: u32, ip_list: &Vec<IPv4>) -> bool {
        let cindex = BigEndian::read_u32(&buffer[8..12]);
        let ip_dst = BigEndian::read_u32(&buffer[12..16]);
        let ip_src = BigEndian::read_u32(&buffer[16..20]);
        let mut ip_found = true;

        if ip_list.len() > 0 {
            ip_found = false;
            for ip in ip_list {
                if IPv4::new(ip.address, ip.mask).is_in_subnet(ip_dst)
                    || IPv4::new(ip.address, ip.mask).is_in_subnet(ip_src)
                {
                    ip_found = true;
                }
            }
        }

        ((cindex & search_value) == search_value) && ip_found
    }

    pub fn index_one_file(&self, file_id: u32) -> bool {
        let master_index = self.index_file(file_id);

        self.save_master(master_index);

        true
    }

    pub fn index_file(&self, filename: u32) -> MasterIndex {
        let mut pfile = PcapFile::new(filename, &CONFIG.db_path);
        let idx_filename = &format!("{}/{}.pidx", &CONFIG.index_path, filename);
        let mut writer = BufWriter::new(File::create(idx_filename).unwrap());
        let mut mindex = MasterIndex::default();
        let mut first_index = false;
        let mut ts: u32 = 0;
        let mut proto_stat = ProtoStat::new(filename);

        let start = Instant::now();
        let mut count = 0;
        let mut dhcp_index = ProtoIndex::new(filename, IndexField::Dhcp as u32);
        let mut dns_index = ProtoIndex::new(filename, IndexField::Dns as u32);

        while let Some(pkt) = pfile.next() {
            count += 1;
            ts = pkt.get_field(fields::FRAME_TIMESTAMP).unwrap().to_u32();

            if !first_index {
                first_index = true;
                mindex.start_timestamp = ts
            }
            writer.write_u32::<BigEndian>(ts).unwrap();
            writer.write_u32::<BigEndian>(pkt.pkt_ptr).unwrap();

            let pindex = self.build_index(&pkt);

            if (pindex & IndexField::Dhcp as u32) == IndexField::Dhcp as u32 {
                dhcp_index.add(&pkt.pkt_ptr);
            }
            if (pindex & IndexField::Dns as u32) == IndexField::Dns as u32 {
                dns_index.add(&pkt.pkt_ptr);
            }

            writer.write_u32::<BigEndian>(pindex).unwrap();
            proto_stat.add(pindex);

            if let Some(ip_dst) = pkt.get_field(fields::IPV4_DST_ADDR) {
                writer.write_u32::<BigEndian>(ip_dst.to_u32()).unwrap();
            } else {
                writer.write_u32::<BigEndian>(0).unwrap();
            }

            if let Some(ip_src) = pkt.get_field(fields::IPV4_SRC_ADDR) {
                writer.write_u32::<BigEndian>(ip_src.to_u32()).unwrap();
            } else {
                writer.write_u32::<BigEndian>(0).unwrap();
            }
        }
        dhcp_index.create_index();
        dns_index.create_index();

        let duration = start.elapsed();
        info!(
            "Index file {} Process {} packets in: {:3.3}ms Per packet: {:3.3}us",
            filename,
            count,
            duration.as_millis(),
            (duration.as_secs_f64() / count as f64) * 1_000_000.0
        );

        match proto_stat.save() {
            Ok(_) => {}
            Err(err) => eprintln!("Error computing protocol stats: {}", err),
        }

        mindex.end_timestamp = ts;
        mindex.file_ptr = filename;

        mindex
    }

    fn build_index(&self, pkt: &Packet) -> u32 {
        let mut index: u32 = 0;

        if pkt.has_ethernet() {
            index += IndexField::Ethernet as u32
        }
        if pkt.has_arp() {
            index += IndexField::Arp as u32
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

    fn get_packet_files(&self) -> Result<Vec<u32>> {
        let pcap_path = format!("{}", &CONFIG.db_path);
        let paths = fs::read_dir(pcap_path).unwrap();

        let mut file_id_list: Vec<u32> = Vec::new();

        for path in paths {
            let id: u32 = Path::new(&path.unwrap().file_name())
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<u32>()?;

            file_id_list.push(id);
        }
        file_id_list.sort();
        file_id_list.reverse();
        Ok(file_id_list)
    }

    pub fn create_index(&self) {
        remove_dir_contents(&CONFIG.index_path).unwrap();
        match self.get_packet_files() {
            Ok(files_list) => {
                let result: Vec<MasterIndex> = (files_list)
                    .into_par_iter()
                    .map(|pkt| self.index_file(pkt as u32))
                    .collect();

                self.create_master(result);
            }
            Err(msg) => error!("Error index files: {}", msg),
        }
    }

    pub fn save_master(&self, master_index: MasterIndex) {
        let index_file = format!("{}/master.pidx", CONFIG.master_index_path);
        let mut writer = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(index_file)
            .unwrap();
        writer
            .write_u32::<BigEndian>(master_index.start_timestamp)
            .unwrap();
        writer
            .write_u32::<BigEndian>(master_index.end_timestamp)
            .unwrap();
        writer
            .write_u32::<BigEndian>(master_index.file_ptr)
            .unwrap();
    }

    pub fn create_master(&self, master_index: Vec<MasterIndex>) {
        let index_file = format!("{}/master.pidx", CONFIG.master_index_path);
        println!("Master index file: {}", index_file);
        let mut writer = BufWriter::new(File::create(index_file).unwrap());
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
                IndexField::IpV6 => ret_type += IndexField::IpV6 as u32,
                IndexField::Icmp => ret_type += IndexField::Icmp as u32,
                IndexField::Udp => ret_type += IndexField::Udp as u32,
                IndexField::Tcp => ret_type += IndexField::Tcp as u32,
                IndexField::Dns => ret_type += IndexField::Dns as u32,
                IndexField::Dhcp => ret_type += IndexField::Dhcp as u32,
                IndexField::Https => ret_type += IndexField::Https as u32,
                IndexField::Http => ret_type += IndexField::Http as u32,
                IndexField::Ssh => ret_type += IndexField::Ssh as u32,
                IndexField::Telnet => ret_type += IndexField::Telnet as u32,
                IndexField::Smtp => ret_type += IndexField::Smtp as u32,
                IndexField::Imap => ret_type += IndexField::Imap as u32,
                IndexField::Imaps => ret_type += IndexField::Imaps as u32,
                IndexField::Pop3 => ret_type += IndexField::Pop3 as u32,
                IndexField::Pop3s => ret_type += IndexField::Pop3s as u32,
                IndexField::Snmp => ret_type += IndexField::Snmp as u32,
                IndexField::Ftp => ret_type += IndexField::Ftp as u32,
                IndexField::Ntp => ret_type += IndexField::Ntp as u32,
                IndexField::Rtp => ret_type += IndexField::Rtp as u32,
                IndexField::RtpC => ret_type += IndexField::RtpC as u32,
                IndexField::Sip => ret_type += IndexField::Sip as u32,
                IndexField::SipTls => ret_type += IndexField::SipTls as u32,
                IndexField::Bgp => ret_type += IndexField::Bgp as u32,
                IndexField::Smb => ret_type += IndexField::Smb as u32,
            }
        }

        return ret_type;
    }

    pub fn search_master_index(&self, start_ts: u32, end_ts: u32) -> Vec<MasterIndex> {
        let mut index_list: Vec<MasterIndex> = Vec::new();

        let idx_filename = &format!("{}/master.pidx", &CONFIG.master_index_path);
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
}
