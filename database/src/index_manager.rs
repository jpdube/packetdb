use crate::config::CONFIG;
use crate::file_manager;
use crate::packet_ptr::PacketPtr;
use crate::parse::PqlStatement;
use crate::pcapfile::PcapFile;
use crate::proto_index::ProtoIndexMgr;
use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use frame::ipv4_address::IPv4;
use frame::layer_index::LayerIndex;
use frame::packet::Packet;
use log::{error, info};
use rayon::prelude::*;
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

// #[derive(Debug, Clone, Eq, PartialEq, Hash)]
// pub enum IndexField {
//     Ethernet = 0x01,
//     Ip = 0x02,
//     IpV6 = 0x04,
//     Udp = 0x08,
//     Tcp = 0x10,
//     Arp = 0x20,
//     Icmp = 0x40,
//     Dns = 0x80,
//     Dhcp = 0x100,
//     Https = 0x200,
//     Http = 0x400,
//     Ssh = 0x800,
//     Telnet = 0x1000,
//     Smtp = 0x2000,
//     Imap = 0x4000,
//     Imaps = 0x8000,
//     Pop3 = 0x10_000,
//     Pop3s = 0x20_000,
//     Snmp = 0x40_000,
//     Ftp = 0x80_000,
//     Ntp = 0x100_000,
//     Rtp = 0x200_000,
//     RtpC = 0x400_000,
//     Sip = 0x800_000,
//     SipTls = 0x1_000_000,
//     Bgp = 0x2_000_000,
//     Smb = 0x4_000_000,
//     Rdp = 0x8_000_000,
// }

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
    pub fn search_index(&mut self, pql: &PqlStatement, file_id: u32) -> Result<PacketPtr> {
        let idx_filename = &format!("{}/{}.pidx", &CONFIG.index_path, file_id);
        let mut file = BufReader::new(File::open(idx_filename)?);
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

        Ok(packet_ptr)
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
        // let mut proto_stat = ProtoStat::new(filename);

        let start = Instant::now();
        let mut count = 0;
        let mut proto_idx_mgr = ProtoIndexMgr::new(filename);

        while let Some(pkt) = pfile.next() {
            count += 1;
            ts = pkt
                .get_field("frame.timestamp".to_string())
                .unwrap()
                .to_u32();

            if !first_index {
                first_index = true;
                mindex.start_timestamp = ts
            }
            writer.write_u32::<BigEndian>(ts).unwrap();
            writer.write_u32::<BigEndian>(pkt.pkt_ptr).unwrap();

            let pindex = self.build_index(&pkt);

            if pindex >= LayerIndex::ARP as u32 {
                if pindex & (LayerIndex::ARP as u32) == LayerIndex::ARP as u32 {
                    proto_idx_mgr.add(LayerIndex::ARP as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::DNS as u32) == LayerIndex::DNS as u32 {
                    proto_idx_mgr.add(LayerIndex::DNS as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::DHCP as u32) == LayerIndex::DHCP as u32 {
                    proto_idx_mgr.add(LayerIndex::DHCP as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::ICMP as u32) == LayerIndex::ICMP as u32 {
                    proto_idx_mgr.add(LayerIndex::ICMP as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::SSH as u32) == LayerIndex::SSH as u32 {
                    proto_idx_mgr.add(LayerIndex::SSH as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::HTTPS as u32) == LayerIndex::HTTPS as u32 {
                    proto_idx_mgr.add(LayerIndex::HTTPS as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::HTTP as u32) == LayerIndex::HTTP as u32 {
                    proto_idx_mgr.add(LayerIndex::HTTP as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::TELNET as u32) == LayerIndex::TELNET as u32 {
                    proto_idx_mgr.add(LayerIndex::TELNET as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::RDP as u32) == LayerIndex::RDP as u32 {
                    proto_idx_mgr.add(LayerIndex::RDP as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::SMB as u32) == LayerIndex::SMB as u32 {
                    proto_idx_mgr.add(LayerIndex::SMB as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::SIP as u32) == LayerIndex::SIP as u32 {
                    proto_idx_mgr.add(LayerIndex::SIP as u32, pkt.pkt_ptr);
                } else if pindex & (LayerIndex::NTP as u32) == LayerIndex::NTP as u32 {
                    proto_idx_mgr.add(LayerIndex::NTP as u32, pkt.pkt_ptr);
                }
            }

            writer.write_u32::<BigEndian>(pindex).unwrap();
            // proto_stat.add(pindex);

            if let Some(ip_dst) = pkt.get_field("ip.dst".to_string()) {
                writer.write_u32::<BigEndian>(ip_dst.to_u32()).unwrap();
            } else {
                writer.write_u32::<BigEndian>(0).unwrap();
            }

            if let Some(ip_src) = pkt.get_field("ip.src".to_string()) {
                writer.write_u32::<BigEndian>(ip_src.to_u32()).unwrap();
            } else {
                writer.write_u32::<BigEndian>(0).unwrap();
            }
        }

        proto_idx_mgr.save();

        let duration = start.elapsed();
        info!(
            "Index file {} Process {} packets in: {:3.3}ms Per packet: {:3.3}us",
            filename,
            count,
            duration.as_millis(),
            (duration.as_secs_f64() / count as f64) * 1_000_000.0
        );

        // match proto_stat.save() {
        //     Ok(_) => {}
        //     Err(err) => eprintln!("Error computing protocol stats: {}", err),
        // }

        mindex.end_timestamp = ts;
        mindex.file_ptr = filename;

        mindex
    }

    fn build_index(&self, pkt: &Packet) -> u32 {
        let mut index: u32 = 0;

        if pkt.has_ethernet() {
            index += LayerIndex::ETH as u32
        }
        if pkt.has_arp() {
            index += LayerIndex::ARP as u32
        }
        if pkt.has_ipv4() {
            index += LayerIndex::IPv4 as u32
        }
        if pkt.has_icmp() {
            index += LayerIndex::ICMP as u32
        }
        if pkt.has_udp() {
            index += LayerIndex::UDP as u32
        }
        if pkt.has_tcp() {
            index += LayerIndex::TCP as u32
        }
        if pkt.has_https() {
            index += LayerIndex::HTTPS as u32
        }
        if pkt.has_dns() {
            index += LayerIndex::DNS as u32
        }
        if pkt.has_dhcp() {
            index += LayerIndex::DHCP as u32
        }
        if pkt.has_ssh() {
            index += LayerIndex::SSH as u32
        }
        if pkt.has_telnet() {
            index += LayerIndex::TELNET as u32
        }
        if pkt.has_http() {
            index += LayerIndex::HTTP as u32
        }
        if pkt.has_rdp() {
            index += LayerIndex::RDP as u32
        }
        if pkt.has_ntp() {
            index += LayerIndex::NTP as u32
        }
        if pkt.has_smb() {
            index += LayerIndex::SMB as u32
        }
        if pkt.has_smtp() {
            index += LayerIndex::SMTP as u32
        }
        if pkt.has_snmp() {
            index += LayerIndex::SMTP as u32
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
                .ok_or(anyhow!("Error extrating file stem"))?
                .to_str()
                .ok_or(anyhow!("Error converting file stem to string"))?
                .parse::<u32>()?;

            file_id_list.push(id);
        }
        file_id_list.sort();
        file_id_list.reverse();
        Ok(file_id_list)
    }

    pub fn create_index(&self) {
        file_manager::clean_indexes();
        // remove_dir_contents(&CONFIG.index_path).unwrap();
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

    pub fn build_search_index(&self, search_type: &HashSet<LayerIndex>) -> u32 {
        // println!("Proto types: {:?}", search_type);
        let mut ret_type: u32 = 0;
        for stype in search_type {
            match stype {
                //--- Ignoring frame for indexing
                LayerIndex::FRAME => ret_type += 0,
                LayerIndex::ETH => ret_type += LayerIndex::ETH as u32,
                LayerIndex::ARP => ret_type += LayerIndex::ARP as u32,
                LayerIndex::IPv4 => ret_type += LayerIndex::IPv4 as u32,
                LayerIndex::IPv6 => ret_type += LayerIndex::IPv6 as u32,
                LayerIndex::ICMP => ret_type += LayerIndex::ICMP as u32,
                LayerIndex::UDP => ret_type += LayerIndex::UDP as u32,
                LayerIndex::TCP => ret_type += LayerIndex::TCP as u32,
                LayerIndex::DNS => ret_type += LayerIndex::DNS as u32,
                LayerIndex::DHCP => ret_type += LayerIndex::DHCP as u32,
                LayerIndex::HTTPS => ret_type += LayerIndex::HTTPS as u32,
                LayerIndex::HTTP => ret_type += LayerIndex::HTTP as u32,
                LayerIndex::SSH => ret_type += LayerIndex::SSH as u32,
                LayerIndex::TELNET => ret_type += LayerIndex::TELNET as u32,
                LayerIndex::SMTP => ret_type += LayerIndex::SMTP as u32,
                LayerIndex::IMAP => ret_type += LayerIndex::IMAP as u32,
                LayerIndex::IMAPS => ret_type += LayerIndex::IMAPS as u32,
                LayerIndex::POP3 => ret_type += LayerIndex::POP3 as u32,
                LayerIndex::POP3S => ret_type += LayerIndex::POP3S as u32,
                LayerIndex::SNMP => ret_type += LayerIndex::SNMP as u32,
                LayerIndex::FTP => ret_type += LayerIndex::FTP as u32,
                LayerIndex::NTP => ret_type += LayerIndex::NTP as u32,
                LayerIndex::RTP => ret_type += LayerIndex::RTP as u32,
                LayerIndex::RTPC => ret_type += LayerIndex::RTPC as u32,
                LayerIndex::SIP => ret_type += LayerIndex::SIP as u32,
                LayerIndex::SIPTLS => ret_type += LayerIndex::SIPTLS as u32,
                LayerIndex::BGP => ret_type += LayerIndex::BGP as u32,
                LayerIndex::SMB => ret_type += LayerIndex::SMB as u32,
                LayerIndex::RDP => ret_type += LayerIndex::RDP as u32,
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
