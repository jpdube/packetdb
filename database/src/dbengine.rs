use crate::config::CONFIG;
use crate::cursor::Cursor;
use crate::exec_plan::ExecutionPlan;
use crate::index_manager::{IndexField, IndexManager};
use crate::interpreter::Interpreter;
use crate::packet_ptr::PacketPtr;
use crate::parse::Parse;
use crate::pcapfile::PcapFile;
use crate::proto_index::ProtoIndex;
use crate::query_result::QueryResult;
use frame::packet::Packet;

use anyhow::Result;
use log::{debug, info};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug, Default)]
pub struct DbEngine {
    exec_plan: ExecutionPlan,
    offset: usize,
}

impl DbEngine {
    pub fn new() -> Self {
        Self {
            exec_plan: ExecutionPlan::default(),
            offset: 0,
        }
    }

    pub fn run(&mut self, query: &str) -> Result<Cursor, String> {
        println!("Searching for: {}", query);
        let mut parse = Parse::new();

        self.exec_plan.start("Start search");
        if let Ok(expr) = parse.parse_select(query) {
            debug!("--> Select query: {:?}", expr.search_type);

            let mut query_result = QueryResult::new(expr.clone());

            let mut file_count = 0;
            let interpreter = Interpreter::new(expr.clone());

            self.offset = 0;
            let mut proto_search: u32 = 0;

            if expr.has_id_search() {
                debug!("In ID search");
                let pkt_result = self.get_id_packets(expr.id_search);
                for p in pkt_result {
                    query_result.add(p);
                }

                self.exec_plan.stop();
                self.exec_plan.show();
                Ok(query_result.get_result())
            } else {
                let files_list: Result<Vec<u32>>;

                if let Some(proto_id) = self.has_proto(&expr.search_type) {
                    info!("FOUND PROTO INDEX {:?}", proto_id);
                    proto_search = proto_id as u32;
                    files_list = self.get_proto_files(proto_search);
                } else {
                    files_list = self.get_index_files();
                }
                match files_list {
                    Ok(search_list) => {
                        while !query_result.count_reach() {
                            for file_id in &search_list {
                                file_count += 1;
                                let pkt_index: Result<PacketPtr>;

                                if proto_search > IndexField::Arp as u32 {
                                    let mut proto_index = ProtoIndex::new(*file_id, proto_search);
                                    pkt_index = proto_index.read();
                                } else {
                                    let mut index = IndexManager::default();
                                    pkt_index = index.search_index(&expr, *file_id);
                                }
                                match pkt_index {
                                    Ok(ptr) => {
                                        let c = interpreter.run_pgm_seek(&ptr, expr.top);

                                        for r in c {
                                            query_result.add(r);
                                            if query_result.count_reach() {
                                                break;
                                            }
                                        }
                                        if query_result.count_reach() {
                                            break;
                                        }
                                    }
                                    Err(msg) => eprintln!("Error reading DB: {}", msg),
                                }
                            }
                        }
                        info!("Nbr files searched: {}", file_count);
                    }
                    Err(e) => println!("Error with index error:{}", e),
                }

                self.exec_plan.stop();
                self.exec_plan.show();
                Ok(query_result.get_result())
            }
        } else {
            Err(String::from("Error reading database"))
        }
    }

    fn has_proto(&self, search_type: &HashSet<IndexField>) -> Option<IndexField> {
        let search_proto = vec![
            IndexField::Arp,
            IndexField::Icmp,
            IndexField::Dns,
            IndexField::Dhcp,
            IndexField::Https,
            IndexField::Http,
            IndexField::Ssh,
            IndexField::Telnet,
            IndexField::Smtp,
            IndexField::Imap,
            IndexField::Pop3,
            IndexField::Snmp,
            IndexField::Ftp,
            IndexField::Ntp,
            IndexField::Rtp,
            IndexField::Sip,
            IndexField::SipTls,
            IndexField::Smb,
            IndexField::Rdp,
        ];

        for st in search_type {
            if search_proto.contains(&st) {
                return Some(st.clone());
            }
        }

        return None;
    }

    fn get_id_packets(&self, id_list: Vec<u64>) -> Vec<Packet> {
        let mut result: Vec<Packet> = Vec::new();

        for id in id_list {
            let file_id: u32 = (id >> 32) as u32;
            let ptr: u32 = (id & 0xffff) as u32;
            debug!("ID search for {}:{}", file_id, ptr);
            let mut pcapfile = PcapFile::new(file_id, &CONFIG.db_path);

            if let Some(pkt) = pcapfile.seek(ptr) {
                debug!("ID pkt ID: {}", pkt.get_field(7).unwrap().to_usize());
                result.push(pkt);
            }
        }
        // debug!("ID seek result: {:#?}", result);

        result
    }

    // fn chunk_size(&self, expr: &PqlStatement) -> usize {
    //     let ix_manager = IndexManager::default();
    //     let search_proto = ix_manager.build_search_index(&expr.search_type);
    //     let proto_stat = ProtoStat::new(0);

    //     let avg_file = proto_stat.get_count_stats(search_proto);

    //     let mut chunk_size: usize = 1;

    //     if avg_file != 0 {
    //         chunk_size = ((&expr.top + &expr.offset) / avg_file) + 1;
    //         println!(
    //             "Chunk size raw: Proto: {search_proto}, top: {}, Avg: {avg_file}, chunk: {chunk_size}",
    //             &expr.top
    //         );

    //         if chunk_size == 0 {
    //             chunk_size = 1;
    //         }

    //         if chunk_size > 8 {
    //             chunk_size = 8;
    //         }
    //     }

    //     chunk_size
    // }

    fn get_proto_files(&self, proto_id: u32) -> Result<Vec<u32>> {
        let paths = fs::read_dir(format!("{}/{:x}", &CONFIG.proto_index_path, proto_id))?;
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

    fn get_index_files(&self) -> Result<Vec<u32>> {
        let paths = fs::read_dir(&CONFIG.index_path)?;
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
        let t_init = SystemTime::now();
        let index_manager = IndexManager::default();
        index_manager.create_index();

        info!(
            "DB index creation time: {}ms",
            t_init.elapsed().unwrap().as_millis()
        );
    }
}
