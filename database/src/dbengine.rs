use crate::config::CONFIG;
use crate::exec_plan::ExecutionPlan;
use crate::index_manager::IndexManager;
use crate::interpreter::Interpreter;
use crate::packet_ptr::PacketPtr;
use crate::parse::{Parse, SelectField};
use crate::pkt_index::PktIndex;
use crate::query_result::{get_field_type, Field, QueryResult, Record};
use crate::seek_packet::SeekPacket;

use anyhow::Result;
use log::info;
// use rayon::prelude::*;
use std::fs;
// use std::fs::read_dir;
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug, Default)]
pub struct DbEngine {
    result: QueryResult,
    exec_plan: ExecutionPlan,
}

impl DbEngine {
    pub fn new() -> Self {
        Self {
            result: QueryResult::default(),
            exec_plan: ExecutionPlan::default(),
        }
    }

    pub fn run(&mut self, query: &str) -> Result<&QueryResult, String> {
        println!("Searching for...");
        let mut parse = Parse::new();

        self.exec_plan.start("Start search");
        if let Ok(expr) = parse.parse_select(query) {
            let mut count: usize = 0;
            let mut top_limit: usize = expr.top;
            let mut ptr_result: Vec<PacketPtr> = Vec::new();
            let mut file_count = 0;

            let mut pkt_index = PktIndex::default();
            match self.get_index_files() {
                Ok(pkt_list) => {
                    for file_id in pkt_list {
                        // println!("Looking at index: {}", file_id);
                        file_count += 1;
                        let interpreter = Interpreter::new(expr.clone());
                        // println!("Before index search: {}", file_id);
                        let ptr = pkt_index.search_index(&expr, file_id);

                        let result = interpreter.run_pgm_seek(&ptr, top_limit);
                        count += result.pkt_ptr.len();
                        top_limit = expr.top - count;
                        ptr_result.push(result);

                        if count >= expr.top {
                            println!("len: {}", count);
                            break;
                        }
                    }

                    for p in &ptr_result {
                        self._get_fields(&expr.select, &p);
                    }

                    info!("Nbr files searched: {}", file_count);
                }
                Err(e) => println!("Error with index error:{}", e),
            }
            // if let Ok(pkt_list) = self.get_index_files().as_ref() {
            //     println!("In loop for search................");
            //     for file_id in pkt_list {
            //         println!("Looking at index: {}", file_id);
            //         file_count += 1;
            //         let interpreter = Interpreter::new(expr.clone());
            //         println!("Before index search: {}", file_id);
            //         let ptr = pkt_index.search_index(&expr, *file_id);

            //         let result = interpreter.run_pgm_seek(&ptr, top_limit);
            //         count += result.pkt_ptr.len();
            //         top_limit = expr.top - count;
            //         ptr_result.push(result);

            //         if count >= expr.top {
            //             println!("len: {}", count);
            //             break;
            //         }
            //     }

            //     for p in &ptr_result {
            //         self._get_fields(&expr.select, &p);
            //     }

            //     info!("Nbr files searched: {}", file_count);
            // }
        }

        self.exec_plan.stop();
        self.exec_plan.show();
        Ok(&self.result)
    }

    fn get_index_files(&self) -> Result<Vec<u32>> {
        let paths = fs::read_dir(&CONFIG.index_path).unwrap();
        let mut file_id_list: Vec<u32> = Vec::new();

        for path in paths {
            let id: u32 = Path::new(&path.unwrap().file_name())
                .file_stem()
                .unwrap()
                .to_str()
                .unwrap()
                .parse::<u32>()?;

            file_id_list.push(id);
            println!("File id:{id}");
        }
        // println!("File count: {}", file_id_list.len());
        file_id_list.sort();
        file_id_list.reverse();
        // println!("Name: {:?}", &file_id_list);
        Ok(file_id_list)
    }

    // pub fn exec_file(&mut self, pql_file: String) {
    //     // self.read_db_files();

    //     info!("Executing script {}", pql_file);
    //     let data = fs::read_to_string(pql_file);
    //     match data {
    //         Ok(pql) => {
    //             self.execution_plan(&pql).unwrap();
    //         }
    //         Err(error_msg) => error!("Error reading pql file: {}", error_msg),
    //     }
    // }

    // pub fn exec_script(&mut self, query: &str) -> Result<&QueryResult, String> {
    //     self.exec_plan.set_pql(query);
    //     match self.execution_plan(query) {
    //         Ok(_) => {
    //             self.exec_plan.show();
    //             Ok(&self.result)
    //         }
    //         Err(message) => {
    //             error!("Error executing: {}", message);
    //             self.exec_plan.show();
    //             Err(message)
    //         }
    //     }
    // }

    // fn _execute(&self, query: &str) {
    //     let mut parse = Parse::new();

    //     match parse.parse_select(query) {
    //         Ok(expr) => self._search_seq(&expr),
    //         Err(error_list) => {
    //             for e in error_list {
    //                 error!("{}", e);
    //             }
    //         }
    //     }
    // }

    // fn _search_seq(&self, expr: &PqlStatement) {
    //     let interpreter = Interpreter::new(expr.clone());
    //     let t_init = SystemTime::now();

    //     let result: Vec<_> = (0..CONFIG.block_size)
    //         .into_par_iter()
    //         .map(|p| interpreter._run_pgm(p as u32))
    //         .collect();

    //     let mut total: usize = 0;
    //     let mut pkt_list: Vec<u32> = Vec::new();
    //     for r in result.clone() {
    //         total += r.pkt_ptr.len();
    //         for p in r.pkt_ptr {
    //             pkt_list.push(p);
    //         }
    //     }

    //     let mut top_total = 0;
    //     for _ in pkt_list {
    //         if top_total < expr.top {
    //             top_total += 1;
    //         }
    //     }

    //     info!(
    //         "DB exec time: {}ms total: {}",
    //         t_init.elapsed().unwrap().as_millis(),
    //         total
    //     );
    // }

    // fn _read_db_files(&self) {
    //     let files = read_dir(&CONFIG.index_path).unwrap();
    //     for f in files {
    //         if let Ok(file) = f {
    //             let filename: String = file.file_name().into_string().unwrap();
    //             let _fname: Vec<_> = filename.split(".").collect();
    //         }
    //     }
    // }

    // fn execution_plan(&mut self, query: &str) -> Result<Vec<PacketPtr>, String> {
    //     let mut parse = Parse::new();

    //     self.exec_plan.start("Execution plan");
    //     match parse.parse_select(query) {
    //         Ok(expr) => {
    //             self.exec_plan.stop();
    //             Ok(self.search_db(&expr).unwrap())
    //         }
    //         Err(error_list) => {
    //             self.exec_plan.stop();
    //             for e in error_list {
    //                 error!("{}", e);
    //             }
    //             Err("Error in executing pql script".to_string())
    //         }
    //     }
    // }

    // fn search_db(&mut self, expr: &PqlStatement) -> Result<Vec<PacketPtr>, String> {
    //     let index_manager = IndexManager::default();
    //     let interpreter = Interpreter::new(expr.clone());
    //     let index_result: Vec<_>;

    //     // self.exec_plan.start("Index search");
    //     let t_init = SystemTime::now();
    //     if let Some(interval) = &expr.interval {
    //         self.exec_plan.start("Master Index search");
    //         let master_index = index_manager.search_master_index(interval.from, interval.to);
    //         self.exec_plan.stop();
    //         info!("Using master index, {} found", master_index.len());
    //         self.exec_plan.start("Packet index search");
    //         index_result = master_index
    //             .into_par_iter()
    //             .map(|index| index_manager.search_index(&expr, index.file_ptr))
    //             .collect();
    //         self.exec_plan.stop();
    //     } else {
    //         self.exec_plan
    //             .start("Packet index without master index search");
    //         info!("Scanning indexes");
    //         index_result = (0..CONFIG.block_size)
    //             .into_par_iter()
    //             .map(|index| index_manager.search_index(&expr, index as u32))
    //             .collect();
    //         self.exec_plan.stop();
    //     }

    //     // self.exec_plan.stop();

    //     self.exec_plan.start("Packet search");
    //     // let mut result: Vec<PacketPtr> = Vec::new();
    //     // println!("Index: {:?}", index_result.len());
    //     // for si in index_result {
    //     //     let search_result = interpreter.run_pgm_seek(&si);
    //     //     // println!("{:?}", search_result);
    //     //     result.push(search_result);
    //     // }
    //     let result: Vec<_> = index_result
    //         .into_par_iter()
    //         .map(|idx| interpreter.run_pgm_seek(&idx, 0))
    //         .collect();

    //     let mut total: usize = 0;

    //     for ptr in &result {
    //         total += ptr.pkt_ptr.len();
    //     }

    //     let mut top_result: Vec<PacketPtr> = Vec::new();
    //     let mut top_count = 0;
    //     let mut offset = 0;
    //     for ptr in &result {
    //         let mut pkt_ref = PacketPtr::default();
    //         pkt_ref.file_id = ptr.file_id;

    //         for pkt in &ptr.pkt_ptr {
    //             if offset != expr.offset {
    //                 offset += 1;
    //                 continue;
    //             }

    //             if expr.top != 0 {
    //                 if top_count <= expr.top {
    //                     pkt_ref.pkt_ptr.push(*pkt);
    //                     top_count += 1;

    //                     if top_count == expr.top {
    //                         break;
    //                     }
    //                 }
    //             } else {
    //                 pkt_ref.pkt_ptr.push(*pkt);
    //             }
    //         }
    //         top_result.push(pkt_ref);
    //         if top_count == expr.top {
    //             break;
    //         }
    //     }

    //     for p in &top_result {
    //         self._get_fields(&expr.select, &p);
    //     }

    //     info!(
    //         "Index search packets: {} time: {}ms",
    //         total,
    //         t_init.elapsed().unwrap().as_millis()
    //     );

    //     self.exec_plan.stop();
    //     Ok(result)
    // }

    fn _get_fields(&mut self, fields_list: &Vec<SelectField>, packet_list: &PacketPtr) {
        if packet_list.pkt_ptr.len() == 0 {
            return;
        }

        let mut seek_pkt = SeekPacket::new(packet_list.clone());

        while let Some(pkt) = seek_pkt.next() {
            let mut record = Record::default();
            for field in fields_list {
                if let Some(field_value) = get_field_type(field.id, pkt.get_field(field.id)) {
                    record.add_field(Field {
                        name: field.name.clone(),
                        field: field_value,
                    });
                }
            }
            self.result.add_record(record);
        }
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
