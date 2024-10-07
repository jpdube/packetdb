use crate::config::CONFIG;
use crate::cursor::Cursor;
use crate::exec_plan::ExecutionPlan;
use crate::index_manager::{IndexManager, ProtoStat};
use crate::interpreter::Interpreter;
use crate::parse::{Parse, PqlStatement};
use crate::query_result::QueryResult;

use anyhow::Result;
use log::{debug, info};
use rayon::prelude::*;
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

        debug!("==================================================");
        self.exec_plan.start("Start search");
        if let Ok(expr) = parse.parse_select(query) {
            debug!("--> Select query: {}", expr);

            let mut query_result = QueryResult::new(expr.clone());

            let mut file_count = 0;
            let interpreter = Interpreter::new(expr.clone());

            self.offset = 0;
            println!("Chunk size: {}", self.chunk_size(&expr));
            let nbr_cores = self.chunk_size(&expr);

            match self.get_index_files() {
                Ok(pkt_list) => {
                    while !query_result.count_reach() {
                        for chunk_id in pkt_list.chunks(nbr_cores) {
                            file_count += nbr_cores;

                            let interp_result: Vec<_> = chunk_id
                                .into_par_iter()
                                .map(|file_id| {
                                    let mut pkt_index = IndexManager::default();
                                    let ptr = pkt_index.search_index(&expr, *file_id);

                                    interpreter.run_pgm_seek(&ptr, expr.top)
                                })
                                .collect();

                            for c in interp_result {
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
                            if query_result.count_reach() {
                                break;
                            }
                        }
                        info!("Nbr files searched: {}", file_count);
                    }
                }
                Err(e) => println!("Error with index error:{}", e),
            }

            self.exec_plan.stop();
            self.exec_plan.show();
            Ok(query_result.get_result())
        } else {
            Err(String::from("Error reading database"))
        }
    }

    // pub fn run(&mut self, query: &str) -> Result<&Cursor, String> {
    //     println!("Searching for: {}", query);
    //     let mut parse = Parse::new();

    //     self.exec_plan.start("Start search");
    //     if let Ok(expr) = parse.parse_select(query) {
    //         let query_result = QueryResult::new(expr);

    //         let mut count: usize = 0;
    //         let mut top_limit: usize = expr.top;
    //         let mut file_count = 0;
    //         let top_offset: usize = expr.top + expr.offset;
    //         let mut stop = false;
    //         let interpreter = Interpreter::new(expr.clone());

    //         self.offset = 0;
    //         println!("Chunk size: {}", self.chunk_size(&expr));
    //         let nbr_cores = self.chunk_size(&expr);

    //         // println!("Top: {}, Offset: {}", expr.top, expr.offset);
    //         match self.get_index_files() {
    //             Ok(pkt_list) => {
    //                 while !stop {
    //                     for chunk_id in pkt_list.chunks(nbr_cores) {
    //                         file_count += nbr_cores;

    //                         let interp_result: Vec<_> = chunk_id
    //                             .into_par_iter()
    //                             .map(|file_id| {
    //                                 let mut pkt_index = IndexManager::default();
    //                                 let ptr = pkt_index.search_index(&expr, *file_id);

    //                                 interpreter.run_pgm_seek(&ptr, top_limit)
    //                             })
    //                             .collect();

    //                         for r in &interp_result {
    //                             count += r.len();
    //                         }

    //                         top_limit = top_offset - count;

    //                         let mut result_count = 0;
    //                         if count >= top_offset {
    //                             println!("len: {}", count);
    //                             for c in interp_result {
    //                                 for r in c {
    //                                     if self.offset < expr.offset {
    //                                         self.offset += 1;
    //                                         continue;
    //                                     } else {
    //                                         if result_count < expr.top {
    //                                             self.result.add_record(r);
    //                                             result_count += 1;
    //                                         } else {
    //                                             break;
    //                                         }
    //                                     }
    //                                 }
    //                             }

    //                             stop = true;
    //                             break;
    //                         }
    //                     }

    //                     info!("Nbr files searched: {}", file_count);
    //                 }
    //             }
    //             Err(e) => println!("Error with index error:{}", e),
    //         }
    //     }

    //     self.exec_plan.stop();
    //     self.exec_plan.show();
    //     Ok(&self.result)
    // }

    fn chunk_size(&self, expr: &PqlStatement) -> usize {
        let ix_manager = IndexManager::default();
        let search_proto = ix_manager.build_search_index(&expr.search_type);
        let proto_stat = ProtoStat::new(0);

        let avg_file = proto_stat.get_count_stats(search_proto);

        let mut chunk_size: usize = 2;

        if avg_file != 0 {
            chunk_size = (&expr.top + &expr.offset) / avg_file;
            println!(
                "Chunk size raw: Proto: {search_proto}, top: {}, Avg: {avg_file}, chunk: {chunk_size}",
                &expr.top
            );

            if chunk_size == 0 {
                chunk_size = 1;
            }

            if chunk_size > 8 {
                chunk_size = 8;
            }
        }

        chunk_size
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
