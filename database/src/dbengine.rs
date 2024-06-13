use crate::config::CONFIG;
use crate::exec_plan::ExecutionPlan;
use crate::index_manager::IndexManager;
use crate::interpreter::Interpreter;
use crate::parse::Parse;
use crate::pkt_index::PktIndex;
use crate::query_result::QueryResult;

use anyhow::Result;
use log::info;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug, Default)]
pub struct DbEngine {
    result: QueryResult,
    exec_plan: ExecutionPlan,
    offset: usize,
}

impl DbEngine {
    pub fn new() -> Self {
        Self {
            result: QueryResult::default(),
            exec_plan: ExecutionPlan::default(),
            offset: 0,
        }
    }

    pub fn run(&mut self, query: &str) -> Result<&QueryResult, String> {
        println!("Searching for: {}", query);
        let mut parse = Parse::new();

        self.exec_plan.start("Start search");
        if let Ok(expr) = parse.parse_select(query) {
            let mut count: usize = 0;
            let mut top_limit: usize = expr.top;
            let mut file_count = 0;
            let top_offset: usize = expr.top + expr.offset;

            self.offset = 0;

            let mut pkt_index = PktIndex::default();
            println!("Top: {}, Offset: {}", expr.top, expr.offset);
            match self.get_index_files() {
                Ok(pkt_list) => {
                    for file_id in pkt_list {
                        file_count += 1;
                        let interpreter = Interpreter::new(expr.clone());
                        let ptr = pkt_index.search_index(&expr, file_id);

                        let result = interpreter.run_pgm_seek(&ptr, top_limit);
                        count += result.len();
                        top_limit = top_offset - count;

                        for r in result {
                            if self.offset < expr.offset {
                                self.offset += 1;
                                continue;
                            } else {
                                self.result.add_record(r);
                            }
                        }

                        if count >= top_offset {
                            println!("len: {}", count);
                            break;
                        }
                    }

                    info!("Nbr files searched: {}", file_count);
                }
                Err(e) => println!("Error with index error:{}", e),
            }
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
