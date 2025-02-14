use crate::config::CONFIG;
// use anyhow::Result;
use rusqlite::Connection;

struct FileID {
    file_id: usize,
}

#[derive(Default, Debug)]
pub struct DBConfig {}

impl DBConfig {
    pub fn next_fileid(&mut self) -> u32 {
        let conn = Connection::open(format!("{}/master.db", &CONFIG.master_index_path)).unwrap();

        let mut stmt = conn
            .prepare("select file_id from config where id = 1;")
            .unwrap();

        let fileid_iter = stmt
            .query_map([], |row| {
                Ok(FileID {
                    file_id: row.get(0).unwrap(),
                })
            })
            .unwrap();

        let mut file_id: usize = 0;
        for c in fileid_iter {
            file_id = c.unwrap().file_id;
        }

        self.increment_fileid(file_id as u32);

        file_id as u32
    }

    fn increment_fileid(&mut self, file_id: u32) {
        let conn = Connection::open(format!("{}/master.db", &CONFIG.master_index_path)).unwrap();

        let sql = "update config set file_id = ? where id = 1;";

        let _ = conn.execute(sql, [file_id + 1]);
    }
}
