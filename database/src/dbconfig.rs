use crate::config::CONFIG;
use anyhow::Result;
use rusqlite::Connection;

struct FileID {
    file_id: usize,
}

#[derive(Default, Debug)]
pub struct DBConfig {}

impl DBConfig {
    pub fn next_fileid(&mut self) -> Result<u32> {
        let path = format!("{}/master.db", &CONFIG.master_index_path);

        let conn = Connection::open(path)?;

        let mut stmt = conn.prepare("select file_id from config where id = 1;")?;

        let fileid_iter = stmt
            .query_map([], |row| {
                Ok(FileID {
                    file_id: row.get(0)?,
                })
            })
            .unwrap();

        let mut file_id: usize = 0;
        for c in fileid_iter {
            file_id = c.unwrap().file_id;
        }

        let inc_sql = "update config set file_id = ? where id = 1;";

        let _ = conn.execute(inc_sql, [file_id + 1]);

        Ok(file_id as u32)
    }
}
