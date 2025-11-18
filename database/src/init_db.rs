use anyhow::Result;
use dblib::config::CONFIG;
use log::info;
// use remove_dir_all::remove_dir_contents;
use rusqlite::Connection;

#[derive(Default, Debug)]
pub struct InitDb {}

impl InitDb {
    pub fn init_db(&self) -> Result<()> {
        let mfile_name = format!("{}/master.db", &CONFIG.master_index_path);
        let conn = Connection::open(&mfile_name)?;

        info!("Checking and creating config table: {}", mfile_name);
        conn.execute(
            r#"create table if not exists config (
               id integer primary key,
               file_id integer
            );"#,
            [],
        )?;

        conn.execute(
            r#"create table if not exists capture (
                id integer primary key,
                name varchar(60),
                folder varchar(250),
                iface varchar(20),
                packets_per_file integer,
                filter varchar(2048)
            );"#,
            [],
        )?;

        Ok(())
    }
}
