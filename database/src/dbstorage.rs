use anyhow::Result;
use frame::pfield::{Field, FieldType};
use rusqlite::Connection;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::Instant;

pub struct DBStorage {
    segment_width: usize,
    segment_size: usize,
    current_db: usize,
    segments: Vec<DbSegment>,
}

impl DBStorage {
    pub fn new() -> Self {
        let mut my_self = DBStorage {
            segment_width: 4,
            segment_size: 4,
            current_db: 0,
            segments: Vec::new(),
        };

        for i in 0..my_self.segment_width {
            let seg = DbSegment::new(format!("/opt/pcapdb/test/1_{}.db", i), 2);
            my_self.segments.push(seg);
        }

        my_self
    }

    pub fn create(&mut self) {
        println!("Segment list: {:#?}", self.segments);
        for s in &mut self.segments {
            s.create().unwrap();

            let mut field_list: Vec<Field> = Vec::new();
            field_list.push(Field::set_field(
                FieldType::Ipv4(0xc0a80301, 32),
                "ip.src".to_string(),
            ));
            field_list.push(Field::set_field(
                FieldType::Ipv4(0xc0a80301, 32),
                "ip.dst".to_string(),
            ));
            field_list.push(Field::set_field(
                FieldType::Int16(443),
                "tcp.dport".to_string(),
            ));
            let create_sql = s.build_create_table(field_list);
            println!("{}", create_sql);
        }
    }
}

#[derive(Debug)]
pub struct DbSegment {
    filename: String,
    // segment_size: usize,
    // recv: Receiver<String>,
    // xmit: Sender<String>,
}

impl DbSegment {
    pub fn new(filename: String, segment_size: usize) -> Self {
        // let (tx, rx) = mpsc::channel();

        Self {
            filename,
            // // segment_size,
            // recv: rx,
            // xmit: tx,
        }
    }

    // pub fn start(&self) {
    //     thread::spawn(|| {
    //         let sql = "INSERT INTO";

    //         for file_id in &self.recv {}
    //     });
    // }

    pub fn add(&mut self, _field: String) {}

    pub fn create(&mut self) -> Result<()> {
        let conn = Connection::open(&self.filename)?;

        conn.execute_batch(
            "PRAGMA journal_mode = MEMORY;
                    PRAGMA cache_size = 1000000;
                    PRAGMA temp_store = MEMORY;
                    PRAGMA threads=4;",
        )
        .expect("PRAGMA");

        conn.execute(
            "create table packet_data (id integer primary key, 
                                    ts integer, ip_src integer, ip_dst integer, 
                                    tcp_dport integer, tcp_sport integer);",
            [],
        )?;

        // conn.execute(
        //     "create index if not exists timestamp_idx on packet_data(ts);",
        //     [],
        // )?;

        Ok(())
    }

    fn build_create_table(&mut self, field_list: Vec<Field>) -> String {
        let mut sql = String::new();

        sql += "CREATE TABLE packet_data (
                    id integer primary key,
                    ts integer,";

        for (idx, f) in field_list.iter().enumerate() {
            sql += &f.name;

            match f.field {
                FieldType::Int64(_)
                | FieldType::Int32(_)
                | FieldType::Ipv4(_, _)
                | FieldType::Int16(_) => sql += &format!(" INTEGER"),
                _ => sql += "",
            }

            if idx < field_list.len() - 1 {
                sql += ","
            }
        }

        sql += ");";

        sql
    }

    pub fn add_record(&mut self) -> Result<()> {
        let sql = "insert into packet_data (ts, ip_src, ip_dst, tcp_dport, tcp_sport) values (?,?,?,?,?);";
        let mut conn = Connection::open(self.filename.clone())?;

        const ROW_COUNT: usize = 1_000_000;

        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = normal;")
            .expect("PRAGMA");

        let tx = conn.transaction()?;
        tx.prepare(sql)?;
        let start = Instant::now();
        for i in 0..ROW_COUNT {
            tx.execute(sql, [i, i + 1, i + 2, i + 3, i + 4])?;
        }

        tx.commit()?;
        let duration = start.elapsed();

        println!(
            "Execution time: {}ms, per row: {}us",
            duration.as_millis(),
            (duration.as_secs_f64() / ROW_COUNT as f64) * 1_000_000.0
        );

        Ok(())
    }

    fn _write_db(&mut self, _sql_insert: &str) -> Result<()> {
        // let conn = Connection::open(&self.filename)?;

        Ok(())
    }
}

use byteorder::{BigEndian, WriteBytesExt};
use std::fs;
use std::fs::File;
use std::io::BufWriter;

pub struct Row {
    pub ip_src: u32,
    pub ip_dst: u32,
    pub dport: u16,
    pub sport: u16,
}

pub struct DbWriter {
    filename: String,
    magic_no: u32,
    version: u16,
}

impl DbWriter {
    pub fn new(filename: String) -> Self {
        Self {
            filename,
            magic_no: 0xa1b2c3d4,
            version: 1,
        }
    }

    pub fn create(&mut self) {
        let mut writer = BufWriter::new(File::create(&self.filename).unwrap());

        //--- Write header
        writer.write_u32::<BigEndian>(self.magic_no).unwrap();
        writer.write_u16::<BigEndian>(self.version).unwrap();
    }

    pub fn append(&mut self, data: Vec<Row>) {
        let start = Instant::now();
        let mut writer = BufWriter::new(
            fs::OpenOptions::new()
                // .create(true)
                .append(true)
                .open(&self.filename)
                .unwrap(),
        );

        for row in &data {
            writer.write_u32::<BigEndian>(row.ip_src).unwrap();
            writer.write_u32::<BigEndian>(row.ip_dst).unwrap();
            writer.write_u16::<BigEndian>(row.dport).unwrap();
            writer.write_u16::<BigEndian>(row.sport).unwrap();
        }

        let duration = start.elapsed();

        println!(
            "Execution time: {}us per row: {}ns",
            duration.as_micros(),
            (duration.as_secs_f32() / data.len() as f32) * 1_000_000_000.0
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_db_insert() {
        let mut dbnode = DbSegment::new("/opt/pcapdb/test.db".to_string(), 0);

        dbnode.create().unwrap();
        dbnode.add_record().unwrap();
        assert_eq!(true, true, "Command options");
    }
}
