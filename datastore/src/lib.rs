pub mod cursor;
pub mod index_meta;
pub mod record;
pub mod row;
pub mod schema;
pub mod table;
pub mod table_index;
pub mod test_db;

use crate::record::Record;
use crate::schema::Schema;
use crate::table::DBTable;
use anyhow::{Result, anyhow};
use dblib::config::CONFIG;
use field::field_type;
use field::pfield::Field;
use pcap::pcapfile::PcapFile;
use rayon::prelude::*;
use std::fs;
use std::path::Path;
use std::time::Instant;

pub fn packet_to_db(packet_file: u32, table_name: &str) -> Result<()> {
    let mut pcap_file = PcapFile::new(packet_file, &CONFIG.db_path);

    let mut db = DBTable::new(&format!("/opt/pcapdb/db/import/{}", table_name));
    db.create_table(
        vec![
            Schema::new(field_type::INT32, "frame.timestamp"),
            Schema::new(field_type::INT32, "frame.inclen"),
            Schema::new(field_type::INT32, "frame.origlen"),
            Schema::new(field_type::IPV4, "ip.src"),
            Schema::new(field_type::IPV4, "ip.dst"),
            Schema::new(field_type::BYTE_ARRAY, "frame.packet"),
        ],
        vec![
            Schema::new(field_type::IPV4, "ip.src"),
            Schema::new(field_type::INT16, "ip.dst"),
            Schema::new(field_type::INT16, "frame.timestamp"),
        ],
    )
    .unwrap();

    let mut count = 0;
    let start = Instant::now();
    while let Some(pkt) = pcap_file.next() {
        count += 1;

        let mut row = Record::default();

        if let Some(field_ts) = pkt.get_field("frame.timestamp") {
            row.add(field_ts);
        } else {
            return Err(anyhow!(format!("Field not found: {}", "frame.timestamp")));
        }

        if let Some(field_inclen) = pkt.get_field("frame.inclen") {
            row.add(field_inclen);
        } else {
            return Err(anyhow!(format!("Field not found: {}", "frame.inclen")));
        }

        if let Some(field_origlen) = pkt.get_field("frame.origlen") {
            row.add(field_origlen);
        } else {
            return Err(anyhow!(format!("Field not found: {}", "frame.origlen")));
        }

        if pkt.has_ipv4() {
            if let Some(field_ipsrc) = pkt.get_field("ip.src") {
                row.add(field_ipsrc);
            } else {
                return Err(anyhow!(format!("Field not found: {}", "ip.ip_src")));
            }
            if let Some(field_ipdst) = pkt.get_field("ip.dst") {
                row.add(field_ipdst);
            } else {
                return Err(anyhow!(format!("Field not found: {}", "ip.ip_dst")));
            }
        } else {
            row.add(Field::set_field(
                field::pfield::FieldType::Ipv4(0, 0),
                "ip.src",
            ));
            row.add(Field::set_field(
                field::pfield::FieldType::Ipv4(0, 0),
                "ip.dst",
            ));
        }

        row.add(pkt.get_bytes().unwrap());

        db.add_record(row)?;
    }

    db.flush()?;

    let duration = start.elapsed();
    println!(
        "Packet import time: {:4.2}s per row: {:4.2}us",
        duration.as_secs_f32(),
        (duration.as_secs_f32() / count as f32) * 1_000_000.0
    );
    println!("Read {} packets", count);

    Ok(())
}

pub fn mass_import_packet() -> Result<()> {
    if let Ok(files_list) = get_packet_files() {
        let result: Vec<Result<(), anyhow::Error>> = files_list
            .clone()
            .into_par_iter()
            .map(|pkt_file| packet_to_db(pkt_file, &format!("packet_{}", pkt_file)))
            .collect();

        println!("Save index result: {:?}", result);

        // for f in files_list {
        //     eprintln!("Importing packet: {f}");
        //     packet_to_db(f, &format!("packet_{}", f))?;
        // }
    }

    Ok(())
}

fn get_packet_files() -> Result<Vec<u32>> {
    let pcap_path = &CONFIG.db_path.to_string();
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
