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
use dblib::config::CONFIG;
use field::field_type;
use field::pfield::Field;
use pcap::pcapfile::PcapFile;
use std::time::Instant;

pub fn packet_to_db(packet_file: u32, table_name: &str) {
    let mut pcap_file = PcapFile::new(packet_file, &CONFIG.db_path);

    let mut db = DBTable::new(&format!("/opt/pcapdb/{}", table_name));
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

    let mut data: Vec<Record> = Vec::new();

    let mut count = 0;
    let start = Instant::now();
    while let Some(pkt) = pcap_file.next() {
        count += 1;

        let mut row = Record::default();

        row.add(pkt.get_field("frame.timestamp").unwrap());
        row.add(pkt.get_field("frame.inclen").unwrap());
        row.add(pkt.get_field("frame.origlen").unwrap());
        if pkt.has_ipv4() {
            row.add(pkt.get_field("ip.src").unwrap());
            row.add(pkt.get_field("ip.dst").unwrap());
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

        data.push(row);
    }

    let dl = data.len();
    db.append(data).unwrap();

    let duration = start.elapsed();
    println!(
        "Packet import time: {:4.2}s per row: {:4.2}us",
        duration.as_secs_f32(),
        (duration.as_secs_f32() / dl as f32) * 1_000_000.0
    );
    println!("Read {} packets", count);
}
