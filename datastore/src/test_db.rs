use crate::packet_to_db;
use crate::record::Record;
use crate::schema::Schema;
use crate::table::DBTable;
use crate::table_index::TableIndex;
use field::field_type;
use field::pfield::{Field, FieldType};

pub fn test_db() {
    packet_to_db(0, "packet_table");
}

pub fn _test_db_logic() {
    let mut db = DBTable::new("/opt/pcapdb/new_table");
    db.create_table(
        vec![
            Schema::new(field_type::IPV4, "ip.src"),
            Schema::new(field_type::IPV4, "ip.dst"),
            Schema::new(field_type::INT16, "tcp.dport"),
            Schema::new(field_type::INT16, "tcp.sport"),
            Schema::new(field_type::STRING, "iface.name"),
            Schema::new(field_type::BYTE_ARRAY, "raw_packet"),
        ],
        vec![
            Schema::new(field_type::IPV4, "ip.src"),
            Schema::new(field_type::INT16, "tcp.dport"),
        ],
    )
    .unwrap();

    let mut data: Vec<Record> = Vec::new();
    let mut raw_packet: Vec<u8> = Vec::new();
    raw_packet.resize(300, 0xaa);

    let mut j: u16 = 0;
    for i in 0..50_000 {
        let mut row = Record::default();

        if i % 2 == 0 {
            row.add(Field::set_field(FieldType::Ipv4(0xc0a80310, 32), "ip.src"));
        } else {
            row.add(Field::set_field(FieldType::Ipv4(0xc0a801aa, 32), "ip.src"));
        }
        row.add(Field::set_field(FieldType::Ipv4(0xc0a802b1, 32), "ip.dst"));

        row.add(Field::set_field(FieldType::Int16(443), "tcp.dport"));

        if j > 65535 - 1024 {
            j = 0;
        } else {
            j += 1;
        }
        row.add(Field::set_field(FieldType::Int16(j + 1024), "tcp.sport"));

        row.add(Field::set_field(
            FieldType::String(format!("iface-0{}", i * i)),
            "iface.name",
        ));

        row.add(Field::set_field(
            FieldType::ByteArray(raw_packet.clone()),
            "raw_packet",
        ));

        data.push(row);
    }

    db.append(data).unwrap();

    let mut ip_src_idx = TableIndex::new(
        "/opt/pcapdb/new_table",
        Schema::new(field_type::IPV4, "ip.src"),
    );
    ip_src_idx.read().unwrap();
    db.read_record().unwrap();
}
