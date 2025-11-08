pub mod api_server;
pub mod jwebtoken;

use crate::api_server::web_main;
use database::config::CONFIG;
use database::dbengine::DbEngine;
use database::dbstorage::{DBStorage, Row, Schema};
use database::init_db::InitDb;
use frame::field_type;
use frame::pfield::{Field, FieldType};
use log::info;
use sniffer::capture::capture;
use std::{env, process};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = String::new())]
    config: String,

    #[arg(short, long, default_value_t = false)]
    index: bool,

    #[arg(long, default_value_t = String::new())]
    capture: String,

    #[arg(short, long, default_value_t = false)]
    testdb: bool,
}
fn test_db() {
    // let mut db_file = DBFile::new("zzzzzzz".to_string());
    // db_file.create_file().unwrap();
    // let mut dbnode = DbSegment::new("/opt/pcapdb/test.db".to_string(), 0);

    // dbnode.create().unwrap();
    // dbnode.add_record().unwrap();

    let mut dbwriter = DBStorage::new("/opt/pcapdb/test_raw.pdb".to_string());

    let mut fields_def: Vec<Schema> = Vec::new();
    fields_def.push(Schema::new(field_type::IPV4, "ip.src".to_string()));

    fields_def.push(Schema::new(field_type::IPV4, "ip.dst".to_string()));

    fields_def.push(Schema::new(field_type::INT16, "tcp.dport".to_string()));

    fields_def.push(Schema::new(field_type::INT16, "tcp.sport".to_string()));
    fields_def.push(Schema::new(field_type::STRING, "port_name".to_string()));

    dbwriter.define_fields(fields_def);
    dbwriter.create().unwrap();

    let mut row = Row::new();
    row.add(Field::set_field(
        FieldType::Ipv4(0xc0a80310, 32),
        "ip.src".to_string(),
    ));
    row.add(Field::set_field(
        FieldType::Ipv4(0xc0a802b1, 32),
        "ip.dst".to_string(),
    ));

    row.add(Field::set_field(FieldType::Int16(443), "dport".to_string()));

    row.add(Field::set_field(
        FieldType::Int16(31234),
        "sport".to_string(),
    ));

    row.add(Field::set_field(
        FieldType::String("iface_01".to_string()),
        "iface.name".to_string(),
    ));

    let mut data: Vec<Row> = Vec::new();
    for _ in 0..4096 {
        data.push(row.clone());
    }

    dbwriter.append(data).unwrap();

    dbwriter.read_record().unwrap();
}

fn process_params() {
    unsafe {
        env::set_var("RUST_LOG", "debug");
    }

    let args = Args::parse();
    env_logger::init();

    if args.config.len() > 0 {
        unsafe {
            env::set_var("PACKETDB_CONFIG", args.config);
        }
        let init_db = InitDb::default();
        init_db.init_db().unwrap();
    }

    if args.capture.len() > 0 {
        match capture(&args.capture) {
            Ok(()) => println!("Capture sucessfull"),
            Err(msg) => eprintln!("Error capturing: {}", msg),
        }
    }

    if args.index {
        let db = DbEngine::new();
        db.create_index();
        process::exit(0);
    }

    if args.testdb {
        test_db();
        process::exit(0);
    }

    info!("Config: {}", CONFIG.db_path);
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    about();

    process_params();
    web_main().await?;

    Ok(())
}

fn about() {
    println!("-----------------------");
    println!("Numa informatique Inc.");
    println!("Packet server");
    println!("Version 0.1");
    println!("-----------------------");
}
