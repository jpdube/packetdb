pub mod api_server;
pub mod jwebtoken;

use crate::api_server::web_main;
use database::config::CONFIG;
use database::dbengine::DbEngine;
use database::file_manager::FileManager;
use database::init_db::InitDb;
use database::proto_index::ProtoIndex;
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

    #[arg(long, default_value_t = false)]
    proto_index: bool,

    #[arg(long, default_value_t = false)]
    proto_file: bool,
}

fn process_params() {
    env::set_var("RUST_LOG", "debug");

    let args = Args::parse();
    env_logger::init();

    if args.config.len() > 0 {
        env::set_var("PACKETDB_CONFIG", args.config);
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

    if args.proto_file {
        let fm = FileManager::default();
        fm.proto_index_list();
        // println!("{:#?}", fm.proto_index_list());
    }

    if args.proto_index {
        let mut proto_index = ProtoIndex::new(99_999_999, 128);
        for i in 0..8 {
            proto_index.add(&(i as u32));
        }

        proto_index.create_index();

        proto_index.clear();
        for i in 0..8 {
            proto_index.add(&(i as u32));
        }

        proto_index.append();

        proto_index.clear();
        for i in 0..16 {
            proto_index.add(&(i as u32));
        }

        proto_index.append();
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
