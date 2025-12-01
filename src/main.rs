pub mod api_server;
pub mod jwebtoken;

use crate::api_server::web_main;
use database::dbengine::DbEngine;
use database::init_db::InitDb;
use datastore::test_db::test_db;
use dblib::config::CONFIG;
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

fn process_params() {
    unsafe {
        env::set_var("RUST_LOG", "debug");
    }

    let args = Args::parse();
    env_logger::init();

    if !args.config.is_empty() {
        unsafe {
            env::set_var("PACKETDB_CONFIG", args.config);
        }
        let init_db = InitDb::default();
        init_db.init_db().unwrap();
    }

    if !args.capture.is_empty() {
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
