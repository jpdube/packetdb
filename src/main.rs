pub mod api_server;
pub mod jwebtoken;

use database::config::CONFIG;
use database::dbengine::DbEngine;
use log::info;
use std::{env, process};

use crate::api_server::web_main;
use clap::Parser;
use sniffer::capture::capture;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = String::new())]
    config: String,

    #[arg(short, long, default_value_t = false)]
    index: bool,
}

fn process_params() {
    env::set_var("RUST_LOG", "debug");

    let args = Args::parse();
    env_logger::init();

    if args.config.len() > 0 {
        env::set_var("PACKETDB_CONFIG", args.config);
    }

    if args.index {
        let db = DbEngine::new();
        db.create_index();
        process::exit(0);
    }

    info!("Config: {}", CONFIG.db_path);
}

fn main() {
    about();
    match capture("en0") {
        Ok(_) => println!("Success"),
        Err(msg) => println!("Error: {}", msg),
    }
}
// #[actix_web::main]
// async fn main() -> std::io::Result<()> {
//     about();
//     process_params();
//     web_main().await?;
//     Ok(())
// }

fn about() {
    println!("-----------------------");
    println!("Numa informatique Inc.");
    println!("Packet server");
    println!("Version 0.1");
    println!("-----------------------");
}
