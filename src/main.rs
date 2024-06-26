use actix_cors::Cors;
use database::config::CONFIG;
use database::dbengine::DbEngine;
use log::info;
use serde_json::Value;
use std::collections::BTreeMap;
use std::{env, process};

use clap::Parser;

use actix_web::{
    http::header, middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder,
};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = String::new())]
    config: String,

    #[arg(short, long, default_value_t = false)]
    index: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Command {
    command: String,
}

#[derive(Serialize, Debug)]
pub struct CmdResponse<'a> {
    success: bool,
    result: Vec<BTreeMap<&'a str, Value>>,
}

#[post("/execute")]
async fn execute(name: web::Json<Command>) -> impl Responder {
    let mut db = DbEngine::new();
    let response = db.run(&name.command);
    // let response = db.exec_script(&name.command);
    let result = CmdResponse {
        success: true,
        result: response.unwrap().to_json(),
    };

    HttpResponse::Ok().json(result)
}

fn process_params() {
    env::set_var("RUST_LOG", "info");

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

// fn main() {
//     about();
//     process_params();

//     let mut db = DbEngine::new();
//     db.run();
// let index = IndexManager::default();
// let query =
//     "select tcp.dport, tcp.sport from a where tcp.dport == HTTPS or tcp.sport == HTTPS top 10;";
// let mut parse = Parse::new();

// let pql = parse.parse_select(query).unwrap();
// let mut plan = ExecutionPlan::default();
// plan.start("Index search");
// let result = index.search(&pql);
// plan.stop();
// plan.show();
// println!("Index count: {}", result.pkt_ptr.len());
// }

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    web_main().await?;
    Ok(())
}

async fn web_main() -> std::io::Result<()> {
    // load TLS keys
    // to create a self-signed temporary cert for testing:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'`
    about();
    process_params();

    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    builder
        .set_private_key_file("./misc/key.pem", SslFiletype::PEM)
        .unwrap();
    builder
        .set_certificate_chain_file("./misc/cert.pem")
        .unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(
                Cors::default()
                    .allowed_origin("http://localhost:9000")
                    .allowed_origin_fn(|origin, _req_head| {
                        origin.as_bytes().ends_with(b".localhost")
                    })
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                    .allowed_header(header::CONTENT_TYPE)
                    .allowed_header(header::AUTHORIZATION)
                    .supports_credentials()
                    .max_age(3600),
            )
            .wrap(Logger::default())
            .service(execute)
    })
    .bind("localhost:9001")?
    // .bind_openssl("localhost:7443", builder)?
    .run()
    .await
}

fn about() {
    println!("-----------------------");
    println!("Numa informatique Inc.");
    println!("Packet server");
    println!("Version 0.1");
    println!("-----------------------");
}
