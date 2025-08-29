use actix_cors::Cors;
use database::dbengine::DbEngine;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeMap;

use actix_web::{
    http::header, middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder,
};

use actix_web::web::Json;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use crate::jwebtoken::{get_jwt, User};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Command {
    command: String,
}

#[derive(Serialize, Debug)]
pub struct CmdResponse {
    success: bool,
    result: Vec<BTreeMap<String, Value>>,
}

#[post("/execute")]
async fn execute(name: web::Json<Command>) -> impl Responder {
    let mut db = DbEngine::new();
    let response = db.run(&name.command).unwrap().clone();
    let result = CmdResponse {
        success: true,
        result: response.to_json(),
    };

    HttpResponse::Ok().json(result)
}

#[post("/login")]
async fn login(Json(user): Json<User>) -> HttpResponse {
    println!("User info: {:?}", user);

    let token = get_jwt(user);

    match token {
        Ok(token) => HttpResponse::Ok().json(json!({
          "success": true,
          "data": {
            "token": token
          }
        })),

        Err(error) => HttpResponse::BadRequest().json(json!({
          "success": false,
          "data": {
            "message": error
          }
        })),
    }
}

pub async fn web_main() -> std::io::Result<()> {
    // load TLS keys
    // to create a self-signed temporary cert for testing:
    // `openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj '/CN=localhost'`

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
            .service(login)
    })
    // .bind("0.0.0.0:9001")?
    .bind_openssl("0.0.0.0:7443", builder)?
    .run()
    .await
}

fn _get_hash_pwd(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn _validate_pwd(password: &str, password_hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}
