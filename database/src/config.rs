use log::error;
use serde_derive::Deserialize;
use std::env;
use std::fs;
use std::process::exit;
use toml;

lazy_static! {
    pub static ref CONFIG: Config = read();
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub db_path: String,
    pub index_path: String,
    pub master_index_path: String,
    pub db_segment_size: usize,
    pub block_size: usize,
}

pub fn read() -> Config {
    match &env::var("PACKETDB_CONFIG") {
        Ok(config_file) => {
            let contents = match fs::read_to_string(config_file) {
                Ok(c) => c,
                Err(_) => {
                    error!("Could not read config file `{}`", config_file);
                    exit(1);
                }
            };

            let data: Config = match toml::from_str(&contents) {
                Ok(d) => d,
                Err(_) => {
                    error!("Unable to load data from `{}`", config_file);
                    exit(1);
                }
            };

            return data;
        }
        Err(_) => {
            error! {"PACKETDB_CONFIG env variable is not defined"}
            exit(1);
        }
    };
}
