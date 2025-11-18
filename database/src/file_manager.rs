use anyhow::Result;
use filetime::FileTime;
use std::fs;
use std::path::Path;

use dblib::config::CONFIG;

pub fn clean_indexes() {
    clean_index();
    clean_proto_index();
}

pub fn clean_proto_index() {
    let paths: Vec<_> = fs::read_dir(&CONFIG.proto_index_path)
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    for path in paths {
        println!("Deleting: {:?}", path.path());
        fs::remove_dir_all(&path.path()).unwrap();
    }
}

pub fn clean_index() {
    let paths: Vec<_> = fs::read_dir(&CONFIG.index_path)
        .unwrap()
        .map(|r| r.unwrap())
        .collect();

    for path in paths {
        println!("Deleting: {:?}", path.path());
        fs::remove_file(&path.path()).unwrap();
    }
}

pub fn proto_index_filename(file_id: u32, proto_id: u32) -> String {
    format!(
        "{}/{}_{:x}.pidx",
        &CONFIG.proto_index_path, file_id, proto_id
    )
}

pub fn index_filename(file_id: u32) -> String {
    format!("{}/{}.pidx", &CONFIG.index_path, file_id)
}

pub fn path_exists(path_name: &str) -> bool {
    let path = Path::new(path_name);
    if path.exists() && path.is_dir() {
        // println!("The directory exists.");
        return true;
    } else {
        // println!("The directory does not exist.");
        return false;
    }
}

pub fn create_path(path_name: &str) -> Result<()> {
    if !path_exists(path_name) {
        fs::create_dir(path_name)?;
    }
    return Ok(());
}

pub fn proto_index_list() -> Vec<String> {
    let mut result: Vec<String> = Vec::new();

    let mut paths: Vec<_> = fs::read_dir(&CONFIG.index_path)
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    paths.sort_by_key(|dir| {
        FileTime::from_creation_time(&dir.metadata().unwrap())
            .unwrap()
            .nanoseconds()
    });
    for path in paths {
        println!(
            "Name: {} -> {:?}",
            path.path().display(),
            FileTime::from_last_modification_time(&path.metadata().unwrap()).nanoseconds()
        );
        result.push(path.file_name().into_string().unwrap());
    }

    result
}
