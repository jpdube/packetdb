use filetime::FileTime;
use std::fs;

use crate::config::CONFIG;

#[derive(Default, Debug)]
pub struct FileManager {}

impl FileManager {
    pub fn proto_index_filename(&self, file_id: u32, proto_id: u32) -> String {
        format!(
            "{}/{}_{:x}.pidx",
            &CONFIG.proto_index_path, file_id, proto_id
        )
    }

    pub fn index_filename(&self, file_id: u32) -> String {
        format!("{}/{}.pidx", &CONFIG.index_path, file_id)
    }

    pub fn empty_proto_index(&self) {}

    pub fn proto_index_list(&self) -> Vec<String> {
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
}
