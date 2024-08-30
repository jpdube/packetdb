use std::usize;

use frame::packet::Packet;

use crate::cursor::{get_field_type, Cursor, Field, Record};
use crate::parse::PqlStatement;
use frame::fields::FRAME_TIMESTAMP;
use log::debug;

pub struct QueryResult {
    model: PqlStatement,
    ts_start: usize,
    ts_end: usize,
    result: Cursor,
    offset: usize,
}

impl QueryResult {
    pub fn new(model: PqlStatement) -> Self {
        Self {
            model,
            ts_start: usize::max_value(),
            ts_end: 0,
            result: Cursor::default(),
            offset: 0,
        }
    }

    pub fn count_reach(&self) -> bool {
        // println!("COUNT REACHED: {}:{}", self.result.len(), self.model.top);
        self.result.len() >= self.model.top
    }

    pub fn add(&mut self, pkt: &Packet) {
        if self.model.offset > 0 && self.offset < self.model.offset {
            self.offset += 1;
            return;
        }

        let mut record = Record::default();
        for field in &self.model.select {
            if let Some(field_value) = get_field_type(field.id, pkt.get_field(field.id)) {
                record.add_field(Field {
                    name: field.name.clone(),
                    field: field_value,
                });
            }
        }

        let ts = pkt.get_field(FRAME_TIMESTAMP);
        record.add_field(Field {
            name: String::from("frame.timestamp"),
            field: get_field_type(FRAME_TIMESTAMP, ts).unwrap(),
        });

        if ts < self.ts_start {
            self.ts_start = ts;
        }

        if ts > self.ts_end {
            self.ts_end = ts;
        }

        self.result.add_record(record);
    }

    pub fn get_result(&self) -> Cursor {
        debug!("Start ts: {}, end ts: {}", self.ts_start, self.ts_end);
        self.result.clone()
    }
}
