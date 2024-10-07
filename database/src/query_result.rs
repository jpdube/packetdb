use std::collections::HashMap;
use std::usize;

use frame::packet::Packet;
// use frame::pfield::FieldType;

use crate::cursor::{get_field_type, Cursor, Field, FieldType, Record};
use crate::parse::PqlStatement;
use frame::fields::FRAME_TIMESTAMP;
use log::debug;

pub struct QueryResult {
    model: PqlStatement,
    ts_start: usize,
    ts_end: usize,
    result: Cursor,
    offset: usize,
    groupby: GroupBy,
}

impl QueryResult {
    pub fn new(model: PqlStatement) -> Self {
        Self {
            ts_start: usize::max_value(),
            ts_end: 0,
            result: Cursor::default(),
            offset: 0,
            groupby: GroupBy::new(model.clone()),
            model,
        }
    }

    pub fn count_reach(&self) -> bool {
        // println!("COUNT REACHED: {}:{}", self.result.len(), self.model.top);
        self.result.len() >= self.model.top
    }

    pub fn add(&mut self, pkt: Packet) {
        if self.model.has_groupby() {
            self.groupby.add(pkt.clone());
        }

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

        let pkt_id = pkt.get_id();
        record.add_field(Field {
            name: String::from("frame.id"),
            field: FieldType::Str(pkt_id),
        });

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

    pub fn get_result(&mut self) -> Cursor {
        debug!("Start ts: {}, end ts: {}", self.ts_start, self.ts_end);
        if self.model.has_groupby() {
            return self.groupby.get_result();
        } else {
            return self.result.clone();
        }
    }
}

pub struct GroupBy {
    model: PqlStatement,
    grp_result: HashMap<String, Vec<Packet>>,
    result: Cursor,
}

impl GroupBy {
    pub fn new(model: PqlStatement) -> Self {
        Self {
            model,
            grp_result: HashMap::new(),
            result: Cursor::default(),
        }
    }

    pub fn add(&mut self, pkt: Packet) {
        let mut key = String::new();

        for k in &self.model.groupby_fields {
            key.push_str(&format!("{}", pkt.get_field(k.id)));
        }

        if let Some(aggr_key) = self.grp_result.get_mut(&key) {
            aggr_key.push(pkt);
        } else {
            let mut grp_vec: Vec<Packet> = Vec::new();
            grp_vec.push(pkt);
            self.grp_result.insert(key, grp_vec);
        }

        // debug!("Group ADD: {:?}", &self.grp_result);
    }

    pub fn get_result(&mut self) -> Cursor {
        let mut record: Record;
        for (k, grp) in self.grp_result.iter() {
            debug!("GroupBy RESULT: Key: {}, Len: {}", k, grp.len());

            record = Record::default();
            for aggr in &self.model.aggr_list {
                let aggr_field = Field {
                    name: aggr.as_of().clone(),
                    field: FieldType::Number(aggr.compute(grp)),
                };

                record.add_field(aggr_field);
                self.result.add_record(record.clone());
            }
        }

        // debug!("Aggr result: {:?}", self.result);

        self.result.clone()
    }
}
