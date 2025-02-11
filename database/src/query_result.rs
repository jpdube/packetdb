use std::collections::{HashMap, HashSet};
use std::usize;

use frame::packet::Packet;

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
    aggregate: AggregateResult,
    distinct_list: HashSet<String>,
}

impl QueryResult {
    pub fn new(model: PqlStatement) -> Self {
        Self {
            ts_start: usize::max_value(),
            ts_end: 0,
            result: Cursor::default(),
            offset: 0,
            groupby: GroupBy::new(model.clone()),
            aggregate: AggregateResult::new(model.clone()),
            model,
            distinct_list: HashSet::new(),
        }
    }

    pub fn count_reach(&self) -> bool {
        if self.model.has_groupby() {
            return self.groupby.count_reach();
        } else if self.model.has_distinct {
            return self.distinct_list.len() >= self.model.top;
        } else {
            return self.result.len() >= self.model.top;
        }
    }

    pub fn add(&mut self, pkt: Packet) {
        if self.model.has_groupby() {
            self.groupby.add(pkt.clone());
        } else if self.model.has_aggregate() && !self.model.has_groupby() {
            self.aggregate.add(pkt.clone());
        }

        if self.model.offset > 0 && self.offset < self.model.offset {
            self.offset += 1;
            return;
        }

        let mut record = Record::default();
        let mut distinct_key = String::new();

        for field in &self.model.select {
            if let Some(field_value) = get_field_type(field.id, pkt.get_field(field.id)) {
                record.add_field(Field {
                    name: field.name.clone(),
                    field: field_value.clone(),
                });

                if self.model.has_distinct {
                    distinct_key = format!("{}|{}", distinct_key, field_value.to_string());
                }
            }
        }

        let pkt_id = pkt.get_id() as u64;
        // println!("FRAME ID: {:x}", pkt_id);
        record.add_field(Field {
            name: String::from("frame.id"),
            field: FieldType::Number(pkt_id as usize),
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

        if self.model.has_distinct {
            if !self.distinct_list.contains(&distinct_key) {
                self.result.add_record(record);
                self.distinct_list.insert(distinct_key.clone());
            }
        } else {
            self.result.add_record(record);
        }
    }

    pub fn get_result(&mut self) -> Cursor {
        debug!("Start ts: {}, end ts: {}", self.ts_start, self.ts_end);
        if self.model.has_groupby() {
            return self.groupby.get_result();
        } else if self.model.has_aggregate() && !self.model.has_groupby() {
            return self.aggregate.get_result();
        } else {
            return self.result.clone();
        }
    }
}

pub struct AggregateResult {
    model: PqlStatement,
    pkt_list: Vec<Packet>,
    result: Cursor,
}

impl AggregateResult {
    pub fn new(model: PqlStatement) -> Self {
        Self {
            model,
            pkt_list: Vec::new(),
            result: Cursor::default(),
        }
    }

    pub fn add(&mut self, packet: Packet) {
        self.pkt_list.push(packet);
    }

    pub fn count_reach(&self) -> bool {
        self.pkt_list.len() >= self.model.top
    }

    pub fn get_result(&mut self) -> Cursor {
        let mut record = Record::default();
        for aggr in &self.model.aggr_list {
            let aggr_field = Field {
                name: aggr.as_of().clone(),
                field: FieldType::Number(aggr.compute(&self.pkt_list)),
            };

            record.add_field(aggr_field);
        }

        self.result.add_record(record.clone());

        self.result.clone()
    }
}

pub struct GroupBy {
    model: PqlStatement,
    grp_result: HashMap<Vec<usize>, Vec<Packet>>,
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

    pub fn count_reach(&self) -> bool {
        self.grp_result.keys().len() >= self.model.top
    }

    pub fn add(&mut self, pkt: Packet) {
        let mut key = Vec::new();

        for k in &self.model.groupby_fields {
            key.push(pkt.get_field(k.id));
        }

        if let Some(aggr_key) = self.grp_result.get_mut(&key) {
            aggr_key.push(pkt);
        } else {
            let mut grp_vec: Vec<Packet> = Vec::new();
            grp_vec.push(pkt);
            self.grp_result.insert(key, grp_vec);
        }

        // debug!("Group ADD: {:#?}", &self.grp_result);
    }

    pub fn get_result(&mut self) -> Cursor {
        let mut record: Record;

        for (k, grp) in self.grp_result.iter() {
            record = Record::default();

            for (idx, gfield) in k.iter().enumerate() {
                let field_name = self.model.groupby_fields[idx].name.clone();
                let field_value: FieldType;

                if field_name.contains("ip") {
                    field_value = FieldType::Ipv4(*gfield as u32);
                } else {
                    field_value = FieldType::Number(*gfield);
                }

                let aggr_field = Field {
                    name: field_name,
                    field: field_value,
                };

                record.add_field(aggr_field);
            }

            for aggr in &self.model.aggr_list {
                let aggr_field = Field {
                    name: aggr.as_of().clone(),
                    field: FieldType::Number(aggr.compute(grp)),
                };

                record.add_field(aggr_field);
            }
            self.result.add_record(record.clone());
        }

        self.result.clone()
    }
}
