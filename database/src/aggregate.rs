use std::fmt;

use frame::packet::Packet;

#[derive(Debug, Clone)]
pub enum Aggregate {
    Count(String),
    Avg(u32, String),
    Min(u32, String),
    Max(u32, String),
    Sum(u32, String),
    Bandwidth(u32, String),
}

impl Aggregate {
    pub fn compute(&self, pkt_list: &Vec<Packet>) -> usize {
        match &self {
            Self::Count(_) => self.count(&pkt_list),
            Self::Avg(field_id, _) => self.avg(field_id, &pkt_list),
            Self::Min(field_id, _) => self.min(field_id, &pkt_list),
            Self::Max(field_id, _) => self.max(field_id, &pkt_list),
            Self::Sum(field_id, _) => self.sum(field_id, &pkt_list),
            Self::Bandwidth(field_id, _) => self.bandwidth(field_id, &pkt_list),
        }
    }

    pub fn as_of(&self) -> &String {
        match self {
            Self::Count(field) => field,
            Self::Avg(_, field) => field,
            Self::Min(_, field) => field,
            Self::Max(_, field) => field,
            Self::Sum(_, field) => field,
            Self::Bandwidth(_, field) => field,
        }
    }

    fn count(&self, pkt_list: &Vec<Packet>) -> usize {
        pkt_list.len()
    }

    fn bandwidth(&self, _field_id: &u32, _pkt_list: &Vec<Packet>) -> usize {
        let result: usize = 0;

        result
    }

    fn sum(&self, field_id: &u32, pkt_list: &Vec<Packet>) -> usize {
        let mut result: usize = 0;

        for pkt in pkt_list {
            result += pkt.get_field(*field_id);
        }

        result
    }

    fn avg(&self, field_id: &u32, pkt_list: &Vec<Packet>) -> usize {
        let mut result: usize = 0;

        for pkt in pkt_list {
            result += pkt.get_field(*field_id);
        }

        result / pkt_list.len()
    }

    fn min(&self, field_id: &u32, pkt_list: &Vec<Packet>) -> usize {
        let mut result: usize = usize::max_value();

        for pkt in pkt_list {
            let r = pkt.get_field(*field_id);
            if r < result {
                result = r;
            }
        }

        result
    }

    fn max(&self, field_id: &u32, pkt_list: &Vec<Packet>) -> usize {
        let mut result: usize = 0;

        for pkt in pkt_list {
            let r = pkt.get_field(*field_id);
            if r > result {
                result = r;
            }
        }

        result
    }
}

impl fmt::Display for Aggregate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Count(as_of) => write!(f, " Count({}) ", as_of),
            Self::Avg(field, as_of) => write!(f, " Average({}, {}) ", field, as_of),
            Self::Min(field, as_of) => write!(f, " Min({}, {}) ", field, as_of),
            Self::Max(field, as_of) => write!(f, " Max({}, {}) ", field, as_of),
            Self::Sum(field, as_of) => write!(f, " Sum({}, {}) ", field, as_of),
            Self::Bandwidth(field, as_of) => write!(f, " Bandwidth({}, {}) ", field, as_of),
        }
    }
}
