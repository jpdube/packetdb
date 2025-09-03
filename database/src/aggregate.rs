use std::fmt;

use frame::packet::Packet;

#[derive(Debug, Clone)]
pub enum Aggregate {
    Count(String),
    Avg(String, String),
    Min(String, String),
    Max(String, String),
    Sum(String, String),
    Bandwidth(String, String),
}

impl Aggregate {
    pub fn compute(&self, pkt_list: &Vec<Packet>) -> usize {
        match &self {
            Self::Count(_) => self.count(&pkt_list),
            Self::Avg(field_id, _) => self.avg(field_id.clone(), &pkt_list),
            Self::Min(field_id, _) => self.min(field_id.clone(), &pkt_list),
            Self::Max(field_id, _) => self.max(field_id.clone(), &pkt_list),
            Self::Sum(field_id, _) => self.sum(field_id.clone(), &pkt_list),
            Self::Bandwidth(field_id, _) => self.bandwidth(field_id.clone(), &pkt_list),
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

    pub fn field_id(&self) -> String {
        match self {
            Self::Count(_) => "0".to_string(),
            Self::Avg(field, _) => field.clone(),
            Self::Min(field, _) => field.clone(),
            Self::Max(field, _) => field.clone(),
            Self::Sum(field, _) => field.clone(),
            Self::Bandwidth(field, _) => field.clone(),
        }
    }

    fn count(&self, pkt_list: &Vec<Packet>) -> usize {
        pkt_list.len()
    }

    fn bandwidth(&self, _field_id: String, _pkt_list: &Vec<Packet>) -> usize {
        let result: usize = 0;

        result
    }

    fn sum(&self, field_id: String, pkt_list: &Vec<Packet>) -> usize {
        let mut result: usize = 0;

        for pkt in pkt_list {
            if let Some(field) = pkt.get_field(field_id.clone()) {
                result += field.to_usize();
            }
        }

        result
    }

    fn avg(&self, field_id: String, pkt_list: &Vec<Packet>) -> usize {
        let mut result: usize = 0;

        for pkt in pkt_list {
            if let Some(field) = pkt.get_field(field_id.clone()) {
                result += field.to_usize();
            }
        }

        result / pkt_list.len()
    }

    fn min(&self, field_id: String, pkt_list: &Vec<Packet>) -> usize {
        let mut result: usize = usize::max_value();

        for pkt in pkt_list {
            if let Some(r) = pkt.get_field(field_id.clone()) {
                if r.to_usize() < result {
                    result = r.to_usize();
                }
            }
        }

        result
    }

    fn max(&self, field_id: String, pkt_list: &Vec<Packet>) -> usize {
        let mut result: usize = 0;

        for pkt in pkt_list {
            if let Some(r) = pkt.get_field(field_id.clone()) {
                if r.to_usize() > result {
                    result = r.to_usize();
                }
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
