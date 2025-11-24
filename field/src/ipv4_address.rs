use ipnet::Ipv4Net;
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IPv4 {
    pub address: u32,
    pub mask: u8,
}

impl fmt::Display for IPv4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}/{}",
            (self.address >> 24) as u8,
            (self.address >> 16) as u8,
            (self.address >> 8) as u8,
            (self.address & 0xff) as u8,
            self.mask
        )
    }
}

impl IPv4 {
    pub fn new(address: u32, mask: u8) -> Self {
        Self { address, mask }
    }

    pub fn set_from_string(ip_str: &str) -> Self {
        Self {
            address: from_string_to_ip(ip_str),
            mask: 32,
        }
    }

    pub fn is_in_subnet(&self, sa: u32) -> bool {
        let target: Ipv4Addr = Ipv4Addr::from(sa);
        let network: Ipv4Net = Ipv4Net::new(Ipv4Addr::from(self.address), self.mask).unwrap();

        network.contains(&target)
    }
}

pub fn from_string_to_ip(ip_str: &str) -> u32 {
    let mut result: u32 = 0;
    let mut int_field: u32;

    let fields: Vec<&str> = ip_str.split(".").collect();
    if fields.len() == 4 {
        int_field = fields[0].parse().unwrap();
        result += int_field << 24;

        int_field = fields[1].parse().unwrap();
        result += int_field << 16;

        int_field = fields[2].parse().unwrap();
        result += int_field << 8;

        int_field = fields[3].parse().unwrap();
        result += int_field;
    }

    result
}
