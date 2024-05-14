use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct IPv4 {
    pub address: u32,
    pub mask: u8,
}

pub fn string_ipv4_to_int(ip_str: &str) -> u32 {
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

pub fn ipv4_to_string(ip: u32) -> String {
    let result: String;

    result = format!(
        "{}.{}.{}.{}",
        (ip >> 24) as u8,
        (ip >> 16) as u8,
        (ip >> 8) as u8,
        (ip & 0xff) as u8
    );

    result
}

pub fn is_ip_in_range(sa: u32, ip: u32, mask: u8) -> bool {
    let target: Ipv4Addr = Ipv4Addr::from(sa);
    let network: Ipv4Net = Ipv4Net::new(Ipv4Addr::from(ip), mask).unwrap();

    network.contains(&target)
}
