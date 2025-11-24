use std::fmt;

pub struct MacAddr {
    pub address: u64,
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            (self.address >> 40) as u8,
            (self.address >> 32) as u8,
            (self.address >> 24) as u8,
            (self.address >> 16) as u8,
            (self.address >> 8) as u8,
            (self.address & 0xff) as u8
        )
    }
}

impl MacAddr {
    pub fn set_from_int(address: &u64) -> Self {
        Self { address: *address }
    }

    pub fn set_from_str(address: &str) -> Self {
        Self {
            address: string_mac_to_int(address),
        }
    }
}

pub fn string_mac_to_int(ip_str: &str) -> u64 {
    let mut result: u64 = 0;
    let mut int_field: u64;

    let fields: Vec<&str> = ip_str.split(":").collect();
    if fields.len() == 6 {
        int_field = u64::from_str_radix(fields[0], 16).unwrap();
        result += int_field << 40;

        int_field = u64::from_str_radix(fields[1], 16).unwrap();
        result += int_field << 32;

        int_field = u64::from_str_radix(fields[2], 16).unwrap();
        result += int_field << 24;

        int_field = u64::from_str_radix(fields[3], 16).unwrap();
        result += int_field << 16;

        int_field = u64::from_str_radix(fields[4], 16).unwrap();
        result += int_field << 8;

        int_field = u64::from_str_radix(fields[5], 16).unwrap();
        result += int_field;
    }

    result
}
