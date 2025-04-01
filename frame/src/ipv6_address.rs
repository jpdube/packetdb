use std::fmt;

pub struct IPv6 {
    pub address: u128,
    pub mask: u8,
}

impl fmt::Display for IPv6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.to_string(), self.mask)
    }
}

impl IPv6 {
    pub fn new(address: u128, mask: u8) -> Self {
        Self { address, mask }
    }

    pub fn to_string(&self) -> String {
        let result: String;

        result = format!(
            "{:0x}:{:0x}:{:0x}:{:0x}:{:0x}:{:0x}:{:0x}:{:0x}",
            (self.address >> 112) as u16,
            (self.address >> 96) as u16,
            (self.address >> 80) as u16,
            (self.address >> 64) as u16,
            (self.address >> 48) as u16,
            (self.address >> 32) as u16,
            (self.address >> 16) as u16,
            (self.address & 0xff) as u16,
        );

        result
    }
}
