use std::fmt;

#[derive(Default, Clone)]
pub struct PacketID {
    file_id: u32,
    pkt_ptr: u32,
}

impl fmt::Display for PacketID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.file_id, self.pkt_ptr)
    }
}

impl PacketID {
    pub fn to_u64(&self) -> u64 {
        let mut id: u64 = (self.file_id as u64) << 32;
        id += self.pkt_ptr as u64;

        id
    }
}
