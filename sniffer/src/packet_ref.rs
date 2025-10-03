#[derive(Default, Debug, Clone)]
pub struct PacketRef {
    pub packet: Vec<u8>,
    pub orig_len: u32,
    pub cap_len: u32,
    pub timestamp: u32,
    pub ts_us: u32,
}
