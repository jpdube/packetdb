use crate::fields;
use crate::ipv4_address::IPv4;
use crate::layer::Layer;
use crate::packet_display::PacketDisplay;
use byteorder::{BigEndian, ByteOrder};

#[derive(Debug, Clone, Default)]
pub struct IpFrame<'a> {
    // ip_packet: Vec<u8>,
    ip_packet: &'a [u8],
}

impl<'a> IpFrame<'a> {
    pub fn new(packet: &'a [u8]) -> Self {
        Self { ip_packet: packet }
    }

    pub fn _offset(&self) -> usize {
        (self.header_len() * 4) as usize
    }

    pub fn header_len(&self) -> u8 {
        let hdr_len = self.ip_packet[0];

        hdr_len & 0x0f
    }

    pub fn tos(&self) -> u8 {
        self.ip_packet[1]
    }

    pub fn ttl(&self) -> u8 {
        self.ip_packet[8]
    }

    pub fn src(&self) -> u32 {
        BigEndian::read_u32(&self.ip_packet[12..16])
    }

    pub fn dst(&self) -> u32 {
        BigEndian::read_u32(&self.ip_packet[16..20])
    }

    pub fn proto(&self) -> u8 {
        self.ip_packet[9]
    }
}

impl<'a> Layer for IpFrame<'a> {
    fn get_name(&self) -> String {
        "ip".to_string()
    }

    fn get_field(&self, field: u32) -> usize {
        match field {
            fields::IPV4_SRC_ADDR => self.src() as usize,
            fields::IPV4_DST_ADDR => self.dst() as usize,
            fields::IPV4_TOS => self.tos() as usize,
            fields::IPV4_TTL => self.ttl() as usize,
            fields::IPV4_PROTOCOL => self.proto() as usize,
            fields::IPV4_HEADER_LEN => self.header_len() as usize,
            _ => 0,
        }
    }

    fn get_field_bytes(&self, _field_name: u32) -> Option<Vec<u8>> {
        None
    }
}

impl<'a> PacketDisplay for IpFrame<'a> {
    fn summary(&self) -> String {
        let result: String;

        result = format!(
            "IP -> Src:{}, Dst:{}",
            IPv4::new(self.src(), 32),
            IPv4::new(self.dst(), 32),
        );

        result
    }

    fn show_detail(&self) -> String {
        "UDP Detail".to_string()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_frame() {
        let packet: Vec<u8> = vec![
            0x45, 0x00, 0x01, 0x54, 0x0e, 0x3c, 0x40, 0x00, 0x7d, 0x06, 0x01, 0xc8, 0xc0, 0xa8,
            0x67, 0x64, 0xc0, 0xa8, 0x03, 0xeb, 0xc8, 0xcf, 0x01, 0xbd, 0x1e, 0x54, 0x73, 0xc3,
            0xe4, 0x56, 0x89, 0x7c, 0x50, 0x18, 0x20, 0x35, 0x7c, 0xbf, 0x00, 0x00,
        ];

        let mut pkt = IpFrame::default();
        pkt.set_packet(packet);

        assert_eq!(pkt.proto(), 0x06, "IP proto");
        assert_eq!(pkt.header_len(), 5, "IP Header len");
        assert_eq!(pkt.tos(), 0, "IP TOS");
        assert_eq!(pkt.ttl(), 125, "IP TTL");
        assert_eq!(pkt.src(), 0xc0a86764, "Ip src");
        assert_eq!(pkt.dst(), 0xc0a803eb, "Ip dst");
    }
}
