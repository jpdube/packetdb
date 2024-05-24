use crate::layer::Layer;
use crate::{fields, packet_display::PacketDisplay};
use byteorder::{BigEndian, ByteOrder};

const _UDP_HEADER_LEN: u8 = 8;

#[derive(Debug, Default, Clone)]
pub struct UdpFrame {
    raw_packet: Vec<u8>,
}

impl UdpFrame {
    pub fn set_packet(&mut self, packet: Vec<u8>) {
        self.raw_packet = packet;
    }

    pub fn dport(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[2..4])
    }
    pub fn sport(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[0..2])
    }

    pub fn length(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[4..6])
    }

    pub fn checksum(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[6..8])
    }

    pub fn _payload(&self) -> Vec<u8> {
        self.raw_packet[8..].to_vec()
    }

    pub fn payload_range(&self, offset: usize, len: usize) -> Vec<u8> {
        self.raw_packet[offset..offset + len].to_vec()
    }

    pub fn is_dns(&self) -> bool {
        self.dport() == 53 || self.sport() == 53
    }

    pub fn is_dhcp(&self) -> bool {
        (self.sport() == 68 || self.dport() == 67) || (self.sport() == 67 || self.dport() == 68)
    }
}

impl Layer for UdpFrame {
    fn get_field(&self, field: u32) -> usize {
        match field {
            fields::UDP_SRC_PORT => self.sport() as usize,
            fields::UDP_DEST_PORT => self.dport() as usize,
            fields::UDP_LEN => self.length() as usize,
            fields::UDP_CHEKCSUM => self.checksum() as usize,
            _ => 0,
        }
    }

    fn get_field_bytes(&self, _field_name: u32) -> Option<Vec<u8>> {
        None
    }

    fn get_name(&self) -> String {
        return "Udp".to_string();
    }
}

impl PacketDisplay for UdpFrame {
    fn summary(&self) -> String {
        let result: String;

        result = format!(
            "UDP -> Src port: {}, Dst port: {}",
            self.sport(),
            self.dport(),
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
    fn udp_frame_length() {
        let packet: Vec<u8> = vec![
            0x2f, 0xd2, 0x40, 0x16, 0x00, 0xb4, 0x79, 0x15, 0x80, 0x00, 0x35, 0x49, 0x00, 0x11,
            0xb8, 0x70, 0x47, 0x47, 0x28, 0x6c, 0x7c, 0x7d, 0x7d, 0x7d, 0x7d, 0x7d, 0x7e, 0x7f,
            0x7f, 0x7f, 0x7f, 0xfe, 0xfd, 0xfd, 0xfc, 0xfd, 0xfd, 0xfe, 0x7f, 0x7f, 0x7e, 0x7e,
            0x7e, 0x7d, 0x7e, 0xff, 0xfe, 0xfe, 0xfe, 0xfd, 0xfe, 0x7f, 0xfe, 0x7f, 0x7f, 0x7f,
            0x7f, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfe, 0xfd,
            0xfd, 0xfe, 0xfe, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 0xfe,
            0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfd, 0xfe, 0xff, 0x7e, 0x7e, 0xff, 0xff, 0xfe, 0xff,
            0x7e, 0x7d, 0x7d, 0x7c, 0x7d, 0x7e, 0x7e, 0x7e, 0x7f, 0x7f, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfd, 0xfe, 0xff, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7f,
            0x7f, 0x7e, 0x7e, 0x7d, 0x7c, 0x7c, 0x7d, 0x7c, 0x7d, 0x7e, 0x7e, 0x7e, 0x7e, 0x7d,
            0x7d, 0x7c, 0x7d, 0xff, 0x7e, 0x7e, 0xff, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0x7f, 0xfe, 0x7f, 0x7d, 0x7d, 0x7c, 0x7b, 0x7c, 0x7d,
            0x7f, 0x7f, 0x7e, 0x7d, 0x7d, 0x7d, 0x7e, 0xff, 0xff, 0xff, 0xff, 0xfe,
        ];

        let mut pkt = UdpFrame::default();
        pkt.set_packet(packet);

        assert_eq!(pkt.length(), 0x00b4, "UDP length");
        assert_eq!(
            pkt._payload().len(),
            0x00b4 - _UDP_HEADER_LEN as usize,
            "UDP length in payload"
        );
    }

    #[test]
    fn udp_frame_checksum() {
        let packet: Vec<u8> = vec![
            0x2f, 0xd2, 0x40, 0x16, 0x00, 0xb4, 0x79, 0x15, 0x80, 0x00, 0x35, 0x49, 0x00, 0x11,
            0xb8, 0x70, 0x47, 0x47, 0x28, 0x6c, 0x7c, 0x7d, 0x7d, 0x7d, 0x7d, 0x7d, 0x7e, 0x7f,
            0x7f, 0x7f, 0x7f, 0xfe, 0xfd, 0xfd, 0xfc, 0xfd, 0xfd, 0xfe, 0x7f, 0x7f, 0x7e, 0x7e,
            0x7e, 0x7d, 0x7e, 0xff, 0xfe, 0xfe, 0xfe, 0xfd, 0xfe, 0x7f, 0xfe, 0x7f, 0x7f, 0x7f,
            0x7f, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfd, 0xfe, 0xfd,
            0xfd, 0xfe, 0xfe, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f, 0xfe,
            0xfc, 0xfc, 0xfc, 0xfc, 0xfc, 0xfd, 0xfe, 0xff, 0x7e, 0x7e, 0xff, 0xff, 0xfe, 0xff,
            0x7e, 0x7d, 0x7d, 0x7c, 0x7d, 0x7e, 0x7e, 0x7e, 0x7f, 0x7f, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfd, 0xfe, 0xff, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7e, 0x7f,
            0x7f, 0x7e, 0x7e, 0x7d, 0x7c, 0x7c, 0x7d, 0x7c, 0x7d, 0x7e, 0x7e, 0x7e, 0x7e, 0x7d,
            0x7d, 0x7c, 0x7d, 0xff, 0x7e, 0x7e, 0xff, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
            0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0x7f, 0xfe, 0x7f, 0x7d, 0x7d, 0x7c, 0x7b, 0x7c, 0x7d,
            0x7f, 0x7f, 0x7e, 0x7d, 0x7d, 0x7d, 0x7e, 0xff, 0xff, 0xff, 0xff, 0xfe,
        ];

        let mut pkt = UdpFrame::default();
        pkt.set_packet(packet);

        assert_eq!(pkt.checksum(), 0x7915, "UDP checksum");
    }

    #[test]
    fn udp_frame_sport() {
        let packet: Vec<u8> = vec![0x2f, 0xd2, 0x40, 0x16, 0x00, 0xb4, 0x79, 0x15];

        let mut pkt = UdpFrame::default();
        pkt.set_packet(packet);

        assert_eq!(pkt.sport(), 0x2fd2, "UDP source port");
    }

    #[test]
    fn udp_frame_dport() {
        let packet: Vec<u8> = vec![0x2f, 0xd2, 0x40, 0x16, 0x00, 0xb4, 0x79, 0x15];

        let mut pkt = UdpFrame::default();
        pkt.set_packet(packet);

        assert_eq!(pkt.dport(), 0x4016, "UDP destination port");
    }
}
