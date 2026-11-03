use crate::{
    arp::Arp, dhcp::Dhcp, dns::Dns, eth::EtherFrame, frame::Frame, ip::IpFrame, layer::Layer,
    net_field, tcp::Tcp, udp::UdpFrame,
};
use byteorder::{BigEndian, ByteOrder};
use field::pfield::Field;

#[derive(Clone)]
pub struct PacketDecode {
    header: Box<[u8]>,
    pub packet: Box<[u8]>,
    offset: usize,
    pub file_id: u32,
    pub pkt_ptr: u32,
    ip_offset: usize,
}

impl PacketDecode {
    pub fn new(header: Box<[u8]>, packet: Box<[u8]>, file_id: u32, pkt_ptr: u32) -> Self {
        let eth_type = BigEndian::read_u16(&packet[12..14]);
        let offset: usize = if eth_type == 0x8100 { 18 } else { 14 };
        let eth = EtherFrame::new(&packet[0..offset]);

        let mut ip_offset: usize = 0;
        if eth.has_ipv4() {
            ip_offset = ((packet[offset] & 0x0f) * 4) as usize;
            // println!("Has IPV4: {}", ip_offset);
        }

        let slf = PacketDecode {
            packet,
            header,
            offset,
            file_id,
            pkt_ptr,
            ip_offset,
        };

        slf
    }

    pub fn get_field_byte(&self, _field_id: u32, _offset: usize, _len: usize) -> Vec<u8> {
        let v: Vec<u8> = vec![1, 2, 3];

        v
    }

    pub fn get_field(&self, field_id: u32) -> Option<Field> {
        match field_id & net_field::SECTION_MASK {
            net_field::FRAME_BASE => {
                let frame = Frame::new(&self.header, self.file_id, self.pkt_ptr);
                return frame.get_field(field_id);
            }
            net_field::ETH_BASE => {
                return self.eth().get_field(field_id);
            }
            net_field::ARP_BASE => {
                if self.eth().has_arp() {
                    let arp = Arp::new(&self.packet[self.offset..]);
                    return arp.get_field(field_id);
                }

                return None;
            }
            net_field::IPV4_BASE => {
                if let Some(ip) = self.ip() {
                    return ip.get_field(field_id);
                } else {
                    return None;
                }
            }
            net_field::TCP_BASE => {
                if let Some(ip) = self.ip()
                    && ip.has_tcp()
                {
                    return self.tcp().get_field(field_id);
                }

                return None;
            }
            net_field::UDP_BASE => {
                if let Some(ip) = self.ip()
                    && ip.has_udp()
                {
                    return self.udp().get_field(field_id);
                }

                return None;
            }
            net_field::DNS_BASE => {
                if let Some(ip) = self.ip()
                    && ip.has_udp()
                {
                    if self.udp().is_dns() {
                        let payload = self.udp().payload();
                        let dns = Dns::new(&payload);
                        return dns.get_field(field_id);
                    }
                }

                return None;
            }
            net_field::DHCP_BASE => {
                if let Some(ip) = self.ip()
                    && ip.has_udp()
                {
                    if self.udp().is_dhcp() {
                        let payload = self.udp().payload();
                        let dhcp = Dhcp::new(&payload);
                        return dhcp.get_field(field_id);
                    }
                }

                return None;
            }
            _ => return None,
        };
    }

    pub fn get_id(&self) -> u64 {
        Frame::new(&self.header, self.file_id, self.pkt_ptr).get_id()
    }

    fn eth(&self) -> EtherFrame<'_> {
        EtherFrame::new(&self.packet[0..self.offset])
    }

    fn ip(&self) -> Option<IpFrame<'_>> {
        if self.eth().has_ipv4() {
            let ip = IpFrame::new(&self.packet[self.offset..self.offset + self.ip_offset]);

            return Some(ip);
        }
        None
    }

    fn tcp(&self) -> Tcp<'_> {
        Tcp::new(&self.packet[self.ip_offset + self.offset..])
    }

    fn udp(&self) -> UdpFrame<'_> {
        UdpFrame::new(&self.packet[self.ip_offset + self.offset..])
    }

    pub fn has_ethernet(&self) -> bool {
        self.eth().ethertype() == 0x0800
    }

    pub fn has_tcp(&self) -> bool {
        if let Some(ip) = self.ip() {
            return ip.has_tcp();
        }

        false
    }

    pub fn has_udp(&self) -> bool {
        if let Some(ip) = self.ip() {
            return ip.has_udp();
        }

        false
    }

    pub fn has_arp(&self) -> bool {
        self.eth().has_arp()
    }

    pub fn has_icmp(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_icmp()
        {
            return true;
        }

        false
    }

    pub fn has_ipv4(&self) -> bool {
        self.eth().has_ipv4()
    }

    pub fn has_dns(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_udp()
        {
            return self.udp().is_dns();
        }

        false
    }

    pub fn has_dhcp(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_udp()
        {
            return self.udp().is_dhcp();
        }

        false
    }

    pub fn has_https(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_tcp()
        {
            return self.tcp().is_https();
        }

        false
    }

    pub fn has_http(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_tcp()
        {
            return self.tcp().is_http();
        }

        false
    }

    pub fn has_ssh(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_tcp()
        {
            return self.tcp().is_ssh();
        }

        false
    }

    pub fn has_telnet(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_tcp()
        {
            return self.tcp().is_telnet();
        }

        false
    }

    pub fn has_rdp(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_tcp()
        {
            return self.tcp().is_rdp();
        }

        false
    }

    pub fn has_ntp(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_udp()
        {
            return self.udp().is_ntp();
        }

        false
    }

    pub fn has_smtp(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_tcp()
        {
            return self.tcp().is_smtp();
        }

        false
    }

    pub fn has_snmp(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_tcp()
        {
            return self.tcp().is_snmp();
        }

        false
    }

    pub fn has_smb(&self) -> bool {
        if let Some(ip) = self.ip()
            && ip.has_tcp()
        {
            return self.tcp().is_smb();
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn get_tcp_rdp_packet() -> [u8; 74] {
        [
            0x5c, 0xf9, 0xdd, 0xe6, 0x4e, 0xcf, 0xe8, 0x1c, 0xba, 0x17, 0x7d, 0x6a, 0x81, 0x0, 0x0,
            0x3d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x38, 0x42, 0xe1, 0x40, 0x0, 0x7c, 0x6, 0xdb, 0xd7,
            0xa, 0x14, 0x11, 0xc7, 0xc0, 0xa8, 0x3, 0x84, 0xd, 0x3d, 0xe0, 0x73, 0xc7, 0xaf, 0x49,
            0x0, 0x95, 0xe4, 0xc5, 0x6c, 0x50, 0x18, 0xf5, 0xff, 0xe3, 0x2a, 0x0, 0x0, 0xc0, 0x10,
            0xc, 0x1c, 0xed, 0x75, 0x16, 0xfa, 0xf2, 0xe8, 0xc3, 0xbb, 0xa8, 0x51, 0x6d, 0x45,
        ]
    }
    fn get_tcp_https_packet() -> [u8; 70] {
        [
            0x5c, 0xf9, 0xdd, 0xe6, 0x4e, 0xcf, 0xe8, 0x1c, 0xba, 0x17, 0x7d, 0x6a, 0x81, 0x0, 0x0,
            0x3d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x34, 0x0, 0x0, 0x40, 0x0, 0x37, 0x6, 0xb, 0x31, 0x45,
            0x41, 0x2f, 0x26, 0xc0, 0xa8, 0x3, 0x84, 0x1, 0xbb, 0xf9, 0x8b, 0x17, 0x59, 0x6d, 0xfd,
            0xad, 0x4e, 0xe1, 0xfb, 0x80, 0x12, 0xfa, 0xf0, 0x2b, 0x95, 0x0, 0x0, 0x2, 0x4, 0x5,
            0xb4, 0x1, 0x1, 0x4, 0x2, 0x1, 0x3, 0x3, 0x7,
        ]
    }
    fn get_udp_packet() -> [u8; 52] {
        [
            0x14, 0xb3, 0x1f, 0x1b, 0xf9, 0xae, 0xe8, 0x1c, 0xba, 0x17, 0x7d, 0x6a, 0x81, 0x0, 0x0,
            0x3d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x6b, 0x0, 0x0, 0x40, 0x0, 0x3c, 0x11, 0xbf, 0xd5,
            0xac, 0xd9, 0xd, 0xaa, 0xc0, 0xa8, 0x3, 0x81, 0x1, 0xbb, 0xcf, 0x20, 0x0, 0x57, 0x30,
            0xb, 0x48, 0xd9, 0x49, 0xf7, 0xb1, 0xf3,
        ]
    }

    fn get_arp_packet() -> [u8; 60] {
        [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0, 0x4e, 0x1, 0xa4, 0x4c, 0x8f, 0x8, 0x6, 0x0,
            0x1, 0x8, 0x0, 0x6, 0x4, 0x0, 0x1, 0x0, 0x4e, 0x1, 0xa4, 0x4c, 0x8f, 0xc0, 0xa8, 0x3,
            0x94, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa9, 0xfe, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
        ]
    }

    fn get_icmp_ping_request() -> [u8; 102] {
        [
            0xe8, 0x1c, 0xba, 0x17, 0x7d, 0x6a, 0x0, 0xc, 0x29, 0xc6, 0xa8, 0xa4, 0x81, 0x0, 0x0,
            0x3d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x54, 0x2e, 0x67, 0x40, 0x0, 0x40, 0x1, 0x8a, 0xfe,
            0xc0, 0xa8, 0x3, 0xef, 0xc0, 0xa8, 0xfc, 0x3, 0x8, 0x0, 0x52, 0x91, 0xcf, 0x3e, 0x0,
            0x1, 0x8a, 0xd3, 0x30, 0x62, 0x0, 0x0, 0x0, 0x0, 0x51, 0x26, 0xb, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
            0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ]
    }

    fn get_icmp_ping_reply() -> [u8; 102] {
        [
            0x0, 0xc, 0x29, 0xc6, 0xa8, 0xa4, 0xe8, 0x1c, 0xba, 0x17, 0x7d, 0x6a, 0x81, 0x0, 0x0,
            0x3d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x54, 0xc3, 0xd3, 0x0, 0x0, 0xfe, 0x1, 0x77, 0x91,
            0xc0, 0xa8, 0xfc, 0x3, 0xc0, 0xa8, 0x3, 0xef, 0x0, 0x0, 0xdf, 0x2d, 0xcf, 0x3e, 0x0,
            0x2, 0x8b, 0xd3, 0x30, 0x62, 0x0, 0x0, 0x0, 0x0, 0xd3, 0x88, 0x3, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
            0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        ]
    }

    fn get_icmp_dest_unreachable() -> [u8; 240] {
        [
            0xe8, 0x1c, 0xba, 0x17, 0x7d, 0x6a, 0xa4, 0xbb, 0x6d, 0x4e, 0x1b, 0x96, 0x81, 0x0, 0x0,
            0x3d, 0x8, 0x0, 0x45, 0x0, 0x0, 0xde, 0x84, 0xff, 0x0, 0x0, 0x80, 0x1, 0x2d, 0x66,
            0xc0, 0xa8, 0x3, 0x83, 0xc0, 0xa8, 0x2, 0xe6, 0x3, 0x3, 0x85, 0x76, 0x0, 0x0, 0x0, 0x0,
            0x45, 0x0, 0x0, 0xc2, 0x25, 0xe3, 0x0, 0x0, 0x7d, 0x11, 0x8f, 0x8e, 0xc0, 0xa8, 0x2,
            0xe6, 0xc0, 0xa8, 0x3, 0x83, 0x0, 0x35, 0xe8, 0x99, 0x0, 0xae, 0x39, 0x99, 0x16, 0x5d,
            0x81, 0x80, 0x0, 0x1, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x4, 0x73, 0x65, 0x6c, 0x66, 0x6,
            0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x4, 0x64, 0x61, 0x74, 0x61, 0x9, 0x6d, 0x69, 0x63,
            0x72, 0x6f, 0x73, 0x6f, 0x66, 0x74, 0x3, 0x63, 0x6f, 0x6d, 0x0, 0x0, 0x1, 0x0, 0x1,
            0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1c, 0x0, 0x25, 0x10, 0x73, 0x65, 0x6c,
            0x66, 0x2d, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x2d, 0x64, 0x61, 0x74, 0x61, 0xe,
            0x74, 0x72, 0x61, 0x66, 0x66, 0x69, 0x63, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
            0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x3c, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x0, 0x28, 0x0,
            0x29, 0x10, 0x6f, 0x6e, 0x65, 0x64, 0x73, 0x63, 0x6f, 0x6c, 0x70, 0x72, 0x64, 0x77,
            0x75, 0x73, 0x30, 0x38, 0x6, 0x77, 0x65, 0x73, 0x74, 0x75, 0x73, 0x8, 0x63, 0x6c, 0x6f,
            0x75, 0x64, 0x61, 0x70, 0x70, 0x5, 0x61, 0x7a, 0x75, 0x72, 0x65, 0xc0, 0x27, 0xc0,
            0x6d, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x7, 0x0, 0x4, 0x14, 0xbd, 0xad, 0x9,
        ]
    }

    fn get_dns_query() -> [u8; 80] {
        [
            0x0, 0xc, 0x29, 0x84, 0xc, 0x65, 0xe8, 0x1c, 0xba, 0x17, 0x7d, 0x6a, 0x81, 0x0, 0x0,
            0x3d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x3e, 0x8b, 0xfd, 0x0, 0x0, 0x7d, 0x11, 0xc5, 0x11,
            0xc0, 0xa8, 0x67, 0x69, 0xc0, 0xa8, 0x3, 0xe6, 0xdb, 0xcb, 0x0, 0x35, 0x0, 0x2a, 0x91,
            0xa1, 0x94, 0x5d, 0x1, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x72, 0xa,
            0x6d, 0x73, 0x66, 0x74, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x3, 0x63, 0x6f, 0x6d, 0x0,
            0x0, 0x1, 0x0, 0x1,
        ]
    }

    fn get_dns_response() -> [u8; 160] {
        [
            0xe8, 0x1c, 0xba, 0x17, 0x7d, 0x6a, 0x0, 0xc, 0x29, 0x84, 0xc, 0x65, 0x81, 0x0, 0x0,
            0x3d, 0x8, 0x0, 0x45, 0x0, 0x0, 0x8e, 0x38, 0x68, 0x0, 0x0, 0x80, 0x11, 0x15, 0x57,
            0xc0, 0xa8, 0x3, 0xe6, 0xc0, 0xa8, 0x67, 0x69, 0x0, 0x35, 0xdb, 0xcb, 0x0, 0x7a, 0xd8,
            0x94, 0x94, 0x5d, 0x81, 0x80, 0x0, 0x1, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x1, 0x72, 0xa,
            0x6d, 0x73, 0x66, 0x74, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x3, 0x63, 0x6f, 0x6d, 0x0,
            0x0, 0x1, 0x0, 0x1, 0xc0, 0xc, 0x0, 0x5, 0x0, 0x1, 0x0, 0x0, 0x49, 0xb5, 0x0, 0x26,
            0x10, 0x72, 0x2d, 0x6d, 0x73, 0x66, 0x74, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x2d,
            0x63, 0x6f, 0x6d, 0x6, 0x61, 0x2d, 0x30, 0x30, 0x31, 0x36, 0x8, 0x61, 0x2d, 0x6d, 0x73,
            0x65, 0x64, 0x67, 0x65, 0x3, 0x6e, 0x65, 0x74, 0x0, 0xc0, 0x2e, 0x0, 0x5, 0x0, 0x1,
            0x0, 0x0, 0x0, 0x8b, 0x0, 0x2, 0xc0, 0x3f, 0xc0, 0x60, 0x0, 0x1, 0x0, 0x1, 0x0, 0x0,
            0x0, 0xa8, 0x0, 0x4, 0xcc, 0x4f, 0xc5, 0xdb,
        ]
    }

    fn get_header() -> [u8; 16] {
        [
            0x62, 0x30, 0xd3, 0x26, 0x00, 0x0e, 0xeb, 0x79, 0x00, 0x00, 0x00, 0xda, 0x00, 0x00,
            0x00, 0xda,
        ]
    }

    #[test]
    fn has_vlan() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(
            pd.get_field(net_field::ETH_VLAN_ID).unwrap().to_bool(),
            > 1,
            "Has vlan"
        );
    }

    #[test]
    fn has_ipv4() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.has_ipv4(), true, "Has IPv4");
    }

    #[test]
    fn ip_src() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.ipv4_src(), 0x45412f26, "Get src ipV4");
    }

    #[test]
    fn ip_dst() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.ipv4_dst(), 0xc0a80384, "Get dst ipV4");
    }

    #[test]
    fn has_tcp() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.has_tcp(), true, "Has TCP");
    }

    #[test]
    fn tcp_sport() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.tcp_sport(), 443, "TCP src port = HTTPS");
    }

    #[test]
    fn tcp_dport() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.tcp_dport(), 63883, "TCP dst port = HTTPS");
    }

    #[test]
    fn has_https() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.has_https(), true, "Has HTTPS in TCP packet");
    }

    #[test]
    fn has_rdp() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_rdp_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.has_rdp(), true, "Has RDP in TCP packet");
    }

    #[test]
    fn has_udp() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_udp_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.has_udp(), true, "Has UDP");
    }

    #[test]
    fn udp_sport() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_udp_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.udp_sport(), 443, "UDP src port");
    }

    #[test]
    fn udp_dport() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_udp_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.udp_dport(), 53024, "UDP dst port");
    }

    #[test]
    fn ip_proto() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.ip_proto(), 0x06, "IPV4 protocol");
    }

    #[test]
    fn has_arp_proto() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_arp_packet()),
            0,
            0,
            false,
        );

        assert_eq!(pd.has_arp(), true, "Has ARP protocol");
    }

    #[test]
    fn has_icmp() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_icmp_ping_request()),
            0,
            0,
            false,
        );

        assert_eq!(pd.has_icmp(), true, "Has ICMP in IPv4 protocol");
    }

    #[test]
    fn has_icmp_ping_request() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_icmp_ping_request()),
            0,
            0,
            false,
        );

        assert_eq!(
            pd.has_icmp_ping_request(),
            true,
            "Has ICMP Ping request protocol"
        );
    }

    #[test]
    fn has_icmp_ping_reply() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_icmp_ping_reply()),
            0,
            0,
            false,
        );

        assert_eq!(
            pd.has_icmp_ping_reply(),
            true,
            "Has ICMP Ping reply protocol"
        );
    }

    #[test]
    fn has_icmp_dest_unreachable() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_icmp_dest_unreachable()),
            0,
            0,
            false,
        );

        assert_eq!(
            pd.has_icmp_dest_unreachable(),
            true,
            "Has ICMP Dest unreachable protocol"
        );
    }

    #[test]
    fn has_dns_query() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_dns_query()),
            0,
            0,
            false,
        );

        assert_eq!(pd.has_dns(), true, "Has DNS query");
    }

    #[test]
    fn has_dns_response() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_dns_response()),
            0,
            0,
            false,
        );

        assert_eq!(pd.has_dns(), true, "Has DNS response");
    }

    #[test]
    fn frame_inc_len() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        assert_eq!(
            pd.get_field("frame.inc_len").unwrap().to_u32(),
            0xda,
            "Frame INC_LEN"
        );
    }

    #[test]
    fn frame_orig_len() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        // assert!(pd.get_field("frame.orig_len").is_none(), "Field is NONE");
        assert_eq!(
            pd.get_field("frame.orig_len").unwrap().to_u32(),
            0xda,
            "Frame ORIG_LEN"
        );
    }

    #[test]
    fn frame_timestamp() {
        let pd = PacketDecode::new(
            Box::new(get_header()),
            Box::new(get_tcp_https_packet()),
            0,
            0,
            false,
        );

        // assert!(pd.get_field("frame.orig_len").is_none(), "Field is NONE");
        assert_eq!(
            pd.get_field("frame.timestamp").unwrap().to_u32(),
            0x6230d326,
            "Frame ORIG_LEN"
        );
    }
}
