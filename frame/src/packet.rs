// #![allow(dead_code)]
use crate::arp::Arp;
use crate::eth::EtherFrame;
use crate::fields;
use crate::icmp::Icmp;
use crate::ip::IpFrame;
use crate::layer::Layer;
use crate::packet_display::PacketDisplay;
use crate::tcp::Tcp;
use crate::udp::UdpFrame;

use byteorder::{BigEndian, ByteOrder, LittleEndian};

// const IP_HDR_LEN_POS: usize = 0x0e;
// const TCP_HDR_LEN_POS: usize = 0x2e;

// const ETHERNET_HDR_LEN: usize = 0x0e;
// const UDP_HEADER_LEN: u8 = 8;

const ETHER_IPV4_PROTO: u16 = 0x0800;
// const ETHER_IPV6_PROTO: u16 = 0x86DD;
const ETHER_ARP_PROTO: u16 = 0x0806;
// const ETHER_8021Q: u16 = 0x8100;

const IP_TCP_PROTO: u8 = 0x06;
const IP_UDP_PROTO: u8 = 0x11;
const IP_ICMP_PROTO: u8 = 0x01;

pub enum LayerType {
    Frame(Packet),
    Vlan,
    Ethernet(EtherFrame),
    IPv4(IpFrame),
    Udp(UdpFrame),
    Tcp(Tcp),
    Icmp(IpFrame),
    Arp(Arp),
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PcapHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub inc_len: u32,
    pub orig_len: u32,
    pub header_len: u8,
}

#[derive(Default, Debug, Clone)]
pub struct Packet {
    header: PcapHeader,
    raw_packet: Vec<u8>,
    eth_packet: Option<EtherFrame>,
    ip_packet: Option<IpFrame>,
    tcp_packet: Option<Tcp>,
    udp_packet: Option<UdpFrame>,
    icmp_packet: Option<Icmp>,
    arp_packet: Option<Arp>,
    pub file_id: u32,
    pub pkt_ptr: u32,
}

impl Packet {
    pub fn new() -> Self {
        Packet::default()
    }

    pub fn set_packet(
        &mut self,
        packet: Vec<u8>,
        header: [u8; 16],
        file_id: u32,
        pkt_ptr: u32,
        little_endian: bool,
    ) {
        if little_endian {
            self.header.ts_sec = LittleEndian::read_u32(&header[0..4]);
            self.header.ts_usec = LittleEndian::read_u32(&header[4..8]);
            self.header.inc_len = LittleEndian::read_u32(&header[8..12]);
            self.header.orig_len = LittleEndian::read_u32(&header[12..16]);
        } else {
            self.header.ts_sec = BigEndian::read_u32(&header[0..4]);
            self.header.ts_usec = BigEndian::read_u32(&header[4..8]);
            self.header.inc_len = BigEndian::read_u32(&header[8..12]);
            self.header.orig_len = BigEndian::read_u32(&header[12..16]);
        }

        if packet.len() < self.header.inc_len as usize {
            return;
        }

        self.file_id = file_id;
        self.pkt_ptr = pkt_ptr;

        self.raw_packet = packet.clone();

        let header = BigEndian::read_u16(&self.raw_packet[12..14]);
        let vo: usize;
        let ip_header_len: usize;

        if header == 0x8100 {
            vo = 18;
        } else {
            vo = 14;
        }

        ip_header_len = (self.raw_packet[vo] as usize & 0x0f) * 4;

        let mut ether = EtherFrame::default();
        ether.set_packet(packet[0..vo].to_vec());

        if ether.ethertype() == ETHER_ARP_PROTO {
            let mut arp_packet = Arp::default();
            arp_packet.set_packet(self.raw_packet[vo..].to_vec());

            self.arp_packet = Some(arp_packet);
        }

        if ether.ethertype() == ETHER_IPV4_PROTO {
            let mut ip_packet = IpFrame::default();

            ip_packet.set_packet(self.raw_packet[vo..vo + ip_header_len].to_vec());
            self.ip_packet = Some(ip_packet);
        }
        self.eth_packet = Some(ether);

        if let Some(p) = &self.ip_packet {
            match p.get_field(fields::IPV4_PROTOCOL) as u8 {
                IP_TCP_PROTO => {
                    let mut tcp_packet = Tcp::default();
                    tcp_packet.set_packet(self.raw_packet[vo + ip_header_len..].to_vec());
                    self.tcp_packet = Some(tcp_packet);
                }
                IP_UDP_PROTO => {
                    let mut udp_packet = UdpFrame::default();
                    udp_packet.set_packet(self.raw_packet[vo + ip_header_len..].to_vec());
                    self.udp_packet = Some(udp_packet);
                }
                IP_ICMP_PROTO => {
                    let mut icmp = Icmp::default();
                    icmp.set_packet(self.raw_packet[vo + ip_header_len..].to_vec());
                    self.icmp_packet = Some(icmp);
                }
                _ => {}
            }
        }
    }

    pub fn has_ethernet(&self) -> bool {
        self.eth_packet.is_some()
    }

    pub fn has_arp(&self) -> bool {
        self.arp_packet.is_some()
    }

    pub fn has_ipv4(&self) -> bool {
        self.ip_packet.is_some()
    }

    pub fn has_udp(&self) -> bool {
        self.udp_packet.is_some()
    }

    pub fn has_tcp(&self) -> bool {
        self.tcp_packet.is_some()
    }
    pub fn has_icmp(&self) -> bool {
        self.icmp_packet.is_some()
    }

    pub fn has_https(&self) -> bool {
        if let Some(pkt) = &self.tcp_packet {
            return pkt.is_https();
        }
        false
    }
    pub fn has_http(&self) -> bool {
        if let Some(pkt) = &self.tcp_packet {
            return pkt.is_http();
        }
        false
    }
    pub fn has_ssh(&self) -> bool {
        if let Some(pkt) = &self.tcp_packet {
            return pkt.is_ssh();
        }
        false
    }
    pub fn has_telnet(&self) -> bool {
        if let Some(pkt) = &self.tcp_packet {
            return pkt.is_telnet();
        }
        false
    }

    pub fn has_dns(&self) -> bool {
        if let Some(pkt) = &self.udp_packet {
            return pkt.is_dns();
        }

        false
    }

    pub fn has_dhcp(&self) -> bool {
        if let Some(pkt) = &self.udp_packet {
            return pkt.is_dhcp();
        }

        false
    }

    fn field_type(&self, field: u32, field_base: u32) -> bool {
        (field & 0xffff0000) == field_base
    }

    pub fn get_field(&self, field: u32) -> usize {
        // let (id_file, id_ptr) = self.decode_id(self.get_id());
        // println!("DECODED ID: {},{}", id_file, id_ptr);
        if self.field_type(field, fields::ETH_BASE) && self.eth_packet.is_some() {
            self.eth_packet.as_ref().unwrap().get_field(field)
        } else if self.field_type(field, fields::ARP_BASE) && self.arp_packet.is_some() {
            self.arp_packet.as_ref().unwrap().get_field(field)
        } else if self.field_type(field, fields::TCP_BASE) && self.tcp_packet.is_some() {
            self.tcp_packet.as_ref().unwrap().get_field(field)
        } else if self.field_type(field, fields::IPV4_BASE) && self.ip_packet.is_some() {
            self.ip_packet.as_ref().unwrap().get_field(field)
        } else if self.field_type(field, fields::UDP_BASE) && self.udp_packet.is_some() {
            self.udp_packet.as_ref().unwrap().get_field(field)
        } else if self.field_type(field, fields::ICMP_BASE) && self.icmp_packet.is_some() {
            self.icmp_packet.as_ref().unwrap().get_field(field)
        } else {
            match field {
                fields::FRAME_TIMESTAMP => self.timestamp() as usize,
                fields::FRAME_OFFSET => self.ts_offset() as usize,
                fields::FRAME_ORIG_LEN => self.orig_len() as usize,
                fields::FRAME_INC_LEN => self.inc_len() as usize,
                fields::FRAME_FILE_ID => self.file_id as usize,
                fields::FRAME_PKT_PTR => self.pkt_ptr as usize,
                fields::FRAME_ID => self.get_id() as usize,
                _ => usize::MAX,
            }
        }
    }

    pub fn get_id(&self) -> u64 {
        let mut result: u64 = self.file_id as u64;

        result = result << 32;
        result = result | self.pkt_ptr as u64;

        result
    }

    pub fn decode_id(&self, id: u64) -> (u32, u32) {
        let file_id: u32 = (id >> 32) as u32;
        let pkt_ptr: u32 = (id & 0x0000ffff) as u32;

        (file_id, pkt_ptr)
    }

    pub fn get_field_byte(&self, field: u32, offset: usize, len: usize) -> Vec<u8> {
        if self.field_type(field, fields::TCP_BASE) && self.tcp_packet.is_some() {
            let pkt_array = self.tcp_packet.as_ref().unwrap().payload_range(offset, len);
            return pkt_array;
        } else if self.field_type(field, fields::UDP_BASE) && self.udp_packet.is_some() {
            let pkt_array = self.udp_packet.as_ref().unwrap().payload_range(offset, len);
            return pkt_array;
        } else if self.field_type(field, fields::ICMP_BASE) && self.icmp_packet.is_some() {
            let pkt_array = self
                .icmp_packet
                .as_ref()
                .unwrap()
                .payload_range(offset, len);
            return pkt_array;
        } else if self.field_type(field, fields::ETH_BASE) && self.eth_packet.is_some() {
            let pkt_array = self.eth_packet.as_ref().unwrap().payload_range(offset, len);
            return pkt_array;
        }

        let pkt: Vec<u8> = Vec::new();
        pkt
    }

    // pub fn get_id(&self) -> String {
    //     format!("{}:{}", self.file_id, self.pkt_ptr)
    // }

    //----------------------------------------------------
    //--- Frame section
    //----------------------------------------------------
    pub fn timestamp(&self) -> u32 {
        self.header.ts_sec
    }

    pub fn ts_offset(&self) -> u32 {
        self.header.ts_usec
    }
    pub fn orig_len(&self) -> u32 {
        self.header.orig_len
    }
    pub fn inc_len(&self) -> u32 {
        self.header.inc_len
    }
}

impl PacketDisplay for Packet {
    fn summary(&self) -> String {
        let mut result: String = String::new();

        if let Some(eth) = &self.eth_packet {
            result += &eth.summary();
        }

        if self.eth_packet.is_some() {
            if let Some(ip) = &self.ip_packet {
                result += &format!("  {}{}", ip.summary(), "\n");
            }
        }

        if let Some(ip) = &self.ip_packet {
            if ip.proto() == IP_TCP_PROTO {
                if let Some(tcp) = &self.tcp_packet {
                    result += &format!("    {}\n", &tcp.summary());
                }
            }
            if ip.proto() == IP_UDP_PROTO {
                if let Some(udp) = &self.udp_packet {
                    result += &format!("    {}\n", &udp.summary());
                }
            }

            if ip.proto() == IP_ICMP_PROTO {
                if let Some(icmp) = &self.icmp_packet {
                    result += &format!("    {}\n", &icmp.summary());
                }
            }
        }

        result += "-------------------------------------------\n";

        result
    }
    fn show_detail(&self) -> String {
        "Packet detail".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
}
