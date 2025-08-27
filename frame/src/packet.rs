use crate::dhcp::Dhcp;
// #![allow(dead_code)]
use crate::eth::EtherFrame;
use crate::fields;
use crate::frame::Frame;
use crate::icmp::Icmp;
use crate::ip::IpFrame;
use crate::layer::Layer;
use crate::layer_index::LayerIndex;
use crate::packet_display::PacketDisplay;
use crate::pfield::Field;
use crate::tcp::Tcp;
use crate::udp::UdpFrame;
use crate::{arp::Arp, dns::Dns, ntp::Ntp};
use indexmap::IndexMap;

use byteorder::{BigEndian, ByteOrder};

const ETHER_IPV4_PROTO: u16 = 0x0800;
const ETHER_ARP_PROTO: u16 = 0x0806;

const IP_TCP_PROTO: u8 = 0x06;
const IP_UDP_PROTO: u8 = 0x11;
const IP_ICMP_PROTO: u8 = 0x01;

#[derive(Debug, Clone)]
pub struct LayerInfo {
    layer_type: LayerIndex,
    start_pos: usize,
    end_pos: usize,
}

#[derive(Default, Debug, Clone)]
pub struct Packet {
    raw_packet: Vec<u8>,
    arp_packet: Option<Arp>,
    pub file_id: u32,
    pub pkt_ptr: u32,
    header: [u8; 16],
    little_endian: bool,

    frame_list: IndexMap<LayerIndex, LayerInfo>,
}

impl Packet {
    pub fn new() -> Self {
        Packet::default()
    }

    pub fn add_layer(&mut self, layer: LayerInfo) {
        self.frame_list.insert(layer.layer_type.clone(), layer);
    }

    pub fn get_layer(&self, layer: LayerIndex) -> Option<&LayerInfo> {
        self.frame_list.get(&layer)
    }

    pub fn get_layer_bytes(&self, layer: LayerIndex) -> Option<&[u8]> {
        match layer {
            LayerIndex::FRAME => {
                if self.frame_list.get(&layer).is_some() {
                    return Some(&self.header);
                }
            }
            _ => {
                if let Some(frame) = self.frame_list.get(&layer) {
                    return Some(&self.raw_packet[frame.start_pos..frame.end_pos]);
                }
            }
        }

        return None;
    }

    pub fn has_layer(&self, layer: LayerIndex) -> bool {
        self.frame_list.contains_key(&layer)
    }

    fn get_ipv4_packet(&self) -> Option<IpFrame<'_>> {
        if let Some(raw_pkt) = self.get_layer_bytes(LayerIndex::IPv4) {
            return Some(IpFrame::new(raw_pkt));
        } else {
            return None;
        }
    }

    fn get_tcp_packet(&self) -> Option<Tcp<'_>> {
        if let Some(raw_pkt) = &self.get_layer_bytes(LayerIndex::TCP) {
            let tcp = Tcp::new(raw_pkt);
            return Some(tcp);
        } else {
            return None;
        }
    }

    fn get_udp_packet(&self) -> Option<UdpFrame<'_>> {
        if let Some(raw_pkt) = self.get_layer_bytes(LayerIndex::UDP) {
            return Some(UdpFrame::new(raw_pkt));
        } else {
            return None;
        }
    }

    fn get_eth_packet(&self) -> Option<EtherFrame<'_>> {
        if let Some(raw_pkt) = self.get_layer_bytes(LayerIndex::ETH) {
            return Some(EtherFrame::new(raw_pkt));
        } else {
            return None;
        }
    }

    fn get_frame_packet(&self) -> Option<Frame<'_>> {
        if let Some(raw_pkt) = self.get_layer_bytes(LayerIndex::FRAME) {
            return Some(Frame::new(raw_pkt, self.little_endian));
        } else {
            return None;
        }
    }

    fn get_dns_packet(&self) -> Option<Dns<'_>> {
        if let Some(raw_pkt) = self.get_layer_bytes(LayerIndex::DNS) {
            let dns = Dns::new(raw_pkt);
            return Some(dns);
        } else {
            return None;
        }
    }

    fn get_dhcp_packet(&self) -> Option<Dhcp<'_>> {
        if let Some(raw_pkt) = self.get_layer_bytes(LayerIndex::DHCP) {
            let dhcp = Dhcp::new(raw_pkt);
            return Some(dhcp);
        } else {
            return None;
        }
    }
    fn get_ntp_packet(&self) -> Option<Ntp<'_>> {
        if let Some(raw_pkt) = self.get_layer_bytes(LayerIndex::NTP) {
            let ntp = Ntp::new(raw_pkt);
            return Some(ntp);
        } else {
            return None;
        }
    }

    pub fn print_layers(&self) {
        println!("Layers: {:#?}", self.frame_list);
    }

    pub fn set_packet(
        &mut self,
        packet: Vec<u8>,
        header: [u8; 16],
        file_id: u32,
        pkt_ptr: u32,
        little_endian: bool,
    ) {
        self.header = header;
        self.little_endian = little_endian;
        self.add_layer(LayerInfo {
            layer_type: LayerIndex::FRAME,
            start_pos: 0,
            end_pos: header.len(),
        });

        if packet.len() < self.get_frame_packet().unwrap().inc_len() as usize {
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

        let ether = EtherFrame::new(&packet[0..vo]);

        //--- Added frame layer
        self.add_layer(LayerInfo {
            layer_type: LayerIndex::FRAME,
            start_pos: 0,
            end_pos: self.raw_packet.len(),
        });

        //--- Added ethernat layer
        self.add_layer(LayerInfo {
            layer_type: LayerIndex::ETH,
            start_pos: 0,
            end_pos: vo,
        });

        if ether.ethertype() == ETHER_ARP_PROTO {
            let mut arp_packet = Arp::default();
            arp_packet.set_packet(self.raw_packet[vo..].to_vec());

            self.arp_packet = Some(arp_packet);

            //--- Add ARP layer
            self.add_layer(LayerInfo {
                layer_type: LayerIndex::ARP,
                start_pos: vo,
                end_pos: self.raw_packet.len() - vo,
            });
        }

        if ether.ethertype() == ETHER_IPV4_PROTO {
            //--- Add IPV4 layer
            self.add_layer(LayerInfo {
                layer_type: LayerIndex::IPv4,
                start_pos: vo,
                end_pos: vo + ip_header_len,
            });
        }

        self.process_ipv4(vo, ip_header_len);
    }

    fn process_ipv4(&mut self, vo: usize, ip_header_len: usize) {
        if let Some(ip_layer) = &self.get_layer_bytes(LayerIndex::IPv4) {
            let p = IpFrame::new(ip_layer);
            if let Some(proto) = p.get_field(fields::IPV4_PROTOCOL) {
                match proto.to_u8() {
                    IP_TCP_PROTO => {
                        //--- Add TCP layer
                        self.add_layer(LayerInfo {
                            layer_type: LayerIndex::TCP,
                            start_pos: vo + ip_header_len,
                            end_pos: self.raw_packet.len(),
                        });
                    }

                    IP_UDP_PROTO => {
                        //--- Add UDP layer
                        self.add_layer(LayerInfo {
                            layer_type: LayerIndex::UDP,
                            start_pos: vo + ip_header_len,
                            end_pos: self.raw_packet.len(),
                        });

                        if let Some(dns) = self.get_udp_packet() {
                            if dns.is_dns() {
                                self.add_layer(LayerInfo {
                                    layer_type: LayerIndex::DNS,
                                    start_pos: vo + ip_header_len + dns.header_len(),
                                    end_pos: self.raw_packet.len(),
                                });
                            }
                        }

                        if let Some(dhcp) = self.get_udp_packet() {
                            if dhcp.is_dhcp() {
                                self.add_layer(LayerInfo {
                                    layer_type: LayerIndex::DHCP,
                                    start_pos: vo + ip_header_len + dhcp.header_len(),
                                    end_pos: self.raw_packet.len(),
                                });
                            }
                        }
                        if let Some(ntp) = self.get_udp_packet() {
                            if ntp.is_ntp() {
                                self.add_layer(LayerInfo {
                                    layer_type: LayerIndex::NTP,
                                    start_pos: vo + ip_header_len + ntp.header_len(),
                                    end_pos: self.raw_packet.len(),
                                });
                            }
                        }
                    }
                    IP_ICMP_PROTO => {
                        //--- Add ICMP layer
                        self.add_layer(LayerInfo {
                            layer_type: LayerIndex::ICMP,
                            start_pos: vo + ip_header_len,
                            end_pos: self.raw_packet.len(),
                        });
                    }

                    _ => {}
                }
            }
        }
    }

    // pub fn has_proto(&self, search_proto: IndexField) -> bool {
    //     match search_proto {
    //         IndexField::Arp =>
    //     }

    //     false
    // }

    pub fn has_ethernet(&self) -> bool {
        self.has_layer(LayerIndex::ETH)
    }

    pub fn has_arp(&self) -> bool {
        self.arp_packet.is_some()
    }

    pub fn has_ipv4(&self) -> bool {
        self.has_layer(LayerIndex::IPv4)
    }

    pub fn has_udp(&self) -> bool {
        self.has_layer(LayerIndex::UDP)
    }

    pub fn has_tcp(&self) -> bool {
        self.has_layer(LayerIndex::TCP)
    }

    pub fn has_icmp(&self) -> bool {
        self.has_layer(LayerIndex::ICMP)
    }

    pub fn has_https(&self) -> bool {
        if let Some(pkt) = self.get_tcp_packet() {
            return pkt.is_https();
        } else {
            false
        }
    }
    pub fn has_http(&self) -> bool {
        if let Some(pkt) = self.get_tcp_packet() {
            return pkt.is_http();
        } else {
            false
        }
    }
    pub fn has_ssh(&self) -> bool {
        if let Some(pkt) = self.get_tcp_packet() {
            return pkt.is_ssh();
        } else {
            false
        }
    }
    pub fn has_telnet(&self) -> bool {
        if let Some(pkt) = self.get_tcp_packet() {
            return pkt.is_telnet();
        } else {
            false
        }
    }

    pub fn has_rdp(&self) -> bool {
        if let Some(pkt) = self.get_tcp_packet() {
            return pkt.is_rdp();
        } else {
            false
        }
    }

    pub fn has_smb(&self) -> bool {
        if let Some(pkt) = self.get_tcp_packet() {
            return pkt.is_smb();
        } else {
            false
        }
    }

    pub fn has_smtp(&self) -> bool {
        if let Some(pkt) = self.get_tcp_packet() {
            return pkt.is_smtp();
        } else {
            false
        }
    }

    pub fn has_dns(&self) -> bool {
        if let Some(pkt) = &self.get_udp_packet() {
            return pkt.is_dns();
        }

        false
    }

    pub fn has_snmp(&self) -> bool {
        if let Some(pkt) = &self.get_udp_packet() {
            return pkt.is_snmp();
        }

        false
    }

    pub fn has_ntp(&self) -> bool {
        if let Some(pkt) = &self.get_udp_packet() {
            return pkt.is_ntp();
        }

        false
    }

    pub fn has_dhcp(&self) -> bool {
        if let Some(pkt) = &self.get_udp_packet() {
            return pkt.is_dhcp();
        }

        false
    }

    fn field_type(&self, field: u32, field_base: u32) -> bool {
        (field & 0xffff0000) == field_base
    }

    pub fn get_field(&self, field: u32) -> Option<Field> {
        if self.field_type(field, fields::ETH_BASE) && self.has_layer(LayerIndex::ETH) {
            if let Some(eth_packet) = self.get_eth_packet() {
                return eth_packet.get_field(field);
            } else {
                None
            }
        } else if self.field_type(field, fields::ARP_BASE) && self.arp_packet.is_some() {
            self.arp_packet.as_ref().unwrap().get_field(field)
        } else if self.field_type(field, fields::TCP_BASE) && self.has_layer(LayerIndex::TCP) {
            if let Some(tcp_packet) = self.get_tcp_packet() {
                return tcp_packet.get_field(field);
            } else {
                None
            }
        } else if self.field_type(field, fields::IPV4_BASE) && self.has_layer(LayerIndex::IPv4) {
            if let Some(ip_packet) = self.get_ipv4_packet() {
                return ip_packet.get_field(field);
            } else {
                None
            }
        } else if self.field_type(field, fields::UDP_BASE) && self.has_layer(LayerIndex::UDP) {
            if let Some(udp_packet) = self.get_udp_packet() {
                udp_packet.get_field(field)
            } else {
                None
            }
        } else if self.field_type(field, fields::FRAME_BASE) && self.has_layer(LayerIndex::FRAME) {
            if let Some(frame_packet) = self.get_frame_packet() {
                frame_packet.get_field(field)
            } else {
                None
            }
        } else if self.field_type(field, fields::ICMP_BASE) && self.has_layer(LayerIndex::ICMP) {
            if let Some(pkt_bytes) = self.get_layer_bytes(LayerIndex::ICMP) {
                let icmp = Icmp::new(pkt_bytes);
                icmp.get_field(field)
            } else {
                None
            }
        } else if self.field_type(field, fields::DNS_BASE) && self.has_layer(LayerIndex::DNS) {
            if let Some(dns_packet) = self.get_dns_packet() {
                dns_packet.get_field(field)
            } else {
                None
            }
        } else if self.field_type(field, fields::DHCP_BASE) && self.has_layer(LayerIndex::DHCP) {
            if let Some(dhcp_packet) = self.get_dhcp_packet() {
                dhcp_packet.get_field(field)
            } else {
                None
            }
        } else if self.field_type(field, fields::NTP_BASE) && self.has_layer(LayerIndex::NTP) {
            if let Some(ntp_packet) = self.get_ntp_packet() {
                ntp_packet.get_field(field)
            } else {
                None
            }
        } else {
            None
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
        if self.field_type(field, fields::TCP_BASE) && self.has_layer(LayerIndex::TCP) {
            if let Some(ip_packet) = self.get_tcp_packet() {
                return ip_packet.payload_range(offset, len);
            }
        } else if self.field_type(field, fields::UDP_BASE) && self.has_layer(LayerIndex::UDP) {
            if let Some(udp_packet) = self.get_udp_packet() {
                return udp_packet.payload_range(offset, len);
            }
        } else if self.field_type(field, fields::ICMP_BASE) && self.has_layer(LayerIndex::ICMP) {
            if let Some(pkt_bytes) = self.get_layer_bytes(LayerIndex::ICMP) {
                let icmp = Icmp::new(pkt_bytes);
                return icmp.payload_range(offset, len);
            }
        } else if self.field_type(field, fields::ETH_BASE) && self.has_layer(LayerIndex::ETH) {
            if let Some(eth) = self.get_eth_packet() {
                return eth.payload_range(offset, len);
            }
        }

        let pkt: Vec<u8> = Vec::new();
        pkt
    }
}

impl PacketDisplay for Packet {
    fn summary(&self) -> String {
        let mut result: String = String::new();

        if let Some(eth) = &self.get_eth_packet() {
            result += &eth.summary();
        }

        if self.has_layer(LayerIndex::ETH) {
            if let Some(ip) = self.get_ipv4_packet() {
                result += &format!("  {}{}", ip.summary(), "\n");
            }
        }

        if let Some(ip) = self.get_ipv4_packet() {
            if ip.proto() == IP_TCP_PROTO {
                if let Some(tcp) = self.get_tcp_packet() {
                    result += &format!("    {}\n", &tcp.summary());
                }
            }
            if ip.proto() == IP_UDP_PROTO {
                if let Some(udp) = self.get_udp_packet() {
                    result += &format!("    {}\n", &udp.summary());
                }
            }

            if ip.proto() == IP_ICMP_PROTO {
                if let Some(pkt_bytes) = self.get_layer_bytes(LayerIndex::ICMP) {
                    let icmp = Icmp::new(pkt_bytes);
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

// #[cfg(test)]
// mod tests {
//     use super::*;
// }
