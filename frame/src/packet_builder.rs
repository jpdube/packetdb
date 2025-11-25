use byteorder::{BigEndian, ByteOrder};
use std::collections::HashMap;

#[derive(Eq, Hash, PartialEq)]
pub enum LayerName {
    Ethernet,
    Arp,
    IPv4,
    IPv6,
    Udp,
    Tcp,
    Icmp,
    Ssh,
    Telnet,
    SMBv1,
    SMBv2,
    HTTPS,
    HTTP,
    DNS,
    DHCP,
}

#[derive(Default)]
pub struct PktLayer {
    offset: usize,
    length: usize,
}

#[derive(Default)]
pub struct PacketBuilder {
    layers_list: HashMap<LayerName, PktLayer>,
    pub file_id: u32,
    pub pkt_ptr: u32,
    pub raw_packet: Vec<u8>,
    pub header: Vec<u8>,
}

impl PacketBuilder {
    pub fn new() -> Self {
        PacketBuilder {
            layers_list: HashMap::new(),
            file_id: 0,
            pkt_ptr: 0,
            raw_packet: Vec::new(),
            header: Vec::new(),
        }
    }

    pub fn add_packet(&mut self, header: Vec<u8>, raw_packet: Vec<u8>) {
        let mut layer = PktLayer::default();

        self.header = header;
        self.raw_packet = raw_packet;

        layer.offset = 0;
        layer.length = 16;

        self.layers_list.insert(LayerName::Ethernet, layer);

        //--- Set the ethernet layer
        self.set_ethernet();
    }

    fn set_ethernet(&mut self) {
        let header = BigEndian::read_u16(&self.raw_packet[12..14]);

        let vo: usize = if header == 0x8100 { 18 } else { 14 };

        let layer = PktLayer {
            offset: 0,
            length: vo,
        };

        self.layers_list.insert(LayerName::Ethernet, layer);
    }
}
