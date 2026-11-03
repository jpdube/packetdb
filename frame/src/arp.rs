use byteorder::{BigEndian, ByteOrder};

use crate::layer::Layer;
use crate::net_field;
use crate::packet_display::PacketDisplay;
use field::ipv4_address::IPv4;
use field::mac_address::MacAddr;
use field::pfield::{Field, FieldType};

/*
*
* ARP dissector
*
*/

#[derive(Debug, Clone)]
pub struct Arp<'a> {
    raw_packet: &'a [u8],
    // name: String,
}

impl<'a> Arp<'a> {
    pub fn new(packet: &'a [u8]) -> Self {
        Self { raw_packet: packet }
    }
    // pub fn set_packet(&mut self, packet: Vec<u8>) {
    //     self.raw_packet = packet.clone();
    // }

    pub fn get_htype(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[0..2])
    }

    pub fn get_ptype(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[2..4])
    }

    pub fn get_hlen(&self) -> u8 {
        self.raw_packet[4]
    }

    pub fn get_plen(&self) -> u8 {
        self.raw_packet[5]
    }

    pub fn get_opcode(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[6..8])
    }

    pub fn get_sha(&self) -> u64 {
        BigEndian::read_u48(&self.raw_packet[8..14])
    }

    pub fn get_spa(&self) -> u32 {
        BigEndian::read_u32(&self.raw_packet[14..18])
    }

    pub fn get_tha(&self) -> u64 {
        BigEndian::read_u48(&self.raw_packet[18..24])
    }

    pub fn get_tpa(&self) -> u32 {
        BigEndian::read_u32(&self.raw_packet[24..28])
    }
}

impl<'a> Layer for Arp<'a> {
    fn get_name(&self) -> String {
        "arp".to_string()
        // self.name.clone()
    }

    fn get_field(&self, field: u32) -> Option<Field> {
        match field {
            net_field::ARP_HTYPE => {
                Some(Field::set_field(FieldType::Int16(self.get_htype()), field))
            }
            net_field::ETH_PROTO => {
                Some(Field::set_field(FieldType::Int16(self.get_ptype()), field))
            }
            net_field::ARP_HLEN => Some(Field::set_field(FieldType::Int8(self.get_hlen()), field)),

            net_field::ARP_OPCODE => {
                Some(Field::set_field(FieldType::Int16(self.get_opcode()), field))
            }
            net_field::ARP_SHA => Some(Field::set_field(FieldType::MacAddr(self.get_sha()), field)),
            net_field::ARP_THA => Some(Field::set_field(FieldType::MacAddr(self.get_tha()), field)),

            net_field::ARP_SPA => {
                Some(Field::set_field(FieldType::Ipv4(self.get_spa(), 32), field))
            }
            net_field::ARP_TPA => {
                Some(Field::set_field(FieldType::Ipv4(self.get_tpa(), 32), field))
            }

            _ => None,
        }
    }

    fn get_field_bytes(&self, _field_name: String) -> Option<Vec<u8>> {
        None
    }
}

impl<'a> PacketDisplay for Arp<'a> {
    fn summary(&self) -> String {
        format!(
            "Eth -> SHA: {}, SPA: {} THA: {} TPA: {}\n",
            MacAddr::set_from_int(&self.get_sha()),
            IPv4::new(self.get_spa(), 32),
            MacAddr::set_from_int(&self.get_tha()),
            IPv4::new(self.get_tpa(), 32),
        )
    }

    fn show_detail(&self) -> String {
        "Arp detail".to_string()
    }
}
