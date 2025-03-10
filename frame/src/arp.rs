use byteorder::{BigEndian, ByteOrder};

use crate::fields;
use crate::ipv4_address::IPv4;
use crate::layer::Layer;
use crate::mac_address::MacAddr;
use crate::packet_display::PacketDisplay;
use crate::pfield::{Field, FieldType};

/*
*
* ARP dissector
*
*/

#[derive(Debug, Clone, Default)]
pub struct Arp {
    raw_packet: Vec<u8>,
    name: String,
}

impl Arp {
    pub fn set_packet(&mut self, packet: Vec<u8>) {
        self.raw_packet = packet.clone();
    }

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

impl Layer for Arp {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_field(&self, field: u32) -> Option<Field> {
        match field {
            fields::ARP_HTYPE => Some(Field::set_field(FieldType::Int16(self.get_htype()), field)),
            fields::ARP_PTYPE => Some(Field::set_field(FieldType::Int16(self.get_ptype()), field)),
            fields::ARP_HLEN => Some(Field::set_field(FieldType::Int8(self.get_hlen()), field)),
            fields::ARP_PLEN => Some(Field::set_field(FieldType::Int8(self.get_hlen()), field)),

            fields::ARP_OPCODE => {
                Some(Field::set_field(FieldType::Int16(self.get_opcode()), field))
            }
            fields::ARP_SHA => Some(Field::set_field(FieldType::MacAddr(self.get_sha()), field)),
            fields::ARP_THA => Some(Field::set_field(FieldType::MacAddr(self.get_tha()), field)),

            fields::ARP_SPA => Some(Field::set_field(FieldType::Ipv4(self.get_spa(), 32), field)),
            fields::ARP_TPA => Some(Field::set_field(FieldType::Ipv4(self.get_tpa(), 32), field)),

            _ => None,
        }
    }

    fn get_field_bytes(&self, _field_name: u32) -> Option<Vec<u8>> {
        None
    }
}

impl PacketDisplay for Arp {
    fn summary(&self) -> String {
        let result: String;

        result = format!(
            "Eth -> SHA: {}, SPA: {} THA: {} TPA: {}\n",
            MacAddr::set_from_int(&self.get_sha()).to_string(),
            IPv4::new(self.get_spa(), 32).to_string(),
            MacAddr::set_from_int(&self.get_tha()).to_string(),
            IPv4::new(self.get_tpa(), 32).to_string(),
        );

        result
    }

    fn show_detail(&self) -> String {
        "Arp detail".to_string()
    }
}
