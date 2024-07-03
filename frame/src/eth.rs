use crate::fields;
use crate::layer::Layer;
use crate::mac_address::mac_to_string;
use crate::packet_display::PacketDisplay;

use byteorder::{BigEndian, ByteOrder};

const ETHER_8021Q: u16 = 0x8100;

#[derive(Debug, Clone, Default)]
pub struct EtherFrame {
    raw_packet: Vec<u8>,
    name: String,
}

impl EtherFrame {
    pub fn set_packet(&mut self, packet: Vec<u8>) {
        self.raw_packet = packet.clone();
    }

    pub fn dst(&self) -> u64 {
        BigEndian::read_u48(&self.raw_packet[0..6])
    }

    pub fn src(&self) -> u64 {
        BigEndian::read_u48(&self.raw_packet[6..12])
    }

    pub fn header(&self) -> u16 {
        BigEndian::read_u16(&self.raw_packet[12..14])
    }

    pub fn ethertype(&self) -> u16 {
        if self.header() != ETHER_8021Q {
            self.header()
        } else {
            BigEndian::read_u16(&self.raw_packet[16..18])
        }
    }

    pub fn vlan_id(&self) -> u16 {
        if self.header() == ETHER_8021Q {
            BigEndian::read_u16(&self.raw_packet[14..16])
        } else {
            1
        }
    }

    pub fn payload_range(&self, offset: usize, len: usize) -> Vec<u8> {
        self.raw_packet[offset..offset + len].to_vec()
    }
}

impl Layer for EtherFrame {
    fn get_name(&self) -> String {
        return self.name.clone();
    }

    // fn get_field(&self, field: u32) -> FieldResult {
    fn get_field(&self, field: u32) -> usize {
        match field {
            // fields::ETH_SRC_MAC => FieldResult::Uint(self.src() as usize),
            fields::ETH_SRC_MAC => self.src() as usize,
            // fields::ETH_DST_MAC => FieldResult::Uint(self.dst() as usize),
            fields::ETH_DST_MAC => self.dst() as usize,
            // fields::ETH_PROTO => FieldResult::Uint(self.ethertype() as usize),
            fields::ETH_PROTO => self.ethertype() as usize,
            // fields::ETH_VLAN_ID => FieldResult::Uint(self.vlan_id() as usize),
            fields::ETH_VLAN_ID => self.vlan_id() as usize,
            _ => 0,
        }
    }

    fn get_field_bytes(&self, _field_name: u32) -> Option<Vec<u8>> {
        None
    }
}

impl PacketDisplay for EtherFrame {
    fn summary(&self) -> String {
        let result: String;

        result = format!(
            "Eth -> DMac: {}, SMac: {} Etype: {:04x} Vlan: {}\n",
            mac_to_string(&self.dst()),
            mac_to_string(&self.src()),
            self.ethertype(),
            self.vlan_id(),
        );

        result
    }

    fn show_detail(&self) -> String {
        "Eth detail".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etherframe_with_vlan() {
        let packet: Vec<u8> = vec![
            0x00, 0x0c, 0x29, 0x24, 0xb8, 0xaf, 0xe8, 0x1c, 0xba, 0x17, 0x7d, 0x6a, 0x81, 0x00,
            0x00, 0x3d, 0x08, 0x00, 0x45, 0x00, 0x01, 0x54, 0x0e, 0x3c, 0x40, 0x00, 0x7d, 0x06,
            0x01, 0xc8, 0xc0, 0xa8, 0x67, 0x64, 0xc0, 0xa8, 0x03, 0xeb, 0xc8, 0xcf, 0x01, 0xbd,
            0x1e, 0x54, 0x73, 0xc3, 0xe4, 0x56, 0x89, 0x7c, 0x50, 0x18, 0x20, 0x35, 0x7c, 0xbf,
            0x00, 0x00,
        ];

        let mut pkt = EtherFrame::default();
        pkt.set_packet(packet);

        assert_eq!(pkt.ethertype(), 0x0800, "Ethertype");
        assert_eq!(pkt.header(), 0x8100, "Eth vlan");
        assert_eq!(pkt.dst(), 0x000c2924b8af, "Eth dst mac");
        assert_eq!(pkt.src(), 0xe81cba177d6a, "Eth src mac");
    }
}
