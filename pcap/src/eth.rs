use byteorder::{BigEndian, ByteOrder};
use field::pfield::{Field, FieldType};

pub fn get_eth(packet: &[u8], field_name: &str) -> Option<Field> {
    match field_name {
        "has_ipv4" => {
            return Some(Field::set_field(
                FieldType::Bool(has_ipv4(&packet)),
                field_name,
            ));
        }
        "has_vlan" => {
            return Some(Field::set_field(
                FieldType::Bool(has_vlan(&packet)),
                field_name,
            ));
        }
        "src" => {
            return Some(Field::set_field(
                FieldType::MacAddr(BigEndian::read_u48(&packet[0..6])),
                field_name,
            ));
        }
        "dst" => {
            return Some(Field::set_field(
                FieldType::MacAddr(BigEndian::read_u48(&packet[6..12])),
                field_name,
            ));
        }
        "type" => {
            return Some(Field::set_field(
                FieldType::Int16(ethertype(&packet)),
                field_name,
            ));
        }
        "vlan" => {
            let vlan: u16 = if has_vlan(&packet) {
                BigEndian::read_u16(&packet[14..16])
            } else {
                1
            };

            return Some(Field::set_field(FieldType::Int16(vlan), field_name));
        }
        _ => return None,
    };
}

pub fn has_vlan(packet: &[u8]) -> bool {
    BigEndian::read_u16(&packet[12..14]) == 0x8100
}

pub fn ethertype(packet: &[u8]) -> u16 {
    if has_vlan(&packet) {
        BigEndian::read_u16(&packet[16..18])
    } else {
        BigEndian::read_u16(&packet[12..14])
    }
}

pub fn has_ipv4(packet: &[u8]) -> bool {
    let eth_type: u16 = if BigEndian::read_u16(&packet[12..14]) == 0x8100 {
        BigEndian::read_u16(&packet[16..18])
    } else {
        BigEndian::read_u16(&packet[12..14])
    };

    eth_type == 0x0800
}
