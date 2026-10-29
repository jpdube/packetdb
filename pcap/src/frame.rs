use byteorder::{BigEndian, ByteOrder, LittleEndian};
use field::pfield::{Field, FieldType};

pub fn get_frame(header: &[u8], field_name: &str, little_endian: bool) -> Option<Field> {
    // println!("FRAME: timestamp: {}", field_name);
    match field_name {
        "timestamp" => {
            return Some(Field::set_field(
                FieldType::Int32(if little_endian {
                    LittleEndian::read_u32(&header[0..4])
                } else {
                    BigEndian::read_u32(&header[0..4])
                }),
                field_name,
            ));
        }
        "ts_offset" => {
            return Some(Field::set_field(
                FieldType::Int32(if little_endian {
                    LittleEndian::read_u32(&header[4..8])
                } else {
                    BigEndian::read_u32(&header[4..8])
                }),
                field_name,
            ));
        }

        "inc_len" => {
            return Some(Field::set_field(
                FieldType::Int32(if little_endian {
                    LittleEndian::read_u32(&header[8..12])
                } else {
                    BigEndian::read_u32(&header[8..12])
                }),
                field_name,
            ));
        }

        "orig_len" => {
            return Some(Field::set_field(
                FieldType::Int32(if little_endian {
                    LittleEndian::read_u32(&header[12..16])
                } else {
                    BigEndian::read_u32(&header[12..16])
                }),
                field_name,
            ));
        }
        _ => None,
    }
}
