use crate::fields;
use crate::layer::Layer;
use crate::pfield::{Field, FieldType};
use byteorder::{BigEndian, ByteOrder, LittleEndian};

#[derive(Debug, Clone, Default)]
pub struct Frame<'a> {
    raw_packet: &'a [u8],
    little_endian: bool,
}

impl<'a> Frame<'a> {
    pub fn new(packet: &'a [u8], little_endian: bool) -> Self {
        Self {
            raw_packet: packet,
            little_endian,
        }
    }

    pub fn timestamp(&self) -> u32 {
        if self.little_endian {
            LittleEndian::read_u32(&self.raw_packet[0..4])
        } else {
            BigEndian::read_u32(&self.raw_packet[0..4])
        }
    }
    pub fn ts_offset(&self) -> u32 {
        if self.little_endian {
            LittleEndian::read_u32(&self.raw_packet[4..8])
        } else {
            BigEndian::read_u32(&self.raw_packet[4..8])
        }
    }
    pub fn inc_len(&self) -> u32 {
        if self.little_endian {
            LittleEndian::read_u32(&self.raw_packet[8..12])
        } else {
            BigEndian::read_u32(&self.raw_packet[8..12])
        }
    }
    pub fn orig_len(&self) -> u32 {
        if self.little_endian {
            LittleEndian::read_u32(&self.raw_packet[12..16])
        } else {
            BigEndian::read_u32(&self.raw_packet[12..16])
        }
    }
}

impl<'a> Layer for Frame<'a> {
    fn get_name(&self) -> String {
        "frame".to_string()
    }

    fn get_field(&self, field: u32) -> Option<Field> {
        match field {
            fields::FRAME_TIMESTAMP => {
                Some(Field::set_field(FieldType::Int32(self.timestamp()), field))
            }
            fields::FRAME_OFFSET => {
                Some(Field::set_field(FieldType::Int32(self.ts_offset()), field))
            }
            fields::FRAME_INC_LEN => {
                Some(Field::set_field(FieldType::Int32(self.inc_len()), field))
            }
            fields::FRAME_ORIG_LEN => {
                Some(Field::set_field(FieldType::Int32(self.orig_len()), field))
            }

            _ => None,
        }
    }

    fn get_field_bytes(&self, _field_name: u32) -> Option<Vec<u8>> {
        None
    }
}
