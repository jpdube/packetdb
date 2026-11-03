use crate::{layer::Layer, net_field};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use field::pfield::{Field, FieldType};

#[derive(Debug, Clone, Default)]
pub struct Frame<'a> {
    raw_packet: &'a [u8],
    little_endian: bool,
    file_id: u32,
    pkt_ptr: u32,
}

impl<'a> Frame<'a> {
    pub fn new(packet: &'a [u8], file_id: u32, pkt_ptr: u32) -> Self {
        Self {
            raw_packet: packet,
            little_endian: BigEndian::read_u32(&packet[0..4]) != 0xa1b2c3d4,
            file_id,
            pkt_ptr,
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
    pub fn get_id(&self) -> u64 {
        let mut result: u64 = self.file_id as u64;

        result <<= 32;
        result |= self.pkt_ptr as u64;

        result
    }
}

impl<'a> Layer for Frame<'a> {
    fn get_name(&self) -> String {
        "frame".to_string()
    }

    fn get_field(&self, field: u32) -> Option<Field> {
        match field {
            net_field::FRAME_TIMESTAMP => {
                Some(Field::set_field(FieldType::Int32(self.timestamp()), field))
            }
            net_field::FRAME_OFFSET => {
                Some(Field::set_field(FieldType::Int32(self.ts_offset()), field))
            }
            net_field::FRAME_INC_LEN => {
                Some(Field::set_field(FieldType::Int32(self.inc_len()), field))
            }
            net_field::FRAME_ORIG_LEN => {
                Some(Field::set_field(FieldType::Int32(self.orig_len()), field))
            }
            net_field::FRAME_ID => Some(Field::set_field(FieldType::Int64(self.get_id()), field)),

            _ => None,
        }
    }

    fn get_field_bytes(&self, _field_name: String) -> Option<Vec<u8>> {
        None
    }
}
