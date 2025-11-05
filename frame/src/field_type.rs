pub const BOOL: u16 = 0;
pub const INT8: u16 = 1;
pub const INT16: u16 = 2;
pub const INT32: u16 = 3;
pub const INT64: u16 = 4;
pub const IPV4: u16 = 5;
pub const MACADDR: u16 = 6;
pub const TIMESTAMP: u16 = 7;
pub const TIMEVALUE: u16 = 8;
pub const IPV6: u16 = 9;
pub const BYTE_ARRAY: u16 = 0x0a;
pub const STRING: u16 = 0x0b;
pub const FIELD_ARRAY: u16 = 0x0c;

pub fn get_type_len(field_type: u16) -> u16 {
    match field_type {
        BOOL => 1 as u16,
        INT8 => 1 as u16,
        INT16 => 2 as u16,
        INT32 => 4 as u16,
        INT64 => 8 as u16,
        IPV4 => 4 as u16,
        MACADDR => 6 as u16,
        TIMESTAMP => 4 as u16,
        TIMEVALUE => 4 as u16,
        IPV6 => 8 as u16,
        _ => 0 as u16,
    }
}
